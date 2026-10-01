"""Operator authority; remote effects are performed only by the leased worker."""

from uuid import uuid4
from psycopg.types.json import Jsonb
from appchi.access import authorize
from appchi.operators import keys
from appchi.operators.grafana import OperatorRouting
from appchi.operators.policy import normalized_name
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import command_result, coordinator, revision, save_result, wire


def get_operator(conn, tenant, identifier, *, lock=False, deleted=False):
    row = conn.execute(
        "SELECT * FROM operators WHERE tenant_id=%s AND id=%s"
        + ("" if deleted else " AND lifecycle<>'deleted'")
        + (" FOR UPDATE" if lock else ""),
        (tenant, identifier),
    ).fetchone()
    if not row:
        raise AppError("not_found", "Operator unavailable.", 404)
    return row


def routing(conn, operator_row):
    pending = operator_row.get("pending_name")
    if not pending:
        return OperatorRouting(operator_row["name"])
    claims = conn.execute(
        "SELECT name_key FROM operator_name_claims WHERE tenant_id=%s AND operator_id=%s",
        (operator_row["tenant_id"], operator_row["id"]),
    ).fetchall()
    held = {row["name_key"] for row in claims}
    operation = active_operation(conn, operator_row)
    proof = bool(
        operation
        and operation["generation"] == operator_row["generation"]
        and operation["kind"] in ("setup", "rename", "cancel", "delete")
    )
    return OperatorRouting(
        operator_row["name"],
        pending,
        proof,
        {operator_row["name_key"], operator_row["pending_name_key"]} <= held,
    )


def active_operation(conn, row):
    return conn.execute(
        "SELECT * FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND completed_at IS NULL",
        (row["tenant_id"], row["id"]),
    ).fetchone()


def credential_rows(conn, row):
    return conn.execute(
        "SELECT * FROM operator_credentials WHERE tenant_id=%s AND operator_id=%s ORDER BY id FOR UPDATE",
        (row["tenant_id"], row["id"]),
    ).fetchall()


def credential_states(rows):
    return tuple(
        keys.Credential(
            str(r["id"]),
            r["state"],
            r["activated_at"],
            r["expires_at"],
            r["revoked_at"],
            r["ciphertext"] is not None,
        )
        for r in rows
    )


def persist_credentials(conn, states):
    # Move old current out of its unique slot before activating its replacement.
    order = {"revoked": 0, "expired": 0, "prepared": 1, "retiring": 2, "current": 3}
    for key in sorted(states, key=lambda k: order[k.state]):
        conn.execute(
            "UPDATE operator_credentials SET state=%s,activated_at=%s,expires_at=%s,revoked_at=%s,"
            "ciphertext=CASE WHEN %s THEN ciphertext ELSE NULL END WHERE id=%s",
            (
                key.state,
                key.activated_at,
                key.expires_at,
                key.revoked_at,
                key.has_ciphertext,
                key.id,
            ),
        )


def audit(conn, row, actor, kind, evidence):
    conn.execute(
        "INSERT INTO operator_activity(id,tenant_id,operator_id,actor_id,actor_label,kind,evidence) VALUES(%s,%s,%s,%s,%s,%s,%s)",
        (
            uuid4(),
            row["tenant_id"],
            row["id"],
            actor.get("id"),
            actor.get("display_name", "system"),
            kind,
            Jsonb(wire(evidence)),
        ),
    )


def claim_name(conn, row, name):
    display, key = normalized_name(name)
    claim = conn.execute(
        "INSERT INTO operator_name_claims(name_key,tenant_id,operator_id,name) VALUES(%s,%s,%s,%s) "
        "ON CONFLICT(name_key) DO NOTHING RETURNING operator_id",
        (key, row["tenant_id"], row["id"], display),
    ).fetchone()
    if not claim:
        claim = conn.execute(
            "SELECT operator_id FROM operator_name_claims WHERE tenant_id=%s AND operator_id=%s AND name_key=%s",
            (row["tenant_id"], row["id"], key),
        ).fetchone()
    if not claim:
        raise AppError("name_unavailable", "Operator name is unavailable.", 409)
    return display, key


def prepare(conn, row, cipher):
    identifier = uuid4()
    material = keys.generate_key()
    ciphertext = cipher.seal(material.value.encode(), f"operator-key:{row['id']}:{identifier}:1")
    conn.execute(
        "INSERT INTO operator_credentials(id,tenant_id,operator_id,state,verifier,ciphertext) VALUES(%s,%s,%s,'prepared',%s,%s)",
        (identifier, row["tenant_id"], row["id"], material.verifier, ciphertext),
    )
    return identifier


def enqueue(conn, row, actor, kind, *, candidate=None, progress=None):
    return conn.execute(
        "INSERT INTO operator_operations(id,tenant_id,operator_id,kind,generation,candidate_id,actor_id,actor_label,progress) "
        "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
        (
            uuid4(),
            row["tenant_id"],
            row["id"],
            kind,
            row["generation"],
            candidate,
            actor.get("id"),
            actor.get("display_name", "system"),
            Jsonb(progress or {}),
        ),
    ).fetchone()


def bump(conn, row, *, generation=True):
    return conn.execute(
        "UPDATE operators SET revision=revision+1,generation=generation+%s,updated_at=clock_timestamp(),"
        "integration_health='pending' WHERE tenant_id=%s AND id=%s RETURNING *",
        (int(generation), row["tenant_id"], row["id"]),
    ).fetchone()


def public(conn, row, *, admin=False):
    result = {
        key: row[key]
        for key in (
            "id",
            "tenant_id",
            "name",
            "pending_name",
            "lifecycle",
            "revision",
            "integration_health",
            "deletion_pending",
            "created_at",
            "updated_at",
            "last_reconciled_at",
        )
    }
    valid = conn.execute(
        "SELECT id,state,expires_at FROM operator_credentials WHERE tenant_id=%s AND operator_id=%s "
        "AND (state='current' OR (state='retiring' AND expires_at>clock_timestamp())) ORDER BY id",
        (row["tenant_id"], row["id"]),
    ).fetchall()
    job = active_operation(conn, row)
    copy_fenced = row["deletion_pending"] or bool(job and (
        job["progress"].get("activation_pending") or job["progress"].get("final_policy_pending")))
    result["current_key_available"] = not copy_fenced and any(r["state"] == "current" for r in valid)
    result["retiring_key_deadline"] = next(
        (r["expires_at"] for r in valid if r["state"] == "retiring"), None
    )
    if admin:
        result["keys"] = [
            dict(r)
            for r in conn.execute(
                "SELECT id,state,activated_at,expires_at,revoked_at,created_at FROM operator_credentials WHERE tenant_id=%s AND operator_id=%s ORDER BY created_at,id",
                (row["tenant_id"], row["id"]),
            )
        ]
        result["operation"] = operation_public(job) if job else None
    return wire(result)


def operation_public(job):
    result = {
        key: job[key]
        for key in (
            "id",
            "operator_id",
            "kind",
            "state",
            "step",
            "attempts",
            "next_attempt_at",
            "error_code",
            "created_at",
            "completed_at",
        )
    }
    result["restoring_cancellation"] = job["kind"] == "cancel" or bool(
        job["progress"].get("restore_cancel")
    )
    result["cancellation_kind"] = (
        job["progress"].get("cancel_kind") if result["restoring_cancellation"] else None
    )
    return wire(result)


def response(conn, row, operation=None):
    return {
        "data": {
            "operator": public(conn, row, admin=True),
            "operation": operation_public(operation) if operation else None,
        },
        "meta": {"revision": str(row["revision"])},
    }


def in_use(conn, row):
    retained = conn.execute(
        "SELECT count(*) AS n FROM alerts a JOIN alert_identities i ON i.id=a.id AND i.tenant_id=a.tenant_id "
        "WHERE a.tenant_id=%s AND a.operator=%s AND a.schema_version='v2' AND i.retired_at IS NULL",
        (row["tenant_id"], str(row["id"])),
    ).fetchone()["n"]
    pending = conn.execute(
        "SELECT count(*) AS n FROM ingest_items WHERE tenant_id=%s AND operator_id=%s AND disposition='pending'",
        (row["tenant_id"], row["id"]),
    ).fetchone()["n"]
    if retained or pending:
        raise AppError(
            "operator_in_use",
            "Retained alerts or pending inputs prevent deletion.",
            409,
            fields={"retained_alerts": str(retained), "pending_inputs": str(pending)},
        )


def create(request, tenant, body):
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "admin", mutation=True)
        scope = f"{tenant}:{actor['id']}:operator-create"
        prior, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if prior is not None:
            return prior
        if (
            conn.execute("SELECT kind FROM tenants WHERE id=%s", (tenant,)).fetchone()["kind"]
            == "global"
        ):
            raise AppError(
                "global_operator_forbidden", "Managed operators require a specific tenant.", 422
            )
        coordinator(conn, tenant)
        name, key = normalized_name(body.name)
        row = conn.execute(
            "INSERT INTO operators(id,tenant_id,name,name_key,lifecycle) VALUES(%s,%s,%s,%s,'setup_pending') RETURNING *",
            (uuid4(), tenant, name, key),
        ).fetchone()
        claim_name(conn, row, name)
        candidate = prepare(conn, row, request.app.state.settings.cipher())
        job = enqueue(conn, row, actor, "setup", candidate=candidate)
        audit(
            conn,
            row,
            actor,
            "operator-created",
            {"operation_id": job["id"], "credential_id": candidate},
        )
        return save_result(conn, scope, body.command_id, fp, response(conn, row, job), 202)


def mutate(request, tenant, identifier, body, action, target=None):
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "admin", mutation=True)
        scope = f"{tenant}:{actor['id']}:operator:{action}"
        prior, fp = command_result(
            conn,
            scope,
            body.command_id,
            {"operator": identifier, "target": target, **body.model_dump()},
        )
        if prior is not None:
            return prior
        _, now = coordinator(conn, tenant)
        row = get_operator(conn, tenant, identifier, lock=True, deleted=action == "retry")
        revision(row, body.expected_revision)
        job = active_operation(conn, row)
        rows = credential_rows(conn, row)
        states = keys.expire(credential_states(rows), now)
        persist_credentials(conn, states)
        superseded_operation = None
        if action in ("rotate", "create_key"):
            restoration = {}
            if action == "create_key" and job and job["kind"] in ("cleanup", "cancel"):
                # A keyless operator must be able to recover while old remote
                # cleanup is pending. The new generation removes invalid IDs
                # before proving the replacement; late cleanup cannot commit.
                superseded_operation = job["id"]
                if job["kind"] == "cancel" or job["progress"].get("restore_cancel"):
                    restoration = {
                        "restore_cancel": True,
                        "cancel_kind": job["progress"]["cancel_kind"],
                        "cancel_operation_id": job["progress"].get("cancel_operation_id"),
                    }
                conn.execute(
                    "UPDATE operator_operations SET state='superseded',completed_at=%s,lease_token=NULL,lease_until=NULL WHERE id=%s",
                    (now, job["id"]),
                )
                job = None
            if job or (row["deletion_pending"] and restoration.get("cancel_kind") != "delete"):
                raise AppError("operation_pending", "A management operation is pending.", 409)
            keys.can_prepare(states, now, rotation=action == "rotate")
            row = bump(conn, row)
            candidate = prepare(conn, row, request.app.state.settings.cipher())
            job = enqueue(conn, row, actor, action, candidate=candidate, progress=restoration)
        elif action == "rename":
            if body.name == row["name"] and not row["pending_name"]:
                return save_result(conn, scope, body.command_id, fp, response(conn, row, job))
            if row["deletion_pending"] or (job and job["kind"] != "setup") or row["pending_name"]:
                raise AppError("operation_pending", "A management operation is pending.", 409)
            name, key = claim_name(conn, row, body.name)
            row = bump(conn, row)
            conn.execute(
                "UPDATE operators SET pending_name=%s,pending_name_key=%s WHERE id=%s",
                (name, key, row["id"]),
            )
            if job:
                conn.execute(
                    "UPDATE operator_operations SET generation=%s,state='pending',progress='{}',lease_token=NULL,lease_until=NULL,next_attempt_at=%s WHERE id=%s",
                    (row["generation"], now, job["id"]),
                )
                job = active_operation(conn, row)
            else:
                job = enqueue(conn, row, actor, "rename")
        elif action in ("revoke", "revoke_all"):
            updated = keys.revoke(states, now, key_id=target if action == "revoke" else None)
            if updated != states:
                persist_credentials(conn, updated)
                row = bump(conn, row)
                cancelled_kind = None
                cancelled_progress = {}
                keyless_rename = (
                    job
                    and job["kind"] == "rename"
                    and not any(key.state == "current" for key in updated)
                )
                if job and (job["kind"] in ("setup", "rotate", "create_key") or keyless_rename):
                    cancelled_kind = job["kind"]
                    cancelled_progress = (
                        {
                            key: job["progress"].get(key)
                            for key in ("restore_cancel", "cancel_kind", "cancel_operation_id")
                        }
                        if job["progress"].get("restore_cancel")
                        else {"cancel_kind": cancelled_kind, "cancel_operation_id": str(job["id"])}
                    )
                    conn.execute(
                        "UPDATE operator_operations SET state='cancelled',completed_at=%s,lease_token=NULL,lease_until=NULL WHERE id=%s",
                        (now, job["id"]),
                    )
                    job = None
                if job:
                    conn.execute(
                        "UPDATE operator_operations SET generation=%s,state='pending',progress=%s,lease_token=NULL,lease_until=NULL,next_attempt_at=%s WHERE id=%s",
                        (
                            row["generation"],
                            Jsonb({**job["progress"], "uncertain": True}),
                            now,
                            job["id"],
                        ),
                    )
                    job = active_operation(conn, row)
                else:
                    job = enqueue(
                        conn,
                        row,
                        actor,
                        "cleanup",
                        progress=cancelled_progress,
                    )
        elif action == "delete":
            in_use(conn, row)
            if row["deletion_pending"]:
                raise AppError("operator_deletion_pending", "Deletion is already pending.", 409)
            if job:
                conn.execute(
                    "UPDATE operator_operations SET state='superseded',completed_at=%s,lease_token=NULL,lease_until=NULL WHERE id=%s",
                    (now, job["id"]),
                )
            row = bump(conn, row)
            conn.execute("UPDATE operators SET deletion_pending=true WHERE id=%s", (row["id"],))
            # Prepared candidates are fenced by generation/deletion; valid keys remain until verified deletion.
            job = enqueue(conn, row, actor, "delete")
        elif action in ("retry", "cancel"):
            if not job or str(job["id"]) != target:
                raise AppError(
                    "operation_not_pending", "Operation is unavailable or already complete.", 409
                )
            if action == "retry":
                conn.execute(
                    "UPDATE operator_operations SET next_attempt_at=%s,error_code=NULL,state=CASE WHEN state='running' THEN state ELSE 'pending' END WHERE id=%s",
                    (now, job["id"]),
                )
            else:
                if job["progress"].get("final_policy_pending"):
                    raise AppError("cancellation_unavailable", "The authoritative change has committed; final gateway verification is pending.", 409)
                if job["kind"] not in ("rotate", "rename", "delete"):
                    raise AppError(
                        "cancellation_unavailable", "This operation cannot be cancelled.", 409
                    )
                if job["kind"] == "rotate":
                    persist_credentials(
                        conn, keys.cancel_rotation(states, str(job["candidate_id"]), now)
                    )
                conn.execute(
                    "UPDATE operator_operations SET state='cancelled',completed_at=%s,lease_token=NULL,lease_until=NULL WHERE id=%s",
                    (now, job["id"]),
                )
                row = bump(conn, row)
                job = enqueue(
                    conn,
                    row,
                    actor,
                    "cancel",
                    progress={"cancel_kind": job["kind"], "cancel_operation_id": str(job["id"])},
                )
        else:
            raise ValueError("Unknown operator command")
        row = get_operator(conn, tenant, identifier, deleted=action == "retry")
        job = active_operation(conn, row)
        audit(
            conn,
            row,
            actor,
            "operator-" + action,
            {
                "operation_id": job["id"] if job else None,
                "credential_id": target if action == "revoke" else None,
                **(
                    {"superseded_operation_id": superseded_operation}
                    if superseded_operation
                    else {}
                ),
            },
        )
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            response(conn, row, job),
            202 if job else 200,
        )


def copy_current(request, tenant, identifier, body):
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "admin", mutation=True)
        scope = f"{tenant}:{actor['id']}:operator-copy"
        prior, fp = command_result(
            conn, scope, body.command_id, {"operator": identifier, **body.model_dump()}
        )
        _, now = coordinator(conn, tenant)
        row = get_operator(conn, tenant, identifier, lock=True)
        revision(row, body.expected_revision)
        operation = active_operation(conn, row)
        if operation and (operation["progress"].get("activation_pending") or operation["progress"].get("final_policy_pending")):
            raise AppError("gateway_activation_pending", "Gateway activation is not yet verified.", 409)
        rows = credential_rows(conn, row)
        key = keys.current_for_copy(
            credential_states(rows), now, deletion_pending=row["deletion_pending"]
        )
        record = next(r for r in rows if str(r["id"]) == key.id)
        try:
            secret = (
                request.app.state.settings.cipher()
                .open(bytes(record["ciphertext"]), f"operator-key:{identifier}:{key.id}:1")
                .decode()
            )
        except Exception:
            raise unavailable("credential_decryption_unavailable") from None
        # Never put the response in generic command receipts: it contains a secret.
        if prior is None:
            audit(
                conn,
                row,
                actor,
                "key-copy",
                {"credential_id": key.id, "command_id": body.command_id},
            )
            save_result(
                conn, scope, body.command_id, fp, {"data": {"credential_id": key.id}, "meta": {}}
            )
        return {
            "data": {"key": secret, "credential_id": key.id},
            "meta": {"revision": str(row["revision"])},
        }
