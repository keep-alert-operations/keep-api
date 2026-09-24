"""Protected rule retirement; remote durable acknowledgements never hold SQL locks."""

from dataclasses import asdict
from hashlib import sha256
from uuid import uuid4, uuid5

from psycopg.types.json import Jsonb

from appchi.access import ROLE_RANK, authorize, effective_role
from appchi.alerts.routes import delete_command
from appchi.ingestion.native import canonical
from appchi.recovery.evidence import Evidence, append_verified
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import command_result, coordinator, revision, save_result, wire
from . import repository as repo
from .runtime import lock_contexts


def _ready(conn):
    gate = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='recovery' FOR SHARE"
    ).fetchone()
    if not gate or not gate["ready"]:
        raise unavailable("recovery_not_ready")


def _evidence(job, state):
    return Evidence(
        str(job[state + "_id"]),
        str(job["tenant_id"]),
        "correlation",
        str(job["rule_id"]),
        job["expected_revision"] + 1,
        state,
        job["digest"],
    )


def _append(store, job, state):
    if store is None:
        raise unavailable("recovery_evidence_required")
    return Jsonb(asdict(append_verified(store, _evidence(job, state))))


def _authorized(conn, job, request):
    if request is not None:
        actor, _, _ = authorize(conn, request, job["tenant_id"], "edit", mutation=True)
        if actor["id"] != job["actor_id"]:
            raise AppError("access_changed", "Deletion authorization changed.", 403)
        return
    conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
    gate = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='human_auth' FOR SHARE"
    ).fetchone()
    if not gate or not gate["ready"]:
        raise unavailable("human_authorization_gated")
    actor = conn.execute("SELECT * FROM principals WHERE id=%s", (job["actor_id"],)).fetchone()
    if (
        not actor
        or actor["kind"] != "user"
        or actor["verified_at"] is None
        or actor["evidence_generation"] < 1
        or ROLE_RANK.get(effective_role(conn, actor, job["tenant_id"]), 0) < 2
    ):
        raise AppError("access_changed", "Deletion authorization changed.", 403)


def _retire(conn, job, row, now):
    tenant, rule = job["tenant_id"], job["rule_id"]
    boundary = conn.execute(
        "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order,change_order",
        (tenant,),
    ).fetchone()
    updated = conn.execute(
        "UPDATE correlation_rules SET revision=revision+1,epoch=epoch+1,enabled=false,health='blocked',blocked_reason='deleted',last_reset_reason='deleted',epoch_boundary_at=%s,epoch_boundary_order=%s,deleted_at=%s,updated_at=%s,updated_by=%s WHERE tenant_id=%s AND id=%s RETURNING revision,epoch,grouping_generation",
        (now, boundary["admission_order"], now, now, job["actor_id"], tenant, rule),
    ).fetchone()
    conn.execute(
        "UPDATE correlation_rule_identities SET deleted_at=%s,final_revision=%s WHERE tenant_id=%s AND id=%s",
        (now, updated["revision"], tenant, rule),
    )
    conn.execute(
        "DELETE FROM correlation_evidence WHERE tenant_id=%s AND rule_id=%s", (tenant, rule)
    )
    conn.execute(
        "INSERT INTO correlation_rule_controls(id,tenant_id,rule_id,revision,epoch,grouping_generation,effective_at,tenant_order,observed_change_order,kind) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'deleted')",
        (
            uuid4(),
            tenant,
            rule,
            updated["revision"],
            updated["epoch"],
            updated["grouping_generation"],
            now,
            boundary["admission_order"],
            boundary["change_order"],
        ),
    )
    snapshot = repo.public(repo.get_rule(conn, tenant, rule, include_deleted=True))
    conn.execute(
        "INSERT INTO correlation_rule_revisions(tenant_id,rule_id,revision,snapshot,action,reset_reason,changed_fields,command_id,recorded_at,actor_id,actor_label) VALUES(%s,%s,%s,%s,'deleted','deleted',%s,%s,%s,%s,%s)",
        (
            tenant,
            rule,
            updated["revision"],
            Jsonb(snapshot),
            Jsonb(["enabled", "deleted_at"]),
            job["command_id"],
            now,
            job["actor_id"],
            job["actor_label"],
        ),
    )
    conn.execute(
        "UPDATE correlation_consumer_state SET pending=true,updated_at=%s WHERE tenant_id=%s",
        (now, tenant),
    )
    generation = conn.execute(
        "UPDATE tenant_view_state SET resource_generation=resource_generation+1,view_generation=view_generation+1 WHERE tenant_id=%s RETURNING resource_generation",
        (tenant,),
    ).fetchone()["resource_generation"]
    conn.execute(
        "INSERT INTO application_outbox(id,tenant_id,stream,stream_order,envelope) VALUES(%s,%s,%s,%s,%s)",
        (
            uuid4(),
            tenant,
            "resource:correlation:" + str(rule),
            updated["revision"],
            canonical(
                wire(
                    {
                        "version": 1,
                        "tenant_id": tenant,
                        "resource_kind": "correlation",
                        "resource_id": rule,
                        "revision": updated["revision"],
                        "resource_generation": generation,
                    }
                )
            ),
        ),
    )
    return {
        "data": {
            "id": str(rule),
            "deleted": True,
            "revision": str(updated["revision"]),
            "operation_id": str(job["id"]),
        },
        "meta": {"revision": str(updated["revision"])},
    }


def _cancelled(job):
    code = job["error_code"] or "revision_conflict"
    return AppError(
        code,
        "Deletion was cancelled because authorization or the rule changed.",
        404
        if code == "not_found"
        else 403
        if code in {"access_changed", "forbidden", "unauthenticated"}
        else 409,
    )


def resume_delete(database, store, tenant_id, job_id, request=None):
    with database.transaction(tenant_id) as conn:
        _ready(conn)
        job = conn.execute(
            "SELECT * FROM correlation_delete_jobs WHERE tenant_id=%s AND id=%s",
            (tenant_id, job_id),
        ).fetchone()
    if not job:
        raise AppError("not_found", "Deletion operation unavailable.", 404)
    if job["state"] == "prepared":
        intent_ack = _append(store, job, "intent")
        with database.transaction(tenant_id) as conn:
            failure = None
            try:
                _authorized(conn, job, request)
            except AppError as error:
                if error.status >= 500:
                    raise
                failure = error
            _ready(conn)
            _, now = coordinator(conn, tenant_id)
            lock_contexts(conn, tenant_id)
            row = repo.get_rule(conn, tenant_id, job["rule_id"], include_deleted=True)
            job = conn.execute(
                "SELECT * FROM correlation_delete_jobs WHERE tenant_id=%s AND id=%s FOR UPDATE",
                (tenant_id, job_id),
            ).fetchone()
            if job["state"] == "prepared":
                if row["deleted_at"] is not None or row["revision"] != job["expected_revision"]:
                    failure = failure or AppError(
                        "revision_conflict", "Rule changed before deletion committed.", 409
                    )
                if failure:
                    conn.execute(
                        "UPDATE correlation_delete_jobs SET state='cancelled',intent_ack=%s,error_code=%s,updated_at=%s WHERE tenant_id=%s AND id=%s",
                        (intent_ack, failure.code, now, tenant_id, job_id),
                    )
                    job = {**job, "state": "cancelled", "error_code": failure.code}
                else:
                    receipt = _retire(conn, job, row, now)
                    conn.execute(
                        "UPDATE correlation_delete_jobs SET state='deleted',intent_ack=%s,receipt=%s,updated_at=%s WHERE tenant_id=%s AND id=%s",
                        (intent_ack, Jsonb(receipt), now, tenant_id, job_id),
                    )
                    job = {**job, "state": "deleted", "receipt": receipt}
    if job["state"] == "cancelled":
        if job["cancel_ack"] is None:
            ack = _append(store, job, "cancel")
            with database.transaction(tenant_id) as conn:
                conn.execute(
                    "UPDATE correlation_delete_jobs SET cancel_ack=%s,updated_at=clock_timestamp() WHERE tenant_id=%s AND id=%s AND state='cancelled'",
                    (ack, tenant_id, job_id),
                )
        raise _cancelled(job)
    if job["state"] == "deleted":
        ack = _append(store, job, "final")
        with database.transaction(tenant_id) as conn:
            _ready(conn)
            conn.execute(
                "SELECT id FROM correlation_delete_jobs WHERE tenant_id=%s AND id=%s FOR UPDATE",
                (tenant_id, job_id),
            )
            conn.execute(
                "UPDATE correlation_delete_jobs SET state='final_protected',final_ack=%s,updated_at=clock_timestamp() WHERE tenant_id=%s AND id=%s AND state='deleted'",
                (ack, tenant_id, job_id),
            )
            if not conn.execute(
                "SELECT 1 FROM command_receipts WHERE scope=%s AND command_id=%s",
                (job["scope"], job["command_id"]),
            ).fetchone():
                save_result(
                    conn,
                    job["scope"],
                    str(job["command_id"]),
                    bytes(job["fingerprint"]),
                    job["receipt"],
                )
    return job["receipt"]


def delete_rule(request, tenant_id, rule_id):
    command = delete_command(request)
    database = request.app.state.db
    store = getattr(request.app.state, "recovery_store", None)
    with database.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:correlation:{rule_id}:delete"
        prior, fingerprint = command_result(conn, scope, command.command_id, command.model_dump())
        if prior is not None:
            return prior
        _ready(conn)
        if store is None:
            raise unavailable("recovery_evidence_required")
        _, now = coordinator(conn, tenant_id)
        lock_contexts(conn, tenant_id)
        job = conn.execute(
            "SELECT * FROM correlation_delete_jobs WHERE scope=%s AND command_id=%s",
            (scope, command.command_id),
        ).fetchone()
        if job:
            if bytes(job["fingerprint"]) != fingerprint:
                raise AppError(
                    "idempotency_conflict", "Command identity has different content.", 409
                )
        else:
            row = repo.get_rule(conn, tenant_id, rule_id)
            revision(row, command.expected_revision)
            if conn.execute(
                "SELECT 1 FROM correlation_delete_jobs WHERE tenant_id=%s AND rule_id=%s AND (state<>'cancelled' OR cancel_ack IS NULL)",
                (tenant_id, rule_id),
            ).fetchone():
                raise AppError(
                    "deletion_pending", "A protected deletion is already in progress.", 409
                )
            identity = uuid4()
            digest = sha256(
                canonical(
                    {
                        "tenant": tenant_id,
                        "job_id": str(identity),
                        "kind": "correlation",
                        "rule": rule_id,
                        "revision": str(row["revision"] + 1),
                    }
                )
            ).hexdigest()
            job = conn.execute(
                "INSERT INTO correlation_delete_jobs(id,tenant_id,rule_id,scope,command_id,fingerprint,expected_revision,actor_id,actor_label,intent_id,final_id,cancel_id,digest,state,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared',%s,%s) RETURNING *",
                (
                    identity,
                    tenant_id,
                    rule_id,
                    scope,
                    command.command_id,
                    fingerprint,
                    row["revision"],
                    actor["id"],
                    actor["display_name"],
                    uuid5(identity, "intent"),
                    uuid5(identity, "final"),
                    uuid5(identity, "cancel"),
                    digest,
                    now,
                    now,
                ),
            ).fetchone()
    result = resume_delete(database, store, tenant_id, job["id"], request=request)
    with database.transaction() as conn:
        authorize(conn, request, tenant_id, "edit", mutation=True)
    return result


def operation(request, tenant_id, job_id):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        row = conn.execute(
            "SELECT id,rule_id,state,expected_revision,error_code,created_at,updated_at FROM correlation_delete_jobs WHERE tenant_id=%s AND id=%s",
            (tenant_id, job_id),
        ).fetchone()
        if row is None:
            raise AppError("not_found", "Deletion operation unavailable.", 404)
        return {"data": wire(row), "meta": {}}
