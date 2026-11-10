"""Protected configuration deletion; independent evidence never spans SQL locks."""

from dataclasses import asdict
from hashlib import sha256
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from psycopg import sql
from psycopg.types.json import Jsonb

from keep.access import ROLE_RANK, authorize, effective_role
from keep.alerts.routes import delete_command
from keep.configuration.routes import TABLES, get_definition, public
from keep.ingestion.native import canonical
from keep.models import uuid_string
from keep.recovery.evidence import Evidence, append_verified
from keep.shared.errors import AppError, unavailable
from keep.shared.transactions import command_result, revision, save_result
from keep.serialization import wire

from keep.configuration.guards import _ready as _ready, _guard as _guard

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])


def _references(conn, tenant, resource):
    count = conn.execute(
        "SELECT count(*) AS n FROM dashboard_panels p JOIN dashboards d ON d.tenant_id=p.tenant_id AND d.id=p.dashboard_id "
        "WHERE p.tenant_id=%s AND p.preset_id=%s AND d.deleted_at IS NULL",
        (tenant, resource),
    ).fetchone()["n"]
    if count:
        raise AppError(
            "preset_in_use",
            "Current dashboard panels reference this preset.",
            409,
            fields={
                "reference_count": str(count),
                "references": f"/api/tenants/{tenant}/presets/{resource}/references",
            },
        )


def _evidence(job, state):
    return Evidence(
        str(job[state + "_id"]),
        str(job["tenant_id"]),
        job["resource_kind"],
        str(job["resource_id"]),
        job["expected_revision"] + 1,
        state,
        job["digest"],
    )


def _append(store, job, state):
    if store is None:
        raise unavailable("recovery_evidence_required")
    evidence = _evidence(job, state)
    ack = append_verified(store, evidence)
    return Jsonb(asdict(ack))


def _authorized_commit(conn, job, request):
    if request is not None:
        actor, _, _ = authorize(conn, request, job["tenant_id"], "edit", mutation=True)
        _ready(conn, "human_auth")
        if actor["id"] != job["actor_id"]:
            raise AppError("access_changed", "Deletion authorization changed.", 403)
        return
    # The worker resumes a previously accepted command, but revocation still wins
    # before logical commit. Acquire the same guard used by identity publication.
    conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
    _ready(conn, "human_auth")
    actor = conn.execute("SELECT * FROM principals WHERE id=%s", (job["actor_id"],)).fetchone()
    if (
        not actor
        or actor["kind"] != "user"
        or actor["verified_at"] is None
        or actor["evidence_generation"] < 1
        or ROLE_RANK.get(effective_role(conn, actor, job["tenant_id"]), 0) < 2
    ):
        raise AppError("access_changed", "Deletion authorization changed.", 403)


def _cancel_error(job):
    code = job["error_code"] or "revision_conflict"
    return AppError(
        code,
        "Deletion was cancelled because its authorization, revision or references changed.",
        {"access_changed": 403, "forbidden": 403, "unauthenticated": 401, "not_found": 404}.get(
            code, 409
        ),
    )


def resume_delete(database, store, tenant_id, job_id, request=None):
    """Resume accepted deletion or its final/cancel protection; no physical purge."""
    with database.transaction(tenant_id) as conn:
        _ready(conn)
        job = conn.execute(
            "SELECT * FROM configuration_delete_jobs WHERE tenant_id=%s AND id=%s",
            (tenant_id, job_id),
        ).fetchone()
    if not job:
        raise AppError("not_found", "Deletion operation unavailable.", 404)
    table = job["resource_kind"] + "s"
    if job["state"] == "prepared":
        intent_ack = _append(store, job, "intent")
        with database.transaction(tenant_id) as conn:
            # Authorization -> reference guard -> resource -> owned job. All
            # writers using configuration resources take this same guard first.
            failure = None
            try:
                _authorized_commit(conn, job, request)
            except AppError as error:
                if error.status >= 500:
                    raise
                failure = error
            _ready(conn)
            _guard(conn, tenant_id)
            row = conn.execute(
                sql.SQL("SELECT * FROM {} WHERE tenant_id=%s AND id=%s FOR UPDATE").format(
                    sql.Identifier(table)
                ),
                (tenant_id, job["resource_id"]),
            ).fetchone()
            job = conn.execute(
                "SELECT * FROM configuration_delete_jobs WHERE tenant_id=%s AND id=%s FOR UPDATE",
                (tenant_id, job_id),
            ).fetchone()
            if job["state"] == "prepared":
                if not row or row["deleted_at"] or row["revision"] != job["expected_revision"]:
                    failure = failure or AppError(
                        "revision_conflict", "Configuration changed.", 409
                    )
                if not failure and table == "presets":
                    try:
                        _references(conn, tenant_id, job["resource_id"])
                    except AppError as error:
                        failure = error
                now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                if failure:
                    conn.execute(
                        "UPDATE configuration_delete_jobs SET state='cancelled',intent_ack=%s,error_code=%s,updated_at=%s WHERE id=%s",
                        (intent_ack, failure.code, now, job_id),
                    )
                    job = {**job, "state": "cancelled", "error_code": failure.code}
                else:
                    snapshot = public(get_definition(conn, tenant_id, table, job["resource_id"]))
                    final_revision = row["revision"] + 1
                    snapshot.update(
                        revision=str(final_revision),
                        deleted_at=wire(now),
                        updated_at=wire(now),
                        updated_by=str(job["actor_id"]),
                    )
                    conn.execute(
                        sql.SQL(
                            "UPDATE {} SET revision=%s,deleted_at=%s,updated_at=%s,updated_by=%s WHERE tenant_id=%s AND id=%s"
                        ).format(sql.Identifier(table)),
                        (final_revision, now, now, job["actor_id"], tenant_id, job["resource_id"]),
                    )
                    if table == "dashboards":
                        conn.execute(
                            "DELETE FROM dashboard_panels WHERE tenant_id=%s AND dashboard_id=%s",
                            (tenant_id, job["resource_id"]),
                        )
                    conn.execute(
                        sql.SQL(
                            "INSERT INTO {}(tenant_id,id,revision,snapshot,recorded_at,actor_id) VALUES(%s,%s,%s,%s,%s,%s)"
                        ).format(sql.Identifier(TABLES[table])),
                        (
                            tenant_id,
                            job["resource_id"],
                            final_revision,
                            Jsonb(snapshot),
                            now,
                            job["actor_id"],
                        ),
                    )
                    conn.execute(
                        "INSERT INTO configuration_activity(id,tenant_id,resource_kind,resource_id,revision,kind,command_id,actor_id,actor_label,before_revision,after_revision,recorded_at) VALUES(%s,%s,%s,%s,%s,'deleted',%s,%s,%s,%s,%s,%s)",
                        (
                            uuid4(),
                            tenant_id,
                            job["resource_kind"],
                            job["resource_id"],
                            final_revision,
                            job["command_id"],
                            job["actor_id"],
                            job["actor_label"],
                            job["expected_revision"],
                            final_revision,
                            now,
                        ),
                    )
                    receipt = {
                        "data": {
                            "id": str(job["resource_id"]),
                            "deleted": True,
                            "revision": str(final_revision),
                        },
                        "meta": {"revision": str(final_revision)},
                    }
                    save_result(
                        conn,
                        job["scope"],
                        str(job["command_id"]),
                        bytes(job["fingerprint"]),
                        receipt,
                    )
                    conn.execute(
                        "UPDATE configuration_delete_jobs SET state='deleted',intent_ack=%s,receipt=%s,updated_at=%s WHERE id=%s",
                        (intent_ack, Jsonb(receipt), now, job_id),
                    )
                    # The live_hint_outbox trigger commits its durable hint here.
                    conn.execute(
                        "UPDATE tenant_view_state SET view_generation=view_generation+1,resource_generation=resource_generation+1 WHERE tenant_id=%s",
                        (tenant_id,),
                    )
                    job = {**job, "state": "deleted", "receipt": receipt}
    if job["state"] == "cancelled":
        if job["cancel_ack"] is None:
            ack = _append(store, job, "cancel")
            with database.transaction(tenant_id) as conn:
                conn.execute(
                    "UPDATE configuration_delete_jobs SET cancel_ack=%s,updated_at=clock_timestamp() WHERE tenant_id=%s AND id=%s AND cancel_ack IS NULL",
                    (ack, tenant_id, job_id),
                )
        raise _cancel_error(job)
    if job["state"] == "deleted":
        ack = _append(store, job, "final")
        with database.transaction(tenant_id) as conn:
            conn.execute(
                "UPDATE configuration_delete_jobs SET final_ack=%s,state='final_protected',updated_at=clock_timestamp() WHERE tenant_id=%s AND id=%s AND state='deleted'",
                (ack, tenant_id, job_id),
            )
    return job["receipt"]


def delete(request, tenant_id, resource_id, table):
    try:
        uuid_string(tenant_id)
        uuid_string(resource_id)
    except ValueError:
        raise AppError("invalid_identifier", "Canonical UUID required.") from None
    body = delete_command(request)
    database = request.app.state.db
    store = getattr(request.app.state, "recovery_store", None)
    with database.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        # Presets require target-scoped receipt identity; dashboards use the
        # operation family with their immutable target in the fingerprint.
        scope = f"{tenant_id}:{actor['id']}:{table}:delete" + (
            f":{resource_id}" if table == "presets" else ""
        )
        payload = {**body.model_dump(), "resource_id": resource_id, "resource_kind": table[:-1]}
        prior, fingerprint = command_result(conn, scope, body.command_id, payload)
        job = conn.execute(
            "SELECT * FROM configuration_delete_jobs WHERE tenant_id=%s AND scope=%s AND command_id=%s",
            (tenant_id, scope, body.command_id),
        ).fetchone()
        if job and bytes(job["fingerprint"]) != fingerprint:
            raise AppError("idempotency_conflict", "Command identity has different content.", 409)
        if prior is not None and (not job or job["state"] == "final_protected"):
            return prior
        _ready(conn)
        if store is None:
            raise unavailable("recovery_evidence_required")
        if not job:
            _guard(conn, tenant_id)
            row = get_definition(conn, tenant_id, table, resource_id, True)
            revision(row, body.expected_revision)
            if table == "presets":
                _references(conn, tenant_id, resource_id)
            pending = conn.execute(
                "SELECT 1 FROM configuration_delete_jobs WHERE tenant_id=%s AND resource_kind=%s AND resource_id=%s AND (state IN ('prepared','deleted') OR (state='cancelled' AND cancel_ack IS NULL))",
                (tenant_id, table[:-1], resource_id),
            ).fetchone()
            if pending:
                raise AppError(
                    "deletion_pending",
                    "An accepted deletion needs reconciliation before another command.",
                    409,
                )
            job_id = uuid4()
            digest = sha256(
                canonical(
                    {
                        "job_id": str(job_id),
                        "tenant_id": tenant_id,
                        "resource_id": resource_id,
                        "kind": table[:-1],
                        "revision": str(row["revision"] + 1),
                    }
                )
            ).hexdigest()
            job = conn.execute(
                "INSERT INTO configuration_delete_jobs(id,tenant_id,resource_kind,resource_id,scope,command_id,fingerprint,expected_revision,actor_id,actor_label,intent_id,final_id,cancel_id,digest,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared') RETURNING *",
                (
                    job_id,
                    tenant_id,
                    table[:-1],
                    resource_id,
                    scope,
                    body.command_id,
                    fingerprint,
                    row["revision"],
                    actor["id"],
                    actor["display_name"],
                    uuid4(),
                    uuid4(),
                    uuid4(),
                    digest,
                ),
            ).fetchone()
    result = resume_delete(database, store, tenant_id, job["id"], request)
    # Reauthorize after the final network hop before releasing protected output.
    with database.transaction() as conn:
        authorize(conn, request, tenant_id, "edit", mutation=True)
    return result


def _route(table):
    def endpoint(tenant_id: str, resource_id: str, request: Request):
        result = delete(request, tenant_id, resource_id, table)
        return JSONResponse(result, headers={"ETag": '"' + result["meta"]["revision"] + '"'})

    return endpoint


for _table in TABLES:
    router.add_api_route(
        "/" + _table + "/{resource_id}", _route(_table), methods=["DELETE"], name="delete_" + _table
    )
