"""Resume protected configuration deletions after crashes and evidence outages."""

from dataclasses import dataclass
from time import monotonic

from appchi.shared.errors import AppError, unavailable


@dataclass(frozen=True)
class DeletionPage:
    attempted: int
    completed: int
    deferred: int
    cursor: tuple[str, str, str] | None


def resume_one(db, store, row):
    tenant, job = row["tenant_id"], row["id"]
    if row["kind"] == "configuration":
        from appchi.configuration.deletion import resume_delete

        return resume_delete(db, store, tenant, job)
    if row["kind"] == "correlation":
        from appchi.correlation.deletion import resume_delete

        return resume_delete(db, store, tenant, job)
    from appchi.maintenance.routes import compiled, resume_delete

    # Compilation must finish before the deletion function takes write locks.
    with db.transaction(tenant) as conn:
        window = conn.execute(
            "SELECT w.cel FROM maintenance_windows w JOIN maintenance_delete_jobs j "
            "ON j.tenant_id=w.tenant_id AND j.window_id=w.id WHERE j.tenant_id=%s AND j.id=%s",
            (tenant, job),
        ).fetchone()
    if not window:
        raise unavailable("maintenance_delete_definition_missing")
    return resume_delete(db, store, tenant, job, compiled(window["cel"]))


def deletion_turn(db, store, *, cursor=None):
    with db.transaction() as conn:
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='recovery'"
        ).fetchone()
        if not gate or not gate["ready"]:
            raise unavailable("recovery_not_ready")
        rows = conn.execute(
            """SELECT kind,tenant_id,id FROM (
            SELECT 'configuration' AS kind,tenant_id,id FROM configuration_delete_jobs
              WHERE state IN ('prepared','deleted') OR (state='cancelled' AND cancel_ack IS NULL)
            UNION ALL SELECT 'correlation',tenant_id,id FROM correlation_delete_jobs
              WHERE state IN ('prepared','deleted') OR (state='cancelled' AND cancel_ack IS NULL)
            UNION ALL SELECT 'maintenance',tenant_id,id FROM maintenance_delete_jobs
              WHERE state IN ('prepared','deleted') OR (state='cancelled' AND cancel_ack IS NULL)
            ) pending WHERE (%s::text IS NULL OR (kind,tenant_id,id)>(%s::text,%s::uuid,%s::uuid))
            ORDER BY kind,tenant_id,id LIMIT 101""",
            (cursor[0] if cursor else None, *(cursor or (None, None, None))),
        ).fetchall()
    start = monotonic()
    completed = deferred = attempted = 0
    last = None
    for row in rows[:100]:
        try:
            resume_one(db, store, row)
            completed += 1
        except AppError:
            # Each durable state machine retains its exact operation and evidence
            # identity. A failed tenant must not starve the rest of this page.
            deferred += 1
        attempted += 1
        last = (row["kind"], str(row["tenant_id"]), str(row["id"]))
        if monotonic() - start >= 0.1:
            break
    return DeletionPage(attempted, completed, deferred, last if len(rows) > attempted else None)
