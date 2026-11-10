"""Bounded preset/dashboard cleanup under the shared reference/hold guard."""

from dataclasses import dataclass
from datetime import timedelta
from time import monotonic

from psycopg import sql

from keep.configuration.guards import _guard, _ready
from keep.configuration.retention import TABLES, retained_args, retained_versions


def _scrub_jobs(conn, tenant, kind, resource, limit):
    return conn.execute(
        """UPDATE configuration_delete_jobs SET actor_label=NULL WHERE id IN (
          SELECT j.id FROM configuration_delete_jobs j WHERE j.tenant_id=%s AND j.resource_kind=%s AND j.resource_id=%s
          AND j.actor_label IS NOT NULL AND j.receipt IS NULL AND j.updated_at+interval '2160 hours'<=clock_timestamp()
          AND ((j.state='final_protected' AND j.final_ack IS NOT NULL) OR (j.state='cancelled' AND j.cancel_ack IS NOT NULL))
          AND NOT EXISTS(SELECT 1 FROM command_retention c WHERE c.configuration_delete_id=j.id)
          AND NOT EXISTS(SELECT 1 FROM configuration_retention_holds h WHERE h.tenant_id=j.tenant_id
                AND h.resource_kind=j.resource_kind AND h.resource_id=j.resource_id AND h.released_at IS NULL
                AND (h.revision IS NULL OR h.revision=j.expected_revision+1))
          ORDER BY j.updated_at,j.id LIMIT %s)""",
        (tenant, kind, resource, limit),
    ).rowcount


def cleanup_configuration(db, tenant, kind, resource, *, limit=100):
    if kind not in TABLES or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Known configuration kind and cleanup limit 1..100 required")
    table, revisions = TABLES[kind]
    with db.transaction(tenant) as conn:
        _ready(conn)
        _guard(conn, tenant)
        scrubbed = _scrub_jobs(conn, tenant, kind, resource, limit)
        if scrubbed == limit:
            return False
        limit -= scrubbed
        row = conn.execute(
            """SELECT resource_id AS id,final_revision AS revision,deleted_at
            FROM configuration_identities WHERE tenant_id=%s AND resource_kind=%s AND resource_id=%s FOR UPDATE""",
            (tenant, kind, resource),
        ).fetchone()
        if not row:
            return True
        body = conn.execute(
            sql.SQL("SELECT revision FROM {} WHERE tenant_id=%s AND id=%s FOR UPDATE").format(
                sql.Identifier(table)
            ),
            (tenant, resource),
        ).fetchone()
        if row["deleted_at"] is None:
            if not body:
                return False  # Missing active content is not proof of erasure eligibility.
            row["revision"] = body["revision"]
        elif body and body["revision"] != row["revision"]:
            return False
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        # An accepted delete or unresolved cancellation needs its exact base.
        pending = conn.execute(
            "SELECT 1 FROM configuration_delete_jobs WHERE tenant_id=%s AND resource_kind=%s AND resource_id=%s AND (state IN ('prepared','deleted') OR (state='cancelled' AND cancel_ack IS NULL) OR (state='final_protected' AND final_ack IS NULL)) LIMIT 1",
            (tenant, kind, resource),
        ).fetchone()
        if pending:
            return False
        if row["deleted_at"] is not None:
            proof = conn.execute(
                "SELECT 1 FROM configuration_delete_jobs j JOIN configuration_identities i USING(tenant_id,resource_kind,resource_id) WHERE j.tenant_id=%s AND j.resource_kind=%s AND j.resource_id=%s AND j.state='final_protected' AND j.final_ack IS NOT NULL AND j.expected_revision+1=%s AND i.final_revision=%s AND i.deleted_at=%s",
                (tenant, kind, resource, row["revision"], row["revision"], row["deleted_at"]),
            ).fetchone()
            if not proof:
                return False
        removed = conn.execute(
            """DELETE FROM configuration_activity WHERE id IN (
              SELECT a.id FROM configuration_activity a WHERE tenant_id=%s AND resource_kind=%s AND resource_id=%s
              AND recorded_at+interval '2160 hours'<=%s
              AND NOT (a.kind='deleted' AND configuration_pending_revision(a.tenant_id,a.resource_kind,a.resource_id,a.revision,true))
              AND NOT EXISTS(SELECT 1 FROM configuration_retention_holds h WHERE h.tenant_id=a.tenant_id
                AND h.resource_kind=a.resource_kind AND h.resource_id=a.resource_id AND h.released_at IS NULL
                AND (h.revision IS NULL OR h.revision=a.revision))
              ORDER BY recorded_at,id LIMIT %s)""",
            (tenant, kind, resource, now, limit),
        ).rowcount
        remaining = limit - removed
        if remaining:
            removed += conn.execute(
                sql.SQL("""DELETE FROM {revisions} WHERE (tenant_id,id,revision) IN (
                    SELECT r.tenant_id,r.id,r.revision FROM {revisions} r
                    WHERE r.tenant_id=%s AND r.id=%s AND NOT EXISTS (SELECT 1 FROM ({retained}) kept WHERE kept.revision=r.revision)
                    ORDER BY r.revision LIMIT %s)""").format(
                    revisions=sql.Identifier(revisions), retained=retained_versions(kind)
                ),
                (tenant, resource, *retained_args(tenant, resource, now), remaining),
            ).rowcount
        if removed == limit:
            return False
        if row["deleted_at"] is None:
            return True
        body_needed = conn.execute(
            sql.SQL("""SELECT
              EXISTS(SELECT 1 FROM ({retained}) kept WHERE kept.revision=%s) OR
              EXISTS(SELECT 1 FROM dashboard_panels WHERE tenant_id=%s AND {reference}=%s) AS blocked""").format(
                retained=retained_versions(kind),
                reference=sql.Identifier("preset_id" if kind == "preset" else "dashboard_id"),
            ),
            (*retained_args(tenant, resource, now), row["revision"], tenant, resource),
        ).fetchone()["blocked"]
        if body_needed or row["deleted_at"] > now - timedelta(days=90):
            return False
        # An older held snapshot does not extend the current body's lifetime.
        # Histories resolve from the minimal identity after this row is removed.
        conn.execute(
            sql.SQL("DELETE FROM {} WHERE tenant_id=%s AND id=%s").format(sql.Identifier(table)),
            (tenant, resource),
        )
        # The separate minimal identity and protected command fences survive.
        retained = conn.execute(
            sql.SQL("SELECT 1 FROM {} WHERE tenant_id=%s AND id=%s LIMIT 1").format(
                sql.Identifier(revisions)
            ),
            (tenant, resource),
        ).fetchone()
        return not retained


@dataclass(frozen=True)
class CleanupTurn:
    attempted: int
    completed: int
    cursor: tuple | None


def configuration_cleanup_turn(db, *, cursor=None, limit=20):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup scan limit must be 1..100")
    with db.transaction() as conn:
        _ready(conn)
        query = """SELECT * FROM (
          SELECT tenant_id,'dashboard' AS kind,id FROM dashboards
          UNION SELECT tenant_id,'preset' AS kind,id FROM presets
          UNION SELECT tenant_id,'dashboard',id FROM dashboard_revisions
          UNION SELECT tenant_id,'preset',id FROM preset_revisions
          UNION SELECT tenant_id,resource_kind,resource_id FROM configuration_activity
          UNION SELECT tenant_id,resource_kind,resource_id FROM configuration_delete_jobs
            WHERE actor_label IS NOT NULL AND state IN ('final_protected','cancelled')) resources"""
        args = []
        if cursor is not None:
            query += " WHERE (tenant_id,kind,id)>(%s,%s,%s)"
            args.extend(cursor)
        query += " ORDER BY tenant_id,kind,id LIMIT %s"
        rows = conn.execute(query, (*args, limit + 1)).fetchall()
    completed = attempted = 0
    position = None
    started = monotonic()
    for row in rows[:limit]:
        completed += cleanup_configuration(db, row["tenant_id"], row["kind"], row["id"])
        attempted += 1
        position = (row["tenant_id"], row["kind"], row["id"])
        if monotonic() - started >= 0.1:
            break
    return CleanupTurn(attempted, completed, position if attempted < len(rows) else None)
