"""Bounded terminal diagnostics erasure; operation identities remain replay fences.

Executor label journals are recovery inputs until their pending consumers leave.
No credential, routing binding, operator history or remote state is modified.
"""

from dataclasses import dataclass
from datetime import timedelta
from time import monotonic

from keep.recovery.incidents import ready
from keep.shared.transactions import coordinator

TERMINAL = frozenset({"completed", "cancelled", "superseded"})


def _journal_required(conn, operator, job):
    """Match executor_ledger's explicit and fallback predecessor lookups.

    A pending name also protects the predecessor before a future cancellation
    is requested. The operator lock serializes cancellation and this check.
    Tied created_at values are all protected because the executor's existing
    fallback orders only by that timestamp.
    """
    return (
        conn.execute(
            """SELECT 1 FROM operator_operations old
        WHERE old.tenant_id=%s AND old.operator_id=%s AND old.id=%s AND (
          EXISTS(SELECT 1 FROM operator_operations pending
            WHERE pending.tenant_id=old.tenant_id AND pending.operator_id=old.operator_id
            AND (pending.completed_at IS NULL OR pending.state NOT IN ('completed','cancelled','superseded'))
            AND (pending.progress->>'cancel_operation_id'=old.id::text OR (
              (pending.kind='cancel' OR (pending.kind='cleanup' AND %s)
                OR (pending.kind='create_key' AND pending.progress->>'restore_cancel'='true'))
              AND pending.progress->>'cancel_operation_id' IS NULL
              AND old.kind=coalesce(pending.progress->>'cancel_kind','setup')
              AND NOT EXISTS(SELECT 1 FROM operator_operations newer
                WHERE newer.tenant_id=old.tenant_id AND newer.operator_id=old.operator_id
                AND newer.kind=old.kind AND newer.completed_at IS NOT NULL
                AND newer.id<>pending.id AND newer.created_at>old.created_at))))
          OR (%s AND (
            (old.kind IN ('setup','rename') AND old.state IN ('superseded','cancelled')
              AND NOT EXISTS(SELECT 1 FROM operator_operations newer
                WHERE newer.tenant_id=old.tenant_id AND newer.operator_id=old.operator_id
                AND newer.kind IN ('setup','rename') AND newer.state IN ('superseded','cancelled')
                AND newer.created_at>old.created_at))
            OR (old.kind='setup' AND NOT EXISTS(SELECT 1 FROM operator_operations newer
                WHERE newer.tenant_id=old.tenant_id AND newer.operator_id=old.operator_id
                AND newer.kind='setup' AND newer.completed_at IS NOT NULL
                AND newer.created_at>old.created_at)))))""",
            (
                job["tenant_id"],
                job["operator_id"],
                job["id"],
                operator["pending_name"] is not None,
                operator["pending_name"] is not None,
            ),
        ).fetchone()
        is not None
    )


def _receipt_required(conn, identifier):
    # Protected compaction releases the FK only after its verified final fence.
    # Legacy, not-yet-classified receipt bodies are also conservative dependencies.
    return (
        conn.execute(
            """SELECT 1 WHERE EXISTS(SELECT 1 FROM command_retention WHERE operator_operation_id=%s)
        OR EXISTS(SELECT 1 FROM command_receipts WHERE result IS NOT NULL
          AND result->'data'->'operation'->>'id'=%s)""",
            (identifier, str(identifier)),
        ).fetchone()
        is not None
    )


def cleanup_operation(db, tenant, operator_id, operation_id, *, limit=100):
    """Erase at most limit step rows; return True only when fully scrubbed."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup limit must be 1..100")
    with db.transaction(tenant) as conn:
        ready(conn)
        _, now = coordinator(conn, tenant)
        operator = conn.execute(
            "SELECT * FROM operators WHERE tenant_id=%s AND id=%s FOR UPDATE",
            (tenant, operator_id),
        ).fetchone()
        job = conn.execute(
            "SELECT * FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND id=%s FOR UPDATE",
            (tenant, operator_id, operation_id),
        ).fetchone()
        if not operator or not job:
            return False
        if job["diagnostics_retired_at"]:
            return True
        if (
            job["state"] not in TERMINAL
            or job["completed_at"] is None
            or job["completed_at"] + timedelta(days=90) > now
        ):
            return False
        if _receipt_required(conn, job["id"]) or _journal_required(conn, operator, job):
            return False
        conn.execute(
            """DELETE FROM operator_steps WHERE id IN (
              SELECT id FROM operator_steps WHERE tenant_id=%s AND operator_id=%s AND operation_id=%s
              ORDER BY id LIMIT %s)""",
            (tenant, operator_id, operation_id, limit),
        )
        if conn.execute(
            "SELECT 1 FROM operator_steps WHERE tenant_id=%s AND operator_id=%s AND operation_id=%s LIMIT 1",
            (tenant, operator_id, operation_id),
        ).fetchone():
            return False
        conn.execute(
            """UPDATE operator_operations SET progress='{}',actor_id=NULL,actor_label=NULL,
            error_code=NULL,attempts=0,step='retired',lease_token=NULL,lease_until=NULL,
            next_attempt_at=completed_at,diagnostics_retired_at=%s WHERE id=%s""",
            (now, operation_id),
        )
        return True


@dataclass(frozen=True)
class CleanupTurn:
    attempted: int
    completed: int
    cursor: tuple | None


def cleanup_turn(db, *, cursor=None, limit=20, step_limit=100):
    """A bounded keyset sweep; caller persists cursor and restarts after None."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Cleanup scan limit must be 1..100")
    if type(step_limit) is not int or not 1 <= step_limit <= 100:
        raise ValueError("Step cleanup limit must be 1..100")
    with db.transaction() as conn:
        query = """SELECT completed_at,tenant_id,operator_id,id FROM operator_operations
          WHERE diagnostics_retired_at IS NULL AND completed_at IS NOT NULL
          AND state IN ('completed','cancelled','superseded')
          AND completed_at<=clock_timestamp()-interval '2160 hours'"""
        args = []
        if cursor:
            query += " AND (completed_at,tenant_id,operator_id,id)>(%s,%s,%s,%s)"
            args.extend(cursor)
        rows = conn.execute(
            query + " ORDER BY completed_at,tenant_id,operator_id,id LIMIT %s", args + [limit + 1]
        ).fetchall()
    attempted = completed = 0
    deadline = monotonic() + 0.1
    for row in rows[:limit]:
        completed += cleanup_operation(
            db, row["tenant_id"], row["operator_id"], row["id"], limit=step_limit
        )
        attempted += 1
        if monotonic() >= deadline:
            break
    last = rows[attempted - 1] if attempted else None
    next_cursor = (
        tuple(last[key] for key in ("completed_at", "tenant_id", "operator_id", "id"))
        if last and len(rows) > attempted
        else None
    )
    return CleanupTurn(attempted, completed, next_cursor)
