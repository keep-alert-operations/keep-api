"""Request-owned provisioning; durable progress supports explicit safe retries."""

from contextlib import contextmanager
import time

from appchi.access import authorize
from appchi.operators import repository as repo
from appchi.operators.worker import run_one
from appchi.shared.errors import AppError, unavailable

# Assistant-selected: leave room for up to three bounded remote phases.
REQUEST_BUDGET_SECONDS = 90
ATTEMPT_RESERVE_SECONDS = 35


@contextmanager
def runtime(request):
    from appchi.operators.executor import configured_executor, PlatformCredentials

    settings = request.app.state.settings
    tokens = (settings.operator_grafana_token, settings.operator_kong_token,
              settings.operator_probe_token)
    if not settings.operator_binding or not settings.operator_database_url or not all(tokens):
        raise unavailable("operator_capabilities_unverified")
    # The API's ordinary RLS connection must not become a fleet-wide writer.
    db = request.app.state.operator_db
    if db is None:
        raise unavailable("operator_capabilities_unverified")
    adapter = None
    try:
        adapter = configured_executor(
            settings.operator_binding, db,
            PlatformCredentials(*(token.get_secret_value() for token in tokens)),
            settings=settings,
        )
        yield db, adapter
    finally:
        if adapter is not None:
            adapter.close()


def snapshot(request, tenant, operator, operation):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant, "admin")
        row = repo.get_operator(conn, tenant, operator, deleted=True)
        job = conn.execute(
            "SELECT *,greatest(0,extract(epoch FROM next_attempt_at-clock_timestamp())) AS wait_seconds "
            "FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND id=%s",
            (tenant, operator, operation),
        ).fetchone()
        if not job:
            raise AppError("not_found", "Operation unavailable.", 404)
        return repo.response(conn, row, job), job


def finish(request, tenant, accepted):
    """No 202 or detached task: return verified completion or explicit failure.

    Replaying a command inspects its original operation, never creates a new key.
    A recorded failure needs the explicit retry action before another attempt.
    A failed request can leave partial remote work; the operation ID is retained.
    """
    operation = accepted["data"].get("operation")
    if not operation:
        return accepted
    operator_id = accepted["data"]["operator"]["id"]
    operation_id = operation["id"]
    deadline = time.monotonic() + REQUEST_BUDGET_SECONDS
    fields = {"operator_id": operator_id, "operation_id": operation_id,
              "retry_action": "retry", "outcome_may_be_partial": True}
    try:
        current, job = snapshot(request, tenant, operator_id, operation_id)
        if job["state"] == "completed" and not job["progress"].get("continuation_id"):
            return current
        with runtime(request) as (db, adapter):
            while time.monotonic() + ATTEMPT_RESERVE_SECONDS < deadline:
                current, job = snapshot(request, tenant, operator_id, operation_id)
                if job["state"] == "completed":
                    if job["progress"].get("continuation_id"):
                        operation_id = job["progress"]["continuation_id"]
                        fields["operation_id"] = operation_id
                        continue
                    return current
                if job["completed_at"]:
                    raise AppError("operator_operation_superseded", "Operation was cancelled or superseded.", 409)
                if job["error_code"] and job["error_code"] != "operator_kafka_drain_pending":
                    raise unavailable(job["error_code"])
                if job["wait_seconds"] > 0:
                    time.sleep(min(float(job["wait_seconds"]), 0.25))
                    continue
                run_one(db, request.app.state.settings.cipher(), adapter,
                        tenant=tenant, operation_id=operation_id)
                # A competing request may own the lease. Never steal it.
                time.sleep(0.05)
            current, job = snapshot(request, tenant, operator_id, operation_id)
            if job["state"] == "completed" and not job["progress"].get("continuation_id"):
                return current
            raise unavailable("operator_request_incomplete")
    except AppError as error:
        if error.status in (401, 403, 404):
            raise
        raise AppError(error.code,
                       "Operator change did not complete. Remote changes may be partial; inspect the operation and retry it.",
                       error.status, fields=fields) from None
    except Exception:
        raise AppError("operator_request_incomplete",
                       "Operator outcome is uncertain. Inspect the operation before retrying.",
                       503, fields=fields) from None
