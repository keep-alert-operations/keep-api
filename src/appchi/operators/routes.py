"""Tenant-scoped operator commands. Remote acceptance always remains explicit."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from appchi.access import authorize
from appchi.alerts.routes import delete_command
from appchi.models import Command
from appchi.operators.models import OperatorCreate, OperatorRename
from appchi.operators import repository as repo
from appchi.operators.synchronous import finish
from appchi.operators.policy import normalized_name
from appchi.shared.cursors import Cursor
from appchi.shared.errors import AppError
from appchi.shared.transactions import wire

router = APIRouter(prefix="/api/tenants/{tenant_id}/operators", tags=["operators"])


@router.get("")
def listing(
    tenant_id: str, request: Request, name: str = "", limit: int = 50, cursor: str | None = None
):
    if not 1 <= limit <= 200 or len(name) > 128:
        raise AppError("invalid_query", "Invalid page size or name.", 400)
    term = normalized_name(name)[1] if name.strip() else ""
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        actor, session, role = authorize(conn, request, tenant_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "collection": "operators",
                "name": term,
                "actor": str(actor["id"]),
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        old = codec.decode(cursor) if cursor else None
        query = "SELECT * FROM operators o WHERE tenant_id=%s AND (lifecycle<>'deleted' OR (%s AND EXISTS(SELECT 1 FROM operator_operations j WHERE j.operator_id=o.id AND j.completed_at IS NULL))) AND strpos(name_key,%s)>0"
        args = [tenant_id, role == "admin", term]
        if old:
            query += " AND (name_key,id)>(%s,%s)"
            args += old["position"]
        rows = conn.execute(query + " ORDER BY name_key,id LIMIT %s", args + [limit + 1]).fetchall()
        return {
            "data": [repo.public(conn, r, admin=role == "admin") for r in rows[:limit]],
            "meta": {},
            "next_cursor": codec.encode([rows[limit - 1]["name_key"], rows[limit - 1]["id"]])
            if len(rows) > limit
            else None,
        }


@router.post("", status_code=201)
def create(tenant_id: str, body: OperatorCreate, request: Request):
    return finish(request, tenant_id, repo.create(request, tenant_id, body))


@router.get("/{operator_id}")
def detail(tenant_id: str, operator_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        _, _, role = authorize(conn, request, tenant_id)
        row = repo.get_operator(conn, tenant_id, operator_id, deleted=role == "admin")
        if row["lifecycle"] == "deleted" and not repo.active_operation(conn, row):
            raise AppError("not_found", "Operator unavailable.", 404)
        return {
            "data": repo.public(conn, row, admin=role == "admin"),
            "meta": {"revision": str(row["revision"])},
        }


@router.patch("/{operator_id}")
def rename(tenant_id: str, operator_id: str, body: OperatorRename, request: Request):
    return finish(request, tenant_id, repo.mutate(request, tenant_id, operator_id, body, "rename"))


@router.delete("/{operator_id}")
def delete(tenant_id: str, operator_id: str, request: Request):
    return finish(request, tenant_id, repo.mutate(request, tenant_id, operator_id, delete_command(request), "delete"))


@router.post("/{operator_id}/keys/current/copy")
def copy(tenant_id: str, operator_id: str, body: Command, request: Request):
    return JSONResponse(
        repo.copy_current(request, tenant_id, operator_id, body),
        headers={"Cache-Control": "private, no-store", "Pragma": "no-cache"},
    )


def key_command(action):
    def run(tenant_id: str, operator_id: str, body: Command, request: Request):
        return finish(request, tenant_id, repo.mutate(request, tenant_id, operator_id, body, action))

    return run


for suffix, action, status in [
    ("rotate", "rotate", 200),
    ("create", "create_key", 200),
    ("revoke-all", "revoke_all", 200),
]:
    router.add_api_route(
        "/{operator_id}/keys/" + suffix,
        key_command(action),
        methods=["POST"],
        status_code=status,
        name="operator_" + action,
    )


@router.post("/{operator_id}/keys/{key_id}/revoke")
def revoke(tenant_id: str, operator_id: str, key_id: str, body: Command, request: Request):
    return finish(request, tenant_id, repo.mutate(request, tenant_id, operator_id, body, "revoke", key_id))


@router.get("/{operator_id}/operations/{operation_id}")
def operation(tenant_id: str, operator_id: str, operation_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, "admin")
        repo.get_operator(conn, tenant_id, operator_id, deleted=True)
        row = conn.execute(
            "SELECT * FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND id=%s "
            "AND diagnostics_retired_at IS NULL "
            "AND (completed_at IS NULL OR state NOT IN ('completed','cancelled','superseded') "
            "OR completed_at>clock_timestamp()-interval '2160 hours')",
            (tenant_id, operator_id, operation_id),
        ).fetchone()
        if not row:
            raise AppError("not_found", "Operation unavailable.", 404)
        return {"data": repo.operation_public(row), "meta": {}}


def operation_command(action):
    def run(tenant_id: str, operator_id: str, operation_id: str, body: Command, request: Request):
        return finish(request, tenant_id, repo.mutate(request, tenant_id, operator_id, body, action, operation_id))

    return run


for action in ("retry", "cancel"):
    router.add_api_route(
        "/{operator_id}/operations/{operation_id}/" + action,
        operation_command(action),
        methods=["POST"],
        status_code=200,
        name="operator_operation_" + action,
    )


@router.get("/{operator_id}/audit")
def audit(
    tenant_id: str, operator_id: str, request: Request, limit: int = 50, cursor: str | None = None
):
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Invalid page size.", 400)
    with request.app.state.db.transaction() as conn:
        actor, session, _ = authorize(conn, request, tenant_id, "admin")
        repo.get_operator(conn, tenant_id, operator_id, deleted=True)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "operator": operator_id,
                "collection": "operator-audit",
                "actor": str(actor["id"]),
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        old = codec.decode(cursor) if cursor else None
        upper = old["upper"] if old else wire(now)
        query = "SELECT * FROM operator_activity WHERE tenant_id=%s AND operator_id=%s AND recorded_at>clock_timestamp()-interval '365 days' AND recorded_at<=%s"
        args = [tenant_id, operator_id, upper]
        if old:
            query += " AND (recorded_at,id)<(%s,%s)"
            args += old["position"]
        rows = conn.execute(
            query + " ORDER BY recorded_at DESC,id DESC LIMIT %s", args + [limit + 1]
        ).fetchall()
        return {
            "data": wire(rows[:limit]),
            "meta": {},
            "next_cursor": codec.encode(
                [rows[limit - 1]["recorded_at"], rows[limit - 1]["id"]], upper=upper
            )
            if len(rows) > limit
            else None,
        }
