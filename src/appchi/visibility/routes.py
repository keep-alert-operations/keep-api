"""Explicitly configured capture registry; no rendered-success acceptance yet."""

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from appchi.access import authorize
from appchi.identity.session import _guard
from appchi.shared.errors import unavailable

from . import registry, repository
from .models import ChangeView, Identifier, RegisterView, decode_model
from .registry import RegistryLimits

router = APIRouter(tags=["visibility registry"])


def _limits(request):
    value = getattr(request.app.state, "visibility_registry_limits", None)
    if not isinstance(value, RegistryLimits):
        raise unavailable("visibility_registry_unconfigured")
    return value


async def _body(request, model, limits):
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > limits.max_request_bytes:
            from appchi.shared.errors import AppError

            raise AppError("request_too_large", "Request exceeds its byte allocation.", 413)
    return decode_model(bytes(raw), model, maximum_bytes=limits.max_request_bytes)


@router.post("/api/tenants/{tenant_id}/view-subscriptions")
async def register_view(tenant_id: Identifier, request: Request):
    limits = _limits(request)
    command = await _body(request, RegisterView, limits)

    def execute():
        with request.app.state.db.transaction(tenant_id) as conn:
            return registry.register(conn, request, tenant_id, command, limits)

    return await run_in_threadpool(execute)


@router.patch("/api/tenants/{tenant_id}/view-subscriptions/{view_id}")
async def change_view(tenant_id: Identifier, view_id: Identifier, request: Request):
    limits = _limits(request)
    command = await _body(request, ChangeView, limits)

    def execute():
        with request.app.state.db.transaction(tenant_id) as conn:
            return registry.change(conn, request, tenant_id, view_id, command, limits)

    return await run_in_threadpool(execute)


@router.get("/api/tenants/{tenant_id}/view-subscriptions/{view_id}")
def read_view(tenant_id: Identifier, view_id: Identifier, request: Request):
    _limits(request)
    with request.app.state.db.transaction(tenant_id) as conn:
        _guard(conn)
        _, session, _ = authorize(conn, request, tenant_id)
        return repository.response(
            repository.get_view(
                conn, tenant_id, view_id, session["handle_hash"], session["deployment_epoch"]
            )
        )
