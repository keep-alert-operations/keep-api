"""ServiceNow ticket counts for dashboard panels and their admin status (REV-65).

Anyone who can read a tenant may ask whether the counting service is configured and
fetch counts for up to 24 (team, ticket state, detection) queries; the queries come
from saved panels or an unsaved dialog preview alike. A failing service never fails
the request: each query gets its own result. Super admins see the connection status
and can test it; nobody can read or change the address through the API.
"""

import asyncio
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from keep.access import authorize
from keep.configuration.models import TicketDetection, TicketState, ticket_team
from keep.identity.authentication import authenticate
from keep.models import StrictModel
from keep.serialization import wire
from keep.shared.display_names import documented
from keep.shared.errors import AppError

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])
admin_router = APIRouter(prefix="/api/admin/integrations", tags=["administration"])


class TicketCountQuery(StrictModel):
    team: str
    ticket_state: TicketState = "open"
    detection: TicketDetection = "hamal"
    _team = field_validator("team")(ticket_team)


class TicketCountRequest(StrictModel):
    # A dashboard holds at most 24 panels.
    queries: list[TicketCountQuery] = Field(min_length=1, max_length=24)


class TicketCountTestRequest(StrictModel):
    """An empty JSON object; product POST bodies are always JSON."""


class _Read(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TicketCountStatus(_Read):
    configured: bool = Field(description="Whether this deployment has a ticket counting service.")


class TicketCountResult(_Read):
    status: Literal["count", "not_found", "no_count", "unavailable", "not_configured"] = Field(
        description="count: the service gave a count; not_found: it doesn't know the team; "
        "no_count: it answered without a usable count; unavailable: it timed out, failed or "
        "gave no valid JSON; not_configured: no service is configured."
    )
    count: str | None = Field(
        description="The ticket count as a decimal string when status is count; else null."
    )
    checked_at: datetime | None = Field(
        description="When this answer was fetched (answers are cached for up to 30 s); "
        "null when not configured or when no call slot was free."
    )
    last_count: str | None = Field(
        description="The last count for this query in the past hour, as a decimal string; "
        "null when none."
    )
    last_counted_at: datetime | None = Field(description="When last_count was fetched.")


class TicketCountResults(_Read):
    results: list[TicketCountResult] = Field(description="One result per query, in request order.")


class TicketCountIntegration(_Read):
    configured: bool
    host: str | None = Field(
        description="The service's scheme, host and port; never its path or query."
    )
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_error: str | None = Field(description="The last failure's kind, such as timeout.")


class TicketCountTest(_Read):
    ok: bool
    message: str
    elapsed_ms: str = Field(description="Milliseconds the test took, as a decimal string.")


class TicketCountStatusRead(_Read):
    data: TicketCountStatus
    meta: dict


class TicketCountResultsRead(_Read):
    data: TicketCountResults
    meta: dict


class TicketCountIntegrationRead(_Read):
    data: TicketCountIntegration
    meta: dict


class TicketCountTestRead(_Read):
    data: TicketCountTest
    meta: dict


def _service(request):
    return request.app.state.ticket_counts


def _tenant_reader(request, tenant_id, mutation):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=mutation)


def _administrator(request, mutation):
    with request.app.state.db.transaction() as conn:
        actor, _ = authenticate(conn, request, mutation=mutation)
        if not actor["super_admin"]:
            raise AppError("forbidden", "Global administration is required.", 403)


@router.get("/ticket-counts/status", responses=documented(TicketCountStatusRead))
async def ticket_count_status(tenant_id: str, request: Request):
    """Whether ServiceNow ticket panels can show counts in this deployment."""
    await asyncio.to_thread(_tenant_reader, request, tenant_id, False)
    return {"data": {"configured": _service(request).configured}, "meta": {}}


@router.post("/ticket-counts", responses=documented(TicketCountResultsRead))
async def ticket_counts(tenant_id: str, body: TicketCountRequest, request: Request):
    """Ticket counts for up to 24 panel queries; each query gets its own result."""
    await asyncio.to_thread(_tenant_reader, request, tenant_id, True)
    results = await _service(request).lookup_many(body.queries)
    return {"data": wire({"results": results}), "meta": {}}


@admin_router.get("/ticket-count", responses=documented(TicketCountIntegrationRead))
async def ticket_count_integration(request: Request):
    """The counting service's connection status, for super admins."""
    await asyncio.to_thread(_administrator, request, False)
    return {"data": wire(_service(request).integration()), "meta": {}}


@admin_router.post("/ticket-count/test", responses=documented(TicketCountTestRead))
async def ticket_count_test(body: TicketCountTestRequest, request: Request):
    """Ask the counting service once, bypassing the cache; any valid JSON answer passes."""
    await asyncio.to_thread(_administrator, request, True)
    return {"data": wire(await _service(request).check()), "meta": {}}
