"""Whether this deployment links incidents to ServiceNow tickets (REV-70).

Any tenant reader may ask, so the incident page knows whether to offer linking and
where ServiceNow's new incident form is. The address is ``KEEP_SERVICENOW_URL``, which
is not a secret; Keep never calls it.
"""

import asyncio

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from keep.access import authorize
from keep.shared.display_names import documented

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["incidents"])


class _Read(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ServiceNowStatus(_Read):
    configured: bool = Field(
        description="Whether incidents can be linked to tickets in this deployment's ServiceNow."
    )
    base_url: str | None = Field(
        description="The configured ServiceNow address without a trailing slash; null when off."
    )


class ServiceNowStatusRead(_Read):
    data: ServiceNowStatus
    meta: dict


def _reader(request, tenant_id):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)


@router.get("/servicenow/status", responses=documented(ServiceNowStatusRead))
async def servicenow_status(tenant_id: str, request: Request):
    """Whether ServiceNow tickets are on, and the ServiceNow address links must use."""
    await asyncio.to_thread(_reader, request, tenant_id)
    servicenow = getattr(request.app.state, "servicenow", None)
    return {
        "data": {
            "configured": servicenow is not None,
            "base_url": servicenow.base_url if servicenow else None,
        },
        "meta": {},
    }
