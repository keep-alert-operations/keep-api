"""Which Grafana instances Grafana dashboard panels may frame (REV-68).

The deployment lists them in ``KEEP_GRAFANA_PANEL_ORIGINS``; start-up parses the list
into ``app.state.grafana_origins`` once. Anyone who can read a tenant may see whether
Grafana panels are on and which Grafana addresses are allowed, so the panel dialog and
the board can check addresses before saving and rendering. Super admins also see the
entries that were ignored and why. The list is not a secret and cannot be changed
through the API.
"""

import asyncio
import logging

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from keep.access import authorize
from keep.configuration.grafana import GrafanaOrigins, parse_grafana_origins
from keep.identity.authentication import authenticate
from keep.shared.display_names import documented
from keep.shared.errors import AppError

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])
admin_router = APIRouter(prefix="/api/admin/integrations", tags=["administration"])
logger = logging.getLogger(__name__)


def configured_origins(settings) -> GrafanaOrigins:
    """Parse ``KEEP_GRAFANA_PANEL_ORIGINS`` once at start-up; never fail start-up.

    Each ignored entry is logged with its reason (entries are not secret). A list that
    cannot be parsed at all turns Grafana panels off.
    """
    try:
        origins = parse_grafana_origins(
            getattr(settings, "grafana_panel_origins", None),
            settings.public_origin,
            settings.environment,
        )
    except Exception:
        logger.warning("KEEP_GRAFANA_PANEL_ORIGINS could not be read; Grafana panels are off.")
        return GrafanaOrigins()
    for item in origins.ignored:
        logger.warning(
            "Ignoring KEEP_GRAFANA_PANEL_ORIGINS entry %r: %s", item["entry"], item["reason"]
        )
    return origins


class _Read(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GrafanaOrigin(_Read):
    origin: str = Field(
        description="An allowed Grafana's scheme, host and non-default port, as a browser "
        "reports URL.origin."
    )
    path_prefix: str = Field(
        description="The Grafana's base path without a trailing slash, or empty when it is "
        "served at the root; panel addresses must start with <path_prefix>/d-solo/."
    )


class GrafanaIgnoredEntry(_Read):
    entry: str = Field(description="A configured entry that was not usable.")
    reason: str = Field(description="Why the entry was ignored.")


class GrafanaPanelStatus(_Read):
    enabled: bool = Field(description="Whether at least one Grafana is allowed.")
    origins: list[GrafanaOrigin] = Field(description="The allowed Grafana instances.")


class GrafanaPanelIntegration(GrafanaPanelStatus):
    ignored: list[GrafanaIgnoredEntry] = Field(
        description="Configured entries that were ignored at start-up, with the reason."
    )


class GrafanaPanelStatusRead(_Read):
    data: GrafanaPanelStatus
    meta: dict


class GrafanaPanelIntegrationRead(_Read):
    data: GrafanaPanelIntegration
    meta: dict


def _origins(request) -> GrafanaOrigins:
    return getattr(request.app.state, "grafana_origins", None) or GrafanaOrigins()


def _status(origins):
    return {
        "enabled": origins.enabled,
        "origins": [
            {"origin": item["origin"], "path_prefix": item["path_prefix"]}
            for item in origins.allowed
        ],
    }


def _tenant_reader(request, tenant_id):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)


def _administrator(request):
    with request.app.state.db.transaction() as conn:
        actor, _ = authenticate(conn, request)
        if not actor["super_admin"]:
            raise AppError("forbidden", "Global administration is required.", 403)


@router.get("/grafana-panels/status", responses=documented(GrafanaPanelStatusRead))
async def grafana_panel_status(tenant_id: str, request: Request):
    """Whether Grafana panels are on and which Grafana addresses they may show."""
    await asyncio.to_thread(_tenant_reader, request, tenant_id)
    return {"data": _status(_origins(request)), "meta": {}}


@admin_router.get("/grafana-panels", responses=documented(GrafanaPanelIntegrationRead))
async def grafana_panel_integration(request: Request):
    """The allowed Grafana list and any ignored entries, for super admins."""
    await asyncio.to_thread(_administrator, request)
    origins = _origins(request)
    ignored = [{"entry": item["entry"], "reason": item["reason"]} for item in origins.ignored]
    return {"data": {**_status(origins), "ignored": ignored}, "meta": {}}
