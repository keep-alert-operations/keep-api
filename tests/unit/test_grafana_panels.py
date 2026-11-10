"""Grafana dashboard panels in the Product API (REV-68): allowed list, save checks, storage."""

from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
import logging
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from keep.configuration import grafana_panel_routes, routes
from keep.configuration.count_routes import DashboardPreview
from keep.configuration.grafana import parse_grafana_origins
from keep.configuration.models import (
    DashboardDefinition,
    presets_of,
    referenced_presets_of,
)
from keep.shared.errors import AppError

TENANT = "00000000-0000-4000-8000-000000000001"
DASHBOARD = "00000000-0000-4000-8000-0000000000d1"
PANEL = "00000000-0000-4000-8000-000000000011"
PUBLIC = "https://keep.example.com"
ALLOWED = "https://grafana.example.com,https://tools.example.com/grafana"
GOOD = "https://grafana.example.com/d-solo/abc123/checkout?orgId=1&panelId=4"
OLD = "https://grafana-old.example.com/d-solo/abc123/checkout?orgId=1&panelId=4"
LAYOUT = {"title": None, "x": 0, "y": 0, "w": 6, "h": 6}
NOW = datetime(2026, 11, 10, 12, tzinfo=UTC)


def settings(origins=ALLOWED, environment="production"):
    return SimpleNamespace(
        role="product-api",
        environment=environment,
        clock_health_file=None,
        public_origin=PUBLIC,
        grafana_panel_origins=origins,
    )


def grafana(url=GOOD, panel_id=PANEL, **extra):
    return {**LAYOUT, "id": panel_id, "type": "grafana", "url": url, **extra}


class Result:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [] if self.row is None else [self.row]


class Connection:
    """Answers the queries a dashboard save makes and records stored panels."""

    def __init__(self, stored):
        self.stored = stored
        self.inserted = []

    def execute(self, query, params=()):
        text = str(query)
        if "FROM dashboard_panels WHERE id=%s" in text:
            return Result(self.stored.get(params[0]))
        if "clock_timestamp" in text:
            return Result({"now": NOW})
        if text.startswith("INSERT INTO dashboard_panels"):
            keys = ("id", "tenant_id", "dashboard_id", "type", "preset_id", "image_id",
                    "title", "x", "y", "w", "h", "thresholds", "content")
            row = dict(zip(keys, params))
            row["thresholds"], row["content"] = row["thresholds"].obj, row["content"].obj
            self.inserted.append(row)
        return Result()


class Database:
    def __init__(self, conn=None):
        self.conn = conn

    @contextmanager
    def transaction(self):
        yield self.conn


def application(monkeypatch, *, origins=ALLOWED, environment="production", stored=None,
                role_ok=True, super_admin=False):
    """The real HTTP stack with authentication and receipts replaced by recorded checks."""
    from keep.http import create_http_app

    calls = []
    conn = Connection(stored or {})

    def authorize(conn, request, tenant, minimum="view", mutation=False):
        calls.append(("tenant", tenant, minimum, mutation))
        if not role_ok:
            raise AppError("not_found", "Resource unavailable.", 404)
        return {"id": "actor", "display_name": "Actor"}, {}, minimum

    def authenticate(conn, request, mutation=False):
        calls.append(("admin", mutation))
        return {"id": "actor", "super_admin": super_admin}, {}

    def get_definition(conn, tenant, table, resource_id, lock=False):
        rows = conn.inserted or list(conn.stored.values())
        return {
            "id": resource_id,
            "tenant_id": tenant,
            "name": "Board",
            "name_key": "board",
            "revision": 2 if conn.inserted else 1,
            "panels": [routes.panel_row(row) for row in rows],
        }

    monkeypatch.setattr(grafana_panel_routes, "authorize", authorize)
    monkeypatch.setattr(grafana_panel_routes, "authenticate", authenticate)
    monkeypatch.setattr(routes, "authorize", authorize)
    monkeypatch.setattr(routes, "get_definition", get_definition)
    monkeypatch.setattr(routes, "command_result", lambda *args: (None, b"fingerprint"))
    monkeypatch.setattr(routes, "save_result", lambda c, s, i, f, result, status=200: result)
    monkeypatch.setattr(routes, "lock_images", lambda *args: None)
    monkeypatch.setattr(routes, "mark_used", lambda *args: None)

    @asynccontextmanager
    async def lifespan(app):
        app.state.grafana_origins = grafana_panel_routes.configured_origins(
            settings(origins, environment)
        )
        # Without clock evidence the HTTP stack serves mutations in development only.
        app.state.settings = settings(origins, "development")
        app.state.db = Database(conn)
        yield

    app = create_http_app(lifespan, product=True)
    app.include_router(routes.router)
    app.include_router(grafana_panel_routes.router)
    app.include_router(grafana_panel_routes.admin_router)
    return app, calls, conn


def stored_panel(url):
    return {
        "id": PANEL,
        "dashboard_id": DASHBOARD,
        "type": "grafana",
        "preset_id": None,
        "image_id": None,
        "thresholds": [],
        "content": {"url": url},
        **LAYOUT,
    }


def replace(client, panels, revision="1"):
    return client.put(
        f"/api/tenants/{TENANT}/dashboards/{DASHBOARD}",
        json={
            "name": "Board",
            "panels": panels,
            "command_id": "00000000-0000-4000-8000-0000000000c1",
            "expected_revision": revision,
        },
    )


def test_tenant_readers_see_whether_grafana_panels_are_on(monkeypatch):
    """Requirements: REV-68; dashboard operations 3; identity access (tenant read)."""
    app, calls, _ = application(monkeypatch)
    with TestClient(app) as client:
        response = client.get(f"/api/tenants/{TENANT}/grafana-panels/status")
    assert response.status_code == 200
    assert response.json() == {
        "data": {
            "enabled": True,
            "origins": [
                {"origin": "https://grafana.example.com", "path_prefix": ""},
                {"origin": "https://tools.example.com", "path_prefix": "/grafana"},
            ],
        },
        "meta": {},
    }
    assert calls == [("tenant", TENANT, "view", False)]
    for origins in (None, "", " , "):
        app, _, _ = application(monkeypatch, origins=origins)
        with TestClient(app) as client:
            data = client.get(f"/api/tenants/{TENANT}/grafana-panels/status").json()["data"]
        assert data == {"enabled": False, "origins": []}


def test_tenant_access_is_required_for_the_status(monkeypatch):
    """Requirements: REV-68; identity access (tenant visibility)."""
    app, _, _ = application(monkeypatch, role_ok=False)
    with TestClient(app) as client:
        assert client.get(f"/api/tenants/{TENANT}/grafana-panels/status").status_code == 404


def test_ignored_entries_are_logged_and_shown_to_super_admins_only(monkeypatch, caplog):
    """Requirements: REV-68; operators 14 (Admin › Integrations); reliability 8."""
    configured = f"{ALLOWED}, http://grafana.example.com, {PUBLIC}, ftp://x.example"
    with caplog.at_level(logging.WARNING, logger=grafana_panel_routes.__name__):
        app, calls, _ = application(monkeypatch, origins=configured)
        with TestClient(app) as client:
            assert client.get("/api/admin/integrations/grafana-panels").status_code == 403
    assert calls == [("admin", False)]
    warnings = [record.getMessage() for record in caplog.records]
    assert len(warnings) == 3
    assert "http://grafana.example.com" in warnings[0] and PUBLIC in warnings[1]
    app, _, _ = application(monkeypatch, origins=configured, super_admin=True)
    with TestClient(app) as client:
        response = client.get("/api/admin/integrations/grafana-panels")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["enabled"] is True
    assert [item["origin"] for item in data["origins"]] == [
        "https://grafana.example.com",
        "https://tools.example.com",
    ]
    assert [item["entry"] for item in data["ignored"]] == [
        "http://grafana.example.com",
        PUBLIC,
        "ftp://x.example",
    ]
    assert data["ignored"][1]["reason"] == "This is Keep's own address."
    assert response.json()["meta"] == {}


def test_startup_never_fails_on_the_setting(monkeypatch, caplog):
    """Requirements: REV-68; reliability 8 (start-up)."""
    def broken(*args):
        raise ValueError("unexpected")

    monkeypatch.setattr(grafana_panel_routes, "parse_grafana_origins", broken)
    with caplog.at_level(logging.WARNING, logger=grafana_panel_routes.__name__):
        origins = grafana_panel_routes.configured_origins(settings("https://grafana.example.com"))
    assert not origins.enabled and origins.ignored == []
    assert caplog.records
    monkeypatch.undo()
    # Loopback http is allowed in development only.
    local = "http://localhost:3000"
    assert grafana_panel_routes.configured_origins(settings(local, "development")).enabled
    assert not grafana_panel_routes.configured_origins(settings(local, "production")).enabled


def test_saving_an_allowed_address_stores_it_with_no_thresholds_or_preset(monkeypatch):
    """Requirements: REV-68; dashboard operations 2 and 3."""
    app, calls, conn = application(monkeypatch)
    link = {"url": "https://grafana.example.com/d/abc123/checkout?viewPanel=4", "label": None}
    under_prefix = "https://tools.example.com/grafana/d-solo/x/y?panelId=1"
    panels = [
        grafana(link=link),
        grafana(under_prefix, "00000000-0000-4000-8000-000000000012", x=6),
    ]
    with TestClient(app) as client:
        response = client.post(
            f"/api/tenants/{TENANT}/dashboards",
            json={"name": "Board", "panels": panels,
                  "command_id": "00000000-0000-4000-8000-0000000000c1"},
        )
    assert response.status_code == 201, response.text
    assert [(row["type"], row["preset_id"], row["image_id"], row["thresholds"], row["content"])
            for row in conn.inserted] == [
        ("grafana", None, None, [], {"link": link, "url": GOOD}),
        ("grafana", None, None, [], {"url": under_prefix}),
    ]
    assert response.json()["data"]["panels"] == [
        {**panels[0], "link": link},
        {**panels[1], "link": None},
    ]
    assert ("tenant", TENANT, "edit", True) in calls


@pytest.mark.parametrize(
    "url, origins, reason",
    [
        (OLD, ALLOWED, "grafana-old.example.com isn't an allowed Grafana."),
        ("https://grafana.example.com/d/abc123/checkout", ALLOWED,
         "Use a single-panel address from Share › Embed. Whole dashboards can't be shown."),
        ("https://tools.example.com/d-solo/x/y", ALLOWED,
         "tools.example.com isn't an allowed Grafana."),
        ("http://grafana.example.com/d-solo/x/y", ALLOWED,
         "Keep is served over https, so the panel address must be https too."),
        (f"{PUBLIC}/d-solo/x/y", ALLOWED, "Keep's own pages can't be shown in a Grafana panel."),
        (GOOD, "", "Grafana panels are turned off."),
    ],
)
def test_a_new_disallowed_address_is_rejected(monkeypatch, url, origins, reason):
    """Requirements: REV-68; dashboard operations 3; shared commands (validation errors)."""
    app, _, conn = application(monkeypatch, origins=origins)
    with TestClient(app) as client:
        response = client.post(
            f"/api/tenants/{TENANT}/dashboards",
            json={"name": "Board", "panels": [grafana(url)],
                  "command_id": "00000000-0000-4000-8000-0000000000c1"},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "grafana_url_invalid"
    assert response.json()["error"]["message"] == reason
    assert not conn.inserted


def test_changing_a_stored_address_is_checked(monkeypatch):
    """Requirements: REV-68; dashboard operations 3."""
    app, _, conn = application(monkeypatch, stored={PANEL: stored_panel(GOOD)})
    with TestClient(app) as client:
        response = replace(client, [grafana(OLD)])
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "grafana_url_invalid"
    assert not conn.inserted


def test_an_unchanged_address_saves_after_its_grafana_was_removed(monkeypatch):
    """Requirements: REV-68 (assistant choice: only new or changed addresses are checked);
    dashboard operations 3."""
    for origins in ("https://tools.example.com/grafana", ""):
        app, _, conn = application(
            monkeypatch, origins=origins, stored={PANEL: stored_panel(GOOD)}
        )
        with TestClient(app) as client:
            response = replace(client, [grafana(GOOD, title="Checkout")])
        assert response.status_code == 200, response.text
        assert conn.inserted[0]["content"] == {"url": GOOD}
        assert conn.inserted[0]["title"] == "Checkout"


def test_validate_does_not_check_grafana_addresses(monkeypatch):
    """Requirements: REV-68 (the dialog checks addresses itself); dashboard operations 3."""
    monkeypatch.setattr(routes, "check_images", lambda *args: None)
    app, _, _ = application(monkeypatch, origins="")
    with TestClient(app) as client:
        response = client.post(
            f"/api/tenants/{TENANT}/dashboards/validate",
            json={"name": "Board", "panels": [grafana(OLD)]},
        )
    assert response.status_code == 200
    assert response.json()["data"]["valid"] is True


def test_content_and_panel_row_round_trip():
    """Requirements: REV-68; dashboard operations 2 and 14."""
    link = {"url": "https://grafana.example.com/d/abc123/checkout?viewPanel=4", "label": "Open"}
    (panel,) = DashboardDefinition(name="Board", panels=[grafana(link=link)]).panels
    assert routes.panel_content(panel) == {"link": link, "url": GOOD}
    row = {
        **{key: grafana()[key] for key in ("id", "type", "title", "x", "y", "w", "h")},
        "preset_id": None,
        "image_id": None,
        "thresholds": [],
        "content": routes.panel_content(panel),
    }
    assert routes.panel_row(row) == {**grafana(), "link": link}
    assert routes.panel_row(row) == panel.model_dump()


def test_grafana_panels_are_never_counted_and_reference_no_preset():
    """Requirements: REV-68; dashboard operations 2, 10 and 14."""
    preset = "00000000-0000-4000-8000-000000000002"
    count = {**LAYOUT, "id": "00000000-0000-4000-8000-000000000010", "x": 6, "w": 3, "h": 2,
             "preset_id": preset}
    parsed = DashboardPreview.model_validate(
        {"name": "Preview", "panels": [count, grafana()], "preset_revisions": {preset: "1"}}
    )
    assert [panel.type for panel in parsed.panels] == ["count", "grafana"]
    assert presets_of(parsed.panels) == [preset]
    assert set(referenced_presets_of(parsed.panels)) == {preset}
    DashboardPreview.model_validate(
        {"name": "Preview", "panels": [grafana()], "preset_revisions": {}}
    )
    with pytest.raises(ValueError):
        DashboardPreview.model_validate(
            {"name": "Preview", "panels": [grafana()], "preset_revisions": {preset: "1"}}
        )


def test_origins_parse_the_documented_format():
    """Requirements: REV-68; delivery (KEEP_GRAFANA_PANEL_ORIGINS)."""
    origins = parse_grafana_origins(f"{ALLOWED},https://grafana.example.com/", PUBLIC, "production")
    assert origins.allowed == [
        {"origin": "https://grafana.example.com", "path_prefix": ""},
        {"origin": "https://tools.example.com", "path_prefix": "/grafana"},
    ]
