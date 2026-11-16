"""Browser monitoring events become metrics and browser log records."""

from uuid import uuid4

import pytest

from keep import rum
from keep.models import RumBatch
from keep.observability.metrics import REGISTRY
from keep.observability.testing import capture_records

USER = str(uuid4())
ROUTES = {
    "/api/tenants/{id}/alerts": "/api/tenants/{tenant_id}/alerts",
    "/api/tenants/{id}/alerts/{id}/commands": "/api/tenants/{tenant_id}/alerts/{alert_id}/commands",
}
COMMANDS = "/api/tenants/{tenant_id}/alerts/{alert_id}/commands"


def value(metric, **labels):
    return REGISTRY.get_sample_value(metric, labels) or 0.0


def send(*events):
    batch = RumBatch.model_validate({"events": list(events)})
    return rum.record(batch.events, principal_id=USER, routes=ROUTES)


@pytest.fixture
def records():
    return capture_records("api", "product-api")


def test_page_timings_and_views_are_measured_by_section(records):
    """Requirements: REV-74; observability 9."""
    views = value("keep_rum_page_views_total", view="alerts")
    paints = value("keep_rum_web_vital_seconds_count", name="lcp", view="alerts")
    shifts = value("keep_rum_layout_shift_count", view="alerts")
    used = send(
        {"kind": "page_view", "view": "alerts"},
        {"kind": "web_vital", "name": "lcp", "view": "alerts", "value": 1.4},
        {"kind": "web_vital", "name": "cls", "view": "alerts", "value": 0.02},
    )
    assert used == 3
    assert value("keep_rum_page_views_total", view="alerts") == views + 1
    assert value("keep_rum_web_vital_seconds_count", name="lcp", view="alerts") == paints + 1
    assert value("keep_rum_layout_shift_count", view="alerts") == shifts + 1
    assert records() == []


def test_api_calls_are_counted_by_the_applications_own_route_template(records):
    """Requirements: REV-74; observability 7 and 9. A browser cannot invent a label."""
    labels = dict(route=COMMANDS, method="POST")
    ok = value("keep_rum_api_requests_total", outcome="ok", **labels)
    fast = value("keep_rum_api_request_seconds_bucket", le="0.25", **labels)
    timed = value("keep_rum_api_request_seconds_count", **labels)
    invalid = value("keep_rum_events_total", kind="api", outcome="invalid")
    used = send(
        {
            "kind": "api",
            "route": "/api/tenants/{id}/alerts/{id}/commands",
            "method": "POST",
            "outcome": "ok",
            "count": 3,
            "buckets": [1, 1, 0, 1, 0, 0, 0, 0],
        },
        # A route the application does not have, and an outcome outside the list.
        {"kind": "api", "route": "/api/made/up", "method": "GET", "outcome": "ok", "count": 1,
         "buckets": [1, 0, 0, 0, 0, 0, 0, 0]},
        {"kind": "api", "route": "/api/tenants/{id}/alerts", "method": "GET", "outcome": "weird",
         "count": 1, "buckets": [1, 0, 0, 0, 0, 0, 0, 0]},
    )
    assert used == 1
    assert value("keep_rum_api_requests_total", outcome="ok", **labels) == ok + 3
    assert value("keep_rum_api_request_seconds_bucket", le="0.25", **labels) == fast + 2
    assert value("keep_rum_api_request_seconds_count", **labels) == timed + 3
    assert value("keep_rum_events_total", kind="api", outcome="invalid") == invalid + 2
    assert not [
        name for name, labels in rum_label_values() if "made" in str(labels) or "weird" in str(labels)
    ]


def rum_label_values():
    for family in REGISTRY.collect():
        if family.name.startswith("keep_rum"):
            for sample in family.samples:
                yield sample.name, sample.labels


def test_a_failed_call_is_logged_for_the_browser_with_the_failed_requests_id(records):
    """Requirements: REV-74; observability 9."""
    failed = str(uuid4())
    send(
        {
            "kind": "api_error",
            "route": "/api/tenants/{id}/alerts",
            "method": "GET",
            "outcome": "server_error",
            "status": 503,
            "request_id": failed,
            "view": "alerts",
        }
    )
    (record,) = records()
    assert record["service"]["name"] == "browser"
    assert record["event"]["action"] == "rum_api_error" and record["log"]["level"] == "warning"
    assert record["http"]["request"]["id"] == failed
    assert record["http"]["response"]["status_code"] == 503
    assert record["user"]["id"] == USER
    assert record["keep"]["route"] == "/api/tenants/{tenant_id}/alerts"
    assert "role" not in record["keep"]


def test_a_javascript_error_is_logged_without_its_text(records):
    """Requirements: REV-74; observability 4 and 9. Class and frames only."""
    errors = value("keep_rum_js_errors_total", kind="error", view="alert")
    alert = str(uuid4())
    send(
        {
            "kind": "js_error",
            "name": "error",
            "view": "alert",
            "error_name": "TypeError",
            "stack": "render (alert-detail.tsx:42)\nrow <anonymous> (table.tsx:7)\n\x1b[31mcanary",
            "alert_id": alert,
        },
        {"kind": "js_error", "name": "error", "view": "alert", "error_name": "bad name!"},
    )
    assert value("keep_rum_js_errors_total", kind="error", view="alert") == errors + 2
    first, second = records()
    assert first["event"]["action"] == "rum_js_error" and first["log"]["level"] == "error"
    assert first["error"]["type"] == "TypeError"
    assert first["error"]["stack_trace"].splitlines()[0] == "render (alert-detail.tsx:42)"
    assert "\x1b" not in first["error"]["stack_trace"]
    assert first["keep"]["alert"]["id"] == alert and first["keep"]["view"] == "alert"
    # A name that is not an identifier is not trusted.
    assert second["error"]["type"] == "Error"


def test_live_connection_time_and_losses_are_measured(records):
    """Requirements: REV-74; observability 9."""
    connected = value("keep_rum_live_state_seconds_total", state="connected")
    lost = value("keep_rum_live_disconnects_total", reason="watchdog")
    seen = value("keep_rum_tab_seconds_total", state="visible")
    dropped = value("keep_rum_events_dropped_total")
    used = send(
        {"kind": "live", "state": "connected", "value": 28.5},
        {"kind": "live_disconnect", "reason": "watchdog", "view": "alerts"},
        {"kind": "live_disconnect", "reason": "gremlins"},
        {"kind": "tab", "state": "visible", "value": 30},
        {"kind": "dropped", "count": 4},
    )
    assert used == 4
    assert value("keep_rum_live_state_seconds_total", state="connected") == connected + 28.5
    assert value("keep_rum_live_disconnects_total", reason="watchdog") == lost + 1
    assert value("keep_rum_tab_seconds_total", state="visible") == seen + 30
    assert value("keep_rum_events_dropped_total") == dropped + 4
    (record,) = records()
    assert record["event"]["action"] == "rum_live_disconnect"
    assert record["keep"]["reason"] == "watchdog"


def test_a_batch_is_bounded_and_strict():
    """Requirements: REV-74; observability 9."""
    event = {"kind": "tab", "state": "visible", "value": 1}
    RumBatch.model_validate({"events": [event] * 100})
    for body in (
        {"events": []},
        {"events": [event] * 101},
        {"events": [{**event, "url": "https://keep.test/?q=secret"}]},
        {"events": [{"kind": "tab", "state": "visible", "value": -1}]},
        {"events": [{"kind": "api_error", "request_id": "not-a-uuid"}]},
        {"events": [event], "extra": True},
    ):
        with pytest.raises(ValueError):
            RumBatch.model_validate(body)


def test_each_session_is_limited_to_a_few_batches_a_minute():
    """Requirements: REV-74; observability 9."""
    session = uuid4().bytes
    assert all(rum.within_rate(session, now=100.0 + i) for i in range(rum.BATCHES_PER_MINUTE))
    assert not rum.within_rate(session, now=115.0)
    assert rum.within_rate(uuid4().bytes, now=115.0)
    # A minute after its first batches the session may send again.
    assert rum.within_rate(session, now=161.0)


def test_route_templates_are_named_as_a_browser_can_name_them():
    """Requirements: REV-74; observability 9."""
    from types import SimpleNamespace

    paths = ["/api/tenants/{tenant_id}/alerts/{alert_id}", "/auth/session", "/livez"]
    app = SimpleNamespace(
        state=SimpleNamespace(), openapi=lambda: {"paths": dict.fromkeys(paths, {})}
    )
    assert rum.route_templates(app) == {
        "/api/tenants/{id}/alerts/{id}": "/api/tenants/{tenant_id}/alerts/{alert_id}",
        "/auth/session": "/auth/session",
    }


def test_the_real_application_names_its_alert_command_route():
    """Requirements: REV-74; observability 9. Routes of included routers are found."""
    from keep.main import create_app

    known = rum.route_templates(create_app())
    assert known["/api/tenants/{id}/alerts/{id}/commands"] == COMMANDS
    assert known["/api/tenants/{id}/events"] == "/api/tenants/{tenant_id}/events"
    assert len(known) > 80
