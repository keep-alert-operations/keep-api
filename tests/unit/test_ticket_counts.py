"""ServiceNow ticket counts against a fake counting service (REV-65)."""

import asyncio
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
import json
import logging
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

from fastapi.testclient import TestClient
import httpx
from pydantic import SecretStr, ValidationError
import pytest

from keep.configuration import ticket_count_routes, ticket_counts
from keep.configuration.ticket_count_routes import TicketCountQuery, TicketCountRequest
from keep.configuration.ticket_counts import (
    TicketCounts,
    interpret,
    parse_endpoint,
    query_url,
)
from keep.shared.errors import AppError

KEY = "s3cret-key-value"
URL = f"https://tickets.example.com:8443/api/count?key={KEY}&team=ignored&format=json"
TENANT = "00000000-0000-4000-8000-000000000001"


class Clock:
    def __init__(self):
        self.value = 1000.0
        self.wall = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.value

    def now(self):
        return self.wall + timedelta(seconds=self.value - 1000.0)


class Service:
    """A fake counting service that records each request it gets."""

    def __init__(self, reply=None):
        self.requests = []
        self.reply = reply or (lambda request: httpx.Response(200, json={"count": 7}))

    def __call__(self, request):
        self.requests.append(request)
        return streamed(self.reply(request))

    def params(self, index=-1):
        return parse_qsl(urlsplit(str(self.requests[index].url)).query, keep_blank_values=True)


def streamed(response):
    """Serve an in-memory reply as a raw stream, as a real connection does."""
    if response.is_stream_consumed or hasattr(response, "_content"):
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=httpx.ByteStream(response.content),
        )
    return response


def counter(service, url=URL, clock=None, **options):
    clock = clock or Clock()
    return TicketCounts(
        parse_endpoint(url),
        transport=httpx.MockTransport(service),
        clock=clock,
        now=clock.now,
        **options,
    )


def run(coroutine):
    return asyncio.run(coroutine)


def test_addresses_must_be_https_with_a_host_or_loopback_http(caplog):
    """Requirements: REV-65; operators 14; reliability 8."""
    endpoint = parse_endpoint(f"  {URL}  ")
    assert endpoint.origin == "https://tickets.example.com:8443"
    assert KEY not in repr(endpoint)
    assert parse_endpoint("https://tickets.example.com").origin == "https://tickets.example.com"
    # Local development only: plain http to a loopback host.
    for address, origin in (
        ("http://localhost:8099/count", "http://localhost:8099"),
        ("http://127.0.0.1:8099/count?key=x", "http://127.0.0.1:8099"),
        ("http://[::1]:8099/count", "http://[::1]:8099"),
    ):
        assert parse_endpoint(address).origin == origin
    assert parse_endpoint(None) is None
    assert parse_endpoint("") is None
    assert parse_endpoint("   ") is None
    assert not caplog.records
    with caplog.at_level(logging.WARNING):
        for address in (
            f"http://tickets.example.com/count?key={KEY}",
            f"http://10.0.0.5/count?key={KEY}",
            f"ftp://tickets.example.com/count?key={KEY}",
            f"https:///count?key={KEY}",
            f"https://user:{KEY}@tickets.example.com/count",
            f"https://tickets.example.com/co unt?key={KEY}",
            f"https://tickets.example.com:99999/count?key={KEY}",
            f"tickets.example.com/count?key={KEY}",
        ):
            assert parse_endpoint(address) is None, address
    assert len(caplog.records) == 8
    assert all(
        KEY not in record.getMessage() and "tickets" not in record.getMessage()
        for record in caplog.records
    )


def test_invalid_configuration_means_not_configured():
    """Requirements: REV-65; dashboard operations 3."""
    for value in (None, SecretStr(""), SecretStr("http://tickets.example.com/count")):
        service = TicketCounts.from_settings(SimpleNamespace(ticket_count_url=value))
        assert not service.configured
        assert service.integration() == {
            "configured": False,
            "host": None,
            "last_success_at": None,
            "last_failure_at": None,
            "last_error": None,
        }
        assert run(service.lookup("Ops", "open", "hamal"))["status"] == "not_configured"
        assert run(service.check())["ok"] is False
    assert TicketCounts.from_settings(SimpleNamespace(ticket_count_url=SecretStr(URL))).configured
    # Plain http to a loopback host is for local development only.
    local = SecretStr("http://127.0.0.1:8099/count")
    for environment, configured in (
        ("development", True),
        ("staging", False),
        ("production", False),
    ):
        settings = SimpleNamespace(ticket_count_url=local, environment=environment)
        assert TicketCounts.from_settings(settings).configured is configured
    assert parse_endpoint("http://localhost:8099/count", development=False) is None
    assert parse_endpoint(URL, development=False).origin == "https://tickets.example.com:8443"


@pytest.mark.parametrize(
    ("state", "detection", "expected"),
    [
        ("open", "hamal", {"state": "new", "system_failure": "true"}),
        ("in_progress", "direct", {"state": "in_progress", "system_failure": "false"}),
        ("both", "all", {"state": "all"}),
    ],
)
def test_panel_values_replace_same_named_parameters_and_keep_the_rest(state, detection, expected):
    """Requirements: REV-65; dashboard operations 3 (KeepHQ's query parameters)."""
    endpoint = parse_endpoint(URL + "&state=closed&system_failure=maybe")
    parts = urlsplit(query_url(endpoint, "Net Ops & Co", state, detection))
    assert (parts.scheme, parts.netloc, parts.path) == (
        "https",
        "tickets.example.com:8443",
        "/api/count",
    )
    params = parse_qsl(parts.query, keep_blank_values=True)
    assert params[:2] == [("key", KEY), ("format", "json")]
    tail = dict(params[2:])
    if detection == "all":
        # All leaves system_failure out; a configured one is kept as configured.
        assert params[2] == ("system_failure", "maybe")
        tail.pop("system_failure")
    assert tail == {"team": "Net Ops & Co", **expected}
    assert [key for key, _ in params].count("team") == 1


def test_counts_are_fetched_with_one_plain_get():
    """Requirements: REV-65; dashboard operations 3; reliability 8."""
    service = Service()
    result = run(counter(service).lookup("Ops", "open", "hamal"))
    assert result == {
        "status": "count",
        "count": 7,
        "checked_at": datetime(2026, 11, 9, 12, 0, tzinfo=UTC),
        "last_count": 7,
        "last_counted_at": datetime(2026, 11, 9, 12, 0, tzinfo=UTC),
    }
    (request,) = service.requests
    assert request.method == "GET"
    assert request.headers["accept"] == "application/json"
    assert request.headers["user-agent"] == "keep-api"
    assert "authorization" not in request.headers and "cookie" not in request.headers
    assert dict(service.params()) == {
        "key": KEY,
        "team": "Ops",
        "format": "json",
        "state": "new",
        "system_failure": "true",
    }


@pytest.mark.parametrize(
    ("body", "status", "count"),
    [
        (b'{"count": 0}', "count", 0),
        (b'{"count": 9007199254740991, "other": 1}', "count", 9007199254740991),
        (b'{"Team not found": true}', "not_found", None),
        (b'{"Team not found": "x", "count": 3}', "not_found", None),
        (b'{"error": "Team not found"}', "not_found", None),
        (b'{"message": "  team NOT found "}', "not_found", None),
        (b'{"count": 9007199254740992}', "no_count", None),
        (b'{"count": -1}', "no_count", None),
        (b'{"count": 2.0}', "no_count", None),
        (b'{"count": "4"}', "no_count", None),
        (b'{"count": true}', "no_count", None),
        (b'{"count": null}', "no_count", None),
        (b'{"team not found": 1}', "no_count", None),
        (b"{}", "no_count", None),
        (b"[1, 2]", "no_count", None),
        (b"5", "no_count", None),
        (b"null", "no_count", None),
    ],
)
def test_reply_kinds(body, status, count):
    """Requirements: REV-65; dashboard operations 3 (Team not found and No count)."""
    reply = interpret(body)
    assert (reply.status, reply.count) == (status, count)


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        (lambda r: httpx.Response(200, content=b"<html>busy</html>"), "invalid JSON"),
        (lambda r: httpx.Response(200, content=b'{"count": NaN}'), "invalid JSON"),
        (lambda r: httpx.Response(200, content=b"\xff\xfe"), "invalid JSON"),
        (lambda r: httpx.Response(200, content=b""), "invalid JSON"),
        (lambda r: httpx.Response(500, json={"count": 3}), "status 500"),
        (lambda r: httpx.Response(404, json={"count": 3}), "status 404"),
        (lambda r: httpx.Response(404, content=b"Team not found"), "status 404"),
        (lambda r: httpx.Response(500, json={"Team not found": True}), "status 500"),
        (
            lambda r: httpx.Response(
                302, headers={"Location": "/x"}, json={"error": "Team not found"}
            ),
            "redirect (status 302) not followed",
        ),
        (
            lambda r: httpx.Response(302, headers={"Location": "https://elsewhere.example.com/"}),
            "redirect (status 302) not followed",
        ),
        (
            lambda r: httpx.Response(200, content=b'{"count": 1, "pad": "' + b"x" * 70000 + b'"}'),
            "reply over 64 KiB",
        ),
        (
            lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused", request=r)),
            "connection error",
        ),
        (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=r)), "timeout"),
    ],
)
def test_failures_are_unavailable_and_logged_by_host_only(reply, error, caplog):
    """Requirements: REV-65; dashboard operations 3; reliability 8."""
    service = Service(reply)
    with caplog.at_level(logging.WARNING):
        result = run(counter(service).lookup("Ops", "open", "hamal"))
    assert result["status"] == "unavailable"
    assert (result["count"], result["last_count"]) == (None, None)
    assert len(service.requests) == 1  # a redirect is never followed
    (record,) = caplog.records
    assert (
        record.getMessage()
        == f"Ticket counting service at https://tickets.example.com:8443 failed: {error}"
    )
    assert KEY not in caplog.text and "/api/count" not in caplog.text


def test_the_whole_call_is_bounded_by_five_seconds(monkeypatch):
    """Requirements: REV-65; reliability 8."""
    monkeypatch.setattr(ticket_counts, "TIMEOUT", 0.05)

    class Slow(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(5)
            return httpx.Response(200, json={"count": 1})

    clock = Clock()
    service = TicketCounts(parse_endpoint(URL), transport=Slow(), clock=clock, now=clock.now)
    result = run(service.lookup("Ops", "open", "hamal"))
    assert result["status"] == "unavailable"
    assert service.integration()["last_error"] == "timeout"
    # The transport ignores httpx's per-phase timeouts; only the total bound stopped it.


def test_answers_are_cached_thirty_seconds_and_failures_ten():
    """Requirements: REV-65; dashboard operations 3 (D3 load control)."""
    replies = iter([200, 200, 503, 200, 200])
    service = Service(
        lambda r: httpx.Response(next(replies), json={"count": len(service.requests)})
    )
    clock = Clock()
    counts = counter(service, clock=clock)

    async def scenario():
        first = await counts.lookup("Ops", "open", "hamal")
        clock.value += 29.9
        assert (await counts.lookup("Ops", "open", "hamal")) == first
        assert len(service.requests) == 1
        clock.value += 0.2
        second = await counts.lookup("Ops", "open", "hamal")
        assert (second["status"], second["count"]) == ("count", 2)
        clock.value += 30
        failed = await counts.lookup("Ops", "open", "hamal")
        # The last good count stays available, with when it was fetched.
        assert failed["status"] == "unavailable"
        assert (failed["last_count"], failed["last_counted_at"]) == (2, second["checked_at"])
        clock.value += 9.9
        assert (await counts.lookup("Ops", "open", "hamal"))["status"] == "unavailable"
        assert len(service.requests) == 3
        clock.value += 0.2
        assert (await counts.lookup("Ops", "open", "hamal"))["count"] == 4
        # Another key is its own entry; the count doesn't depend on the tenant.
        await counts.lookup("Ops", "both", "hamal")
        assert len(service.requests) == 5

    run(scenario())


def test_last_count_is_remembered_for_one_hour():
    """Requirements: REV-65; dashboard operations 3 (stale count)."""
    healthy = [True]
    service = Service(
        lambda r: httpx.Response(200, json={"count": 11}) if healthy[0] else httpx.Response(502)
    )
    clock = Clock()
    counts = counter(service, clock=clock)

    async def scenario():
        await counts.lookup("Ops", "open", "hamal")
        healthy[0] = False
        clock.value += 3599
        assert (await counts.lookup("Ops", "open", "hamal"))["last_count"] == 11
        clock.value += 11
        result = await counts.lookup("Ops", "open", "hamal")
        assert (result["status"], result["last_count"], result["last_counted_at"]) == (
            "unavailable",
            None,
            None,
        )

    run(scenario())


def test_concurrent_requests_for_one_key_share_one_call():
    """Requirements: REV-65; dashboard operations 3 (D3 single flight)."""

    class Gate(httpx.AsyncBaseTransport):
        def __init__(self):
            self.calls = 0
            self.release = asyncio.Event()

        async def handle_async_request(self, request):
            self.calls += 1
            await self.release.wait()
            return streamed(httpx.Response(200, json={"count": 5}))

    async def scenario():
        gate = Gate()
        clock = Clock()
        counts = TicketCounts(parse_endpoint(URL), transport=gate, clock=clock, now=clock.now)
        waiting = [asyncio.create_task(counts.lookup("Ops", "open", "hamal")) for _ in range(20)]
        other = asyncio.create_task(counts.lookup("Ops", "open", "direct"))
        await asyncio.sleep(0.05)
        # A cancelled viewer doesn't cancel the lookup the others wait for.
        waiting[0].cancel()
        await asyncio.sleep(0.01)
        gate.release.set()
        results = await asyncio.gather(*waiting[1:], other)
        assert gate.calls == 2
        assert {result["count"] for result in results} == {5}
        assert not counts.pending

    run(scenario())


def test_duplicate_queries_share_a_lookup_and_results_keep_request_order():
    """Requirements: REV-65; dashboard operations 3 (D4)."""
    service = Service(
        lambda r: httpx.Response(
            200, json={"count": len(dict(parse_qsl(r.url.query.decode()))["team"])}
        )
    )
    counts = counter(service)
    queries = [
        TicketCountQuery(team="A"),
        TicketCountQuery(team="Bee"),
        TicketCountQuery(team="A"),
        TicketCountQuery(team="A", ticket_state="both", detection="all"),
    ]
    results = run(counts.lookup_many(queries))
    assert [result["count"] for result in results] == [1, 3, 1, 1]
    assert len(service.requests) == 3


def test_cache_size_is_bounded():
    """Requirements: REV-65; reliability 8."""
    service = Service()
    counts = counter(service, max_keys=3)

    async def scenario():
        for team in "abcde":
            await counts.lookup(team, "open", "hamal")

    run(scenario())
    assert [key[0] for key in counts.answers] == ["c", "d", "e"]
    assert [key[0] for key in counts.last] == ["c", "d", "e"]


def test_connection_check_bypasses_the_cache_and_accepts_any_json():
    """Requirements: REV-65; operators 14 (Admin › Integrations)."""
    service = Service(lambda r: httpx.Response(200, json={"Team not found": True}))
    clock = Clock()
    counts = counter(service, clock=clock)
    first = run(counts.check())
    assert (first["ok"], first["message"]) == (True, "The service answered.")
    assert isinstance(first["elapsed_ms"], int)
    run(counts.check())
    assert len(service.requests) == 2
    assert dict(service.params()) == {
        "key": KEY,
        "format": "json",
        "team": "__keep_connection_check__",
        "state": "all",
    }
    assert not counts.answers
    assert counts.integration()["last_success_at"] == clock.now()
    service.reply = lambda r: httpx.Response(200, content=b"not json")
    clock.value += 5
    failed = run(counts.check())
    assert failed["ok"] is False and failed["message"] == "The service didn't answer: invalid JSON."
    assert counts.integration() == {
        "configured": True,
        "host": "https://tickets.example.com:8443",
        "last_success_at": clock.wall,
        "last_failure_at": clock.now(),
        "last_error": "invalid JSON",
    }


def test_queries_are_validated_like_panel_settings():
    """Requirements: REV-65; dashboard operations 3."""
    query = TicketCountQuery(team="  Café ")
    assert (query.team, query.ticket_state, query.detection) == ("Café", "open", "hamal")
    for fields in (
        {"team": ""},
        {"team": "x" * 201},
        {"team": "a\nb"},
        {"team": "Ops", "ticket_state": "new"},
        {"team": "Ops", "detection": "grafana"},
        {"team": "Ops", "extra": 1},
    ):
        with pytest.raises(ValidationError):
            TicketCountQuery.model_validate(fields)
    TicketCountRequest(queries=[{"team": "Ops"}] * 24)
    for queries in ([], [{"team": "Ops"}] * 25):
        with pytest.raises(ValidationError):
            TicketCountRequest(queries=queries)


class Database:
    @contextmanager
    def transaction(self):
        yield object()


def application(monkeypatch, service, *, role_ok=True, super_admin=False):
    """The real HTTP stack with authentication replaced by recorded checks."""
    from fastapi import FastAPI  # noqa: F401
    from keep.http import create_http_app

    calls = []

    def authorize(conn, request, tenant, minimum="view", mutation=False):
        calls.append(("tenant", tenant, minimum, mutation))
        if not role_ok:
            raise AppError("not_found", "Resource unavailable.", 404)
        if mutation and request.headers.get("x-csrf-token") != "csrf":
            raise AppError("csrf_rejected", "A valid session CSRF token is required.", 403)
        return {"id": "actor"}, {}, "view"

    def authenticate(conn, request, mutation=False):
        calls.append(("admin", mutation))
        if mutation and request.headers.get("x-csrf-token") != "csrf":
            raise AppError("csrf_rejected", "A valid session CSRF token is required.", 403)
        return {"id": "actor", "super_admin": super_admin}, {}

    monkeypatch.setattr(ticket_count_routes, "authorize", authorize)
    monkeypatch.setattr(ticket_count_routes, "authenticate", authenticate)

    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = SimpleNamespace(
            role="product-api", environment="development", clock_health_file=None
        )
        app.state.db = Database()
        app.state.ticket_counts = service
        yield

    app = create_http_app(lifespan, product=True)
    app.include_router(ticket_count_routes.router)
    app.include_router(ticket_count_routes.admin_router)
    return app, calls


def test_tenant_readers_get_status_and_counts_with_csrf(monkeypatch):
    """Requirements: REV-65; dashboard operations 3; identity access (tenant read, CSRF)."""
    service = Service()
    app, calls = application(monkeypatch, counter(service))
    with TestClient(app) as client:
        status = client.get(f"/api/tenants/{TENANT}/ticket-counts/status")
        assert status.status_code == 200
        assert status.json() == {"data": {"configured": True}, "meta": {}}
        body = {
            "queries": [
                {"team": "Ops"},
                {"team": "Ops", "ticket_state": "both", "detection": "all"},
            ]
        }
        rejected = client.post(f"/api/tenants/{TENANT}/ticket-counts", json=body)
        assert rejected.status_code == 403
        assert not service.requests
        counted = client.post(
            f"/api/tenants/{TENANT}/ticket-counts", json=body, headers={"X-CSRF-Token": "csrf"}
        )
        assert counted.status_code == 200
        results = counted.json()["data"]["results"]
        assert [(r["status"], r["count"], r["last_count"]) for r in results] == [
            ("count", "7", "7")
        ] * 2
        assert results[0]["checked_at"] == "2026-11-09T12:00:00.000000Z"
        assert counted.headers["cache-control"] == "private, no-store"
        assert KEY not in counted.text
        invalid = client.post(
            f"/api/tenants/{TENANT}/ticket-counts",
            json={"queries": [{"team": ""}]},
            headers={"X-CSRF-Token": "csrf"},
        )
        assert invalid.status_code == 422
    assert calls[:3] == [
        ("tenant", TENANT, "view", False),
        ("tenant", TENANT, "view", True),
        ("tenant", TENANT, "view", True),
    ]


def test_a_failing_service_never_fails_the_request(monkeypatch):
    """Requirements: REV-65; dashboard operations 3 (D4); reliability 8."""
    app, _ = application(monkeypatch, counter(Service(lambda r: httpx.Response(503))))
    with TestClient(app) as client:
        response = client.post(
            f"/api/tenants/{TENANT}/ticket-counts",
            json={"queries": [{"team": "Ops"}]},
            headers={"X-CSRF-Token": "csrf"},
        )
    assert response.status_code == 200
    assert response.json()["data"]["results"][0]["status"] == "unavailable"


def test_unconfigured_service_reports_not_configured(monkeypatch):
    """Requirements: REV-65; dashboard operations 3 (not connected)."""
    app, _ = application(monkeypatch, TicketCounts(None))
    with TestClient(app) as client:
        assert client.get(f"/api/tenants/{TENANT}/ticket-counts/status").json()["data"] == {
            "configured": False
        }
        response = client.post(
            f"/api/tenants/{TENANT}/ticket-counts",
            json={"queries": [{"team": "Ops"}]},
            headers={"X-CSRF-Token": "csrf"},
        )
    assert response.json()["data"]["results"] == [
        {
            "status": "not_configured",
            "count": None,
            "checked_at": None,
            "last_count": None,
            "last_counted_at": None,
        }
    ]


def test_tenant_access_is_required(monkeypatch):
    """Requirements: REV-65; identity access (tenant visibility)."""
    service = Service()
    app, _ = application(monkeypatch, counter(service), role_ok=False)
    with TestClient(app) as client:
        assert client.get(f"/api/tenants/{TENANT}/ticket-counts/status").status_code == 404
        response = client.post(
            f"/api/tenants/{TENANT}/ticket-counts",
            json={"queries": [{"team": "Ops"}]},
            headers={"X-CSRF-Token": "csrf"},
        )
        assert response.status_code == 404
        assert client.get("/api/tenants/not-a-uuid/ticket-counts/status").status_code == 422
    assert not service.requests


def test_integration_status_and_test_are_for_super_admins_only(monkeypatch):
    """Requirements: REV-65; operators 14 (Admin › Integrations)."""
    service = Service()
    app, calls = application(monkeypatch, counter(service))
    with TestClient(app) as client:
        assert client.get("/api/admin/integrations/ticket-count").status_code == 403
        denied = client.post(
            "/api/admin/integrations/ticket-count/test", json={}, headers={"X-CSRF-Token": "csrf"}
        )
        assert denied.status_code == 403
    assert not service.requests
    app, calls = application(monkeypatch, counter(service), super_admin=True)
    with TestClient(app) as client:
        status = client.get("/api/admin/integrations/ticket-count")
        assert status.status_code == 200
        assert status.json()["data"] == {
            "configured": True,
            "host": "https://tickets.example.com:8443",
            "last_success_at": None,
            "last_failure_at": None,
            "last_error": None,
        }
        assert client.post("/api/admin/integrations/ticket-count/test", json={}).status_code == 403
        tested = client.post(
            "/api/admin/integrations/ticket-count/test", json={}, headers={"X-CSRF-Token": "csrf"}
        )
        assert tested.status_code == 200
        data = tested.json()["data"]
        assert (data["ok"], data["message"]) == (True, "The service answered.")
        assert data["elapsed_ms"].isdigit()
        after = client.get("/api/admin/integrations/ticket-count").json()["data"]
        assert after["last_success_at"] == "2026-11-09T12:00:00.000000Z"
        assert KEY not in json.dumps(after) and "/api/count" not in json.dumps(after)
    assert calls == [("admin", False), ("admin", True), ("admin", True), ("admin", False)]
    assert len(service.requests) == 1


def test_a_real_loopback_service_over_http(monkeypatch):
    """Requirements: REV-65; dashboard operations 3; reliability 8 (real transport)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    import time

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            team = dict(parse_qsl(urlsplit(self.path).query))["team"]
            if team == "slow":
                time.sleep(0.5)
            if team == "moved":
                self.send_response(301)
                self.send_header("Location", "/count?team=elsewhere")
                self.end_headers()
                return
            body = (
                b'{"count": ' + b"1" * 70000 + b"}"
                if team == "huge"
                else json.dumps(
                    {"count": 42} if team == "Ops" else {"Team not found": team}
                ).encode()
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    monkeypatch.setattr(ticket_counts, "TIMEOUT", 0.3)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        endpoint = parse_endpoint(f"http://127.0.0.1:{server.server_port}/count?key={KEY}")

        async def scenario():
            counts = TicketCounts(endpoint)
            try:
                return await counts.lookup_many(
                    [
                        TicketCountQuery(team=team)
                        for team in ("Ops", "Nobody", "moved", "huge", "slow")
                    ]
                )
            finally:
                await counts.close()

        results = run(scenario())
    finally:
        server.shutdown()
        server.server_close()
    assert [(r["status"], r["count"]) for r in results] == [
        ("count", 42),
        ("not_found", None),
        ("unavailable", None),
        ("unavailable", None),
        ("unavailable", None),
    ]
    assert sorted(dict(parse_qsl(urlsplit(path).query))["team"] for path in seen) == [
        "Nobody",
        "Ops",
        "huge",
        "moved",
        "slow",
    ]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (200, {"Team not found": True}),
        (404, {"Team not found": "Ops"}),
        (400, {"error": "Team not found"}),
        (422, {"message": "team not found"}),
    ],
)
def test_team_not_found_is_an_answer_on_2xx_and_4xx(status, body):
    """Requirements: REV-65; dashboard operations 3 (Team not found); operators 14."""
    service = Service(lambda r: httpx.Response(status, json=body))
    counts = counter(service)
    assert run(counts.lookup("Ops", "open", "hamal"))["status"] == "not_found"
    checked = run(counts.check())
    assert (checked["ok"], checked["message"]) == (True, "The service answered.")
    assert counts.integration()["last_error"] is None
