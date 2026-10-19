"""Private proof endpoint control flow; real Kong/SQL qualification is separate."""

from copy import deepcopy
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, UTC
from hashlib import sha256
import json
from types import SimpleNamespace
import threading
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from appchi.operators.proof import (
    ProofConfiguration, ProofFailure, ProofRequest, ProofService, Snapshot,
    create_app, read_snapshot,
)
from appchi.operators.worker import policy_document


OPERATOR = UUID("00000000-0000-4000-8000-000000000001")
TENANT = UUID("00000000-0000-4000-8000-000000000002")
CREDENTIAL = UUID("00000000-0000-4000-8000-000000000003")
KEY = "vena_" + "k" * 43
TOKEN = "fixture-proof-token-" + "p" * 32
GATEWAY_TOKEN = "fixture-gateway-token-" + "g" * 32


def request(**changes):
    return ProofRequest.model_validate({
        "operator_id": str(OPERATOR), "consumer_id": str(OPERATOR),
        "credential_id": str(CREDENTIAL), "generation": "7", "policy_generation": "12",
        "nonce": "fresh_nonce_123", "key": KEY, "expected_allowed": True, **changes,
    })


def configuration(count=1, **changes):
    return ProofConfiguration.model_validate({
        "ca_file": "fixture-ca.pem", "members": [
            {"member_id": f"node-{i}", "policy_url": f"https://member-{i}.test/policy",
             "auth_url": f"https://member-{i}.test/auth"} for i in range(count)
        ], **changes,
    })


class Database:
    def __init__(self, snapshots):
        self.snapshots, self.calls = snapshots, 0
        self.started, self.closed = False, False

    def startup(self):
        self.started = True
        self.startup_thread = threading.get_ident()

    def snapshot(self, body):
        value = self.snapshots[min(self.calls, len(self.snapshots) - 1)]
        self.calls += 1
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        self.closed = True


class Gateway:
    def __init__(self, snapshot):
        self.snapshot, self.calls, self.change = snapshot, [], None
        self.auth_status = None

    def __call__(self, req):
        self.calls.append(req)
        snapshot = self.snapshot
        assert req.headers["X-Appchi-Probe-Token"] == GATEWAY_TOKEN
        assert req.url.path in ("/policy", "/auth")
        if req.url.path == "/auth":
            assert req.headers["X-API-Key"] == KEY
            assert json.loads(req.content) == {}
            if self.auth_status is not None:
                return httpx.Response(self.auth_status, json={})
            if not snapshot.allowed:
                return httpx.Response(401)
        else:
            assert "X-API-Key" not in req.headers
        data = {
            "member_id": req.url.host.replace("member", "node").replace(".test", ""),
            "operator_id": str(OPERATOR), "tenant_id": str(TENANT),
            "credential_id": str(CREDENTIAL), "generation": "12",
            "policy_digest": snapshot.digest, "version": "1.0.0",
            "expires_at": snapshot.expires_at, "state": snapshot.state,
            "routing_names": list(snapshot.routing_names), "allowed": snapshot.allowed,
            "admitted": False, "nonce": "fresh_nonce_123",
        }
        if self.change:
            return self.change(req, data)
        return httpx.Response(200, json=data)


def kit(*, count=1, allowed=True, state="current", snapshots=None, **config_changes):
    snapshot = Snapshot(("job", "lease", "revision"), str(TENANT), "d" * 64,
                        allowed, state, None, ("Fixture operator",))
    database = Database(snapshots or [snapshot])
    gateway = Gateway(snapshot)
    config = configuration(count, **config_changes)
    service = ProofService(config, SimpleNamespace(serving_members=[m.member_id for m in config.members]),
                           database, TOKEN, GATEWAY_TOKEN,
                           client=httpx.AsyncClient(transport=httpx.MockTransport(gateway)))
    return service, database, gateway, snapshot


async def call(service, body=None, *, headers=None, content=None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(service)),
                                 base_url="https://proof.test") as client:
        kwargs = {"content": content} if content is not None else {
            "json": (body or request()).model_dump(mode="json")}
        return await client.post("/operator-check", headers=headers if headers is not None else {
            "Authorization": "Bearer " + TOKEN}, **kwargs)


@pytest.mark.asyncio
async def test_all_members_authenticate_current_without_admitting_or_forwarding_secrets(caplog):
    service, database, gateway, _ = kit(count=2)
    response = await call(service)
    assert response.status_code == 200
    result = response.json()
    assert result["nonce"] == "fresh_nonce_123" and result["generation"] == "7"
    assert result["admitted"] is False
    assert [m["member_id"] for m in result["members"]] == ["node-0", "node-1"]
    assert all(m["ready"] and m["authentication_checked"] for m in result["members"])
    assert database.calls == 2 and len(gateway.calls) == 4
    assert response.headers["Cache-Control"] == "no-store"
    assert all(secret not in response.text + caplog.text for secret in (KEY, TOKEN, GATEWAY_TOKEN))
    await service.close()


@pytest.mark.asyncio
async def test_prepared_key_requires_real_denial():
    service, database, gateway, _ = kit(allowed=False, state="prepared")
    body = request(expected_allowed=False)
    assert (await call(service, body)).status_code == 200
    assert len(gateway.calls) == 2 and database.calls == 2
    gateway.auth_status = 200
    assert (await call(service, body)).json() == {"error": "member_denial_unproven"}
    await service.close()


@pytest.mark.parametrize("allowed,state", [(True, "current"), (False, "inactive")])
@pytest.mark.asyncio
async def test_old_or_revoked_key_without_raw_secret_is_explicit_policy_only(allowed, state):
    service, _, gateway, _ = kit(allowed=allowed, state=state)
    response = await call(service, request(key=None, expected_allowed=allowed))
    assert response.status_code == 200
    assert response.json()["members"][0]["authentication_checked"] is False
    assert [req.url.path for req in gateway.calls] == ["/policy"]
    await service.close()


@pytest.mark.parametrize("field,value", [
    ("member_id", "replacement-node"), ("tenant_id", str(OPERATOR)),
    ("operator_id", str(TENANT)), ("credential_id", str(TENANT)),
    ("generation", "11"), ("policy_digest", "old"), ("nonce", "replay"),
    ("admitted", True), ("allowed", 1), ("version", "2.0.0"),
    ("state", "prepared"), ("expires_at", 1), ("routing_names", []),
])
@pytest.mark.asyncio
async def test_mismatched_member_proof_fails_closed(field, value):
    service, database, gateway, _ = kit()
    gateway.change = lambda req, data: httpx.Response(200, json={**data, field: value})
    response = await call(service)
    assert response.status_code == 503
    assert response.json() == {"error": "member_proof_invalid"}
    assert database.calls == 1
    await service.close()


@pytest.mark.asyncio
async def test_two_configured_origins_returning_one_actual_node_fail_closed():
    service, _, gateway, _ = kit(count=2)
    gateway.change = lambda req, data: httpx.Response(200, json={**data, "member_id": "node-0"})
    assert (await call(service)).status_code == 503
    await service.close()


@pytest.mark.parametrize("failure", ["outage", "redirect", "oversize", "invalid-json", "secret-exception"])
@pytest.mark.asyncio
async def test_remote_errors_are_bounded_and_redacted(failure, caplog):
    service, _, gateway, _ = kit()

    def fail(req, data):
        if failure == "secret-exception":
            raise httpx.ConnectError(KEY + TOKEN + GATEWAY_TOKEN, request=req)
        return {
            "outage": httpx.Response(503, text=KEY),
            "redirect": httpx.Response(307, headers={"Location": "https://other.test"}),
            "oversize": httpx.Response(200, content=b"x" * 9000),
            "invalid-json": httpx.Response(200, text=KEY),
        }[failure]

    gateway.change = fail
    response = await call(service)
    assert response.status_code == 503
    assert len(gateway.calls) == 1
    assert all(secret not in response.text + caplog.text for secret in (KEY, TOKEN, GATEWAY_TOKEN))
    await service.close()


@pytest.mark.parametrize("before", [True, False])
@pytest.mark.asyncio
async def test_live_sql_fences_checked_before_and_after_network(before):
    service, database, gateway, snapshot = kit()
    database.snapshots = ([ProofFailure()] if before else [snapshot, replace(snapshot, fence=("new-lease",))])
    response = await call(service)
    assert response.status_code in (409, 503)
    assert len(gateway.calls) == (0 if before else 2)
    await service.close()


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"},
    [("Authorization", "Bearer " + TOKEN), ("Authorization", "Bearer " + TOKEN)]])
@pytest.mark.asyncio
async def test_only_one_exact_bearer_is_accepted(headers):
    service, database, gateway, _ = kit()
    response = await call(service, headers=headers)
    assert response.status_code == 401 and database.calls == 0 and not gateway.calls
    await service.close()


@pytest.mark.parametrize("content", [b"x" * 4097, b"not json", json.dumps({"key": KEY}).encode()])
@pytest.mark.asyncio
async def test_bad_input_does_not_echo_secrets_or_reach_database(content):
    service, database, gateway, _ = kit()
    response = await call(service, content=content)
    assert response.status_code == 422
    assert KEY not in response.text and database.calls == 0 and not gateway.calls
    await service.close()


@pytest.mark.asyncio
async def test_overall_deadline_cancels_member_requests():
    service, _, _, _ = kit(deadline_seconds=0.2)
    cancelled = asyncio.Event()

    async def slow(req):
        try:
            await asyncio.sleep(5)
        finally:
            cancelled.set()

    await service.client.aclose()
    service.client = httpx.AsyncClient(transport=httpx.MockTransport(slow))
    assert (await call(service)).status_code == 503
    assert cancelled.is_set()
    assert not service.inflight.locked()
    await service.close()


@pytest.mark.asyncio
async def test_inflight_limit_rejects_instead_of_building_unbounded_queue():
    service, database, gateway, _ = kit(max_inflight=1)
    await service.inflight.acquire()
    try:
        response = await call(service)
        assert response.status_code == 503 and response.json() == {"error": "proof_busy"}
        assert database.calls == 0 and not gateway.calls
    finally:
        service.inflight.release()
        await service.close()


@pytest.mark.asyncio
async def test_startup_establishes_database_before_readiness_and_closes_resources():
    service, database, gateway, _ = kit()
    app = create_app(service)
    assert not database.started
    async with app.router.lifespan_context(app):
        assert database.started and database.startup_thread != threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://proof.test") as client:
            response = await client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"scope": "operator-proof", "configured_members": 1}
        assert not gateway.calls and database.calls == 0
    assert database.closed and service.client.is_closed


@pytest.mark.asyncio
async def test_startup_failure_is_sanitized_and_closes_resources(caplog):
    service, database, _, _ = kit()

    def fail():
        raise RuntimeError(KEY + TOKEN + GATEWAY_TOKEN)

    database.startup = fail
    with pytest.raises(RuntimeError) as error:
        async with create_app(service).router.lifespan_context(None):
            pytest.fail("Failed startup must never yield a ready app")
    assert str(error.value) == "Operator proof startup unavailable."
    assert error.value.__suppress_context__
    assert all(secret not in str(error.value) + caplog.text for secret in (KEY, TOKEN, GATEWAY_TOKEN))
    assert database.closed and service.client.is_closed


def test_database_startup_wait_is_bounded_and_pool_sessions_default_read_only(monkeypatch):
    from appchi.operators import proof

    class Pool:
        def __init__(self, url, **kwargs):
            self.options = kwargs

        def wait(self, *, timeout):
            assert timeout == 10
            raise TimeoutError("fixture unavailable")

    monkeypatch.setattr(proof, "ConnectionPool", Pool)
    database = proof.ProofDatabase("fixture", "epoch", "binding")
    assert database.pool.options["min_size"] == 1
    assert database.pool.options["max_size"] == 2
    assert database.pool.options["kwargs"]["options"] == "-c default_transaction_read_only=on"
    with pytest.raises(TimeoutError):
        database.startup()


@pytest.mark.asyncio
async def test_missing_or_extra_configured_member_fails_startup():
    config = configuration()
    with pytest.raises(ProofFailure, match="serving_pool_mismatch"):
        ProofService(config, SimpleNamespace(serving_members=["other"]), None, TOKEN, GATEWAY_TOKEN)


@pytest.mark.parametrize("url", ["http://member.test/p", "https://u:p@member.test/p",
    "https://member.test/p?q=1", "https://member.test/p#fragment", "https://member.test"])
def test_member_endpoints_require_explicit_direct_https(url):
    with pytest.raises(ValidationError):
        configuration(members=[{"member_id": "n", "policy_url": url, "auth_url": "https://member.test/a"}])


def test_duplicate_member_or_origin_rejected():
    member = configuration().members[0].model_dump()
    for second in (member, {**member, "member_id": "another"}):
        with pytest.raises(ValidationError):
            configuration(members=[member, second])


class Result:
    def __init__(self, data):
        self.data = data

    def fetchone(self):
        return self.data

    def fetchall(self):
        return self.data


class Connection:
    def __init__(self):
        self.now = datetime.now(UTC)
        self.commands = []
        self.locked = True
        self.control = {"deployment_epoch": "epoch", "fenced": False}
        self.operator = {"id": OPERATOR, "tenant_id": TENANT, "generation": 7, "revision": 3,
                         "lifecycle": "active", "deletion_pending": False,
                         "name": "Fixture operator", "pending_name": None}
        self.job = {"id": "job", "generation": 7, "lease_token": "lease",
                    "lease_until": self.now + timedelta(seconds=30), "state": "running",
                    "completed_at": None, "binding_digest": "binding"}
        self.guard = {"lease_token": "lease", "lease_until": self.now + timedelta(seconds=30)}
        self.binding = {"remote_id": "binding"}
        self.rows = [{"id": CREDENTIAL, "state": "current", "expires_at": None,
                      "verifier": sha256(KEY.encode()).digest()}]
        self.refresh_policy()

    def refresh_policy(self):
        self.policy = {"generation": 12, "document": policy_document(self.operator, self.rows)}

    def execute(self, sql, args=None):
        self.commands.append((sql, args))
        if sql.startswith("SET"):
            return Result(None)
        if "pg_try_advisory" in sql:
            return Result({"acquired": self.locked})
        if "clock_timestamp" in sql:
            return Result({"now": self.now})
        for table, value in (("restore_control", self.control), ("FROM operators", self.operator),
                             ("operator_operations", self.job), ("operator_routing_guard", self.guard),
                             ("operator_remote_bindings", self.binding),
                             ("operator_credentials", self.rows), ("operator_gateway_policies", self.policy)):
            if table in sql:
                return Result(value)
        raise AssertionError(sql)


def test_sql_reads_are_read_only_fenced_and_do_not_fetch_ciphertext():
    conn = Connection()
    result = read_snapshot(conn, request(), "binding", "epoch")
    assert result.allowed and result.tenant_id == str(TENANT)
    commands = [sql for sql, _ in conn.commands]
    assert commands[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    assert all(sql.startswith(("SET", "SELECT")) for sql in commands)
    assert not any("ciphertext" in sql for sql in commands)
    assert conn.commands[-1][0] == "SELECT clock_timestamp() AS now"


@pytest.mark.parametrize("target,changes", [
    ("control", {"fenced": True}), ("control", {"deployment_epoch": "old"}),
    ("operator", {"generation": 8}), ("job", {"generation": 8}),
    ("job", {"state": "pending"}), ("job", {"completed_at": "done"}),
    ("job", {"lease_token": "old"}), ("job", {"binding_digest": "old"}),
    ("binding", {"remote_id": "old"}), ("guard", {"lease_token": "other"}),
    ("policy", {"generation": 11}), ("policy", {"document": "{}"}),
])
def test_sql_rejects_stale_authority(target, changes):
    conn = Connection()
    getattr(conn, target).update(changes)
    with pytest.raises(ProofFailure):
        read_snapshot(conn, request(), "binding", "epoch")


@pytest.mark.parametrize("target", ["job", "guard"])
def test_sql_rejects_expired_lease(target):
    conn = Connection()
    getattr(conn, target)["lease_until"] = conn.now - timedelta(seconds=1)
    with pytest.raises(ProofFailure):
        read_snapshot(conn, request(), "binding", "epoch")


def test_sql_restore_lock_and_fresh_database_epoch():
    conn = Connection()
    conn.control["deployment_epoch"] = None
    assert read_snapshot(conn, request(), "binding", "epoch").fence[-1] is None
    conn.locked = False
    with pytest.raises(ProofFailure, match="restore_fenced"):
        read_snapshot(conn, request(), "binding", "epoch")


def test_wrong_prepared_key_cannot_be_passed_off_as_a_verified_denial():
    conn = Connection()
    conn.rows[0]["state"] = "prepared"
    conn.refresh_policy()
    with pytest.raises(ProofFailure, match="credential_mismatch"):
        read_snapshot(conn, request(key="vena_" + "x" * 43, expected_allowed=False), "binding", "epoch")


@pytest.mark.parametrize("state,expiry,allowed", [
    ("prepared", None, False), ("revoked", None, False), ("retiring", None, False),
    ("retiring", -1, False), ("retiring", 10, True), ("current", None, True),
])
def test_sql_credential_disposition_matches_gateway(state, expiry, allowed):
    conn = Connection()
    conn.rows[0].update(state=state, expires_at=(conn.now + timedelta(seconds=expiry))
                       if expiry is not None else None)
    conn.refresh_policy()
    assert read_snapshot(conn, request(key=None, expected_allowed=allowed), "binding", "epoch").allowed is allowed


def test_sql_rejects_unbounded_policy_credentials():
    conn = Connection()
    conn.rows = [deepcopy(conn.rows[0]) for _ in range(1001)]
    with pytest.raises(ProofFailure, match="policy_limit_exceeded"):
        read_snapshot(conn, request(), "binding", "epoch")
