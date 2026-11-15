"""POST /auth/login through the real HTTP middleware with a recording database double.

ldap3 is replaced by a fake connection and ADAPI by a fake client, so these tests
check what reaches LDAP, ADAPI and PostgreSQL for each refused or accepted request.
Real PostgreSQL, OpenLDAP and the mock ADAPI are exercised in keep-delivery's
tests/integration/test_password_login.py.

Requirements: REV-73; identity configuration 2-5, 9-10; plan "Login API", A3, A9, A10, A20.
"""

from __future__ import annotations

import base64
import json
import logging
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from keep.config import Settings
from keep.http import create_http_app
from keep.identity import login as ldap_login
from keep.identity import session
from keep.identity.directory import DirectoryUnavailable

ORIGIN = "https://app.example"
PASSWORD = "Pass-סיסמה-Keep-42"


class Row(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class Database:
    """Answers the statements sign-in sends and records every one of them."""

    def __init__(self):
        self.gate = True
        self.statements = []
        self.principal = Row(
            id="00000000-0000-0000-0000-0000000000aa",
            kind="user",
            eligible=True,
            deleted=False,
            evidence_generation=5,
            verified_at=datetime.now(UTC),
        )

    @contextmanager
    def transaction(self):
        yield self

    def execute(self, query, params=()):
        text = " ".join(query.split())
        self.statements.append((text, params))
        result = None
        if "FROM capability_gates" in text:
            result = Row(ready=self.gate)
        elif "nextval('directory_generation_seq')" in text:
            result = Row(generation=7)
        elif text.startswith("SELECT id,kind,eligible") and "FROM principals" in text:
            result = self.principal
        elif text.startswith("INSERT INTO auth_sessions"):
            result = Row(absolute_at=datetime.now(UTC) + timedelta(hours=24))
        return SimpleNamespace(fetchone=lambda: result, fetchall=lambda: [])

    def sql(self, fragment):
        return [text for text, _ in self.statements if fragment in text]


class FakeConnection:
    created = []
    whoami = "u:CORP\\jdoe"

    def __init__(self, server, **options):
        self.server, self.options, self.password = server, options, options.get("password")
        FakeConnection.created.append(self)
        self.extend = SimpleNamespace(
            standard=SimpleNamespace(who_am_i=lambda: FakeConnection.whoami)
        )

    def bind(self):
        return True

    def unbind(self):
        pass


class FakeADAPI:
    created = []
    rows = [{"sAMAccountName": "jdoe", "displayName": "J Doe", "userAccountControl": "512"}]
    error = None

    def __init__(self, config, *, call_cap, **_):
        self.config, self.call_cap = config, call_cap
        self.lookups = []
        FakeADAPI.created.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def lookup_user_rows(self, username, *, timeout=None):
        self.lookups.append(username)
        if FakeADAPI.error:
            raise FakeADAPI.error
        return [dict(row) for row in FakeADAPI.rows]


@pytest.fixture
def doubles(monkeypatch):
    FakeConnection.created, FakeConnection.whoami = [], "u:CORP\\jdoe"
    FakeADAPI.created, FakeADAPI.error = [], None
    FakeADAPI.rows = [
        {"sAMAccountName": "jdoe", "displayName": "J Doe", "userAccountControl": "512"}
    ]
    monkeypatch.setattr(ldap_login, "Connection", FakeConnection)
    monkeypatch.setattr(ldap_login, "Server", lambda host, **options: (host, options))
    monkeypatch.setattr(session, "ADAPIClient", FakeADAPI)
    # The stored person already matches ADAPI unless a test says otherwise.
    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: True)
    published = []

    def publish(conn, evidence, **kw):
        published.append(evidence)
        return SimpleNamespace(accepted=True, fenced=False)

    monkeypatch.setattr(session, "publish", publish)
    return SimpleNamespace(published=published)


def settings(**overrides):
    values = dict(
        database_url="unused",
        wrapping_key=base64.b64encode(b"k" * 32).decode(),
        deployment_epoch="test-epoch",
        public_origin=ORIGIN,
        ldap_host="ldap.corp.example",
        ldap_bind_format="{username}@corp.example",
        adapi_url="http://adapi.corp.example",
        adapi_client_id="client-id",
        superadmin_group="keep-administrators",
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def api(doubles):
    database = Database()

    def build(**overrides):
        configured = settings(**overrides)

        @asynccontextmanager
        async def lifespan(app):
            app.state.settings, app.state.db = configured, database
            yield

        app = create_http_app(lifespan, product=True)
        app.include_router(session.router)
        return app

    with TestClient(build(), base_url=ORIGIN) as client:
        yield SimpleNamespace(client=client, db=database, build=build, doubles=doubles)


def post(client, body=None, *, raw=None, headers=None):
    sent = {"Origin": ORIGIN, "Content-Type": "application/json"}
    sent.update(headers or {})
    content = raw if raw is not None else json.dumps(body).encode()
    return client.post("/auth/login", content=content, headers=sent)


def credentials(username="jdoe", password=PASSWORD, **extra):
    return {"username": username, "password": password, **extra}


def assert_refused_before_bind(api, response, status, code):
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    assert FakeConnection.created == [] and FakeADAPI.created == []
    assert not api.db.sql("INSERT INTO auth_sessions")
    assert "set-cookie" not in response.headers


def test_closed_gate_answers_503_before_anything_else(api):
    """Requirements: REV-73; identity configuration 2; plan A23."""
    api.db.gate = False
    response = post(api.client, credentials(), headers={"Origin": "https://evil.example"})
    assert_refused_before_bind(api, response, 503, "human_authorization_gated")
    assert api.doubles.published == []


@pytest.mark.parametrize(
    "headers",
    [{"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": ""}],
)
def test_cross_origin_sign_in_is_refused(api, headers):
    """Requirements: REV-73; identity configuration 2, 5."""
    response = post(api.client, credentials(), headers=headers)
    assert_refused_before_bind(api, response, 403, "origin_rejected")


def test_body_limit_encoding_and_media_type_are_enforced_by_the_endpoint(api):
    """Requirements: REV-73; identity configuration 2 (own 4 KiB limit, identity only)."""
    large = credentials(return_to="/" + "a" * 4096)
    assert_refused_before_bind(api, post(api.client, large), 413, "body_too_large")
    gzip = post(api.client, credentials(), headers={"Content-Encoding": "gzip"})
    assert_refused_before_bind(api, gzip, 415, "unsupported_encoding")
    text = post(api.client, credentials(), headers={"Content-Type": "text/plain"})
    assert_refused_before_bind(api, text, 415, "unsupported_media_type")
    assert_refused_before_bind(api, post(api.client, raw=b"{"), 400, "invalid_json")
    duplicate = b'{"username":"jdoe","username":"x","password":"p"}'
    assert_refused_before_bind(api, post(api.client, raw=duplicate), 400, "duplicate_key")


@pytest.mark.parametrize(
    ("body", "field", "code"),
    [
        ({"username": "jdoe"}, "password", "missing"),
        ({"password": PASSWORD}, "username", "missing"),
        ({"username": 7, "password": PASSWORD}, "username", "string_type"),
        (credentials(extra="x"), "extra", "extra_forbidden"),
        (credentials(return_to=5), "return_to", "string_type"),
        ([], "body", "object_type"),
    ],
)
def test_malformed_bodies_are_invalid_fields_without_values(api, body, field, code):
    """Requirements: REV-73; identity configuration 2."""
    response = post(api.client, body)
    assert_refused_before_bind(api, response, 422, "invalid_fields")
    assert {"path": field, "code": code} in response.json()["error"]["fields"]
    assert PASSWORD not in response.text


@pytest.mark.parametrize(
    "username",
    ["", "   ", "a" * 65, "jdoe@corp.example", "CORP\\jdoe", "j*", "x,y", "j\x00doe", "j\ndoe"],
)
def test_refused_usernames_never_bind(api, username):
    """Requirements: REV-73; identity configuration 2."""
    response = post(api.client, credentials(username=username))
    assert_refused_before_bind(api, response, 401, "authentication_rejected")


def test_empty_password_is_refused_before_any_bind(api):
    """Requirements: REV-73; identity configuration 2; plan A3."""
    response = post(api.client, credentials(password=""))
    assert_refused_before_bind(api, response, 401, "authentication_rejected")
    assert response.json()["error"]["message"] == "The username or password wasn't accepted."


def test_sign_in_binds_with_the_format_and_utf8_bytes_then_sets_the_cookie(api):
    """Requirements: REV-73; identity configuration 2-5; plan A9."""
    response = post(api.client, credentials(username="  JDoe ", return_to="/tenants?x=1"))
    assert response.status_code == 200, response.text
    [connection] = FakeConnection.created
    assert connection.options["user"] == "jdoe@corp.example"
    assert connection.options["password"] == PASSWORD.encode("utf-8")
    assert connection.server == (
        "ldap.corp.example",
        {"port": 389, "use_ssl": False, "tls": None, "connect_timeout": 2.0, "get_info": "NO_INFO"},
    )
    [client] = FakeADAPI.created
    assert client.lookups == ["jdoe"] and client.call_cap == 3.0
    data = response.json()["data"]
    assert data["return_to"] == "/tenants?x=1" and data["absolute_at"]
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("__Host-keep_session=")
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert "Path=/" in cookie and "Domain=" not in cookie and "expires" not in cookie.lower()
    assert response.headers["cache-control"] == "private, no-store"
    [insert] = [p for t, p in api.db.statements if t.startswith("INSERT INTO auth_sessions")]
    assert insert[1] == api.db.principal["id"] and insert[4] == "test-epoch"
    assert api.doubles.published == []


@pytest.mark.parametrize("target", ["https://evil.example/", "//evil.example", "/\\evil", None])
def test_unsafe_or_missing_return_paths_go_to_the_workspace_root(api, target):
    """Requirements: REV-73; identity configuration 2."""
    response = post(api.client, credentials(return_to=target))
    assert response.status_code == 200 and response.json()["data"]["return_to"] == "/"


def test_whoami_naming_another_account_is_refused_without_reading_adapi(api):
    """Requirements: REV-73; identity configuration 3; plan A20."""
    FakeConnection.whoami = "u:CORP\\other"
    response = post(api.client, credentials())
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_rejected"
    assert len(FakeConnection.created) == 1 and FakeADAPI.created == []
    assert not api.db.sql("INSERT INTO auth_sessions") and "set-cookie" not in response.headers
    FakeConnection.whoami = "u:CORP\\jdoe"
    assert post(api.client, credentials()).status_code == 200


@pytest.mark.parametrize(
    ("rows", "status", "code"),
    [
        ([], 403, "account_not_in_directory"),
        (
            [{"sAMAccountName": "jdoe", "userAccountControl": "512"}] * 2,
            403,
            "account_ambiguous",
        ),
        ([{"sAMAccountName": "jdoe", "userAccountControl": "514"}], 401, "authentication_rejected"),
        ([{"sAMAccountName": "jdoe"}], 503, "sign_in_unavailable"),
    ],
)
def test_directory_answers_decide_after_a_correct_bind(api, rows, status, code):
    """Requirements: REV-73; identity configuration 3; plan A4, A20."""
    FakeADAPI.rows = rows
    response = post(api.client, credentials())
    assert response.status_code == status and response.json()["error"]["code"] == code
    assert not api.db.sql("INSERT INTO auth_sessions")


def test_directory_outage_and_spent_budget_answer_503_with_nothing_published(api, monkeypatch):
    """Requirements: REV-73; identity configuration 2, 9; plan A5."""
    FakeADAPI.error = DirectoryUnavailable("directory_timeout")
    response = post(api.client, credentials())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "sign_in_unavailable"
    FakeADAPI.error = None
    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: False)
    monkeypatch.setattr(session.request_budget, "remaining", lambda cap=None: 0.5)
    response = post(api.client, credentials())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "sign_in_unavailable"
    assert api.doubles.published == [] and not api.db.sql("INSERT INTO auth_sessions")


def test_ldap_outage_answers_503(api, monkeypatch):
    """Requirements: REV-73; identity configuration 9; plan A5."""

    def unreachable(*args, **kwargs):
        raise ldap_login.SignInUnavailable(ldap_login.UNAVAILABLE_LDAP)

    monkeypatch.setattr(session, "check_password", unreachable)
    response = post(api.client, credentials())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "sign_in_unavailable"
    assert FakeADAPI.created == []


def test_missing_sign_in_settings_answer_503_while_the_app_serves(api):
    """Requirements: REV-73; identity configuration 2, 13."""
    app = api.build(ldap_host=None)
    with TestClient(app, base_url=ORIGIN) as client:
        response = post(client, credentials())
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "sign_in_unavailable"
        assert FakeConnection.created == []
        assert client.get("/auth/session").status_code == 401
    for missing in ({"adapi_url": None}, {"adapi_client_id": None}, {"superadmin_group": None}):
        with TestClient(api.build(**missing), base_url=ORIGIN) as client:
            assert post(client, credentials()).status_code == 503


def test_a_changed_or_disabled_person_is_published_and_disabled_is_refused(api, monkeypatch):
    """Requirements: REV-73; identity configuration 3, 8; plan A23."""
    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: False)
    assert post(api.client, credentials()).status_code == 200
    FakeADAPI.rows = [{"sAMAccountName": "jdoe", "userAccountControl": "514"}]
    response = post(api.client, credentials())
    assert response.status_code == 401
    first, second = api.doubles.published
    assert first.negative_keys == frozenset() and len(second.negative_keys) == 1
    assert len(api.db.sql("INSERT INTO auth_sessions")) == 1


def test_an_old_cookie_is_revoked_by_a_new_sign_in(api):
    """Requirements: REV-73; identity configuration 3, 5; plan A24."""
    api.client.cookies.set("__Host-keep_session", "old-handle")
    response = post(api.client, credentials())
    assert response.status_code == 200
    [(_, params)] = [
        (t, p) for t, p in api.db.statements if t.startswith("UPDATE auth_sessions SET revoked_at")
    ]
    assert params == (session._hash("old-handle"),)


def test_the_password_never_reaches_logs_responses_or_sql(api, caplog, monkeypatch):
    """Requirements: REV-73; identity configuration 3, 13; plan A10."""
    with caplog.at_level(logging.DEBUG):
        texts = [post(api.client, credentials(password="")).text]
        FakeConnection.whoami = "u:CORP\\other"
        texts.append(post(api.client, credentials()).text)
        FakeConnection.whoami = "u:CORP\\jdoe"
        texts.append(post(api.client, credentials()).text)
        FakeADAPI.rows = []
        texts.append(post(api.client, credentials()).text)
    logged = "\n".join(r.getMessage() + repr(r.args) for r in caplog.records)
    assert "sign_in_rejected reason=whoami_mismatch" in logged
    for blob in (logged, "\n".join(texts), repr(api.db.statements)):
        assert PASSWORD not in blob and repr(PASSWORD.encode()) not in blob


def test_logout_is_local_and_has_no_provider_url(api, monkeypatch):
    """Requirements: REV-73; identity configuration 10; plan A8."""
    monkeypatch.setattr(
        session,
        "authenticate",
        lambda conn, request, mutation=False: ({}, {"handle_hash": b"hash"}),
    )
    response = api.client.post("/auth/logout", headers={"Origin": ORIGIN})
    assert response.status_code == 200
    assert response.json() == {"data": {"signed_out": True}, "meta": {}}
    assert api.db.sql("UPDATE auth_sessions SET revoked_at")


def test_removed_provider_routes_are_gone(api):
    """Requirements: REV-73; identity configuration 2."""
    assert api.client.get("/auth/login").status_code == 405
    for method, path in (
        ("get", "/auth/callback"),
        ("post", "/auth/activity"),
        ("post", "/auth/backchannel-logout"),
    ):
        assert getattr(api.client, method)(path, headers={"Origin": ORIGIN}).status_code == 404
