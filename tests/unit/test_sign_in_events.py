"""Every sign-in outcome is one catalogued, counted event that names no username.

The sign-in doubles and helpers are those of test_password_login: a fake LDAP
connection, a fake ADAPI client and a recording database.

Requirements: REV-74; observability 5 and 7. REV-73; identity configuration 3, 13.
REV-76 (no disabled refusal; an unusable stored person is a 503); plan (REV-75/76) B3.
"""

# ruff: noqa: F811 -- the imported fixtures are requested by name
from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.errors import LockNotAvailable
from psycopg_pool import PoolTimeout

from keep import http as keep_http
from keep import request_budget
from keep.identity import login as ldap_login
from keep.identity import session
from keep.identity.directory import DirectoryUnavailable
from keep.observability.metrics import REGISTRY
from keep.observability.testing import capture_records
from keep.shared.errors import AppError, unavailable
from test_password_login import (  # noqa: F401
    ORIGIN,
    PASSWORD,
    FakeADAPI,
    FakeConnection,
    api,
    credentials,
    doubles,
    post,
)

SIGN_IN = (
    "sign_in_completed",
    "sign_in_rejected",
    "sign_in_unavailable",
    "sign_in_configuration_missing",
    "sign_in_publication_fenced",
)
TYPED = "jdoe"


@pytest.fixture
def records():
    return capture_records("api", "product-api")


def counted(event, outcome, reason=""):
    labels = {"event": event, "outcome": outcome, "reason": reason}
    return REGISTRY.get_sample_value("keep_events_total", labels) or 0.0


def timed(event):
    return REGISTRY.get_sample_value("keep_event_duration_seconds_count", {"event": event}) or 0.0


def events(written):
    return [r for r in written if r["event"]["action"] in SIGN_IN]


def assert_names_nobody(written, *texts):
    """No record holds the typed username, the password or the given texts."""
    blob = "\n".join(json.dumps(record, ensure_ascii=False) for record in written)
    for secret in (PASSWORD, repr(PASSWORD.encode()), TYPED + "@", "\\" + TYPED, *texts):
        assert secret not in blob
    for record in written:
        # The username is short, so look for it as a whole value, not as a substring.
        assert TYPED not in json.dumps(record).replace('"', " ").replace("=", " ").split()


def test_a_completed_sign_in_is_one_event_that_names_the_person_by_id(api, records):
    """Requirements: REV-74; observability 5 and 7."""
    before, timings = counted("sign_in_completed", "success"), timed("sign_in_completed")
    response = post(api.client, credentials(TYPED))
    assert response.status_code == 200, response.text
    written = records()
    (event,) = events(written)
    assert event["event"]["action"] == "sign_in_completed"
    assert event["event"]["outcome"] == "success"
    assert event["user"]["id"] == api.db.principal["id"]
    assert event["message"] == "Signed in"
    # The request's own record names the same person, and shares the request ID.
    (request,) = [r for r in written if r["event"]["action"] == "http_request"]
    assert request["user"]["id"] == api.db.principal["id"]
    assert request["http"]["request"]["id"] == event["http"]["request"]["id"]
    assert counted("sign_in_completed", "success") == before + 1
    assert timed("sign_in_completed") == timings + 1
    assert_names_nobody(written)


def wrong_account():
    FakeConnection.whoami = "u:CORP\\other"


def no_row():
    FakeADAPI.rows = []


def two_rows():
    FakeADAPI.rows = FakeADAPI.rows * 2


@pytest.mark.parametrize(
    ("arrange", "sent", "status", "reason"),
    [
        (None, credentials("bad@name"), 401, "invalid_username"),
        (None, credentials(TYPED, password=""), 401, "empty_password"),
        (wrong_account, credentials(TYPED), 401, "whoami_mismatch"),
        (no_row, credentials(TYPED), 403, "account_not_in_directory"),
        (two_rows, credentials(TYPED), 403, "account_ambiguous"),
    ],
)
def test_a_rejected_sign_in_is_one_event_with_its_reason(
    api, records, monkeypatch, arrange, sent, status, reason
):
    """Requirements: REV-74; observability 5 and 7. REV-73; identity configuration 3."""
    if arrange:
        arrange()
    before, timings = counted("sign_in_rejected", "failure", reason), timed("sign_in_rejected")
    response = post(api.client, sent)
    assert response.status_code == status, response.text
    written = records()
    (event,) = events(written)
    assert event["event"]["action"] == "sign_in_rejected"
    assert event["event"]["outcome"] == "failure"
    assert event["keep"]["reason"] == reason
    assert event["log"]["level"] == "info"
    assert "user" not in event
    assert counted("sign_in_rejected", "failure", reason) == before + 1
    assert timed("sign_in_rejected") == timings + 1
    assert_names_nobody(written, "bad@name")


def test_a_refused_bind_is_counted_as_invalid_credentials(api, records, monkeypatch):
    """Requirements: REV-74; observability 5 and 7."""

    def refuse(*args, **kwargs):
        raise ldap_login.SignInRejected(ldap_login.REJECT_CREDENTIALS)

    monkeypatch.setattr(session, "check_password", refuse)
    before = counted("sign_in_rejected", "failure", "invalid_credentials")
    assert post(api.client, credentials(TYPED)).status_code == 401
    (event,) = events(records())
    assert event["keep"]["reason"] == "invalid_credentials"
    assert counted("sign_in_rejected", "failure", "invalid_credentials") == before + 1


def test_an_outage_is_one_warning_that_names_the_dependency(api, records, monkeypatch):
    """Requirements: REV-74; observability 5 and 7. REV-73; identity configuration 9."""
    seen = []

    def expect(reason, dependency):
        before, timings = (
            counted("sign_in_unavailable", "failure", reason),
            timed("sign_in_unavailable"),
        )
        assert post(api.client, credentials(TYPED)).status_code == 503
        assert timed("sign_in_unavailable") == timings + 1
        written = records()
        (event,) = events(written[len(seen) :])
        seen[:] = written
        assert event["event"]["action"] == "sign_in_unavailable"
        assert event["keep"]["reason"] == reason and event["log"]["level"] == "warning"
        assert event["event"]["outcome"] == "failure"
        assert event.get("keep", {}).get("dependency") == dependency
        assert counted("sign_in_unavailable", "failure", reason) == before + 1

    FakeADAPI.error = DirectoryUnavailable("directory_timeout")
    expect("directory_timeout", "adapi")
    FakeADAPI.error = None
    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: False)
    monkeypatch.setattr(session.request_budget, "remaining", lambda cap=None: 0.5)
    expect("request_budget_spent", None)

    def unreachable(*args, **kwargs):
        raise ldap_login.SignInUnavailable(ldap_login.UNAVAILABLE_LDAP)

    monkeypatch.setattr(session, "check_password", unreachable)
    expect("ldap_unavailable", "ldap")
    assert_names_nobody(records())


def database_down(api, monkeypatch):
    def fail(conn):
        raise psycopg.OperationalError(f"connection failed for user {TYPED}@corp.example")

    monkeypatch.setattr(session, "allocate_generation", fail)


def guard_held_too_long(api, monkeypatch):
    def fail(conn):
        raise LockNotAvailable("canceling statement due to lock timeout")

    monkeypatch.setattr(session, "lock_identity", fail)


def no_free_connection(api, monkeypatch):
    def fail(conn):
        raise PoolTimeout("couldn't get a connection after 3.00 sec")

    monkeypatch.setattr(session, "allocate_generation", fail)


def gate_closes_after_the_bind(api, monkeypatch):
    def close(conn):
        api.db.gate = False

    monkeypatch.setattr(session, "lock_identity", close)


def publication_breaks(api, monkeypatch):
    def broken(conn, evidence, **kw):
        raise ValueError(f"cannot publish {TYPED}@corp.example")

    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: False)
    monkeypatch.setattr(session, "publish", broken)


@pytest.mark.parametrize(
    ("arrange", "status", "code", "dependency"),
    [
        (database_down, 503, "database_unavailable", "postgresql"),
        (guard_held_too_long, 503, "database_unavailable", "postgresql"),
        (no_free_connection, 503, "database_unavailable", "postgresql"),
        (gate_closes_after_the_bind, 503, "human_authorization_gated", None),
        (publication_breaks, 500, "internal_error", None),
    ],
)
def test_a_sign_in_that_fails_after_the_bind_is_still_one_event(
    api, records, monkeypatch, arrange, status, code, dependency
):
    """Requirements: REV-74; observability 5 and 7.

    A failure outside sign-in's own checks keeps its answer and is counted under the
    error code the person was answered with.
    """
    arrange(api, monkeypatch)
    before, timings = counted("sign_in_unavailable", "failure", code), timed("sign_in_unavailable")
    client = TestClient(api.client.app, base_url=ORIGIN, raise_server_exceptions=False)
    response = post(client, credentials(TYPED))
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    written = records()
    (event,) = events(written)
    assert event["event"]["action"] == "sign_in_unavailable"
    assert event["event"]["outcome"] == "failure"
    assert event["keep"]["reason"] == code and event["log"]["level"] == "warning"
    assert event["keep"].get("dependency") == dependency
    assert "user" not in event
    assert counted("sign_in_unavailable", "failure", code) == before + 1
    assert timed("sign_in_unavailable") == timings + 1
    assert not api.db.sql("INSERT INTO auth_sessions")
    assert_names_nobody(written, "corp.example", "cannot publish")


def wait_cut_off(conn):
    """A statement held behind a directory publication, ended as the database layer ends it."""
    time.sleep(0.6)
    request_budget.remaining()


def session_saved_late(conn):
    time.sleep(0.6)


@pytest.mark.parametrize("guard", [wait_cut_off, session_saved_late])
def test_a_sign_in_that_outlasts_the_request_is_one_unavailable_event(
    api, records, monkeypatch, guard
):
    """Requirements: REV-74; observability 5 and 7.

    The request's time ends while sign-in waits for the identity guard, and the caller
    is answered request_timeout then. That is the outcome, whether the wait fails or the
    session is saved a moment later. The request's 10 seconds are 0.3 here.
    """
    timeout, budget = asyncio.timeout, keep_http.request_budget
    monkeypatch.setattr(asyncio, "timeout", lambda seconds: timeout(0.3))
    monkeypatch.setattr(keep_http, "request_budget", lambda seconds: budget(0.3))
    monkeypatch.setattr(session, "PUBLISH_RESERVE_SECONDS", 0.01)
    monkeypatch.setattr(session, "lock_identity", guard)
    before = counted("sign_in_unavailable", "failure", "request_timeout")
    completed = counted("sign_in_completed", "success")
    response = post(api.client, credentials(TYPED))
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "request_timeout"
    written = records()
    (event,) = events(written)
    assert event["event"]["action"] == "sign_in_unavailable"
    assert event["keep"]["reason"] == "request_timeout"
    assert "user" not in event
    (request,) = [r for r in written if r["event"]["action"] == "http_request"]
    assert "user" not in request
    assert counted("sign_in_unavailable", "failure", "request_timeout") == before + 1
    assert counted("sign_in_completed", "success") == completed


def test_an_error_outside_sign_ins_checks_is_named_by_a_fixed_code():
    """Requirements: REV-74; observability 5. Never the error's own text."""
    reason = session._outside_reason
    assert reason(unavailable("human_authorization_gated")) == "human_authorization_gated"
    assert reason(psycopg.OperationalError(f"no route for {TYPED}")) == "database_unavailable"
    assert reason(PoolTimeout("no connection")) == "database_unavailable"
    assert reason(AppError(f"{TYPED}@corp.example", "text", 503)) == "other"
    assert reason(asyncio.CancelledError()) == "request_cancelled"
    assert reason(ValueError(f"cannot publish {TYPED}")) == "internal_error"


def test_an_errors_own_text_is_never_a_reason(api, records):
    """Requirements: REV-74; observability 5. A reason is a fixed code or "other"."""
    FakeADAPI.error = DirectoryUnavailable(f"no answer while reading {TYPED}@corp.example")
    before = counted("sign_in_unavailable", "failure", "other")
    assert post(api.client, credentials(TYPED)).status_code == 503
    written = records()
    (event,) = events(written)
    assert event["keep"]["reason"] == "other"
    assert counted("sign_in_unavailable", "failure", "other") == before + 1
    assert_names_nobody(written, "corp.example", "no answer while reading")


def test_missing_settings_are_reported_once_and_each_attempt_is_counted(api, records):
    """Requirements: REV-74; observability 5 and 7. REV-73; identity configuration 13."""
    missing = counted("sign_in_configuration_missing", "failure")
    refused = counted("sign_in_unavailable", "failure", "configuration_missing")
    with TestClient(api.build(ldap_host=None), base_url=ORIGIN) as client:
        assert post(client, credentials(TYPED)).status_code == 503
        assert post(client, credentials(TYPED)).status_code == 503
    written = events(records())
    assert [r["event"]["action"] for r in written] == [
        "sign_in_configuration_missing",
        "sign_in_unavailable",
        "sign_in_unavailable",
    ]
    # The settings line names the settings to set and none of their values.
    assert "KEEP_LDAP_HOST" in written[0]["message"]
    assert counted("sign_in_configuration_missing", "failure") == missing + 1
    assert counted("sign_in_unavailable", "failure", "configuration_missing") == refused + 2


def test_a_fenced_publication_is_recorded_and_the_sign_in_still_completes(
    api, records, monkeypatch
):
    """Requirements: REV-74; observability 5. REV-73; identity configuration 8."""
    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: False)
    monkeypatch.setattr(
        session, "publish", lambda conn, evidence, **kw: SimpleNamespace(fenced=True)
    )
    before = counted("sign_in_publication_fenced", "unknown")
    assert post(api.client, credentials(TYPED)).status_code == 200
    names = [r["event"]["action"] for r in events(records())]
    assert names == ["sign_in_publication_fenced", "sign_in_completed"]
    assert counted("sign_in_publication_fenced", "unknown") == before + 1


@pytest.mark.parametrize(
    "stored",
    [{"eligible": False}, {"deleted": True}],
    ids=["stored-ineligible", "stored-deleted"],
)
def test_a_fenced_publication_leaving_the_person_unusable_is_a_retryable_503(
    api, records, monkeypatch, stored
):
    """A newer publication from an earlier version holds the person unusable.

    Sign-in answers 503 sign_in_unavailable (reason stored_person_unusable) and
    creates no session the next request would reject.

    Requirements: REV-76; identity configuration 3, 8; plan B3.
    """
    monkeypatch.setattr(session, "stored_matches", lambda conn, obj: False)
    monkeypatch.setattr(
        session, "publish", lambda conn, evidence, **kw: SimpleNamespace(fenced=True)
    )
    api.db.principal.update(stored)
    before = counted("sign_in_unavailable", "failure", "stored_person_unusable")
    response = post(api.client, credentials(TYPED))
    assert response.status_code == 503, response.text
    assert response.json()["error"]["code"] == "sign_in_unavailable"
    assert not api.db.sql("INSERT INTO auth_sessions") and "set-cookie" not in response.headers
    written = records()
    names = [r["event"]["action"] for r in events(written)]
    assert names == ["sign_in_publication_fenced", "sign_in_unavailable"]
    (event,) = [r for r in events(written) if r["event"]["action"] == "sign_in_unavailable"]
    assert event["keep"]["reason"] == "stored_person_unusable"
    assert counted("sign_in_unavailable", "failure", "stored_person_unusable") == before + 1
    assert_names_nobody(written)
