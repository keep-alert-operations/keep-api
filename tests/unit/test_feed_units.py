"""Alert-feed transaction and authorization cost, without PostgreSQL or Elasticsearch."""

from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID

import pytest

from keep import search_routes
from keep.search import SearchReader, SearchScope
from keep.shared.crypto import EnvelopeCipher
from keep.shared.errors import AppError

TENANT = "00000000-0000-4000-8000-000000000001"
HANDLE = b"\x01" * 32
NOW = datetime(2026, 10, 21, 12, tzinfo=UTC)
IDS = [str(UUID(int=n)) for n in range(1, 6)]
SHARDS = {"total": 1, "successful": 1, "failed": 0}


class Expression:
    """Stands in for a compiled CEL expression; native compilation is not under test."""

    source, relative = "true", False

    def scoped_query(self, tenant, at, *, include_suppressed):
        return {"bool": {"filter": [{"term": {"tenant_id": tenant}}]}}


def compile_expression(source):
    if source != "true":
        raise AppError("invalid_cel", "Invalid expression")
    return Expression()


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


class Stack:
    """Fake PostgreSQL authority and Elasticsearch index for one feed."""

    def __init__(self, monkeypatch, retired=()):
        self.log, self.units = [], []
        self.pending = False
        self.revoke_on_search = False
        self.revoked = False
        self.retired = set(retired)
        self.cipher = EnvelopeCipher({"test": b"k" * 32}, "test")
        monkeypatch.setattr(search_routes, "authorize", self.authorize)
        monkeypatch.setattr(search_routes, "check_search", lambda conn: None)
        monkeypatch.setattr(search_routes, "enrich_alerts", self.enrich)
        monkeypatch.setattr(search_routes, "compile_expression", compile_expression)
        monkeypatch.setattr(search_routes, "monotonic", lambda: 50.0, raising=False)
        self.request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db=self,
                    search_client=self,
                    settings=SimpleNamespace(
                        elasticsearch_url="http://search",
                        elasticsearch_index="alerts",
                        deployment_epoch="epoch",
                        cipher=lambda: self.cipher,
                    ),
                )
            ),
            cookies={},
            headers={},
        )

    # PostgreSQL
    @contextmanager
    def transaction(self, tenant_id=None, *, read_committed=False):
        self.units.append((tenant_id, read_committed))
        self.log.append("transaction")
        yield self

    def authorize(self, conn, request, tenant):
        self.log.append("authorize")
        if self.revoked:
            raise AppError("unauthenticated", "Sign in is required.", 401)
        return {"id": "user"}, {"handle_hash": HANDLE}, "view"

    def execute(self, sql, params=None):
        if "capability_gates" in sql:
            return Result([{"ready": True}])
        if "tenant_view_state v JOIN" in sql:
            return Result(
                [
                    {
                        "index_epoch": "index-1",
                        "projection_seq": 9,
                        "searchable_seq": 9,
                        "purge_generation": 0,
                        "verified_at": NOW,
                    }
                ]
            )
        if "EXISTS(SELECT 1 FROM projection_work" in sql:
            return Result([{"now": NOW, "pending": self.pending}])
        if "SELECT 1 FROM projection_work" in sql:  # unmodified route
            return Result([{"one": 1}] if self.pending else [])
        if "clock_timestamp() AS now" in sql:  # unmodified route
            return Result([{"now": NOW}])
        if "alert_identities" in sql:
            return Result([{"id": UUID(i)} for i in params[1] if i not in self.retired])
        raise AssertionError(sql)

    def enrich(self, conn, tenant, rows):
        return [{**row, "enriched": True} for row in rows]

    # Elasticsearch
    def options(self, **kwargs):
        return self

    def open_point_in_time(self, **kwargs):
        self.log.append("open")
        return {"id": "pit-1", "_shards": SHARDS}

    def search(self, **kwargs):
        self.log.append("search")
        start = 0 if "search_after" not in kwargs else kwargs["search_after"][0]
        hits = [
            {
                "_id": IDS[n],
                "_source": {
                    "tenant_id": TENANT,
                    "deleted": False,
                    "display": {"id": IDS[n], "status": "firing", "assignee_id": None},
                },
                "sort": [n + 1],
            }
            for n in range(start, min(start + kwargs["size"], len(IDS)))
        ]
        if self.revoke_on_search:
            self.revoked = True
        return {
            "pit_id": "pit-1",
            "timed_out": False,
            "_shards": SHARDS,
            "hits": {"total": {"value": len(IDS), "relation": "eq"}, "hits": hits},
        }

    def close_point_in_time(self, *, id):
        self.log.append("close")

    # Helpers
    def page(self, routes=None, **kwargs):
        self.log.clear()
        self.units.clear()
        return (routes or search_routes).feed(
            TENANT,
            self.request,
            cel=kwargs.pop("cel", "true"),
            q="",
            include_suppressed=False,
            limit=kwargs.pop("limit", 3),
            cursor=kwargs.pop("cursor", None),
            replace_cursor=None,
            sort="timestamp",
            direction="desc",
            **kwargs,
        )

    def opened(self, token):
        scope = SearchScope(TENANT, HANDLE.hex(), "epoch")
        return SearchReader(
            None,
            "alerts",
            self.cipher,
            clock=None,
            state=None,
            authorize=None,
            retained_ids=None,
        )._open_cursor(token, scope)

    def flow(self):
        return [entry for entry in self.log if entry != "transaction"]


def rows(*numbers):
    return [
        {
            "id": IDS[n],
            "status": "firing",
            "assignee_id": None,
            "display_status": "firing",
            "enriched": True,
        }
        for n in numbers
    ]


WATERMARK = {
    "index_epoch": "index-1",
    "committed_seq": "9",
    "searchable_seq": "9",
    "purge_generation": "0",
    "verified_at": "2026-10-21T12:00:00.000000Z",
}


def check_pages(stack, routes=None):
    """The responses of a two-page walk; shared with the unmodified-route comparison."""
    first = stack.page(routes)
    assert first["data"] == rows(0, 1, 2)
    assert first["meta"]["total"] == "5"
    assert first["meta"]["evaluated_at"] == NOW.isoformat()
    assert first["meta"]["updating"] is False
    assert first["meta"]["watermark"] == WATERMARK
    assert first["meta"]["relative"] is False
    assert first["meta"]["close_token"]
    cursor = stack.opened(first["next_cursor"])
    assert cursor["pit"] == "pit-1" and cursor["after"] == [3] and cursor["seen"] == 3
    assert cursor["evaluated_at"] == NOW.isoformat()

    second = stack.page(routes, cursor=first["next_cursor"])
    assert second["data"] == rows(3, 4)
    assert second["meta"]["total"] == "5"
    assert second["meta"]["evaluated_at"] == NOW.isoformat()
    assert second["meta"]["watermark"] == WATERMARK
    assert second["next_cursor"] is None and second["meta"]["close_token"] is None
    return first, second


def test_two_page_walk_returns_the_same_responses(monkeypatch):
    check_pages(Stack(monkeypatch))


def test_first_page_costs_four_units_and_two_authorizations(monkeypatch):
    stack = Stack(monkeypatch)
    stack.page()
    # Authorize+clock+state, PIT re-check, authorize+retained+state, display names.
    assert stack.units == [(None, True), (TENANT, False), (None, True), (TENANT, False)]
    assert stack.flow() == ["authorize", "open", "search", "authorize"]


def test_later_page_costs_three_units_and_two_authorizations(monkeypatch):
    stack = Stack(monkeypatch)
    first = stack.page()
    stack.page(cursor=first["next_cursor"])
    assert stack.units == [(None, True), (None, True), (TENANT, False)]
    assert stack.flow() == ["authorize", "search", "authorize", "close"]


def test_empty_page_authorizes_with_the_observed_state(monkeypatch):
    stack = Stack(monkeypatch)
    monkeypatch.setattr(stack, "search", lambda **kwargs: empty(stack))
    page = stack.page()
    assert page["data"] == [] and page["meta"]["total"] == "0"
    assert stack.units == [(None, True), (TENANT, False), (None, True), (TENANT, False)]
    assert stack.flow() == ["authorize", "open", "search", "authorize", "close"]


def empty(stack):
    stack.log.append("search")
    return {
        "pit_id": "pit-1",
        "timed_out": False,
        "_shards": SHARDS,
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    }


def test_purged_identity_is_dropped_and_total_withheld(monkeypatch):
    stack = Stack(monkeypatch, retired={IDS[1]})
    page = stack.page()
    assert page["data"] == rows(0, 2) and page["meta"]["total"] is None
    assert page["meta"]["updating"] is True


def test_revocation_during_search_returns_no_rows(monkeypatch):
    stack = Stack(monkeypatch)
    stack.revoke_on_search = True
    with pytest.raises(AppError) as error:
        stack.page()
    assert error.value.code == "unauthenticated"
    assert stack.flow() == ["authorize", "open", "search", "authorize", "close"]
    assert len(stack.units) == 3  # no display-name unit


def test_pending_retention_projection_is_unavailable(monkeypatch):
    stack = Stack(monkeypatch)
    stack.pending = True
    with pytest.raises(AppError) as error:
        stack.page()
    assert error.value.code == "retention_projection_pending"
    assert stack.flow() == ["authorize"]  # before any Elasticsearch work


def test_invalid_expression_still_precedes_pending_projection(monkeypatch):
    stack = Stack(monkeypatch)
    stack.pending = True
    with pytest.raises(AppError) as error:
        stack.page(cel="alert.")
    assert error.value.code == "invalid_cel"


def test_search_not_ready_still_rejects_before_elasticsearch(monkeypatch):
    stack = Stack(monkeypatch)
    stack.request.app.state.settings.elasticsearch_url = ""
    with pytest.raises(AppError) as error:
        stack.page()
    assert error.value.code == "search_not_ready" and stack.flow() == ["authorize"]
