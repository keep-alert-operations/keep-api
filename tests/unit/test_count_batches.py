"""ES response/transport control-flow tests, not an Elasticsearch substitute."""

from keep.cel.compiler import negate, suppressed_query
from dataclasses import replace
from datetime import UTC, datetime
import time

import pytest

from keep.cel import compile_expression
from keep.configuration.count_routes import DashboardPreview, PresetPreview
from keep.search.counts import CountReader, CountState
from keep.shared.errors import AppError


NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)
STATE = CountState("index-1", 9, 8, 0, NOW.isoformat(), 0, False, "completion-1")


def result(value=7, **extra):
    return {
        "pit_id": "replacement",
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"total": {"value": value, "relation": "eq"}, "hits": []},
        **extra,
    }


class Responses:
    def __init__(self, responses):
        self.responses, self.calls, self.closed = responses, [], []

    def options(self, **kwargs):
        assert kwargs["request_timeout"] > 0
        assert kwargs["max_retries"] == 0
        return self

    def open_point_in_time(self, **kwargs):
        self.calls.append(("open", kwargs))
        return {"id": "initial", "_shards": {"total": 1, "successful": 1, "failed": 0}}

    def msearch(self, **kwargs):
        self.calls.append(("msearch", kwargs))
        return {"responses": self.responses}

    def close_point_in_time(self, *, id):
        self.closed.append(id)


@pytest.fixture(scope="module")
def expressions():
    return {
        "all": compile_expression("true"),
        "recent": compile_expression('alert.time_created >= now() - duration("1h")'),
    }


def test_same_pit_clock_exact_totals_dedup_and_pre_snapshot_watermark(expressions):
    client = Responses([result(12), result(3, pit_id="replacement-2")])
    reader = CountReader(client, "alerts")
    batch = reader.read(
        {**expressions, "duplicate": expressions["all"]},
        "tenant-a",
        evaluated_at=NOW,
        before=STATE,
        revalidate=lambda: replace(STATE, committed_seq=15, searchable_seq=14),
    )
    assert batch.counts == {"all": 12, "recent": 3, "duplicate": 12}
    assert batch.watermark["searchable_seq"] == 8
    assert batch.observed["searchable_seq"] == 14 and batch.updating
    assert client.calls[0] == (
        "open",
        {"index": "alerts", "keep_alive": "30s", "allow_partial_search_results": False},
    )
    searches = client.calls[1][1]["searches"]
    assert len(searches) == 4
    for body in searches[1::2]:
        assert body["pit"] == {"id": "initial", "keep_alive": "30s"}
        assert body["size"] == 0 and body["track_total_hits"] is True
        assert "index" not in body and "routing" not in body and "preference" not in body
        assert {"term": {"tenant_id": "tenant-a"}} in body["query"]["bool"]["filter"]
        # Requirements: REV-49; alert operations 25, 29. Dismissals hide rows at NOW.
        assert negate(suppressed_query(NOW)) in body["query"]["bool"]["filter"]
        assert body["aggs"]["next_change"]["global"] == {}
        assert {"term": {"deleted": False}} in body["query"]["bool"]["filter"]
    assert searches[3]["query"] == expressions["recent"].scoped_query("tenant-a", NOW)
    assert set(client.closed) == {"initial", "replacement", "replacement-2"}


@pytest.mark.parametrize(
    "bad",
    [
        result(timed_out=True),
        result(_shards={"failed": 1}),
        result(_shards={"total": 2, "successful": 1, "failed": 0}),
        result(_shards={}),
        result(hits={"total": {"value": 10000, "relation": "gte"}}),
        result(hits={"total": {"value": True, "relation": "eq"}}),
        result(error={"type": "rejected"}, status=429),
    ],
)
def test_any_failed_sibling_discards_batch_and_closes_every_context(expressions, bad):
    client = Responses([bad, result(0, pit_id="later-context")])
    with pytest.raises(AppError) as error:
        CountReader(client, "alerts").read(
            expressions, "tenant", evaluated_at=NOW, before=STATE, revalidate=lambda: STATE
        )
    assert error.value.status == 503
    assert set(client.closed) == {"initial", "replacement", "later-context"}


@pytest.mark.parametrize(
    "changed",
    [
        replace(STATE, index_epoch="new"),
        replace(STATE, purge_generation=1),
        replace(STATE, maintenance_generation=1),
        replace(STATE, maintenance_pending=True),
        replace(STATE, maintenance_completion="completed"),
    ],
)
def test_context_changes_discard_the_complete_count(expressions, changed):
    client = Responses([result(0)])
    with pytest.raises(AppError) as error:
        CountReader(client, "alerts").read(
            {"all": expressions["all"]},
            "tenant",
            evaluated_at=NOW,
            before=STATE,
            revalidate=lambda: changed,
        )
    assert error.value.code == "count_snapshot_changed"
    assert set(client.closed) == {"initial", "replacement"}


def test_revocation_deadline_and_empty_dashboard(expressions):
    client = Responses([result(0)])

    def revoked():
        raise AppError("unauthenticated", "Revoked", 401)

    with pytest.raises(AppError) as error:
        CountReader(client, "alerts").read(
            {"all": expressions["all"]},
            "tenant",
            evaluated_at=NOW,
            before=STATE,
            revalidate=revoked,
        )
    assert error.value.status == 401 and client.closed
    empty = Responses([])
    batch = CountReader(empty, "alerts").read(
        {}, "tenant", evaluated_at=NOW, before=STATE, revalidate=lambda: STATE
    )
    assert batch.counts == {} and empty.calls == []
    with pytest.raises(AppError) as error:
        CountReader(empty, "alerts").read(
            {"all": expressions["all"]},
            "tenant",
            evaluated_at=NOW,
            before=STATE,
            revalidate=lambda: STATE,
            deadline=time.monotonic() - 1,
        )
    assert error.value.status == 503 and empty.calls == []


def test_preview_schema_rejects_raw_dsl_conflicting_and_duplicate_sorts():
    candidate = {
        "cel": "true",
        "sort": [
            {"field": "last_received_at", "direction": "desc"},
            {"field": "severity", "direction": "asc"},
        ],
        "columns": ["last_received_at", "message"],
    }
    parsed = PresetPreview.model_validate(candidate)
    assert parsed.sort[0].field == "timestamp" and parsed.columns[0] == "timestamp"
    for update in (
        {"sort": [{"field": "_script", "direction": "asc"}]},
        {"sort": [candidate["sort"][0], candidate["sort"][0]]},
        {"columns": ["source_events"]},
        {"query": {"match_all": {}}},
        {"expected_revision": "1"},
        {"limit": 201},
        {"cursor": "x", "replace_cursor": "y"},
    ):
        with pytest.raises(ValueError):
            PresetPreview.model_validate({**candidate, **update})
    with pytest.raises(ValueError):
        DashboardPreview.model_validate(
            {"name": "Preview", "panels": [], "preset_revisions": {"bad": "1"}}
        )


def test_dashboard_preview_takes_revisions_for_count_panels_only():
    """Requirements: REV-57; dashboard operations 2 and 14."""
    preset = "00000000-0000-4000-8000-000000000002"
    layout = {"title": None, "y": 0, "w": 3, "h": 2}
    panels = [
        {**layout, "id": "00000000-0000-4000-8000-000000000011", "x": 0, "preset_id": preset},
        {**layout, "id": "00000000-0000-4000-8000-000000000012", "x": 3, "type": "html", "html": "<p>Hi</p>"},
    ]
    parsed = DashboardPreview.model_validate(
        {"name": "Preview", "panels": panels, "preset_revisions": {preset: "1"}}
    )
    assert [panel.type for panel in parsed.panels] == ["count", "html"]
    DashboardPreview.model_validate(
        {"name": "Preview", "panels": panels[1:], "preset_revisions": {}}
    )
    with pytest.raises(ValueError):
        DashboardPreview.model_validate(
            {"name": "Preview", "panels": panels[1:], "preset_revisions": {preset: "1"}}
        )


def test_table_panels_are_not_counted_in_dashboard_previews():
    """Requirements: REV-63; dashboard operations 10 and 14."""
    preset, other = "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"
    layout = {"title": None, "y": 0, "w": 3, "h": 2}
    panels = [
        {**layout, "id": "00000000-0000-4000-8000-000000000011", "x": 0, "preset_id": preset},
        {**layout, "id": "00000000-0000-4000-8000-000000000012", "x": 3, "type": "table", "preset_id": other, "rows": 5},
    ]
    parsed = DashboardPreview.model_validate(
        {"name": "Preview", "panels": panels, "preset_revisions": {preset: "1"}}
    )
    assert [panel.type for panel in parsed.panels] == ["count", "table"]
    with pytest.raises(ValueError):
        DashboardPreview.model_validate(
            {"name": "Preview", "panels": panels, "preset_revisions": {preset: "1", other: "1"}}
        )


def test_newest_first_previews_need_a_saved_preset_and_no_group():
    """Requirements: REV-63; dashboard operations 14."""
    saved = {"preset_id": "00000000-0000-4000-8000-000000000002", "expected_revision": "3"}
    assert PresetPreview.model_validate({**saved, "newest_first": True, "limit": 10}).newest_first
    assert not PresetPreview.model_validate(saved).newest_first
    candidate = {"cel": "true", "sort": [{"field": "severity", "direction": "asc"}], "columns": ["message"]}
    for body in (
        {**candidate, "newest_first": True},
        {**saved, "newest_first": True, "group_key": "critical"},
        {**saved, "newest_first": True, "group_empty": True},
    ):
        with pytest.raises(ValueError):
            PresetPreview.model_validate(body)


def test_stored_table_panels_read_back_with_their_rows():
    """Requirements: REV-63; dashboard operations 2 and 14."""
    from keep.configuration.routes import panel_row

    layout = {"id": "p", "title": None, "x": 0, "y": 0, "w": 6, "h": 4}
    assert panel_row(
        {**layout, "type": "table", "preset_id": "s", "thresholds": [], "content": {"rows": 25}}
    ) == {**layout, "link": None, "type": "table", "preset_id": "s", "rows": 25}
    assert panel_row(
        {**layout, "type": "count", "preset_id": "s", "thresholds": [], "content": {}}
    ) == {**layout, "link": None, "type": "count", "preset_id": "s", "thresholds": []}


def test_panel_links_are_stored_in_content_and_read_back():
    """Requirements: REV-66; dashboard operations 2 and 14."""
    from keep.configuration.models import DashboardDefinition
    from keep.configuration.routes import panel_content, panel_row

    link = {"url": "https://runbooks.example/a", "label": "Runbook"}
    layout = {"id": "00000000-0000-4000-8000-000000000010", "title": None,
              "x": 0, "y": 0, "w": 3, "h": 2}
    panels = DashboardDefinition(
        name="Board",
        panels=[
            {**layout, "preset_id": "00000000-0000-4000-8000-000000000002", "link": link},
            {**layout, "id": "00000000-0000-4000-8000-000000000011", "x": 3, "type": "html",
             "html": "<p>Hi</p>", "link": link},
            {**layout, "id": "00000000-0000-4000-8000-000000000012", "x": 6, "type": "html",
             "html": "<p>Hi</p>"},
        ],
    ).panels
    assert panel_content(panels[0]) == {"link": link}
    assert panel_content(panels[1]) == {"link": link, "html": "<p>Hi</p>"}
    assert panel_content(panels[2]) == {"html": "<p>Hi</p>"}
    row = {**layout, "type": "html", "preset_id": None, "thresholds": [],
           "content": panel_content(panels[1])}
    assert panel_row(row)["link"] == link


def test_servicenow_panels_are_not_counted_and_store_settings_in_content():
    """Requirements: REV-65; dashboard operations 2, 3 and 10."""
    from keep.configuration.routes import panel_content, panel_row

    preset = "00000000-0000-4000-8000-000000000002"
    layout = {"title": None, "y": 0, "w": 3, "h": 2}
    tickets = {
        **layout,
        "id": "00000000-0000-4000-8000-000000000012",
        "x": 3,
        "type": "servicenow",
        "team": "Network Ops",
        "ticket_state": "in_progress",
        "detection": "direct",
        "thresholds": [{"lower_bound": "5", "color": "red"}],
    }
    panels = [{**layout, "id": "00000000-0000-4000-8000-000000000011", "x": 0, "preset_id": preset}, tickets]
    parsed = DashboardPreview.model_validate(
        {"name": "Preview", "panels": panels, "preset_revisions": {preset: "1"}}
    )
    assert [panel.type for panel in parsed.panels] == ["count", "servicenow"]
    assert panel_content(parsed.panels[1]) == {
        "team": "Network Ops",
        "ticket_state": "in_progress",
        "detection": "direct",
    }
    stored = {
        **{key: tickets[key] for key in ("id", "type", "title", "x", "y", "w", "h")},
        "preset_id": None,
        "image_id": None,
        "thresholds": tickets["thresholds"],
        "content": panel_content(parsed.panels[1]),
    }
    assert panel_row(stored) == {**tickets, "link": None}
    assert panel_row(stored) == parsed.panels[1].model_dump()
