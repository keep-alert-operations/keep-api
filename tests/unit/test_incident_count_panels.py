"""Incident count panels (REV-69): storage mapping and incident results."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from keep.configuration import count_routes
from keep.configuration.count_routes import DashboardPreview, QuickCountRequest
from keep.configuration.routes import panel_content, panel_row
from keep.search.counts import CountBatch

PRESET = "00000000-0000-4000-8000-000000000002"
OTHER = "00000000-0000-4000-8000-000000000003"
FIRING = "00000000-0000-4000-8000-0000000000a1"
INVESTIGATING = "00000000-0000-4000-8000-0000000000a2"
RESOLVED = "00000000-0000-4000-8000-0000000000a3"
RETIRED = "00000000-0000-4000-8000-0000000000a4"
LAYOUT = {"title": None, "y": 0, "w": 3, "h": 2}


def test_incident_count_panels_are_counted_and_store_their_statuses_in_content():
    """Requirements: REV-69; dashboard operations 2, 3 and 14."""
    incidents = {
        **LAYOUT,
        "id": "00000000-0000-4000-8000-000000000012",
        "x": 3,
        "type": "incident_count",
        "preset_id": OTHER,
        "incident_status": "investigating",
        "thresholds": [{"lower_bound": "2", "color": "red"}],
    }
    panels = [{**LAYOUT, "id": "00000000-0000-4000-8000-000000000011", "x": 0, "preset_id": PRESET}, incidents]
    parsed = DashboardPreview.model_validate(
        {"name": "Preview", "panels": panels, "preset_revisions": {PRESET: "1", OTHER: "4"}}
    )
    assert [panel.type for panel in parsed.panels] == ["count", "incident_count"]
    # The incident count panel's preset is counted, so its revision is required.
    with pytest.raises(ValueError):
        DashboardPreview.model_validate(
            {"name": "Preview", "panels": panels, "preset_revisions": {PRESET: "1"}}
        )
    assert panel_content(parsed.panels[1]) == {"incident_status": "investigating"}
    stored = {
        **{key: incidents[key] for key in ("id", "type", "title", "x", "y", "w", "h")},
        "preset_id": OTHER,
        "image_id": None,
        "thresholds": incidents["thresholds"],
        "content": panel_content(parsed.panels[1]),
    }
    assert panel_row(stored) == {**incidents, "link": None}
    assert panel_row(stored) == parsed.panels[1].model_dump()


def test_quick_counts_accept_an_incident_status_per_query():
    """Requirements: REV-69; dashboard operations 14."""
    body = QuickCountRequest.model_validate(
        {"queries": [{"id": "a", "cel": "true", "incident_status": "open"}, {"id": "b"}]}
    )
    assert [query.incident_status for query in body.queries] == ["open", None]
    with pytest.raises(ValueError):
        QuickCountRequest.model_validate({"queries": [{"id": "a", "incident_status": "resolved"}]})


class Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class Connection:
    """Answers the status query like PostgreSQL: resolved and retired rows are left out."""

    def __init__(self):
        self.queries = []

    def execute(self, query, args):
        self.queries.append((query, args))
        tenant, ids = args
        stored = {FIRING: "open", INVESTIGATING: "investigating"}
        return Rows([{"id": key, "status": stored[key]} for key in ids if key in stored])


def fake_request(connection):
    @contextmanager
    def transaction():
        yield connection

    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db=SimpleNamespace(transaction=transaction))))


def batch(counts, incidents):
    return CountBatch("observation", counts, "2026-11-10T12:00:00+00:00", {}, {}, False, False, None, incidents)


@pytest.fixture
def authorized(monkeypatch):
    checked = []
    monkeypatch.setattr(count_routes, "_begin", lambda conn, request, tenant, deadline: checked.append(tenant))
    return checked


def test_incident_results_count_each_matching_status_once_with_its_alerts(authorized):
    """Requirements: REV-69; dashboard operations 3, 6 and 11."""
    connection = Connection()
    owners = {FIRING: 3, INVESTIGATING: 2, RESOLVED: 4, RETIRED: 1}
    observed = batch({"incidents:p": 12}, {"incidents:p": owners})
    wanted = {
        "both": ("incidents:p", ("open", "investigating")),
        "firing": ("incidents:p", ("open",)),
        "investigating": ("incidents:p", ("investigating",)),
    }
    results = count_routes._incident_results(fake_request(connection), "tenant", 0, observed, wanted)
    # Resolved and retired incidents never count; each incident counts once.
    assert results == {
        "both": {"count": "2", "alerts": "12", "linked_alerts": "5"},
        "firing": {"count": "1", "alerts": "12", "linked_alerts": "3"},
        "investigating": {"count": "1", "alerts": "12", "linked_alerts": "2"},
    }
    # One authorized status read for every incident the batch saw.
    assert authorized == ["tenant"]
    [(query, args)] = connection.queries
    assert "retired_at IS NULL" in query and "<>'resolved'" in query
    assert args == ("tenant", sorted(owners))


def test_incident_results_without_owners_skip_the_database_and_report_zero(authorized):
    """Requirements: REV-69; dashboard operations 3."""
    connection = Connection()
    observed = batch({"q": 5}, {"q": {}})
    assert count_routes._incident_results(
        fake_request(connection), "tenant", 0, observed, {"q": ("q", ("open",))}
    ) == {"q": {"count": "0", "alerts": "5", "linked_alerts": "0"}}
    assert connection.queries == [] and authorized == []


def test_too_many_incidents_is_an_error_for_that_panel_only(authorized):
    """Requirements: REV-69; dashboard operations 11."""
    connection = Connection()
    observed = batch({"a": 9, "b": 4}, {"a": None, "b": {FIRING: 4}})
    results = count_routes._incident_results(
        fake_request(connection),
        "tenant",
        0,
        observed,
        {"a": ("a", ("open",)), "b": ("b", ("open",))},
    )
    assert results["a"]["error"]["code"] == "incident_count_too_large"
    assert results["b"] == {"count": "1", "alerts": "4", "linked_alerts": "4"}
