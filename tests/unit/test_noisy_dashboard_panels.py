"""Noisy presets on dashboards (REV-78): each counted panel result carries its preset's flag."""

from contextlib import contextmanager
import json
from types import SimpleNamespace

import pytest

from keep.cel.compiler import PROFILE
from keep.configuration import count_routes
from keep.configuration.count_routes import DashboardPreview
from keep.search.counts import CountBatch

DASHBOARD = "00000000-0000-4000-8000-000000000020"
LOUD = "00000000-0000-4000-8000-000000000021"
QUIET = "00000000-0000-4000-8000-000000000022"
LAYOUT = {"title": None, "y": 0, "w": 3, "h": 2, "link": None}
PANELS = [
    {**LAYOUT, "id": "00000000-0000-4000-8000-000000000031", "x": 0, "type": "count",
     "preset_id": LOUD, "thresholds": []},
    {**LAYOUT, "id": "00000000-0000-4000-8000-000000000032", "x": 3, "type": "count",
     "preset_id": QUIET, "thresholds": []},
    {**LAYOUT, "id": "00000000-0000-4000-8000-000000000033", "x": 6, "type": "incident_count",
     "preset_id": LOUD, "incident_status": "both", "thresholds": []},
    {**LAYOUT, "id": "00000000-0000-4000-8000-000000000034", "x": 9, "type": "incident_count",
     "preset_id": QUIET, "incident_status": "open", "thresholds": []},
    {**LAYOUT, "id": "00000000-0000-4000-8000-000000000035", "x": 0, "y": 2, "type": "html",
     "html": "<p>On call</p>"},
]
PRESETS = {
    LOUD: {"id": LOUD, "name": "Loud", "noisy": True, "revision": 3, "profile": PROFILE,
           "cel": "severity == 'critical'"},
    QUIET: {"id": QUIET, "name": "Quiet", "noisy": False, "revision": 7, "profile": PROFILE,
            "cel": "true"},
}


class Rows:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def execute(self, query, args=None):
        assert "clock_timestamp" in query
        return Rows({"now": "2026-11-19T12:00:00+00:00"})


def fake_request():
    @contextmanager
    def transaction():
        yield Connection()

    state = SimpleNamespace(
        db=SimpleNamespace(transaction=transaction),
        settings=SimpleNamespace(elasticsearch_index="alerts"),
    )
    return SimpleNamespace(app=SimpleNamespace(state=state))


class Reader:
    """Counts every query: four alerts per preset, and no owning incidents."""

    def __init__(self, client, index):
        pass

    def read(self, expressions, tenant, **_):
        return CountBatch(
            "observation",
            {key: 4 for key in expressions},
            "2026-11-19T12:00:00+00:00",
            {},
            {},
            False,
            False,
            None,
            {key: {} for key in expressions if key.startswith(count_routes.INCIDENTS)},
        )


@pytest.fixture
def counted(monkeypatch):
    def get_definition(conn, tenant, table, resource_id, lock=False):
        if table == "dashboards":
            assert resource_id == DASHBOARD
            return {"revision": 5, "panels": PANELS}
        return PRESETS[resource_id]

    monkeypatch.setattr(count_routes, "get_definition", get_definition)
    monkeypatch.setattr(count_routes, "_begin", lambda conn, request, tenant, deadline: None)
    monkeypatch.setattr(count_routes, "_state", lambda conn, tenant: "state")
    monkeypatch.setattr(count_routes, "CountReader", Reader)
    monkeypatch.setattr(count_routes, "search_client", lambda request: None)
    monkeypatch.setattr(
        count_routes, "compile_expression", lambda cel: SimpleNamespace(source=cel, relative=False)
    )


def flags(response):
    body = json.loads(response.body)
    return [
        (panel["panel_id"][-2:], panel["preset_name"], panel["preset_noisy"])
        for panel in body["data"]["panels"]
    ]


EXPECTED = [("31", "Loud", True), ("32", "Quiet", False), ("33", "Loud", True), ("34", "Quiet", False)]


def test_count_batch_results_carry_each_presets_saved_noisy_flag(counted):
    """Requirements: REV-78; dashboard operations 14."""
    response = count_routes._dashboard_counts(
        fake_request(), "tenant", dashboard_id=DASHBOARD, expected="5"
    )
    # Count and incident count results, noisy and not; the HTML panel is not counted.
    assert flags(response) == EXPECTED
    panels = json.loads(response.body)["data"]["panels"]
    assert panels[0]["count"] == "4" and panels[2]["count"] == "0"


def test_dashboard_preview_results_carry_each_presets_saved_noisy_flag(counted):
    """Requirements: REV-78; dashboard operations 14."""
    candidate = DashboardPreview.model_validate(
        {"name": "Preview", "panels": PANELS, "preset_revisions": {LOUD: "3", QUIET: "7"}}
    )
    response = count_routes._dashboard_counts(fake_request(), "tenant", candidate=candidate)
    assert flags(response) == EXPECTED
