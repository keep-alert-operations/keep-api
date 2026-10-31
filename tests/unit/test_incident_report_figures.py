"""Period planning and figures of the incident report (REV-53)."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from appchi.reports.figures import (
    PeriodError,
    attach_assignments,
    breakdowns,
    percentile,
    plan_period,
    series,
    summarize,
)

JERUSALEM = ZoneInfo("Asia/Jerusalem")
NOW = datetime(2026, 10, 29, 14, 30, tzinfo=JERUSALEM).astimezone(UTC)


def local(day, hour=0, minute=0):
    return datetime(2026, day[0], day[1], hour, minute, tzinfo=JERUSALEM).astimezone(UTC)


def cycle(opened, **values):
    row = {
        "incident_id": values.pop("incident", "i"),
        "opened_at": opened,
        "investigating_at": None,
        "resolved_at": None,
        "cause": None,
        "severity": "high",
        "origin": "manual",
        "rule_id": None,
        "current_assignee": None,
        "first_cycle": True,
        "next_opened_at": None,
        "first_assigned_at": None,
        "resolved_assignee": None,
    }
    row.update(values)
    return row


def test_thirty_days_are_local_calendar_days_across_the_dst_change():
    """Requirements: REV-53; incident operations 20."""
    period = plan_period(local((9, 30)), NOW, JERUSALEM, NOW, True)
    assert period.unit == "day"
    assert len(period.edges) == 30
    assert period.edges[0] == local((9, 30))
    # 25 October 2026 is 25 hours long in Jerusalem; every bin still starts at local midnight.
    day = period.edges.index(local((10, 25)))
    assert period.edges[day + 1] - period.edges[day] == timedelta(hours=25)
    assert all(edge.astimezone(JERUSALEM).hour == 0 for edge in period.edges)
    assert period.previous == (local((8, 31)), local((9, 30)))
    assert period.previous_unavailable is None


def test_ninety_days_use_weeks_and_cannot_compare_past_retention():
    """Requirements: REV-53; incident operations 13, 20."""
    period = plan_period(local((8, 1)), NOW, JERUSALEM, NOW, True)
    assert period.retention_from == local((8, 1))
    assert period.covered_from == local((8, 1))
    assert period.unit == "week"
    assert len(period.edges) == 13
    assert period.previous is None
    assert period.previous_unavailable == "past_retention"


def test_rolling_day_uses_hours_and_compares_with_the_previous_day():
    """Requirements: REV-53; incident operations 20."""
    start = NOW - timedelta(hours=24)
    period = plan_period(start, NOW, JERUSALEM, NOW, True)
    assert period.unit == "hour"
    assert len(period.edges) == 24
    assert period.previous == (start - timedelta(hours=24), start)


def test_custom_range_past_retention_reports_only_retained_history():
    """Requirements: REV-53; incident operations 13, 20."""
    period = plan_period(local((5, 1)), NOW, JERUSALEM, NOW, True)
    assert period.requested_from == local((5, 1))
    assert period.covered_from == local((8, 1))
    assert period.previous_unavailable == "past_retention"
    older = plan_period(local((3, 1)), local((4, 1)), JERUSALEM, NOW, False)
    assert older.covered_from == older.covered_to == local((4, 1))
    assert older.edges == ()
    assert older.previous_unavailable == "not_requested"


@pytest.mark.parametrize(
    "start,end",
    [
        (datetime(2026, 10, 1), NOW),
        (NOW, NOW - timedelta(days=1)),
        (NOW - timedelta(days=1), NOW + timedelta(minutes=6)),
        (NOW - timedelta(days=367), NOW),
    ],
)
def test_invalid_periods_are_rejected(start, end):
    """Requirements: REV-53; system completion 5, 10."""
    with pytest.raises(PeriodError):
        plan_period(start, end, JERUSALEM, NOW, True)


def test_percentiles_interpolate_and_round_half_up():
    """Requirements: REV-53; incident operations 20."""
    assert percentile([], 0.5) is None
    assert percentile([1, 2, 3, 4], 0.5) == 3
    assert percentile([10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 0.9) == 91
    assert percentile([7], 0.9) == 7


def test_summary_counts_cycles_reopenings_causes_and_response():
    """Requirements: REV-53, REV-46; incident operations 4, 20."""
    lower, upper = local((10, 1)), local((10, 29))
    hour = timedelta(hours=1)
    rows = [
        # Assigned after 10 minutes, investigating after 30: the assignment is the response.
        cycle(
            lower + hour,
            first_assigned_at=lower + hour + timedelta(minutes=10),
            investigating_at=lower + hour + timedelta(minutes=30),
            resolved_at=lower + 3 * hour,
            cause="manual",
            next_opened_at=lower + 5 * hour,
        ),
        # The reopening of the first incident; never responded to yet.
        cycle(lower + 5 * hour, first_cycle=False),
        # Investigating only, resolved when its alerts resolved.
        cycle(
            lower + 2 * hour,
            incident="j",
            investigating_at=lower + 2 * hour + timedelta(minutes=20),
            resolved_at=lower + 6 * hour,
            cause="alerts_resolved",
        ),
        # Opened before the period, resolved inside it: counts as resolved only.
        cycle(lower - 5 * hour, incident="k", resolved_at=lower + hour, cause="manual"),
    ]
    figures = summarize(rows, lower, upper, True)
    assert figures["opened"] == 3
    assert (figures["opened_new"], figures["opened_reopened"]) == (2, 1)
    assert figures["resolved"] == 3
    assert figures["resolved_by_cause"] == {"manual": 2, "alerts_resolved": 1, "inactivity": 0}
    assert figures["reopened"] == 1
    assert figures["first_response"] == {
        "median_seconds": 900,
        "p90_seconds": 1140,
        "responded": 2,
        "waiting": 1,
    }
    assert figures["time_to_resolve"] == {"median_seconds": 14400, "p90_seconds": 20160}
    assert summarize(rows, lower, upper, False)["first_response"] is None


def test_reopening_after_the_period_does_not_count():
    """Requirements: REV-53; incident operations 20."""
    lower, upper = local((10, 1)), local((10, 8))
    rows = [
        cycle(lower, resolved_at=lower + timedelta(days=1), cause="manual", next_opened_at=upper)
    ]
    assert summarize(rows, lower, upper, True)["reopened"] == 0


def test_breakdowns_group_and_cap_rules_and_assignees():
    """Requirements: REV-53; incident operations 20."""
    lower, upper = local((10, 1)), local((10, 29))
    rows = [
        cycle(lower, origin="correlation", rule_id="r1", severity="critical"),
        cycle(lower, origin="correlation", rule_id="r1", severity="critical"),
        cycle(lower, origin="correlation", rule_id="r2", current_assignee="u1"),
        cycle(lower, origin="correlation", rule_id="r3"),
        cycle(
            lower,
            resolved_at=lower + timedelta(hours=1),
            cause="manual",
            current_assignee="u9",
            resolved_assignee="u2",
        ),
    ]
    result = breakdowns(rows, lower, upper, True, limit=2)
    assert [row["severity"] for row in result["severity"]] == ["critical", "high", "medium", "low"]
    assert [row["opened"] for row in result["severity"]] == [2, 3, 0, 0]
    assert [(row["origin"], row["opened"]) for row in result["origin"]] == [
        ("correlation", 4),
        ("manual", 1),
    ]
    assert [key for key, _ in result["rule"]["rows"]] == ["r1", "r2"]
    assert result["rule"]["other"] == {"groups": 1, "opened": 1, "resolved": 0, "reopened": 0}
    # The resolved cycle belongs to its assignee at resolution (u2), not the current one (u9).
    assert [key for key, _ in result["assignee"]["rows"]] == [None, "u2"]
    assert result["assignee"]["other"] == {"groups": 1, "opened": 1, "resolved": 0, "reopened": 0}
    every = breakdowns(rows, lower, upper, True)
    assert {key for key, _ in every["assignee"]["rows"]} == {None, "u1", "u2"}
    assert breakdowns(rows, lower, upper, False)["assignee"] is None


def test_series_places_cycles_in_local_day_bins():
    """Requirements: REV-53; incident operations 20."""
    period = plan_period(local((10, 23)), NOW, JERUSALEM, NOW, False)
    rows = [
        cycle(local((10, 25), 23, 30), resolved_at=local((10, 26), 0, 30), cause="manual"),
        cycle(local((10, 29), 9)),
    ]
    bins = series(rows, period)
    assert [item["start"] for item in bins] == list(period.edges)
    counts = {
        item["start"].astimezone(JERUSALEM).day: (item["opened"], item["resolved"]) for item in bins
    }
    assert counts[25] == (1, 0)
    assert counts[26] == (0, 1)
    assert counts[29] == (1, 0)


def test_assignment_history_gives_first_response_and_assignee_at_resolution():
    """Requirements: REV-53, I5; incident operations 3, 20."""
    base = local((10, 1))
    minute = timedelta(minutes=1)
    events = [
        {
            "incident_id": "a",
            "kind": "assignment",
            "recorded_at": base + 10 * minute,
            "assignee": "u1",
        },
        {
            "incident_id": "a",
            "kind": "assignment",
            "recorded_at": base + 300 * minute,
            "assignee": "u2",
        },
        {
            "incident_id": "b",
            "kind": "assignment",
            "recorded_at": base + 5 * minute,
            "assignee": "u3",
        },
        {
            "incident_id": "b",
            "kind": "assignment",
            "recorded_at": base + 50 * minute,
            "assignee": None,
        },
        {
            "incident_id": "c",
            "kind": "assignment",
            "recorded_at": base + 5 * minute,
            "assignee": "u4",
        },
        {
            "incident_id": "c",
            "kind": "eligibility_lost",
            "recorded_at": base + 60 * minute,
            "assignee": None,
        },
    ]
    rows = [
        # Resolved before the second assignment: assigned to u1 at resolution.
        cycle(base, incident="a", resolved_at=base + 120 * minute),
        # Reopened with u1 kept: only the later assignment to u2 is a response.
        cycle(base + 200 * minute, incident="a", first_cycle=False),
        cycle(base, incident="b", resolved_at=base + 100 * minute),
        cycle(base, incident="c", resolved_at=base + 100 * minute),
        cycle(base, incident="d", resolved_at=base + 100 * minute),
    ]
    attach_assignments(rows, list(reversed(events)))
    assert [row["first_assigned_at"] for row in rows] == [
        base + 10 * minute,
        base + 300 * minute,
        base + 5 * minute,
        base + 5 * minute,
        None,
    ]
    assert [row["resolved_assignee"] for row in rows] == ["u1", None, None, None, None]
