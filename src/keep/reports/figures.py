"""Period planning and incident figures for the incident report (REV-53).

Everything here is pure: the route reads one row per lifecycle cycle and, when
it could be read in time, the assignment history of those incidents. Definitions
follow incident operations 20.
"""

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import floor
from zoneinfo import ZoneInfo

RETENTION = timedelta(days=90)
MAX_REQUEST = timedelta(days=366)
FUTURE_SKEW = timedelta(minutes=5)
HOURLY_LIMIT = timedelta(hours=25)
DAILY_LIMIT_DAYS = 45
GROUP_LIMIT = 50
SEVERITIES = ("critical", "high", "medium", "low")
ORIGINS = ("correlation", "manual")
CAUSES = ("manual", "alerts_resolved", "inactivity")


class PeriodError(ValueError):
    pass


@dataclass(frozen=True)
class Period:
    requested_from: datetime
    requested_to: datetime
    covered_from: datetime
    covered_to: datetime
    retention_from: datetime
    unit: str
    edges: tuple[datetime, ...]
    previous: tuple[datetime, datetime] | None
    previous_unavailable: str | None


def _midnight(day, tz: ZoneInfo) -> datetime:
    return datetime(day.year, day.month, day.day, tzinfo=tz).astimezone(UTC)


def _local_date(instant: datetime, tz: ZoneInfo):
    return instant.astimezone(tz).date()


def _next_midnight(instant: datetime, tz: ZoneInfo) -> datetime:
    """The first local midnight at or after ``instant``."""
    day = _local_date(instant, tz)
    start = _midnight(day, tz)
    return start if start >= instant else _midnight(day + timedelta(days=1), tz)


def _local_days(start: datetime, end: datetime, tz: ZoneInfo) -> int:
    """Local calendar days touched by ``[start, end)``."""
    last = _local_date(end - timedelta(microseconds=1), tz)
    return (last - _local_date(start, tz)).days + 1


def _edges(start: datetime, end: datetime, tz: ZoneInfo, unit: str) -> tuple[datetime, ...]:
    if start >= end:
        return ()
    if unit == "hour":
        count = -(-(end - start) // timedelta(hours=1))
        return tuple(start + timedelta(hours=index) for index in range(count))
    step = 7 if unit == "week" else 1
    first = _local_date(start, tz)
    edges, index = [start], 1
    while (edge := _midnight(first + timedelta(days=step * index), tz)) < end:
        edges.append(edge)
        index += 1
    return tuple(edges)


def plan_period(start: datetime, end: datetime, tz: ZoneInfo, now: datetime, compare: bool):
    """Clamp the request to retained history, choose bins and the previous period."""
    if start.tzinfo is None or end.tzinfo is None:
        raise PeriodError("Use instants with a UTC offset.")
    start, end = start.astimezone(UTC), end.astimezone(UTC)
    if start >= end:
        raise PeriodError("The period must end after it starts.")
    if end > now + FUTURE_SKEW:
        raise PeriodError("The period cannot end in the future.")
    if end - start > MAX_REQUEST:
        raise PeriodError("The period can be at most 366 days long.")
    retention_from = _next_midnight(now - RETENTION, tz)
    covered_from = min(max(start, retention_from), end)
    if end - covered_from <= HOURLY_LIMIT:
        unit = "hour"
    elif _local_days(covered_from, end, tz) <= DAILY_LIMIT_DAYS:
        unit = "day"
    else:
        unit = "week"
    previous, reason = None, None
    if not compare:
        reason = "not_requested"
    elif covered_from != start:
        reason = "past_retention"
    else:
        if end - start <= HOURLY_LIMIT and unit == "hour" and start != _next_midnight(start, tz):
            previous = (start - (end - start), start)
        else:
            days = _local_days(start, end, tz)
            previous = (_midnight(_local_date(start, tz) - timedelta(days=days), tz), start)
        if previous[0] < retention_from:
            previous, reason = None, "past_retention"
    return Period(
        start,
        end,
        covered_from,
        end,
        retention_from,
        unit,
        _edges(covered_from, end, tz, unit),
        previous,
        reason,
    )


def percentile(values, fraction):
    """Continuous percentile, like PostgreSQL percentile_cont, in whole seconds."""
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = floor(position)
    high = min(low + 1, len(ordered) - 1)
    return floor(ordered[low] + (ordered[high] - ordered[low]) * (position - low) + 0.5)


def attach_assignments(rows, events):
    """Give each cycle its first assignment and its assignee at resolution.

    ``events`` are an incident's ``assignment`` (assignee or null) and
    ``eligibility_lost`` entries. The first assignment is the earliest one naming
    an assignee within the cycle, so an assignee kept over a reopening is not a
    response. The assignee at resolution is the latest entry at or before it.
    """
    history = {}
    for event in events:
        history.setdefault(str(event["incident_id"]), []).append(event)
    for entries in history.values():
        entries.sort(key=lambda event: event["recorded_at"])
    for row in rows:
        entries = history.get(str(row["incident_id"]), [])
        times = [event["recorded_at"] for event in entries]
        end = row["resolved_at"]
        row["first_assigned_at"] = next(
            (
                event["recorded_at"]
                for event in entries[bisect_left(times, row["opened_at"]) :]
                if (end is None or event["recorded_at"] <= end)
                and event["kind"] == "assignment"
                and event["assignee"] is not None
            ),
            None,
        )
        row["resolved_assignee"] = None
        if end is not None:
            index = bisect_right(times, end) - 1
            if index >= 0 and entries[index]["kind"] == "assignment":
                row["resolved_assignee"] = entries[index]["assignee"]


def response_seconds(row):
    """Opening to the earlier of the first assignment and the first Investigating."""
    marks = [mark for mark in (row["investigating_at"], row.get("first_assigned_at")) if mark]
    return (min(marks) - row["opened_at"]).total_seconds() if marks else None


def resolve_seconds(row):
    return (row["resolved_at"] - row["opened_at"]).total_seconds()


def _within(instant, lower, upper):
    return instant is not None and lower <= instant < upper


def _figures(rows, lower, upper, assignments):
    opened = [row for row in rows if _within(row["opened_at"], lower, upper)]
    resolved = [row for row in rows if _within(row["resolved_at"], lower, upper)]
    reopened = sum(1 for row in resolved if _within(row["next_opened_at"], row["opened_at"], upper))
    durations = [resolve_seconds(row) for row in resolved]
    responses = [response_seconds(row) for row in opened] if assignments else []
    answered = [value for value in responses if value is not None]
    return opened, resolved, reopened, durations, answered


def summarize(rows, lower, upper, assignments):
    opened, resolved, reopened, durations, answered = _figures(rows, lower, upper, assignments)
    fresh = sum(1 for row in opened if row["first_cycle"])
    return {
        "opened": len(opened),
        "opened_new": fresh,
        "opened_reopened": len(opened) - fresh,
        "resolved": len(resolved),
        "resolved_by_cause": {
            cause: sum(1 for row in resolved if row["cause"] == cause) for cause in CAUSES
        },
        "reopened": reopened,
        "time_to_resolve": {
            "median_seconds": percentile(durations, 0.5),
            "p90_seconds": percentile(durations, 0.9),
        }
        if durations
        else None,
        "first_response": {
            "median_seconds": percentile(answered, 0.5),
            "p90_seconds": percentile(answered, 0.9),
            "responded": len(answered),
            "waiting": len(opened) - len(answered),
        }
        if assignments
        else None,
    }


def _group(rows, lower, upper, assignments):
    opened, resolved, reopened, durations, answered = _figures(rows, lower, upper, assignments)
    return {
        "opened": len(opened),
        "resolved": len(resolved),
        "reopened": reopened,
        "first_response_median_seconds": percentile(answered, 0.5),
        "time_to_resolve_median_seconds": percentile(durations, 0.5),
    }


def assignee_of(row):
    """The assignee at resolution for a resolved cycle, else the current visible one."""
    return row.get("resolved_assignee") if row["resolved_at"] else row["current_assignee"]


def _ranked(groups, limit):
    """Busiest groups first; the remainder becomes one Other row."""
    ordered = sorted(
        groups.items(), key=lambda item: (-(item[1]["opened"] + item[1]["resolved"]), str(item[0]))
    )
    kept, rest = ordered[:limit], ordered[limit:]
    other = None
    if rest:
        other = {
            "groups": len(rest),
            **{
                key: sum(values[key] for _, values in rest)
                for key in ("opened", "resolved", "reopened")
            },
        }
    return kept, other


def breakdowns(rows, lower, upper, assignments, limit=GROUP_LIMIT):
    """Per-group figures for cycles opened or resolved in ``[lower, upper)``."""
    current = [
        row
        for row in rows
        if _within(row["opened_at"], lower, upper) or _within(row["resolved_at"], lower, upper)
    ]

    def by(key_of, include=lambda key: True):
        groups = {}
        for row in current:
            key = key_of(row)
            if include(key):
                groups.setdefault(key, []).append(row)
        return {key: _group(members, lower, upper, assignments) for key, members in groups.items()}

    severity = by(lambda row: row["severity"])
    origin = by(lambda row: row["origin"])
    empty = _group([], lower, upper, assignments)
    rules, rule_other = _ranked(
        by(
            lambda row: row["rule_id"] if row["origin"] == "correlation" else None,
            lambda key: key is not None,
        ),
        limit,
    )
    result = {
        "severity": [{"severity": key, **severity.get(key, empty)} for key in SEVERITIES],
        "origin": [{"origin": key, **origin.get(key, empty)} for key in ORIGINS],
        "rule": {"rows": rules, "other": rule_other},
        "assignee": None,
    }
    if assignments:
        people, people_other = _ranked(by(assignee_of), limit)
        result["assignee"] = {"rows": people, "other": people_other}
    return result


def series(rows, period: Period):
    opened = [0] * len(period.edges)
    resolved = [0] * len(period.edges)
    for row in rows:
        for counts, instant in ((opened, row["opened_at"]), (resolved, row["resolved_at"])):
            if _within(instant, period.covered_from, period.covered_to):
                counts[bisect_right(period.edges, instant) - 1] += 1
    return [
        {"start": edge, "opened": opened[index], "resolved": resolved[index]}
        for index, edge in enumerate(period.edges)
    ]
