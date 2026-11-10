"""Incident report for one tenant and period, read from PostgreSQL (REV-53).

Query A reads every lifecycle cycle opened or resolved in the period (and the
previous period when compared) through the 0058 indexes. Query B reads the
assignment history of those incidents in a savepoint with its own time budget,
from which each cycle's first assignment and assignee at resolution follow;
when it runs out, first response and the assignee breakdown are
reported unavailable instead of failing the report. No worker, cache or stored
counter is involved (incident operations 20; worker scope REV-34).
"""

from datetime import datetime

from fastapi import APIRouter, Query, Request
from psycopg.errors import QueryCanceled
from pydantic import BaseModel, ConfigDict, Field

from keep.access import authorize
from keep.db import BudgetConnection
from keep.incidents.listing import ASSIGNEE_QUALIFIES
from keep.maintenance.timezones import ScheduleError, zone
from keep.reports.figures import (
    PeriodError,
    attach_assignments,
    breakdowns,
    plan_period,
    series,
    summarize,
)
from keep.request_budget import remaining
from keep.serialization import wire
from keep.shared.display_names import documented, principal_names
from keep.shared.errors import AppError, unavailable

router = APIRouter(prefix="/api/tenants/{tenant_id}/reports", tags=["reports"])

CYCLE_LIMIT = 100_000
CYCLES_TIMEOUT_MS = 1200
ASSIGNMENTS_TIMEOUT_MS = 700

CYCLES = f"""WITH c AS (
  SELECT * FROM incident_cycles WHERE tenant_id=%(tenant)s AND opened_at>=%(lower)s AND opened_at<%(upper)s
  UNION
  SELECT * FROM incident_cycles WHERE tenant_id=%(tenant)s AND resolved_at>=%(lower)s AND resolved_at<%(upper)s
)
SELECT c.incident_id,c.opened_at,c.investigating_at,c.resolved_at,c.cause,i.severity,i.origin,x.rule_id,
  CASE WHEN i.assignee_id IS NOT NULL AND {ASSIGNEE_QUALIFIES} THEN i.assignee_id END AS current_assignee,
  NOT EXISTS(SELECT 1 FROM incident_cycles e WHERE e.incident_id=c.incident_id AND e.opened_at<c.opened_at) AS first_cycle,
  (SELECT min(n.opened_at) FROM incident_cycles n WHERE n.incident_id=c.incident_id AND n.opened_at>c.opened_at) AS next_opened_at
FROM c
JOIN incidents i ON i.tenant_id=c.tenant_id AND i.id=c.incident_id
JOIN incident_identities ident ON ident.tenant_id=i.tenant_id AND ident.id=i.id AND ident.retired_at IS NULL
LEFT JOIN correlation_contexts x ON x.tenant_id=i.tenant_id AND x.id=i.context_id
LIMIT %(limit)s"""

# One set-based read through incident_activity_assignee (0058): every assignment
# and eligibility_lost event of the period's incidents. Unassigning records an
# assignment with a null assignee; eligibility_lost clears one. Per-cycle
# subqueries would pay partition pruning once per cycle. The id array goes in
# through a scalar subquery so the planner does not estimate and prune each of
# up to 100,000 elements against every partition (seconds of planning).
ASSIGNMENTS = """SELECT a.incident_id,a.kind,a.recorded_at,a.evidence->>'assignee_id' AS assignee
FROM incident_activity a
WHERE a.kind IN ('assignment','eligibility_lost') AND a.incident_id=ANY((SELECT %s::uuid[])::uuid[])"""

# A deleted rule keeps its last name while its final revision is retained, which
# holds while any incident references its context.
RULES = """SELECT r.id,r.name,r.deleted_at IS NOT NULL AS deleted,
  (r.deleted_at IS NULL OR correlation_revision_retained(r.tenant_id,r.id,r.revision,%s)) AS named
FROM correlation_rules r WHERE r.tenant_id=%s AND r.id=ANY(%s::uuid[])"""


def bound(conn, milliseconds):
    """Lower the statement timeout below the request budget for the next queries."""
    limit = max(1, min(milliseconds, int(remaining(4) * 1000)))
    conn.execute(f"SET LOCAL statement_timeout = '{limit}ms'")
    if isinstance(conn, BudgetConnection):
        # The budget wrapper keeps the lower of this and the remaining budget.
        conn.statement_ms = limit


def release(conn):
    if isinstance(conn, BudgetConnection):
        conn.statement_ms = None


def read_cycles(conn, tenant, lower, upper):
    bound(conn, CYCLES_TIMEOUT_MS)
    try:
        rows = conn.execute(
            CYCLES, {"tenant": tenant, "lower": lower, "upper": upper, "limit": CYCLE_LIMIT + 1}
        ).fetchall()
    except QueryCanceled:
        raise unavailable("query_deadline") from None
    if len(rows) > CYCLE_LIMIT:
        raise AppError(
            "report_too_large",
            "This period has too many incident cycles to report on at once. Choose a shorter period.",
        )
    return rows


def read_assignments(conn, rows):
    """Attach first assignment and assignee at resolution; False when out of time."""
    if not rows:
        return True
    incidents = sorted({row["incident_id"] for row in rows})
    try:
        with conn.transaction():
            bound(conn, ASSIGNMENTS_TIMEOUT_MS)
            events = conn.execute(ASSIGNMENTS, (incidents,)).fetchall()
    except QueryCanceled:
        return False
    finally:
        release(conn)
    attach_assignments(rows, events)
    return True


def name_groups(conn, tenant, now, report):
    rules = report["breakdowns"]["rule"]
    found = {}
    if rules["rows"]:
        for row in conn.execute(RULES, (now, tenant, [key for key, _ in rules["rows"]])):
            found[str(row["id"])] = row
    rules["rows"] = [
        {
            "rule_id": key,
            "name": found[str(key)]["name"]
            if str(key) in found and found[str(key)]["named"]
            else None,
            "deleted": str(key) not in found or found[str(key)]["deleted"],
            **figures,
        }
        for key, figures in rules["rows"]
    ]
    people = report["breakdowns"]["assignee"]
    if people is not None:
        names = principal_names(conn, [key for key, _ in people["rows"]])
        people["rows"] = [
            {
                "assignee_id": key,
                "display_name": names.get(str(key)) if key is not None else None,
                **figures,
            }
            for key, figures in people["rows"]
        ]


def build_report(conn, tenant, start, end, time_zone, compare):
    try:
        tz = zone(time_zone)
    except ScheduleError as exc:
        raise AppError(exc.code, str(exc)) from None
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    try:
        period = plan_period(start, end, tz, now, compare)
    except PeriodError as exc:
        raise AppError("invalid_period", str(exc)) from None
    lower = period.previous[0] if period.previous else period.covered_from
    rows = []
    if period.covered_from < period.covered_to:
        rows = [dict(row) for row in read_cycles(conn, tenant, lower, period.covered_to)]
        for row in rows:
            # Evidence stores assignees as text; compare people as text throughout.
            if row["current_assignee"] is not None:
                row["current_assignee"] = str(row["current_assignee"])
    assignments = read_assignments(conn, rows)
    current = (period.covered_from, period.covered_to)
    report = {
        "period": {
            "requested_from": period.requested_from,
            "requested_to": period.requested_to,
            "covered_from": period.covered_from,
            "covered_to": period.covered_to,
            "retention_from": period.retention_from,
            "time_zone": time_zone,
            "bin": period.unit,
        },
        "previous": {"from": period.previous[0], "to": period.previous[1]}
        if period.previous
        else None,
        "previous_unavailable": period.previous_unavailable,
        "summary": summarize(rows, *current, assignments),
        "previous_summary": summarize(rows, *period.previous, assignments)
        if period.previous
        else None,
        "series": series(rows, period),
        "breakdowns": breakdowns(rows, *current, assignments),
        "unavailable": [] if assignments else ["first_response", "assignee"],
    }
    name_groups(conn, tenant, now, report)
    return report, now


class _Doc(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReportPeriod(_Doc):
    requested_from: str
    requested_to: str
    covered_from: str = Field(
        description="Start of the reported range after the 90-day retention clamp."
    )
    covered_to: str
    retention_from: str = Field(
        description="Earliest instant whose history is guaranteed to be retained."
    )
    time_zone: str
    bin: str = Field(description="hour, day or week.")


class ReportRange(_Doc):
    from_: str = Field(alias="from")
    to: str


class ReportDurations(_Doc):
    median_seconds: str | None
    p90_seconds: str | None


class ReportFirstResponse(ReportDurations):
    responded: str
    waiting: str


class ReportResolvedByCause(_Doc):
    manual: str
    alerts_resolved: str
    inactivity: str


class ReportSummary(_Doc):
    opened: str
    opened_new: str
    opened_reopened: str
    resolved: str
    resolved_by_cause: ReportResolvedByCause
    reopened: str
    time_to_resolve: ReportDurations | None
    first_response: ReportFirstResponse | None = Field(
        description="Null when assignment history is unavailable."
    )


class ReportSeriesBin(_Doc):
    start: str
    opened: str
    resolved: str


class ReportGroupFigures(_Doc):
    opened: str
    resolved: str
    reopened: str
    first_response_median_seconds: str | None
    time_to_resolve_median_seconds: str | None


class ReportSeverityGroup(ReportGroupFigures):
    severity: str


class ReportOriginGroup(ReportGroupFigures):
    origin: str


class ReportRuleGroup(ReportGroupFigures):
    rule_id: str
    name: str | None = Field(
        description="Null for a deleted rule whose history is no longer retained."
    )
    deleted: bool


class ReportAssigneeGroup(ReportGroupFigures):
    assignee_id: str | None
    display_name: str | None


class ReportOtherGroups(_Doc):
    groups: str
    opened: str
    resolved: str
    reopened: str


class ReportRuleBreakdown(_Doc):
    rows: list[ReportRuleGroup]
    other: ReportOtherGroups | None


class ReportAssigneeBreakdown(_Doc):
    rows: list[ReportAssigneeGroup]
    other: ReportOtherGroups | None


class ReportBreakdowns(_Doc):
    severity: list[ReportSeverityGroup]
    origin: list[ReportOriginGroup]
    rule: ReportRuleBreakdown
    assignee: ReportAssigneeBreakdown | None = Field(
        description="Null when assignment history is unavailable."
    )


class IncidentReport(_Doc):
    period: ReportPeriod
    previous: ReportRange | None
    previous_unavailable: str | None = Field(description="past_retention, not_requested or null.")
    summary: ReportSummary
    previous_summary: ReportSummary | None
    series: list[ReportSeriesBin]
    breakdowns: ReportBreakdowns
    unavailable: list[str] = Field(description="Sections that could not be read in time.")


class ReportMeta(BaseModel):
    model_config = ConfigDict(extra="allow")
    computed_at: str


class IncidentReportRead(_Doc):
    data: IncidentReport
    meta: ReportMeta


@router.get("/incidents", responses=documented(IncidentReportRead))
def incident_report(
    tenant_id: str,
    request: Request,
    from_: datetime = Query(alias="from"),
    to: datetime = Query(),
    time_zone: str = "UTC",
    compare: bool = True,
):
    """Incident figures for one tenant and period (incident operations 20)."""
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        authorize(conn, request, tenant_id)
        report, now = build_report(conn, tenant_id, from_, to, time_zone, compare)
        return {"data": wire(report), "meta": {"computed_at": wire(now)}}
