from datetime import timedelta
from time import monotonic
from typing import Literal

from appchi.search.control import check_search
from fastapi import APIRouter, Request
from pydantic import Field

from appchi.access import authorize
from appchi.cel import compile_expression
from appchi.models import StrictModel
from appchi.search import GroupPage, SearchReader, SearchScope, SearchState
from appchi.shared.display_names import (
    AlertGroupPage,
    AlertPage,
    documented,
    enrich_alerts,
    group_labels,
)
from appchi.shared.errors import AppError, unavailable
from appchi.serialization import wire
from appchi.search_clients import search_client

router = APIRouter(tags=["search"])

STATE = "SELECT v.*,w.projection_seq FROM tenant_view_state v JOIN tenant_work_state w USING(tenant_id) WHERE tenant_id=%s"
# The EXISTS predicate matches migration 0052's partial index exactly, and the
# uncorrelated searchable_seq bound lets the scan start past it in that index.
PROBE = (
    "SELECT clock_timestamp() AS now,EXISTS(SELECT 1 FROM projection_work WHERE tenant_id=%(tenant)s"
    " AND seq>(SELECT searchable_seq FROM tenant_view_state WHERE tenant_id=%(tenant)s)"
    " AND NOT visible AND (snapshot->>'live'='false' OR snapshot->>'deleted'='true')) AS pending"
)


class FeedUnits:
    """PostgreSQL work for one feed page: two authorizations, few transactions.

    The reader authorizes before its Elasticsearch calls and again after the
    search. Each authorization shares its unit with the reads that follow it:
    the clock and starting search state before, the retained identities and
    observed state after. The snapshot re-check between opening a PIT and the
    search is a tenant-scoped read without authorization; nothing it reads
    reaches the caller before the post-search authorization. No unit selects
    REPEATABLE READ, so unscoped units stay READ COMMITTED with the restore
    guard inside the transaction.
    """

    def __init__(self, request, tenant_id):
        self.request, self.tenant_id = request, tenant_id
        self.db = request.app.state.db
        self.settings = request.app.state.settings
        self.searched = False  # the Elasticsearch search has been sent
        self.authorized = False  # an authorization covers the current phase
        self.ready = None  # a state read not yet handed to the reader
        self.sample = None  # (monotonic, database clock) of the latest unit

    def _authorize(self, conn):
        principal, session, _ = authorize(conn, self.request, self.tenant_id)
        check_search(conn)
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='search'"
        ).fetchone()
        if not gate or not gate["ready"] or not self.settings.elasticsearch_url:
            raise unavailable("search_not_ready")
        self.authorized = True
        return principal, session

    def _observe(self, conn, tenant):
        row = conn.execute(STATE, (tenant,)).fetchone()
        probe = conn.execute(PROBE, {"tenant": tenant}).fetchone()
        self.sample = (monotonic(), probe["now"])
        return row, probe["pending"]

    @staticmethod
    def _state(row, pending):
        if pending:
            raise unavailable("retention_projection_pending")
        return SearchState(
            row["index_epoch"],
            row["projection_seq"],
            row["searchable_seq"],
            row["purge_generation"],
            wire(row["verified_at"]),
        )

    def begin(self):
        """Authorize the page and read its clock and starting state."""
        with self.db.transaction(read_committed=True) as conn:
            principal, session = self._authorize(conn)
            self.ready = self._observe(conn, self.tenant_id)
        return principal, session

    def search_sent(self):
        self.searched, self.authorized, self.ready = True, False, None

    def check(self, scope=None):
        if not self.authorized:
            with self.db.transaction(read_committed=True) as conn:
                self._authorize(conn)

    def clock(self):
        # The database clock of the latest unit, advanced by local elapsed time.
        taken, now = self.sample
        return now + timedelta(seconds=monotonic() - taken)

    def state(self, tenant):
        if self.ready is not None:
            value, self.ready = self.ready, None
        elif self.searched:
            # No retained-identity unit ran (no hits): authorize here.
            with self.db.transaction(read_committed=True) as conn:
                self._authorize(conn)
                value = self._observe(conn, tenant)
        else:
            with self.db.transaction(tenant) as conn:
                value = self._observe(conn, tenant)
        return self._state(*value)

    def retained(self, tenant, ids):
        with self.db.transaction(read_committed=True) as conn:
            self._authorize(conn)
            retained = {
                str(row["id"])
                for row in conn.execute(
                    "SELECT id FROM alert_identities WHERE tenant_id=%s AND id=ANY(%s::uuid[]) AND retired_at IS NULL",
                    (tenant, ids),
                )
            }
            if self.searched:
                self.ready = self._observe(conn, tenant)
        return retained


class SearchSent:
    """Mark the end of the pre-search phase when the reader sends its search."""

    def __init__(self, client, units):
        self.client, self.units = client, units

    def search(self, **kwargs):
        self.units.search_sent()
        return self.client.search(**kwargs)

    def __getattr__(self, name):
        return getattr(self.client, name)


def requested_group(group_by, group_key, group_empty):
    """One group's rows (REV-44): a field with exactly one of its value or the empty group."""
    if group_by is None:
        if group_key is not None or group_empty:
            raise AppError("invalid_group", "Group rows need group_by", 422)
        return None
    if (group_key is None) == (not group_empty):
        raise AppError("invalid_group", "Give either group_key or group_empty", 422)
    return (group_by, None if group_empty else group_key)


def grouped_response(conn, tenant, group_by, page: GroupPage) -> dict:
    """Group page body with read-time labels; rows are enriched in one batch."""
    rows = [row for group in page.groups for row in group.items]
    items = iter(enrich_alerts(conn, tenant, rows))
    labels = group_labels(conn, tenant, group_by, [group.key for group in page.groups])

    def counts(value):
        return None if value is None else {key: str(count) for key, count in value.items()}

    data = [
        {
            "key": group.key,
            "label": labels.get(group.key) if group.key is not None else None,
            "total": None if group.total is None else str(group.total),
            "severity": counts(group.severity),
            "status": counts(group.status),
            "data": [next(items) for _ in group.items],
            "next_cursor": group.next_cursor,
        }
        for group in page.groups
    ]
    return {
        "data": data,
        "meta": {
            "total": None if page.total is None else str(page.total),
            "group_count": str(page.group_count),
            "group_by": group_by,
            "evaluated_at": page.evaluated_at,
            "updating": page.updating,
            "watermark": wire(page.watermark),
            "close_token": page.close_token,
            "next_change_at": page.next_change_at,
        },
        "next_group_cursor": page.next_group_cursor,
    }


def _feed_reader(request, tenant_id):
    settings = request.app.state.settings
    units = FeedUnits(request, tenant_id)
    principal, session = units.begin()
    reader = SearchReader(
        SearchSent(search_client(request), units),
        settings.elasticsearch_index,
        settings.cipher(),
        clock=units.clock,
        state=units.state,
        authorize=units.check,
        retained_ids=units.retained,
    )
    scope = SearchScope(tenant_id, bytes(session["handle_hash"]).hex(), settings.deployment_epoch)
    return reader, scope


@router.get("/api/tenants/{tenant_id}/alerts", responses=documented(AlertPage))
def feed(
    tenant_id: str,
    request: Request,
    cel: str = "true",
    q: str = "",
    include_suppressed: bool = False,
    limit: int = 50,
    cursor: str | None = None,
    replace_cursor: str | None = None,
    sort: str = "timestamp",
    direction: str = "desc",
    group_by: str | None = None,
    group_key: str | None = None,
    group_empty: bool = False,
):
    db = request.app.state.db
    reader, scope = _feed_reader(request, tenant_id)
    group = requested_group(group_by, group_key, group_empty)
    expression = compile_expression(cel)
    page = reader.page(
        expression,
        scope,
        q=q,
        include_suppressed=include_suppressed,
        sort=sort,
        direction=direction,
        page_size=limit,
        cursor=cursor,
        replace_cursor=replace_cursor,
        group=group,
    )
    with db.transaction(tenant_id) as conn:
        # Read-time labels from PG; search documents never carry display names.
        items = enrich_alerts(conn, tenant_id, page.items)
    return {
        "data": items,
        "meta": {
            "total": None if page.total is None else str(page.total),
            "evaluated_at": page.evaluated_at,
            "updating": page.updating,
            "watermark": wire(page.watermark),
            "relative": expression.relative,
            "close_token": page.close_token,
            "next_change_at": page.next_change_at,
        },
        "next_cursor": page.next_cursor,
    }


class AlertGroupsRequest(StrictModel):
    cel: str = Field(default="true", max_length=16384)
    q: str = Field(default="", max_length=256)
    include_suppressed: bool = False
    sort: str = "timestamp"
    direction: Literal["asc", "desc"] = "desc"
    group_by: str
    group_limit: int = Field(default=10, ge=1, le=50)
    rows_per_group: int = Field(default=5, ge=1, le=50)
    group_cursor: str | None = Field(default=None, min_length=1, max_length=65536)


@router.post("/api/tenants/{tenant_id}/alerts/groups", responses=documented(AlertGroupPage))
def feed_groups(tenant_id: str, body: AlertGroupsRequest, request: Request):
    """Grouped first view of the Feed (REV-44); group rows continue through the feed."""
    reader, scope = _feed_reader(request, tenant_id)
    expression = compile_expression(body.cel)
    page = reader.groups(
        expression,
        scope,
        group_by=body.group_by,
        q=body.q,
        include_suppressed=body.include_suppressed,
        sort=body.sort,
        direction=body.direction,
        group_limit=body.group_limit,
        rows_per_group=body.rows_per_group,
        group_cursor=body.group_cursor,
    )
    with request.app.state.db.transaction(tenant_id) as conn:
        result = grouped_response(conn, tenant_id, body.group_by, page)
    result["meta"]["relative"] = expression.relative
    return result
