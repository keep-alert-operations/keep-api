from datetime import timedelta
from time import monotonic

from appchi.search.control import check_search
from fastapi import APIRouter, Request

from appchi.access import authorize
from appchi.cel import compile_expression
from appchi.search import SearchReader, SearchScope, SearchState
from appchi.shared.display_names import AlertPage, documented, enrich_alerts
from appchi.shared.errors import unavailable
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
):
    settings = request.app.state.settings
    db = request.app.state.db
    units = FeedUnits(request, tenant_id)
    principal, session = units.begin()
    expression = compile_expression(cel)

    client = SearchSent(search_client(request), units)
    reader = SearchReader(
        client,
        settings.elasticsearch_index,
        settings.cipher(),
        clock=units.clock,
        state=units.state,
        authorize=units.check,
        retained_ids=units.retained,
    )
    page = reader.page(
        expression,
        SearchScope(tenant_id, bytes(session["handle_hash"]).hex(), settings.deployment_epoch),
        q=q,
        include_suppressed=include_suppressed,
        sort=sort,
        direction=direction,
        page_size=limit,
        cursor=cursor,
        replace_cursor=replace_cursor,
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
        },
        "next_cursor": page.next_cursor,
    }
