from appchi.search.control import check_search
from elasticsearch import Elasticsearch
from fastapi import APIRouter, Request

from appchi.access import authorize
from appchi.cel import compile_expression
from appchi.search import SearchReader, SearchScope, SearchState
from appchi.shared.display_names import AlertPage, documented, enrich_alerts
from appchi.shared.errors import unavailable
from appchi.shared.transactions import wire
from appchi.service_clients import elasticsearch_options

router = APIRouter(tags=["search"])


@router.get("/api/tenants/{tenant_id}/alerts", responses=documented(AlertPage))
def feed(
    tenant_id: str,
    request: Request,
    cel: str = "true",
    q: str = "",
    include_suppressed: bool = False,
    limit: int = 50,
    cursor: str | None = None,
    sort: str = "timestamp",
    direction: str = "desc",
):
    settings = request.app.state.settings
    db = request.app.state.db

    def check(scope=None):
        with db.transaction() as conn:
            principal, session, _ = authorize(conn, request, tenant_id)
            check_search(conn)
            gate = conn.execute(
                "SELECT ready FROM capability_gates WHERE capability='search'"
            ).fetchone()
            if not gate or not gate["ready"] or not settings.elasticsearch_url:
                raise unavailable("search_not_ready")
            return principal, session

    principal, session = check()
    expression = compile_expression(cel)

    def clock():
        with db.transaction() as conn:
            return conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]

    def state(tenant):
        with db.transaction() as conn:
            authorize(conn, request, tenant)
            row = conn.execute(
                "SELECT v.*,w.projection_seq FROM tenant_view_state v JOIN tenant_work_state w USING(tenant_id) WHERE tenant_id=%s",
                (tenant,),
            ).fetchone()
            if conn.execute(
                "SELECT 1 FROM projection_work WHERE tenant_id=%s AND seq>(SELECT searchable_seq FROM tenant_view_state WHERE tenant_id=projection_work.tenant_id) AND NOT visible AND (snapshot->>'live'='false' OR snapshot->>'deleted'='true') LIMIT 1",
                (tenant,),
            ).fetchone():
                raise unavailable("retention_projection_pending")
            return SearchState(
                row["index_epoch"],
                row["projection_seq"],
                row["searchable_seq"],
                row["purge_generation"],
                wire(row["verified_at"]),
            )

    def retained(tenant, ids):
        with db.transaction() as conn:
            authorize(conn, request, tenant)
            return {
                str(row["id"])
                for row in conn.execute(
                    "SELECT id FROM alert_identities WHERE tenant_id=%s AND id=ANY(%s::uuid[]) AND retired_at IS NULL",
                    (tenant, ids),
                )
            }

    with Elasticsearch(settings.elasticsearch_url, **elasticsearch_options(settings)) as client:
        reader = SearchReader(
            client,
            settings.elasticsearch_index,
            settings.cipher(),
            clock=clock,
            state=state,
            authorize=check,
            retained_ids=retained,
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
        },
        "next_cursor": page.next_cursor,
    }
