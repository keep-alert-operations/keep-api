"""Read-only authorized dashboard observations and saved/unsaved preset feeds."""

from hashlib import sha256
import time

from elasticsearch import Elasticsearch
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator, model_validator

from appchi.access import authorize
from appchi.cel import compile_expression
from appchi.cel.compiler import PROFILE
from appchi.configuration.models import DashboardDefinition, PresetDefinition, Sort
from appchi.configuration.routes import get_definition
from appchi.models import Command, StrictModel, uuid_string
from appchi.search import SearchReader, SearchScope, SearchState
from appchi.search.control import check_search
from appchi.search.counts import CountReader, CountState
from appchi.search.projection import canonical
from appchi.search.reader import sort_spec
from appchi.shared.display_names import AlertPage, documented, enrich_alerts
from appchi.shared.errors import AppError, unavailable
from appchi.serialization import wire
from appchi.service_clients import elasticsearch_options

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])


class CountRequest(StrictModel):
    expected_revision: str
    _revision = field_validator("expected_revision")(Command.revision.__func__)


class DashboardPreview(DashboardDefinition):
    preset_revisions: dict[str, str]

    @field_validator("preset_revisions")
    @classmethod
    def revisions(cls, value):
        if len(value) > 24:
            raise ValueError("At most 24 preset revisions are allowed")
        for key, revision in value.items():
            uuid_string(key)
            Command.revision(revision)
        return value

    @model_validator(mode="after")
    def referenced(self):
        if set(self.preset_revisions) != {panel.preset_id for panel in self.panels}:
            raise ValueError("Supply exactly the referenced preset revisions")
        return self


class PresetPreview(StrictModel):
    preset_id: str | None = None
    expected_revision: str | None = None
    cel: str | None = Field(default=None, max_length=16384)
    sort: list[Sort] | None = Field(default=None, min_length=1, max_length=3)
    columns: list[str] | None = Field(default=None, min_length=1, max_length=30)
    q: str = Field(default="", max_length=256)
    include_suppressed: bool = False
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, min_length=1, max_length=65536)
    replace_cursor: str | None = Field(default=None, min_length=1, max_length=65536)

    @model_validator(mode="after")
    def selection(self):
        if self.preset_id is not None:
            uuid_string(self.preset_id)
            if self.expected_revision is None or any(
                value is not None for value in (self.cel, self.sort, self.columns)
            ):
                raise ValueError("Saved preview requires a revision and excludes candidate fields")
            Command.revision(self.expected_revision)
        else:
            if self.expected_revision is not None or any(
                value is None for value in (self.cel, self.sort, self.columns)
            ):
                raise ValueError("Candidate preview requires CEL, sort and columns")
            normalized = PresetDefinition(
                name="Preview", cel=self.cel, sort=self.sort, columns=self.columns
            )
            self.sort, self.columns = normalized.sort, normalized.columns
        if self.cursor and self.replace_cursor:
            raise ValueError("Continue a cursor or replace it, not both")
        return self


def _budget(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0.05:
        raise unavailable("query_deadline")
    return remaining


def _begin(conn, request, tenant, deadline):
    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    conn.execute(
        "SELECT set_config('statement_timeout',%s,true)",
        (str(max(1, min(4000, int(_budget(deadline) * 1000)))),),
    )
    actor, session, _ = authorize(conn, request, tenant, mutation=True)
    check_search(conn)
    gate = conn.execute("SELECT ready FROM capability_gates WHERE capability='search'").fetchone()
    if not gate or not gate["ready"] or not request.app.state.settings.elasticsearch_url:
        raise unavailable("search_not_ready")
    return actor, session


def _state(conn, tenant):
    row = conn.execute(
        """SELECT v.*,w.projection_seq FROM tenant_view_state v
        JOIN tenant_work_state w USING(tenant_id) WHERE tenant_id=%s""",
        (tenant,),
    ).fetchone()
    if not row:
        raise unavailable("search_state_unavailable")
    pending_retirement = conn.execute(
        """SELECT EXISTS(SELECT 1 FROM projection_work
        WHERE tenant_id=%s AND seq>(SELECT searchable_seq FROM tenant_view_state WHERE tenant_id=projection_work.tenant_id) AND NOT visible AND
        (snapshot->>'live'='false' OR snapshot->>'deleted'='true')) AS pending""",
        (tenant,),
    ).fetchone()
    if pending_retirement["pending"]:
        raise unavailable("retention_projection_pending")
    # The existing schema records completion as job state and required projection
    # positions, not a separate completion counter. Hash that exact evidence.
    maintenance = conn.execute(
        """SELECT
        coalesce(bool_or(state IN ('pending','blocked') OR
            (state='complete' AND coalesce(required_projection_seq,0)>%s)),false) AS pending,
        encode(sha256(convert_to(coalesce(string_agg(
            jsonb_build_array(id,state,generation,cursor_alert_id,required_projection_seq)::text,
            ',' ORDER BY id),''),'UTF8')),'hex') AS completion
        FROM maintenance_fanout_jobs WHERE tenant_id=%s AND due_at<=clock_timestamp()
    """,
        (row["searchable_seq"], tenant),
    ).fetchone()
    return CountState(
        row["index_epoch"],
        row["projection_seq"],
        row["searchable_seq"],
        row["purge_generation"],
        wire(row["verified_at"]),
        row["maintenance_generation"],
        maintenance["pending"],
        maintenance["completion"],
    )


def _presets(conn, tenant, panels):
    result = {}
    for preset in sorted({str(panel["preset_id"]) for panel in panels}):
        row = get_definition(conn, tenant, "presets", preset)
        if row["profile"] != PROFILE:
            raise unavailable("preset_profile_unavailable")
        result[preset] = row
    return result


def _revision_map(presets):
    return {key: str(value["revision"]) for key, value in presets.items()}


def _dashboard_counts(request, tenant, *, dashboard_id=None, expected=None, candidate=None):
    deadline = time.monotonic() + 10
    db, settings = request.app.state.db, request.app.state.settings
    with db.transaction() as conn:
        _begin(conn, request, tenant, deadline)
        dashboard = (
            get_definition(conn, tenant, "dashboards", dashboard_id) if dashboard_id else None
        )
        if dashboard and str(dashboard["revision"]) != expected:
            raise AppError("dashboard_changed", "Dashboard changed; reload before counting.", 409)
        panels = (
            dashboard["panels"] if dashboard else [panel.model_dump() for panel in candidate.panels]
        )
        if len(panels) > 24:
            raise unavailable("dashboard_definition_invalid")
        presets = _presets(conn, tenant, panels)
        revisions = _revision_map(presets)
        if candidate and candidate.preset_revisions != revisions:
            raise AppError(
                "preset_changed", "Referenced presets changed; reload before counting.", 409
            )
        before = _state(conn, tenant)
        evaluated_at = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    expressions, compiled = {}, {}
    for key, preset in presets.items():
        _budget(deadline)
        context = (preset["profile"], preset["cel"])
        if context not in compiled:
            compiled[context] = compile_expression(preset["cel"])
        expressions[key] = compiled[context]

    def revalidate():
        with db.transaction() as conn:
            _begin(conn, request, tenant, deadline)
            current_panels = panels
            if dashboard_id:
                try:
                    current = get_definition(conn, tenant, "dashboards", dashboard_id)
                except AppError as exc:
                    if exc.code == "not_found":
                        raise AppError(
                            "dashboard_changed", "Dashboard changed; retry the count.", 409
                        ) from None
                    raise
                if current["revision"] != dashboard["revision"]:
                    raise AppError("dashboard_changed", "Dashboard changed; retry the count.", 409)
                current_panels = current["panels"]
            try:
                current_revisions = _revision_map(_presets(conn, tenant, current_panels))
            except AppError as exc:
                if exc.code == "not_found":
                    raise AppError(
                        "preset_changed", "Preset changed; retry the count.", 409
                    ) from None
                raise
            if current_revisions != revisions:
                raise AppError("preset_changed", "Preset changed; retry the count.", 409)
            return _state(conn, tenant)

    with Elasticsearch(settings.elasticsearch_url, **elasticsearch_options(settings)) as client:
        batch = CountReader(client, settings.elasticsearch_index).read(
            expressions,
            tenant,
            evaluated_at=evaluated_at,
            before=before,
            revalidate=revalidate,
            deadline=deadline,
        )
    _budget(deadline)
    data = {
        "observation_id": batch.observation_id,
        "dashboard_revision": expected,
        "preset_revisions": revisions,
        "evaluated_at": batch.evaluated_at,
        "relative": any(expression.relative for expression in expressions.values()),
        "watermark": batch.watermark,
        "observed": batch.observed,
        "updating": batch.updating,
        "updating_suppression": batch.updating_suppression,
        "panels": [
            {
                "panel_id": str(panel["id"]),
                "preset_id": str(panel["preset_id"]),
                "preset_name": presets[str(panel["preset_id"])]["name"],
                "count": str(batch.counts[str(panel["preset_id"])]),
            }
            for panel in panels
        ],
    }
    headers = {"ETag": '"' + expected + '"'} if expected is not None else {}
    return JSONResponse({"data": wire(data), "meta": {"profile": PROFILE}}, headers=headers)


@router.post("/dashboards/{dashboard_id}/counts")
def dashboard_counts(tenant_id: str, dashboard_id: str, body: CountRequest, request: Request):
    return _dashboard_counts(
        request, tenant_id, dashboard_id=dashboard_id, expected=body.expected_revision
    )


@router.post("/dashboards/preview")
def dashboard_preview(tenant_id: str, body: DashboardPreview, request: Request):
    return _dashboard_counts(request, tenant_id, candidate=body)


class _DeadlineClient:
    def __init__(self, client, deadline):
        self.client, self.deadline = client, deadline

    def __getattr__(self, name):
        def call(**kwargs):
            return getattr(
                self.client.options(request_timeout=min(5, _budget(self.deadline)), max_retries=0),
                name,
            )(**kwargs)

        return call


@router.post("/presets/preview", responses=documented(AlertPage))
def preset_preview(tenant_id: str, body: PresetPreview, request: Request):
    deadline = time.monotonic() + 10
    db, settings = request.app.state.db, request.app.state.settings
    with db.transaction() as conn:
        _, session = _begin(conn, request, tenant_id, deadline)
        if body.preset_id:
            saved = get_definition(conn, tenant_id, "presets", body.preset_id)
            if str(saved["revision"]) != body.expected_revision:
                raise AppError(
                    "preset_changed", "Preset changed; reload or preview a candidate.", 409
                )
            if saved["profile"] != PROFILE:
                raise unavailable("preset_profile_unavailable")
            definition = {key: saved[key] for key in ("cel", "sort", "columns")}
        else:
            definition = {
                "cel": body.cel,
                "sort": [item.model_dump() for item in body.sort],
                "columns": body.columns,
            }
    expression = compile_expression(definition["cel"])
    order = []
    for item in definition["sort"]:
        order.extend(sort_spec(item["field"], item["direction"])[:-1])
    order.append({"id": "asc"})
    context = {
        "definition": definition,
        "preset_id": body.preset_id,
        "revision": body.expected_revision,
    }
    scope = SearchScope(
        tenant_id,
        bytes(session["handle_hash"]).hex() + ":preview:" + sha256(canonical(context)).hexdigest(),
        settings.deployment_epoch,
    )

    def check(_scope=None):
        with db.transaction() as conn:
            _begin(conn, request, tenant_id, deadline)
            if body.preset_id:
                current = get_definition(conn, tenant_id, "presets", body.preset_id)
                if str(current["revision"]) != body.expected_revision:
                    raise AppError("preset_changed", "Preset changed; restart preview.", 409)

    def clock():
        _budget(deadline)
        with db.transaction() as conn:
            return conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]

    def state(tenant):
        with db.transaction() as conn:
            _begin(conn, request, tenant, deadline)
            captured = _state(conn, tenant)
            if not captured.verified_at or captured.index_epoch == "uninitialized":
                raise unavailable("search_not_verified")
            return SearchState(
                captured.index_epoch,
                captured.committed_seq,
                captured.searchable_seq,
                captured.purge_generation,
                captured.verified_at,
            )

    def retained(tenant, ids):
        with db.transaction() as conn:
            _begin(conn, request, tenant, deadline)
            return {
                str(row["id"])
                for row in conn.execute(
                    "SELECT id FROM alert_identities WHERE tenant_id=%s AND id=ANY(%s::uuid[]) AND retired_at IS NULL",
                    (tenant, ids),
                )
            }

    with Elasticsearch(settings.elasticsearch_url, **elasticsearch_options(settings)) as client:
        reader = SearchReader(
            _DeadlineClient(client, deadline),
            settings.elasticsearch_index,
            settings.cipher(),
            clock=clock,
            state=state,
            authorize=check,
            retained_ids=retained,
        )
        page = reader.page(
            expression,
            scope,
            q=body.q,
            include_suppressed=body.include_suppressed,
            ordering=order,
            page_size=body.limit,
            cursor=body.cursor,
            replace_cursor=body.replace_cursor,
        )
    _budget(deadline)
    with db.transaction(tenant_id) as conn:
        # Read-time labels from PG; search documents never carry display names.
        items = enrich_alerts(conn, tenant_id, page.items)
    headers = {"ETag": '"' + body.expected_revision + '"'} if body.preset_id else {}
    return JSONResponse(
        {
            "data": items,
            "meta": wire(
                {
                    "total": page.total,
                    "evaluated_at": page.evaluated_at,
                    "updating": page.updating,
                    "watermark": page.watermark,
                    "observed": page.observed,
                    "profile": PROFILE,
                    "applied": context,
                }
            ),
            "next_cursor": page.next_cursor,
        },
        headers=headers,
    )
