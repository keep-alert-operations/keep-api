from uuid import uuid4
from psycopg import sql
from psycopg.types.json import Jsonb
from fastapi import APIRouter, Request

from appchi.access import authorize
from appchi.configuration.models import (
    DashboardCreate,
    DashboardDefinition,
    DashboardReplace,
    PresetCreate,
    PresetDefinition,
    PresetReplace,
    name_key,
    images_of,
    referenced_presets_of,
    sanitize_panels,
)
from appchi.configuration.image_routes import check_images, lock_images, mark_used
from appchi.shared.display_names import ActorPage, ActorRead, documented, enrich_actors
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import command_result, revision, save_result
from appchi.serialization import wire

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])
TABLES = {"presets": "preset_revisions", "dashboards": "dashboard_revisions"}


def get_definition(conn, tenant, table, resource_id, lock=False):
    query = sql.SQL(
        "SELECT * FROM {} WHERE tenant_id=%s AND id=%s AND deleted_at IS NULL"
        + (" FOR UPDATE" if lock else "")
    ).format(sql.Identifier(table))
    row = conn.execute(query, (tenant, resource_id)).fetchone()
    if not row:
        raise AppError("not_found", "Resource unavailable.", 404)
    if table == "dashboards":
        row["panels"] = [
            panel_row(panel)
            for panel in conn.execute(
                "SELECT id,type,preset_id,image_id,title,x,y,w,h,thresholds,content FROM dashboard_panels WHERE tenant_id=%s AND dashboard_id=%s ORDER BY y,x,id",
                (tenant, resource_id),
            ).fetchall()
        ]
    return row


def panel_row(row):
    """A stored panel in its wire shape: each type carries only its own settings."""
    panel = {key: row[key] for key in ("id", "type", "title", "x", "y", "w", "h")}
    # Every panel type may have a link button; older panels have none (REV-66).
    panel["link"] = row["content"].get("link")
    if row["type"] == "html":
        panel["html"] = row["content"]["html"]
    elif row["type"] == "image":
        content = row["content"]
        panel.update(
            image_id=str(row["image_id"]) if row["image_id"] else None,
            url=content.get("url"),
            fit=content.get("fit", "contain"),
            alt=content.get("alt"),
        )
    elif row["type"] == "table":
        panel.update(preset_id=row["preset_id"], rows=row["content"]["rows"])
    else:
        panel.update(preset_id=row["preset_id"], thresholds=row["thresholds"])
    return panel


def panel_content(panel):
    """Settings stored in content: the panel link (REV-66) and type-specific settings;
    count panels keep theirs in columns instead."""
    content = {"link": panel.link.model_dump()} if panel.link else {}
    if panel.type == "html":
        content["html"] = panel.html
    elif panel.type == "image":
        content["fit"] = panel.fit
        if panel.url is not None:
            content["url"] = panel.url
        if panel.alt is not None:
            content["alt"] = panel.alt
    elif panel.type == "table":
        content["rows"] = panel.rows
    return content


def sanitized(panels):
    """Sanitize HTML panels once the caller is authorized; return what was removed."""
    try:
        return sanitize_panels(panels)
    except ValueError as exc:
        raise AppError("invalid_html", str(exc), 422) from None


def save(request, tenant, table, body, resource_id=None):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant, "edit", mutation=True)
    if table == "dashboards":
        sanitized(body.panels)
    definition = body.model_dump(exclude={"command_id", "expected_revision"})
    if table == "presets":
        from appchi.cel import compile_expression, CELValidationError, CELUnavailableError

        try:
            compile_expression(body.cel)
        except CELValidationError:
            raise AppError("invalid_cel", "CEL expression is invalid.", 422) from None
        except CELUnavailableError:
            raise unavailable("cel_compilation_unavailable") from None
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
        scope = f"{tenant}:{actor['id']}:{table}:{resource_id or 'create'}"
        payload = body.model_dump()
        if table == "presets" and payload.get("group_by") is None:
            # Commands sent before REV-44 had no group_by; their retries still match.
            payload.pop("group_by", None)
        if table == "presets" and payload.get("noisy") is False:
            # Likewise for commands sent before REV-58 had the alarm flag.
            payload.pop("noisy", None)
        if table == "dashboards":
            # Commands sent before REV-57 had no panel type; their retries still match.
            for panel in payload["panels"]:
                if panel["type"] == "count":
                    del panel["type"]
                # Likewise for commands sent before REV-66 had panel links.
                if panel["link"] is None:
                    del panel["link"]
        prior, fp = command_result(conn, scope, body.command_id, payload)
        if prior is not None:
            return prior
        conn.execute(
            "SELECT tenant_id FROM tenant_configuration_guard WHERE tenant_id=%s FOR UPDATE",
            (tenant,),
        )
        if table == "dashboards":
            for preset_id in sorted(referenced_presets_of(body.panels)):
                get_definition(conn, tenant, "presets", preset_id, True)
            # Images lock after presets and before dashboard rows (REV-62).
            lock_images(conn, tenant, images_of(body.panels))
            for panel in body.panels:
                existing = conn.execute(
                    "SELECT dashboard_id,type FROM dashboard_panels WHERE id=%s", (panel.id,)
                ).fetchone()
                if existing and str(existing["dashboard_id"]) != resource_id:
                    raise AppError(
                        "panel_identity_conflict", "Panel belongs to another dashboard.", 409
                    )
                if existing and existing["type"] != panel.type:
                    raise AppError("panel_type_changed", "A panel keeps its type.", 422)
        previous = get_definition(conn, tenant, table, resource_id, True) if resource_id else None
        if previous:
            revision(previous, body.expected_revision)
        duplicate = conn.execute(
            sql.SQL(
                "SELECT id FROM {} WHERE tenant_id=%s AND name_key=%s AND deleted_at IS NULL AND id<>%s"
            ).format(sql.Identifier(table)),
            (tenant, name_key(body.name), resource_id or uuid4()),
        ).fetchone()
        if duplicate:
            raise AppError("name_unavailable", "Name is unavailable.", 409)
        same = previous and all(public(previous)[k] == v for k, v in definition.items())
        if same:
            return save_result(
                conn,
                scope,
                body.command_id,
                fp,
                {"data": public(previous), "meta": {"revision": str(previous["revision"])}},
            )
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        resource_id = resource_id or str(uuid4())
        rev = previous["revision"] + 1 if previous else 1
        common = (
            resource_id,
            tenant,
            body.name,
            name_key(body.name),
            rev,
            now,
            now,
            actor["id"],
            actor["id"],
        )
        if table == "presets":
            conn.execute(
                "INSERT INTO presets(id,tenant_id,name,name_key,revision,created_at,updated_at,created_by,updated_by,cel,profile,sort,columns,group_by,noisy) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,name_key=EXCLUDED.name_key,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by,cel=EXCLUDED.cel,sort=EXCLUDED.sort,columns=EXCLUDED.columns,group_by=EXCLUDED.group_by,noisy=EXCLUDED.noisy",
                common
                + (
                    body.cel,
                    "appchi-cel-v1",
                    Jsonb(definition["sort"]),
                    Jsonb(definition["columns"]),
                    definition["group_by"],
                    definition["noisy"],
                ),
            )
        else:
            conn.execute(
                "INSERT INTO dashboards(id,tenant_id,name,name_key,revision,created_at,updated_at,created_by,updated_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,name_key=EXCLUDED.name_key,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at,updated_by=EXCLUDED.updated_by",
                common,
            )
            conn.execute(
                "DELETE FROM dashboard_panels WHERE tenant_id=%s AND dashboard_id=%s",
                (tenant, resource_id),
            )
            mark_used(conn, tenant, images_of(body.panels), now)
            for panel in body.panels:
                count = panel.type == "count"
                image = panel.type == "image"
                conn.execute(
                    "INSERT INTO dashboard_panels(id,tenant_id,dashboard_id,type,preset_id,image_id,title,x,y,w,h,thresholds,content) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        panel.id,
                        tenant,
                        resource_id,
                        panel.type,
                        panel.preset_id if panel.type in ("count", "table") else None,
                        panel.image_id if image else None,
                        panel.title,
                        panel.x,
                        panel.y,
                        panel.w,
                        panel.h,
                        Jsonb([t.model_dump() for t in panel.thresholds] if count else []),
                        Jsonb(panel_content(panel)),
                    ),
                )
        result = get_definition(conn, tenant, table, resource_id)
        conn.execute(
            sql.SQL(
                "INSERT INTO {}(tenant_id,id,revision,snapshot,recorded_at,actor_id) VALUES(%s,%s,%s,%s,%s,%s)"
            ).format(sql.Identifier(TABLES[table])),
            (tenant, resource_id, rev, Jsonb(public(result)), now, actor["id"]),
        )
        conn.execute(
            "INSERT INTO configuration_activity(id,tenant_id,resource_kind,resource_id,revision,kind,command_id,actor_id,actor_label,before_revision,after_revision,recorded_at,changed_fields) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                tenant,
                table[:-1],
                resource_id,
                rev,
                "updated" if previous else "created",
                body.command_id,
                actor["id"],
                actor["display_name"],
                previous["revision"] if previous else None,
                rev,
                now,
                sorted(
                    key
                    for key, value in definition.items()
                    if not previous or public(previous)[key] != value
                ),
            ),
        )
        conn.execute(
            "UPDATE tenant_view_state SET view_generation=view_generation+1,resource_generation=resource_generation+1 WHERE tenant_id=%s",
            (tenant,),
        )
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {"data": public(result), "meta": {"revision": str(rev)}},
            200 if previous else 201,
        )


def public(row):
    result = wire({key: value for key, value in row.items() if key != "name_key"})
    if "panels" in result:
        result["panel_count"] = str(len(result["panels"]))
        for panel in result["panels"]:
            for key in ("x", "y", "w", "h"):
                panel[key] = int(panel[key])
            if "rows" in panel:
                # A table panel's row count is a small integer, like its layout (REV-63).
                panel["rows"] = int(panel["rows"])
    return result


@router.post("/presets", status_code=201)
def create_preset(tenant_id: str, body: PresetCreate, request: Request):
    return save(request, tenant_id, "presets", body)


@router.put("/presets/{resource_id}")
def replace_preset(tenant_id: str, resource_id: str, body: PresetReplace, request: Request):
    return save(request, tenant_id, "presets", body, resource_id)


@router.post("/dashboards", status_code=201)
def create_dashboard(tenant_id: str, body: DashboardCreate, request: Request):
    return save(request, tenant_id, "dashboards", body)


@router.put("/dashboards/{resource_id}")
def replace_dashboard(tenant_id: str, resource_id: str, body: DashboardReplace, request: Request):
    return save(request, tenant_id, "dashboards", body, resource_id)


@router.post("/presets/validate")
def validate_preset(tenant_id: str, body: PresetDefinition, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
    from appchi.cel import compile_expression

    try:
        compile_expression(body.cel)
    except ValueError:
        return {
            "data": {
                "valid": False,
                "diagnostics": [{"path": "cel", "message": "Expression is invalid."}],
            },
            "meta": {},
        }
    return {"data": {"valid": True, "profile": "appchi-cel-v1"}, "meta": {}}


@router.post("/dashboards/validate")
def validate_dashboard(tenant_id: str, body: DashboardDefinition, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        for preset_id in referenced_presets_of(body.panels):
            get_definition(conn, tenant_id, "presets", preset_id)
        check_images(conn, tenant_id, images_of(body.panels))
    return {"data": {"valid": True, "removed": sanitized(body.panels)}, "meta": {}}


def read_routes(table):
    def listing(
        tenant_id: str,
        request: Request,
        limit: int = 50,
        name: str = "",
        cursor: str | None = None,
        state: str = "active",
        sort: str = "name",
        direction: str = "asc",
    ):
        from appchi.shared.cursors import Cursor
        from appchi.configuration.retention import (
            deleted_args,
            deleted_definitions,
            warm_history_names,
        )

        if not 1 <= limit <= 200 or len(name) > 128 or state not in {"active", "deleted"}:
            raise AppError("invalid_query", "Invalid page size or name.")
        if sort not in {"name", "updated_at"} or direction not in {"asc", "desc"}:
            raise AppError("invalid_query", "Invalid configuration ordering.")
        if table != "dashboards" and (sort != "name" or direction != "asc"):
            raise AppError("invalid_query", "This collection uses name ordering.")
        order_column = (
            "name_key"
            if sort == "name"
            else ("recorded_at" if state == "deleted" else "updated_at")
        )
        if state == "deleted":
            # Derived historical-name cache only. Commit bounded warmup even if
            # more rows require a later request; never approximate full casefold.
            with request.app.state.db.transaction() as conn:
                authorize(conn, request, tenant_id)
                conn.execute(
                    "SELECT tenant_id FROM tenant_configuration_guard WHERE tenant_id=%s FOR UPDATE",
                    (tenant_id,),
                )
                warm_history_names(conn, tenant_id, table[:-1])
        with request.app.state.db.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            actor, session, _ = authorize(conn, request, tenant_id)
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            generation = conn.execute(
                "SELECT resource_generation FROM tenant_view_state WHERE tenant_id=%s", (tenant_id,)
            ).fetchone()["resource_generation"]
            codec = Cursor(
                request.app.state.settings.cipher(),
                {
                    "tenant": tenant_id,
                    "collection": table,
                    "name": name_key(name),
                    "state": state,
                    "sort": sort,
                    "direction": direction,
                    "actor": str(actor["id"]),
                    "session": bytes(session["handle_hash"]).hex(),
                    "epoch": request.app.state.settings.deployment_epoch,
                },
                now,
            )
            old = codec.decode(cursor) if cursor else None
            if old and old["generation"] != str(generation):
                raise AppError("list_changed", "Configuration changed; restart the list.", 409)
            retained_revision = None
            if state == "deleted":
                source = deleted_definitions(table[:-1])
                source_args = deleted_args(tenant_id, now)
                if conn.execute(
                    sql.SQL("SELECT 1 FROM ({}) candidates WHERE name_key IS NULL LIMIT 1").format(
                        source
                    ),
                    source_args,
                ).fetchone():
                    raise unavailable("configuration_history_name_index_pending")
                query = sql.SQL("SELECT * FROM ({}) candidates WHERE strpos(name_key,%s)>0").format(
                    source
                )
                args = [*source_args, name_key(name)]
                # Retention/hold changes can change the newest visible name
                # without a user save. Bind the cursor to that exact result set.
                retained_revision = conn.execute(
                    sql.SQL("""SELECT encode(sha256(convert_to(coalesce(
                    string_agg(jsonb_build_array(id,revision,name_key,final_revision,deleted_at)::text,',' ORDER BY name_key,id),
                    ''),'UTF8')),'hex') AS digest FROM ({}) visible""").format(query),
                    args,
                ).fetchone()["digest"]
                if old and old.get("retained_revision") != retained_revision:
                    raise AppError(
                        "list_changed", "Retained configuration changed; restart the list.", 409
                    )
            else:
                query = sql.SQL(
                    "SELECT * FROM {} WHERE tenant_id=%s AND deleted_at IS NULL AND strpos(name_key,%s)>0"
                ).format(sql.Identifier(table))
                args = [tenant_id, name_key(name)]
            if old:
                query += sql.SQL(" AND ({} {} %s OR ({}=%s AND id>%s))").format(
                    sql.Identifier(order_column),
                    sql.SQL(">" if direction == "asc" else "<"),
                    sql.Identifier(order_column),
                )
                position, identity = old["position"]
                args += [position, position, identity]
            query += sql.SQL(" ORDER BY {} {},id ASC LIMIT %s").format(
                sql.Identifier(order_column), sql.SQL(direction)
            )
            rows = conn.execute(query, args + [limit + 1]).fetchall()
            return {
                "data": enrich_actors(
                    conn,
                    [
                        public(get_definition(conn, tenant_id, table, row["id"]))
                        if state == "active"
                        else public(
                            {
                                **row["snapshot"],
                                "deleted_at": row["deleted_at"],
                                "history_revision": row["revision"],
                                "final_revision": row["final_revision"],
                                **(
                                    {"updated_at": row["recorded_at"]}
                                    if table == "dashboards"
                                    else {}
                                ),
                            }
                        )
                        for row in rows[:limit]
                    ],
                ),
                "meta": {},
                "next_cursor": codec.encode(
                    [rows[limit - 1][order_column], rows[limit - 1]["id"]],
                    generation=generation,
                    retained_revision=retained_revision,
                )
                if len(rows) > limit
                else None,
            }

    def detail(tenant_id: str, resource_id: str, request: Request):
        with request.app.state.db.transaction() as conn:
            authorize(conn, request, tenant_id)
            row = get_definition(conn, tenant_id, table, resource_id)
            (data,) = enrich_actors(conn, [public(row)])
            return {"data": data, "meta": {"revision": str(row["revision"])}}

    return listing, detail


for table in TABLES:
    listing, detail = read_routes(table)
    router.add_api_route(
        "/" + table,
        listing,
        methods=["GET"],
        name="list_" + table,
        responses=documented(ActorPage),
    )
    router.add_api_route(
        "/" + table + "/{resource_id}",
        detail,
        methods=["GET"],
        name="get_" + table,
        responses=documented(ActorRead),
    )
