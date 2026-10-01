"""Authorized, retained configuration history and current reference pagination.

Revision snapshots are the persisted evidence available in this schema. These
routes do not fabricate missing command/change-event or actor-display evidence.
"""

from datetime import UTC, datetime
import re

from fastapi import APIRouter, Query, Request
from psycopg import sql

from appchi.access import authorize
from appchi.configuration.retention import retained_args, retained_versions
from appchi.shared.cursors import Cursor
from appchi.shared.errors import AppError
from appchi.shared.transactions import wire

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["configuration"])
TABLES = {"presets": "preset_revisions", "dashboards": "dashboard_revisions"}


def _utc(value):
    if value is None:
        return None
    try:
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value
        ):
            raise ValueError()
        return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        raise AppError("invalid_query", "Use an explicit UTC timestamp.", 400) from None


def _page_parameters(limit, cursor):
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Page size must be between 1 and 200.", 400)
    if cursor is not None and (not cursor or len(cursor) > 65536):
        raise AppError("invalid_cursor", "Cursor is invalid for this view.", 400)


def _context(request, tenant, resource, actor, session, collection, **filters):
    return {
        "tenant": tenant,
        "resource": resource,
        "collection": collection,
        "actor": str(actor["id"]),
        "session": bytes(session["handle_hash"]).hex(),
        "epoch": request.app.state.settings.deployment_epoch,
        **wire(filters),
    }


def _resource(conn, tenant, table, resource, now, *, active=False):
    row = conn.execute(
        sql.SQL("""SELECT coalesce(p.revision,i.final_revision) AS revision,i.deleted_at,p.id AS body_id
          FROM configuration_identities i LEFT JOIN {} p ON p.tenant_id=i.tenant_id AND p.id=i.resource_id
          WHERE i.tenant_id=%s AND i.resource_kind=%s AND i.resource_id=%s""").format(
            sql.Identifier(table)
        ),
        (tenant, table[:-1], resource),
    ).fetchone()
    if not row or (active and (row["deleted_at"] is not None or row["body_id"] is None)):
        raise AppError("not_found", "Resource unavailable.", 404)
    if (
        not active
        and not conn.execute(
            sql.SQL("SELECT 1 FROM ({}) retained LIMIT 1").format(retained_versions(table[:-1])),
            retained_args(tenant, resource, now),
        ).fetchone()
    ):
        raise AppError("not_found", "Resource unavailable.", 404)
    return row


def _retained_query(table):
    return retained_versions(table[:-1])


def _activity(conn, tenant, kind, resource, revision, now):
    return conn.execute(
        """SELECT id,kind,command_id,actor_id,actor_label,before_revision,after_revision,changed_fields,recorded_at FROM configuration_activity a
        WHERE tenant_id=%s AND resource_kind=%s AND resource_id=%s AND revision=%s AND (
          recorded_at+interval '2160 hours'>%s
          OR (a.kind='deleted' AND configuration_pending_revision(a.tenant_id,a.resource_kind,a.resource_id,a.revision,true)) OR EXISTS(
            SELECT 1 FROM configuration_retention_holds h WHERE h.tenant_id=a.tenant_id
            AND h.resource_kind=a.resource_kind AND h.resource_id=a.resource_id AND h.released_at IS NULL
            AND (h.revision IS NULL OR h.revision=a.revision)))""",
        (tenant, kind, resource, revision, now),
    ).fetchone()


def _history_routes(table):
    def history(
        tenant_id: str,
        resource_id: str,
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = None,
    ):
        _page_parameters(limit, cursor)
        start, end = _utc(from_), _utc(to)
        if start is not None and end is not None and start >= end:
            raise AppError("invalid_query", "From must precede to.", 400)
        with request.app.state.db.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            actor, session, _ = authorize(conn, request, tenant_id)
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            resource = _resource(conn, tenant_id, table, resource_id, now)
            context = _context(
                request,
                tenant_id,
                resource_id,
                actor,
                session,
                table + ":history",
                from_=start,
                to=end,
            )
            codec = Cursor(request.app.state.settings.cipher(), context, now)
            old = codec.decode(cursor) if cursor else None
            upper = int(old["upper_revision"]) if old else resource["revision"]
            recorded_through = old["recorded_through"] if old else now
            query = sql.SQL(
                "SELECT * FROM ({}) retained WHERE revision<=%s AND recorded_at<=%s"
            ).format(_retained_query(table))
            args = [*retained_args(tenant_id, resource_id, now), upper, recorded_through]
            if start is not None:
                query += sql.SQL(" AND recorded_at>=%s")
                args.append(start)
            if end is not None:
                query += sql.SQL(" AND recorded_at<%s")
                args.append(end)
            if old:
                query += sql.SQL(" AND (recorded_at,revision)<(%s,%s)")
                args.extend(old["position"])
            query += sql.SQL(" ORDER BY recorded_at DESC,revision DESC LIMIT %s")
            args.append(limit + 1)
            rows = conn.execute(query, args).fetchall()
            next_cursor = None
            if len(rows) > limit:
                last = rows[limit - 1]
                next_cursor = codec.encode(
                    [last["recorded_at"], last["revision"]],
                    upper_revision=upper,
                    recorded_through=recorded_through,
                )
            return {
                "data": wire(
                    [
                        {
                            "revision": row["revision"],
                            "recorded_at": row["recorded_at"],
                            "definition_available": True,
                            "activity_available": bool(
                                _activity(
                                    conn, tenant_id, table[:-1], resource_id, row["revision"], now
                                )
                            ),
                        }
                        for row in rows[:limit]
                    ]
                ),
                "meta": {"recorded_through": wire(recorded_through)},
                "next_cursor": next_cursor,
            }

    def detail(tenant_id: str, resource_id: str, revision: str, request: Request):
        if not re.fullmatch(r"[1-9][0-9]{0,18}", revision) or int(revision) > 9223372036854775807:
            raise AppError("invalid_revision", "Canonical positive revision required.", 400)
        with request.app.state.db.transaction() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            authorize(conn, request, tenant_id)
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            _resource(conn, tenant_id, table, resource_id, now)
            row = conn.execute(
                sql.SQL("SELECT * FROM ({}) retained WHERE revision=%s").format(
                    _retained_query(table)
                ),
                (*retained_args(tenant_id, resource_id, now), int(revision)),
            ).fetchone()
            if row is None:
                raise AppError("not_found", "Revision unavailable.", 404)
            activity = _activity(conn, tenant_id, table[:-1], resource_id, int(revision), now)
            before = None
            if activity and activity["before_revision"]:
                prior = conn.execute(
                    sql.SQL(
                        "SELECT snapshot FROM {} WHERE tenant_id=%s AND id=%s AND revision=%s"
                    ).format(sql.Identifier(TABLES[table])),
                    (tenant_id, resource_id, activity["before_revision"]),
                ).fetchone()
                before = prior["snapshot"] if prior else None
            return {
                "data": {
                    "definition": row["snapshot"],
                    "activity": wire(activity),
                    "before_definition": before,
                },
                "meta": {"revision": revision},
            }

    return history, detail


for _table in TABLES:
    _history, _detail = _history_routes(_table)
    router.add_api_route(
        "/" + _table + "/{resource_id}/history", _history, methods=["GET"], name=_table + "_history"
    )
    router.add_api_route(
        "/" + _table + "/{resource_id}/history/{revision}",
        _detail,
        methods=["GET"],
        name=_table + "_history_revision",
    )


@router.get("/presets/{resource_id}/references")
def preset_references(
    tenant_id: str,
    resource_id: str,
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
):
    _page_parameters(limit, cursor)
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        actor, session, _ = authorize(conn, request, tenant_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        _resource(conn, tenant_id, "presets", resource_id, now, active=True)
        context = _context(request, tenant_id, resource_id, actor, session, "preset:references")
        codec = Cursor(request.app.state.settings.cipher(), context, now)
        old = codec.decode(cursor) if cursor else None
        # Hash the exact returned reference set, including displayed names. An
        # unrelated configuration edit does not invalidate this traversal.
        source = """FROM dashboard_panels p JOIN dashboards d
                    ON d.tenant_id=p.tenant_id AND d.id=p.dashboard_id
                    WHERE p.tenant_id=%s AND p.preset_id=%s AND d.deleted_at IS NULL"""
        state = conn.execute(
            """SELECT count(*) AS total,encode(sha256(convert_to(COALESCE(
                string_agg(jsonb_build_array(d.id,d.name,p.id)::text,',' ORDER BY d.id,p.id),
                ''),'UTF8')),'hex') AS revision """
            + source,
            (tenant_id, resource_id),
        ).fetchone()
        if old and old["reference_revision"] != state["revision"]:
            raise AppError("list_changed", "References changed; restart from the first page.", 409)
        query = "SELECT d.id AS dashboard_id,d.name AS dashboard_name,p.id AS panel_id " + source
        args = [tenant_id, resource_id]
        if old:
            query += " AND (d.id,p.id)>(%s,%s)"
            args.extend(old["position"])
        query += " ORDER BY d.id,p.id LIMIT %s"
        args.append(limit + 1)
        rows = conn.execute(query, args).fetchall()
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = codec.encode(
                [last["dashboard_id"], last["panel_id"]], reference_revision=state["revision"]
            )
        return {
            "data": wire(rows[:limit]),
            "meta": {"total": str(state["total"]), "reference_revision": state["revision"]},
            "next_cursor": next_cursor,
        }
