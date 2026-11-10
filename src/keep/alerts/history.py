from psycopg import sql
from fastapi import Request
from keep.access import authorize
from keep.alerts.routes import router
from keep.alerts.state import retained
from keep.shared.cursors import Cursor
from keep.shared.errors import AppError
from keep.serialization import wire

COLLECTIONS = {
    "history": ("alert_activity", "change_order", "id"),
    "source-events": ("alert_source_events", "admission_order", "id"),
    "occurrences": ("alert_occurrences", "number", "id"),
    "notes": ("alert_notes", "created_at", "id"),
}


def collection_route(collection):
    table, order, id_column = COLLECTIONS[collection]

    def read(
        tenant_id: str,
        alert_id: str,
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
        direction: str = "desc",
        include_deleted: bool = False,
    ):
        if not 1 <= limit <= 200 or direction not in ("asc", "desc"):
            raise AppError("invalid_query", "Invalid history query.")
        if collection != "notes" and "include_deleted" in request.query_params:
            raise AppError("invalid_query", "Deleted-note discovery applies only to notes.")
        with request.app.state.db.transaction() as conn:
            actor, session, _ = authorize(conn, request, tenant_id)
            retained(conn, tenant_id, alert_id)
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            context = {
                "tenant": tenant_id,
                "alert": alert_id,
                "collection": collection,
                "actor": str(actor["id"]),
                "session": bytes(session["handle_hash"]).hex(),
                "direction": direction,
                "include_deleted": include_deleted,
                "epoch": request.app.state.settings.deployment_epoch,
            }
            codec = Cursor(request.app.state.settings.cipher(), context, now)
            old = codec.decode(cursor) if cursor else None
            maximum = (
                old["upper"]
                if old
                else conn.execute(
                    sql.SQL(
                        "SELECT max({}) AS maximum FROM {} WHERE tenant_id=%s AND alert_id=%s"
                    ).format(sql.Identifier(order), sql.Identifier(table)),
                    (tenant_id, alert_id),
                ).fetchone()["maximum"]
            )
            if maximum is None:
                return {"data": [], "meta": {}, "next_cursor": None}
            columns = (
                sql.SQL("*")
                if collection != "source-events"
                else sql.SQL(
                    "tenant_id,alert_id,id,admission_order,received_at,time_defaulted,occurrence_id,adapter_version"
                )
            )
            query = sql.SQL(
                "SELECT {} FROM {} WHERE tenant_id=%s AND alert_id=%s AND {}<=%s"
            ).format(columns, sql.Identifier(table), sql.Identifier(order))
            args = [tenant_id, alert_id, maximum]
            if collection == "notes" and not include_deleted:
                query += sql.SQL(" AND NOT deleted")
            if old:
                query += sql.SQL(" AND ({},{}) {} (%s,%s)").format(
                    sql.Identifier(order),
                    sql.Identifier(id_column),
                    sql.SQL("<" if direction == "desc" else ">"),
                )
                args += old["position"]
            query += sql.SQL(" ORDER BY {} {},{} {} LIMIT %s").format(
                sql.Identifier(order),
                sql.SQL(direction),
                sql.Identifier(id_column),
                sql.SQL(direction),
            )
            args.append(limit + 1)
            rows = conn.execute(query, args).fetchall()
            if collection == "notes":
                for row in rows:
                    if row["deleted"]:
                        row["text"] = None
            next_cursor = (
                codec.encode([rows[limit - 1][order], rows[limit - 1][id_column]], upper=maximum)
                if len(rows) > limit
                else None
            )
            return {"data": wire(rows[:limit]), "meta": {}, "next_cursor": next_cursor}

    return read


for collection in COLLECTIONS:
    router.add_api_route(
        "/{alert_id}/" + collection,
        collection_route(collection),
        methods=["GET"],
        name="alert_" + collection,
    )


@router.get("/{alert_id}/source-events/{event_id}")
def source(tenant_id: str, alert_id: str, event_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        retained(conn, tenant_id, alert_id)
        row = conn.execute(
            "SELECT * FROM alert_source_events WHERE tenant_id=%s AND alert_id=%s AND id=%s",
            (tenant_id, alert_id, event_id),
        ).fetchone()
        if not row:
            raise AppError("not_found", "Source event unavailable.", 404)
        row["raw_json"] = bytes(row["raw_json"]).decode("utf-8")
        return {"data": wire(row), "meta": {}}


@router.get("/{alert_id}/notes/{note_id}/history")
def note_history(
    tenant_id: str,
    alert_id: str,
    note_id: str,
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
):
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Invalid history page size.")
    with request.app.state.db.transaction() as conn:
        actor, session, _ = authorize(conn, request, tenant_id)
        retained(conn, tenant_id, alert_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "alert": alert_id,
                "note": note_id,
                "collection": "note_history",
                "actor": str(actor["id"]),
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        old = codec.decode(cursor) if cursor else None
        upper = (
            old["upper"]
            if old
            else conn.execute(
                "SELECT max(revision) AS rev FROM alert_note_revisions WHERE tenant_id=%s AND alert_id=%s AND note_id=%s",
                (tenant_id, alert_id, note_id),
            ).fetchone()["rev"]
        )
        if upper is None:
            raise AppError("not_found", "Note history unavailable.", 404)
        rows = conn.execute(
            "SELECT * FROM alert_note_revisions WHERE tenant_id=%s AND alert_id=%s AND note_id=%s AND revision<=%s AND revision<%s ORDER BY revision DESC LIMIT %s",
            (
                tenant_id,
                alert_id,
                note_id,
                upper,
                old["position"] if old else int(upper) + 1,
                limit + 1,
            ),
        ).fetchall()
        return {
            "data": wire(rows[:limit]),
            "meta": {},
            "next_cursor": codec.encode(rows[limit - 1]["revision"], upper=upper)
            if len(rows) > limit
            else None,
        }
