"""Incident-owned note and history HTTP contracts."""

from uuid import uuid4
from appchi.alerts.presentation import present_alert
from fastapi import Request
from psycopg import sql

from appchi.access import authorize
from appchi.alerts.routes import delete_command, derived_read
from appchi.incidents.routes import router, get_incident, activity, update_tokens
from appchi.models import NoteCommand
from appchi.shared.cursors import Cursor
from appchi.shared.errors import AppError
from appchi.shared.transactions import command_result, coordinator, revision, save_result, wire


def mutate_note(request, tenant, incident_id, body, note_id=None, delete=False):
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
        scope = f"{tenant}:{actor['id']}:incident-note:{'delete' if delete else 'edit' if note_id else 'create'}"
        result, fp = command_result(
            conn,
            scope,
            body.command_id,
            {"target": incident_id, "note_id": note_id, **body.model_dump()},
        )
        if result is not None:
            return result
        _, now = coordinator(conn, tenant)
        row = get_incident(conn, tenant, incident_id, True)
        revision(row, body.expected_revision)
        previous = None
        if note_id:
            previous = conn.execute(
                "SELECT * FROM incident_notes WHERE tenant_id=%s AND incident_id=%s AND id=%s AND NOT deleted",
                (tenant, incident_id, note_id),
            ).fetchone()
            if not previous:
                raise AppError("not_found", "Note unavailable.", 404)
        text = previous["text"] if delete else body.text
        changed = not previous or delete or previous["text"] != text
        note_id = note_id or str(uuid4())
        if changed:
            rev = previous["revision"] + 1 if previous else 1
            conn.execute(
                "INSERT INTO incident_notes(id,tenant_id,incident_id,text,deleted,revision,actor_id,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO UPDATE SET text=EXCLUDED.text,deleted=EXCLUDED.deleted,revision=EXCLUDED.revision",
                (note_id, tenant, incident_id, text, delete, rev, actor["id"], now),
            )
            conn.execute(
                "INSERT INTO incident_note_revisions(tenant_id,incident_id,note_id,revision,text,deleted,actor_id,actor_display_name,recorded_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    tenant,
                    incident_id,
                    note_id,
                    rev,
                    text,
                    delete,
                    actor["id"],
                    actor["display_name"],
                    now,
                ),
            )
            activity(
                conn,
                row,
                now,
                actor["id"],
                "note-deleted" if delete else "note-edited" if previous else "note-created",
                {"note_id": note_id, "revision": str(rev)},
            )
            update_tokens(conn, tenant, incident_id)
        updated = get_incident(conn, tenant, incident_id)
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {
                "data": {
                    "id": note_id,
                    "text": None if delete else text,
                    "deleted": delete,
                    "revision": str(updated["revision"]),
                },
                "meta": {"revision": str(updated["revision"])},
            },
            200 if previous else 201,
            resources=[(tenant, "incident", incident_id)],
        )


@router.post("/{incident_id}/notes", status_code=201)
def add_note(tenant_id: str, incident_id: str, body: NoteCommand, request: Request):
    return mutate_note(request, tenant_id, incident_id, body)


@router.patch("/{incident_id}/notes/{note_id}")
def edit_note(tenant_id: str, incident_id: str, note_id: str, body: NoteCommand, request: Request):
    return mutate_note(request, tenant_id, incident_id, body, note_id)


@router.delete("/{incident_id}/notes/{note_id}")
def remove_note(tenant_id: str, incident_id: str, note_id: str, request: Request):
    return mutate_note(request, tenant_id, incident_id, delete_command(request), note_id, True)


def locked_note_parent(conn, tenant, incident):
    row = conn.execute(
        "SELECT i.revision FROM incidents i JOIN incident_identities x ON x.id=i.id AND x.tenant_id=i.tenant_id WHERE i.tenant_id=%s AND i.id=%s AND x.retired_at IS NULL FOR SHARE OF i",
        (tenant, incident),
    ).fetchone()
    if not row:
        raise AppError("not_found", "Incident unavailable.", 404)
    return row


@router.get("/{incident_id}/notes/{note_id}/history")
def note_history(
    tenant_id: str,
    incident_id: str,
    note_id: str,
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
):
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Page size must be 1–200.")
    with request.app.state.db.transaction() as conn:
        conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
        actor, session, _ = authorize(conn, request, tenant_id)
        parent = locked_note_parent(conn, tenant_id, incident_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "incident": incident_id,
                "note": note_id,
                "collection": "incident-note-history",
                "direction": "revision-desc",
                "actor": str(actor["id"]),
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        old = codec.decode(cursor) if cursor else None
        # Per-note revisions are serialized by the aggregate lock. This immutable
        # high watermark excludes subsequent edits/deletions on every later page.
        upper = (
            old["upper"]
            if old
            else conn.execute(
                "SELECT max(revision) AS upper FROM incident_note_revisions WHERE tenant_id=%s AND incident_id=%s AND note_id=%s",
                (tenant_id, incident_id, note_id),
            ).fetchone()["upper"]
        )
        if upper is None:
            raise AppError("not_found", "Note history unavailable.", 404)
        rows = conn.execute(
            "SELECT note_id,revision,text,deleted,actor_id,actor_display_name,recorded_at FROM incident_note_revisions WHERE tenant_id=%s AND incident_id=%s AND note_id=%s AND revision<=%s AND (%s::bigint IS NULL OR revision<%s) ORDER BY revision DESC LIMIT %s",
            (
                tenant_id,
                incident_id,
                note_id,
                upper,
                old["position"] if old else None,
                old["position"] if old else None,
                limit + 1,
            ),
        ).fetchall()
        return {
            "data": wire(rows[:limit]),
            "meta": {"revision": str(parent["revision"]), "upper_revision": str(upper)},
            "next_cursor": codec.encode(rows[limit - 1]["revision"], upper=upper)
            if len(rows) > limit
            else None,
        }


def collection_route(collection):
    table, order = {
        "activity": ("incident_activity", "recorded_at"),
        "cycles": ("incident_cycles", "opened_at"),
        "notes": ("incident_notes", "created_at"),
    }[collection]

    def read(
        tenant_id: str,
        incident_id: str,
        request: Request,
        limit: int = 50,
        cursor: str | None = None,
        include_deleted: bool = False,
    ):
        if not 1 <= limit <= 200:
            raise AppError("invalid_query", "Page size must be 1–200.")
        with request.app.state.db.transaction() as conn:
            if collection == "notes":
                conn.execute(
                    "SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE"
                )
            actor, session, _ = authorize(conn, request, tenant_id)
            if collection == "notes":
                parent = locked_note_parent(conn, tenant_id, incident_id)
            else:
                parent = get_incident(conn, tenant_id, incident_id)
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            codec = Cursor(
                request.app.state.settings.cipher(),
                {
                    "tenant": tenant_id,
                    "incident": incident_id,
                    "collection": collection,
                    "include_deleted": include_deleted if collection == "notes" else False,
                    "session": bytes(session["handle_hash"]).hex(),
                    "epoch": request.app.state.settings.deployment_epoch,
                },
                now,
            )
            old = codec.decode(cursor) if cursor else None
            upper = old["upper"] if old else wire(now)
            query = sql.SQL(
                "SELECT * FROM {} WHERE tenant_id=%s AND incident_id=%s AND {}<=%s"
            ).format(sql.Identifier(table), sql.Identifier(order))
            args = [tenant_id, incident_id, upper]
            if collection == "notes" and not include_deleted:
                query += sql.SQL(" AND NOT deleted")
            if old:
                query += sql.SQL(" AND ({},id)<(%s,%s)").format(sql.Identifier(order))
                args += old["position"]
            query += sql.SQL(" ORDER BY {} DESC,id DESC LIMIT %s").format(sql.Identifier(order))
            args.append(limit + 1)
            rows = conn.execute(query, args).fetchall()
            if collection == "notes":
                for row in rows:
                    if row["deleted"]:
                        row["text"] = None
            cursor = (
                codec.encode([rows[limit - 1][order], rows[limit - 1]["id"]], upper=upper)
                if len(rows) > limit
                else None
            )
            return {
                "data": wire(rows[:limit]),
                "meta": {"revision": str(parent["revision"])} if collection == "notes" else {},
                "next_cursor": cursor,
            }

    return read


for collection in ("activity", "cycles", "notes"):
    router.add_api_route(
        "/{incident_id}/" + collection,
        collection_route(collection),
        methods=["GET"],
        name="incident_" + collection,
    )


@router.get("/{incident_id}/alerts")
def linked_alerts(
    tenant_id: str, incident_id: str, request: Request, limit: int = 50, cursor: str | None = None
):
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Invalid page size.")
    with request.app.state.db.transaction() as conn:
        _, session, _ = authorize(conn, request, tenant_id)
        get_incident(conn, tenant_id, incident_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "incident": incident_id,
                "collection": "alerts",
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        old = codec.decode(cursor) if cursor else None
        rows = conn.execute(
            "SELECT l.alert_id AS reference_id,l.linked_at,a.* FROM incident_alert_links l LEFT JOIN alert_identities ai ON ai.id=l.alert_id AND ai.tenant_id=l.tenant_id AND ai.retired_at IS NULL LEFT JOIN alerts a ON a.id=ai.id AND a.tenant_id=ai.tenant_id WHERE l.tenant_id=%s AND l.incident_id=%s AND l.unlinked_at IS NULL AND (%s::uuid IS NULL OR l.alert_id>%s::uuid) ORDER BY l.alert_id LIMIT %s",
            (
                tenant_id,
                incident_id,
                old["position"] if old else None,
                old["position"] if old else None,
                limit + 1,
            ),
        ).fetchall()
        next_cursor = codec.encode(rows[limit - 1]["reference_id"]) if len(rows) > limit else None
        return {
            "data": wire(
                [
                    present_alert(derived_read(conn, row) if row.get("id") else row)
                    for row in rows[:limit]
                ]
            ),
            "meta": {},
            "next_cursor": next_cursor,
        }
