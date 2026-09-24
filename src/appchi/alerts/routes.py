from uuid import uuid4
from fastapi import APIRouter, Request

from appchi.access import assignee, authorize
from appchi.alerts.lifecycle import apply_command
from appchi.alerts.repository import publish, store_alert
from appchi.models import AlertCommand, BulkCommand, NoteCommand, Command
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import command_result, coordinator, revision, save_result, wire
from appchi.maintenance.runtime import prepare_for_tenant, lock_catalog, apply_transition
from appchi.maintenance.processing import derive_current
from appchi.maintenance.temporal import MaintenanceProofError
from appchi.cel.catalog import RULE_FIELDS
from appchi.shared.display_names import AlertRead, active_incident_ids, documented, enrich_alerts

router = APIRouter(prefix="/api/tenants/{tenant_id}/alerts", tags=["alerts"])


def request_catalog(request, tenant):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant)
    return prepare_for_tenant(
        request.app.state.db, tenant, getattr(request.app.state, "profile", None)
    )


def maintenance_adjust(conn, row, updated, now, cause, catalog):
    order = None
    if any(row[field] != updated[field] for field in RULE_FIELDS):
        order = conn.execute(
            "UPDATE tenant_work_state SET admission_order=admission_order+1 WHERE tenant_id=%s RETURNING admission_order",
            (row["tenant_id"],),
        ).fetchone()["admission_order"]
    updated, changed, effects = apply_transition(
        conn, row, updated, now, order, cause, now, catalog
    )
    return updated, changed, effects, order


def with_current_assignee(conn, row):
    from appchi.identity.cleanup import visible_assignee

    assignee_id, pending_cleanup = visible_assignee(conn, row["tenant_id"], row.get("assignee_id"))
    return dict(row, assignee_id=assignee_id, assignment_cleanup_pending=pending_cleanup)


def derived_read(conn, row):
    row = with_current_assignee(conn, row)
    gate = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='maintenance'"
    ).fetchone()
    if gate and gate["ready"]:
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        try:
            suppressed, updating = derive_current(conn, row, now)
        except MaintenanceProofError:
            raise unavailable("maintenance_proof_unavailable") from None
        return dict(row, suppressed=suppressed, maintenance_updating=updating)
    if conn.execute(
        "SELECT 1 FROM maintenance_segments WHERE tenant_id=%s LIMIT 1", (row["tenant_id"],)
    ).fetchone():
        raise unavailable("maintenance_gate_closed_with_timeline")
    return row


def retained(conn, tenant, alert_id, lock=False):
    row = conn.execute(
        "SELECT a.* FROM alerts a JOIN alert_identities i ON i.id=a.id AND i.tenant_id=a.tenant_id WHERE a.tenant_id=%s AND a.id=%s AND i.retired_at IS NULL"
        + (" FOR UPDATE OF a" if lock else ""),
        (tenant, alert_id),
    ).fetchone()
    if row is None:
        raise AppError("not_found", "Alert unavailable.", 404)
    return row


def pending(conn, tenant, row):
    from hashlib import sha256

    if conn.execute(
        "SELECT 1 FROM ingest_items WHERE tenant_id=%s AND version=%s AND key_digest=%s AND disposition='pending' LIMIT 1",
        (tenant, row["schema_version"], sha256(row["key_field"].encode()).digest()),
    ).fetchone():
        raise AppError(
            "source_updates_pending", "Earlier source updates must finish before this command.", 409
        )


@router.get("/{alert_id}", responses=documented(AlertRead))
def detail(tenant_id: str, alert_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        authorize(conn, request, tenant_id)
        row = retained(conn, tenant_id, alert_id)
        data = wire(derived_read(conn, row))
        # Read-time only: active ownership comes from PG in this snapshot. The id
        # is exposed only when the same-tenant owner is retained (title resolved).
        owner = active_incident_ids(conn, tenant_id, [row["id"]]).get(str(row["id"]))
        (labelled,) = enrich_alerts(conn, tenant_id, [{**data, "active_incident_id": owner}])
        if labelled["active_incident_title"] is None:
            labelled["active_incident_id"] = None
        return {"data": labelled, "meta": {"revision": str(row["revision"])}}


@router.post("/{alert_id}/commands")
def command(tenant_id: str, alert_id: str, body: AlertCommand, request: Request):
    catalog = request_catalog(request, tenant_id)
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:alert-command"
        result, fp = command_result(
            conn, scope, body.command_id, {"target": alert_id, **body.model_dump()}
        )
        if result is not None:
            return result
        _, now = coordinator(conn, tenant_id)
        lock_catalog(conn, catalog)
        from appchi.incidents.routes import lock_linked_incidents, linked_transition

        linked = lock_linked_incidents(conn, tenant_id, alert_id)
        row = retained(conn, tenant_id, alert_id, True)
        pending(conn, tenant_id, row)
        revision(row, body.expected_revision)
        if body.kind == "set_assignee":
            assignee(conn, tenant_id, body.value)
        updated, changed = apply_command(row, body.kind, body.value, actor["id"], now)
        updated, changed, effects, order = maintenance_adjust(
            conn, row, updated, now, body.kind, catalog
        )
        if changed or (effects and effects.history_changed):
            store_alert(conn, updated)
            linked_transition(conn, linked, row, updated, now)
            publish(
                conn,
                row,
                updated,
                now,
                body.kind,
                actor=actor["id"],
                semantic=changed,
                original_order=order,
                maintenance_input_recorded=True,
            )
        result = {"data": wire(updated), "meta": {"revision": str(updated["revision"])}}
        return save_result(
            conn, scope, body.command_id, fp, result, resources=[(tenant_id, "alert", alert_id)]
        )


@router.post("/bulk-commands")
def bulk(tenant_id: str, body: BulkCommand, request: Request):
    catalog = request_catalog(request, tenant_id)
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:alert-bulk"
        result, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if result is not None:
            return result
        _, now = coordinator(conn, tenant_id)
        lock_catalog(conn, catalog)
        selected = {item.alert_id: item.expected_revision for item in body.items}
        from appchi.incidents.routes import linked_transition

        linked_rows = conn.execute(
            "SELECT i.*,l.alert_id AS linked_alert_id FROM incidents i JOIN incident_alert_links l ON l.tenant_id=i.tenant_id AND l.incident_id=i.id WHERE l.tenant_id=%s AND l.alert_id=ANY(%s::uuid[]) AND l.unlinked_at IS NULL AND i.status<>'resolved' ORDER BY i.id FOR UPDATE OF i",
            (tenant_id, list(selected)),
        ).fetchall()
        linked_by_alert = {key: [] for key in selected}
        for incident in linked_rows:
            linked_by_alert[str(incident["linked_alert_id"])].append(incident)
        locked = {key: retained(conn, tenant_id, key, True) for key in sorted(selected)}
        for key, row in locked.items():
            pending(conn, tenant_id, row)
            revision(row, selected[key])
        if body.kind == "set_assignee":
            assignee(conn, tenant_id, body.value)
        results = {}
        for key, row in locked.items():
            updated, changed = apply_command(row, body.kind, body.value, actor["id"], now)
            updated, changed, effects, order = maintenance_adjust(
                conn, row, updated, now, body.kind, catalog
            )
            if changed or (effects and effects.history_changed):
                store_alert(conn, updated)
                linked_transition(conn, linked_by_alert[key], row, updated, now)
                publish(
                    conn,
                    row,
                    updated,
                    now,
                    body.kind,
                    actor=actor["id"],
                    semantic=changed,
                    original_order=order,
                    maintenance_input_recorded=True,
                )
            results[key] = wire(updated)
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {"data": [results[key] for key in selected], "meta": {}},
            resources=[(tenant_id, "alert", key) for key in selected],
        )


def mutate_note(conn, request, tenant, alert_id, body, note_id=None, delete=False, catalog=None):
    actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
    operation = "note-delete" if delete else "note-edit" if note_id else "note-create"
    scope = f"{tenant}:{actor['id']}:{operation}"
    result, fp = command_result(
        conn, scope, body.command_id, {"target": alert_id, "note": note_id, **body.model_dump()}
    )
    if result is not None:
        return result
    _, now = coordinator(conn, tenant)
    lock_catalog(conn, catalog)
    from appchi.incidents.routes import lock_linked_incidents

    lock_linked_incidents(conn, tenant, alert_id)
    row = retained(conn, tenant, alert_id, True)
    pending(conn, tenant, row)
    revision(row, body.expected_revision)
    previous = None
    if note_id:
        previous = conn.execute(
            "SELECT * FROM alert_notes WHERE tenant_id=%s AND alert_id=%s AND id=%s",
            (tenant, alert_id, note_id),
        ).fetchone()
        if not previous or previous["deleted"]:
            raise AppError("not_found", "Note unavailable.", 404)
    text = previous["text"] if delete else body.text
    changed = not previous or delete or previous["text"] != text
    note_id = note_id or str(uuid4())
    if changed:
        note_revision = previous["revision"] + 1 if previous else 1
        conn.execute(
            "INSERT INTO alert_notes(id,tenant_id,alert_id,text,deleted,revision,actor_id,created_at,occurrence_id,actor_display_name) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(id) DO UPDATE SET text=EXCLUDED.text,deleted=EXCLUDED.deleted,revision=EXCLUDED.revision",
            (
                note_id,
                tenant,
                alert_id,
                text,
                delete,
                note_revision,
                actor["id"],
                now,
                row["occurrence_id"],
                actor["display_name"],
            ),
        )
        conn.execute(
            "INSERT INTO alert_note_revisions(tenant_id,alert_id,note_id,revision,text,deleted,actor_id,recorded_at,actor_display_name) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                tenant,
                alert_id,
                note_id,
                note_revision,
                text,
                delete,
                actor["id"],
                now,
                actor["display_name"],
            ),
        )
        updated = {
            **row,
            "revision": row["revision"] + 1,
            "projection_version": row["projection_version"] + 1,
        }
    else:
        updated = row
    updated, semantic, effects, order = maintenance_adjust(
        conn, row, updated, now, operation, catalog
    )
    if semantic or (effects and effects.history_changed):
        store_alert(conn, updated)
        publish(
            conn,
            row,
            updated,
            now,
            operation,
            actor=actor["id"],
            semantic=semantic,
            original_order=order,
            maintenance_input_recorded=True,
        )
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
        201 if not previous else 200,
        resources=[(tenant, "alert", alert_id)],
    )


@router.post("/{alert_id}/notes", status_code=201)
def create_note(tenant_id: str, alert_id: str, body: NoteCommand, request: Request):
    catalog = request_catalog(request, tenant_id)
    with request.app.state.db.transaction() as conn:
        return mutate_note(conn, request, tenant_id, alert_id, body, catalog=catalog)


@router.patch("/{alert_id}/notes/{note_id}")
def edit_note(tenant_id: str, alert_id: str, note_id: str, body: NoteCommand, request: Request):
    catalog = request_catalog(request, tenant_id)
    with request.app.state.db.transaction() as conn:
        return mutate_note(conn, request, tenant_id, alert_id, body, note_id, catalog=catalog)


@router.delete("/{alert_id}/notes/{note_id}")
def delete_note(tenant_id: str, alert_id: str, note_id: str, request: Request):
    body = delete_command(request)
    catalog = request_catalog(request, tenant_id)
    with request.app.state.db.transaction() as conn:
        return mutate_note(conn, request, tenant_id, alert_id, body, note_id, True, catalog)


def delete_command(request):
    match = request.headers.get("if-match", "")
    if len(match) < 3 or not match.startswith('"') or not match.endswith('"'):
        raise AppError("revision_required", "Quoted If-Match revision required.", 422)
    try:
        return Command(
            command_id=request.headers.get("idempotency-key"), expected_revision=match[1:-1]
        )
    except ValueError:
        raise AppError(
            "invalid_command", "Valid command and revision headers required.", 422
        ) from None
