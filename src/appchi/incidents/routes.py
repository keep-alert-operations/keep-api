import hashlib
import unicodedata
from datetime import datetime, timedelta
from typing import Literal
from uuid import uuid4
from psycopg.types.json import Jsonb
from fastapi import APIRouter, Request

from appchi.access import authorize, assignee
from appchi.alerts.repository import publish, store_alert
from appchi.alerts.routes import retained, pending, request_catalog, maintenance_adjust
from appchi.maintenance.runtime import lock_catalog
from appchi.incidents.models import (
    IncidentCreate,
    IncidentStatus,
    IncidentAssignment,
    IncidentContent,
    IncidentLinks,
    IncidentMove,
)
from appchi.shared.display_names import (
    IncidentPage,
    IncidentRead,
    documented,
    enrich_incidents,
)
from appchi.shared.errors import AppError
from appchi.shared.transactions import coordinator, command_result, revision, save_result, wire
from appchi.correlation.runtime import lock_contexts, release_alert, resolve_context, reopen_context

router = APIRouter(prefix="/api/tenants/{tenant_id}/incidents", tags=["incidents"])


def get_incident(conn, tenant, incident_id, lock=False):
    row = conn.execute(
        "SELECT i.* FROM incidents i JOIN incident_identities x ON x.id=i.id AND x.tenant_id=i.tenant_id WHERE i.tenant_id=%s AND i.id=%s AND x.retired_at IS NULL"
        + (" FOR UPDATE OF i" if lock else ""),
        (tenant, incident_id),
    ).fetchone()
    if not row:
        raise AppError("not_found", "Incident unavailable.", 404)
    return row


def tokens(text):
    token = ""
    result = set()
    for c in text:
        if unicodedata.category(c)[0] in "LMN" or c == "_":
            token += c
        elif token:
            result.add(token.casefold())
            token = ""
    if token:
        result.add(token.casefold())
    return result


def update_tokens(conn, tenant, incident_id):
    incident = get_incident(conn, tenant, incident_id)
    notes = conn.execute(
        "SELECT text FROM incident_notes WHERE tenant_id=%s AND incident_id=%s AND NOT deleted",
        (tenant, incident_id),
    ).fetchall()
    values = tokens(
        incident["title"]
        + " "
        + incident["description"]
        + " "
        + " ".join(row["text"] for row in notes)
    )
    conn.execute(
        "DELETE FROM incident_search_tokens WHERE tenant_id=%s AND incident_id=%s",
        (tenant, incident_id),
    )
    for token in values:
        if len(token.encode()) <= 3072:
            conn.execute(
                "INSERT INTO incident_search_tokens(tenant_id,incident_id,id,token_digest,token_text) VALUES(%s,%s,%s,%s,%s)",
                (tenant, incident_id, uuid4(), hashlib.sha256(token.encode()).digest(), token),
            )


def activity(conn, row, now, actor, kind, evidence, qualifying=True):
    recorded_now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    conn.execute(
        "INSERT INTO incident_activity(tenant_id,incident_id,id,kind,recorded_at,actor_id,evidence) VALUES(%s,%s,%s,%s,%s,%s,%s)",
        (
            row["tenant_id"],
            row["id"],
            uuid4(),
            kind,
            recorded_now,
            actor,
            Jsonb(wire({**evidence, "effective_at": now})),
        ),
    )
    conn.execute(
        "UPDATE incidents SET revision=revision+1,updated_at=%s,last_activity=CASE WHEN status<>'resolved' AND %s THEN greatest(last_activity,%s) ELSE last_activity END WHERE tenant_id=%s AND id=%s",
        (recorded_now, qualifying, now, row["tenant_id"], row["id"]),
    )
    conn.execute(
        "UPDATE tenant_view_state SET view_generation=view_generation+1,resource_generation=resource_generation+1 WHERE tenant_id=%s",
        (row["tenant_id"],),
    )


def alert_link_change(conn, row, now, actor, kind, catalog=None):
    updated = {
        **row,
        "revision": row["revision"] + 1,
        "projection_version": row["projection_version"] + 1,
    }
    updated, changed, _, order = maintenance_adjust(conn, row, updated, now, kind, catalog)
    store_alert(conn, updated)
    publish(
        conn,
        row,
        updated,
        now,
        kind,
        actor=actor,
        semantic=changed,
        original_order=order,
        maintenance_input_recorded=True,
    )


def link_set(conn, tenant, incident, ids, now, actor, unlink=False, catalog=None):
    if incident["status"] == "resolved":
        raise AppError("incident_resolved", "Reopen before changing links.", 409)
    alerts = {key: retained(conn, tenant, key, True) for key in sorted(ids)}
    for key, row in alerts.items():
        pending(conn, tenant, row)
        claim = conn.execute(
            "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
            (tenant, key),
        ).fetchone()
        if not unlink and claim and claim["incident_id"] != incident["id"]:
            raise AppError(
                "ownership_conflict", "An alert already has an active incident owner.", 409
            )
    changed = []
    for key, row in alerts.items():
        link = conn.execute(
            "SELECT * FROM incident_alert_links WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s AND unlinked_at IS NULL",
            (tenant, incident["id"], key),
        ).fetchone()
        if unlink and link:
            conn.execute(
                "UPDATE incident_alert_links SET unlinked_at=%s WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s",
                (now, tenant, incident["id"], key),
            )
            conn.execute(
                "DELETE FROM alert_active_ownership WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s",
                (tenant, incident["id"], key),
            )
            boundary(conn, tenant, key, now)
        elif not unlink and not link:
            conn.execute(
                "INSERT INTO incident_alert_links(tenant_id,incident_id,alert_id,linked_at) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant_id,incident_id,alert_id) DO UPDATE SET linked_at=EXCLUDED.linked_at,unlinked_at=NULL",
                (tenant, incident["id"], key, now),
            )
            conn.execute(
                "INSERT INTO alert_active_ownership(tenant_id,alert_id,incident_id) VALUES(%s,%s,%s)",
                (tenant, key, incident["id"]),
            )
        else:
            continue
        changed.append(key)
        alert_link_change(
            conn, row, now, actor, "incident-unlink" if unlink else "incident-link", catalog
        )
    return changed


def boundary(conn, tenant, alert_id, now):
    release_alert(conn, tenant, alert_id, now)


@router.post("", status_code=201)
def create(tenant_id: str, body: IncidentCreate, request: Request):
    catalog = request_catalog(request, tenant_id)
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:incident-create"
        result, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if result is not None:
            return result
        _, now = coordinator(conn, tenant_id)
        lock_contexts(conn, tenant_id)
        lock_catalog(conn, catalog)
        incident_id, cycle_id = uuid4(), uuid4()
        conn.execute(
            "INSERT INTO incident_identities(id,tenant_id) VALUES(%s,%s)", (incident_id, tenant_id)
        )
        conn.execute(
            "INSERT INTO incidents(id,tenant_id,title,description,severity,status,origin,cycle_id,created_at,updated_at,last_activity) VALUES(%s,%s,%s,%s,%s,'open','manual',%s,%s,%s,%s)",
            (
                incident_id,
                tenant_id,
                body.title,
                body.description,
                body.severity,
                cycle_id,
                now,
                now,
                now,
            ),
        )
        conn.execute(
            "INSERT INTO incident_cycles(tenant_id,incident_id,id,opened_at) VALUES(%s,%s,%s,%s)",
            (tenant_id, incident_id, cycle_id, now),
        )
        row = get_incident(conn, tenant_id, incident_id)
        link_set(conn, tenant_id, row, body.alert_ids, now, actor["id"], catalog=catalog)
        conn.execute(
            "INSERT INTO incident_activity(tenant_id,incident_id,id,kind,recorded_at,actor_id,evidence) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (
                tenant_id,
                incident_id,
                uuid4(),
                "created",
                now,
                actor["id"],
                Jsonb(body.model_dump(exclude={"command_id"})),
            ),
        )
        update_tokens(conn, tenant_id, incident_id)
        conn.execute(
            "UPDATE tenant_view_state SET view_generation=view_generation+1,resource_generation=resource_generation+1 WHERE tenant_id=%s",
            (tenant_id,),
        )
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {"data": wire(row), "meta": {"revision": "1"}},
            201,
            resources=[(tenant_id, "incident", row["id"])],
        )


def mutate(tenant, incident_id, body, request, operation):
    catalog = request_catalog(request, tenant)
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
        scope = f"{tenant}:{actor['id']}:incident-{operation}"
        result, fp = command_result(
            conn, scope, body.command_id, {"target": incident_id, **body.model_dump()}
        )
        if result is not None:
            return result
        _, now = coordinator(conn, tenant)
        lock_contexts(conn, tenant)
        lock_catalog(conn, catalog)
        row = get_incident(conn, tenant, incident_id, True)
        revision(row, body.expected_revision)
        changed = False
        evidence = body.model_dump(exclude={"command_id", "expected_revision"})
        if operation in ("link", "unlink"):
            changed = bool(
                link_set(
                    conn,
                    tenant,
                    row,
                    body.alert_ids,
                    now,
                    actor["id"],
                    unlink=operation == "unlink",
                    catalog=catalog,
                )
            )
        elif operation == "status" and row["status"] != body.status:
            ids = [
                str(link["alert_id"])
                for link in conn.execute(
                    "SELECT alert_id FROM incident_alert_links WHERE tenant_id=%s AND incident_id=%s AND unlinked_at IS NULL ORDER BY alert_id",
                    (tenant, incident_id),
                )
            ]
            alerts = {
                key: retained(conn, tenant, key, True)
                for key in ids
                if conn.execute(
                    "SELECT 1 FROM alert_identities WHERE tenant_id=%s AND id=%s AND retired_at IS NULL",
                    (tenant, key),
                ).fetchone()
            }
            for key, alert in alerts.items():
                pending(conn, tenant, alert)
            if row["status"] == "resolved":
                for key in alerts:
                    owner = conn.execute(
                        "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
                        (tenant, key),
                    ).fetchone()
                    if owner:
                        raise AppError(
                            "ownership_conflict", "A retained alert has another active owner.", 409
                        )
                reopen_context(conn, row)
                cycle = uuid4()
                conn.execute(
                    "INSERT INTO incident_cycles(tenant_id,incident_id,id,opened_at) VALUES(%s,%s,%s,%s)",
                    (tenant, incident_id, cycle, now),
                )
                conn.execute(
                    "UPDATE incidents SET cycle_id=%s,resolved_at=NULL,retention_at=NULL,last_activity=%s WHERE tenant_id=%s AND id=%s",
                    (cycle, now, tenant, incident_id),
                )
                for key in alerts:
                    conn.execute(
                        "INSERT INTO alert_active_ownership(tenant_id,alert_id,incident_id) VALUES(%s,%s,%s)",
                        (tenant, key, incident_id),
                    )
            if body.status == "resolved":
                resolve_context(conn, row, now)
                conn.execute(
                    "UPDATE incident_cycles SET resolved_at=%s,cause='manual' WHERE incident_id=%s AND id=%s",
                    (now, incident_id, row["cycle_id"]),
                )
                conn.execute(
                    "UPDATE incidents SET resolved_at=%s,retention_at=%s WHERE tenant_id=%s AND id=%s",
                    (now, now + timedelta(days=90), tenant, incident_id),
                )
                conn.execute(
                    "DELETE FROM alert_active_ownership WHERE tenant_id=%s AND incident_id=%s",
                    (tenant, incident_id),
                )
                for key in alerts:
                    boundary(conn, tenant, key, now)
            conn.execute(
                "UPDATE incidents SET status=%s WHERE tenant_id=%s AND id=%s",
                (body.status, tenant, incident_id),
            )
            if body.status == "investigating":
                conn.execute(
                    "UPDATE incident_cycles SET investigating_at=coalesce(investigating_at,%s) WHERE incident_id=%s AND id=(SELECT cycle_id FROM incidents WHERE id=%s)",
                    (now, incident_id, incident_id),
                )
            for alert in alerts.values():
                alert_link_change(conn, alert, now, actor["id"], "incident-status", catalog)
            changed = True
        elif operation == "assignment":
            assignee(conn, tenant, body.assignee_id)
            changed = (str(row["assignee_id"]) if row["assignee_id"] else None) != body.assignee_id
            if changed:
                conn.execute(
                    "UPDATE incidents SET assignee_id=%s WHERE tenant_id=%s AND id=%s",
                    (body.assignee_id, tenant, incident_id),
                )
        elif operation == "content":
            changed = row["title"] != body.title or row["description"] != body.description
            if changed:
                conn.execute(
                    "UPDATE incidents SET title=%s,description=%s WHERE tenant_id=%s AND id=%s",
                    (body.title, body.description, tenant, incident_id),
                )
                update_tokens(conn, tenant, incident_id)
        if changed:
            activity(conn, row, now, actor["id"], operation, evidence)
        result = get_incident(conn, tenant, incident_id)
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {"data": wire(result), "meta": {"revision": str(result["revision"])}},
            resources=[(tenant, "incident", incident_id)],
        )


@router.post("/{incident_id}/status")
def status(tenant_id: str, incident_id: str, body: IncidentStatus, request: Request):
    return mutate(tenant_id, incident_id, body, request, "status")


@router.post("/{incident_id}/assignment")
def assignment(tenant_id: str, incident_id: str, body: IncidentAssignment, request: Request):
    return mutate(tenant_id, incident_id, body, request, "assignment")


@router.patch("/{incident_id}")
def content(tenant_id: str, incident_id: str, body: IncidentContent, request: Request):
    return mutate(tenant_id, incident_id, body, request, "content")


@router.post("/{incident_id}/alerts/link")
def link(tenant_id: str, incident_id: str, body: IncidentLinks, request: Request):
    return mutate(tenant_id, incident_id, body, request, "link")


@router.post("/{incident_id}/alerts/unlink")
def unlink(tenant_id: str, incident_id: str, body: IncidentLinks, request: Request):
    return mutate(tenant_id, incident_id, body, request, "unlink")


@router.get("", responses=documented(IncidentPage))
def listing(
    tenant_id: str,
    request: Request,
    view: Literal["active", "resolved", "all"] = "active",
    q: str = "",
    limit: int = 50,
    cursor: str | None = None,
    status: Literal["open", "investigating", "resolved"] | None = None,
    severity: Literal["critical", "high", "medium", "low"] | None = None,
    assignee: str | None = None,
    origin: Literal["manual", "correlation"] | None = None,
    rule_id: str | None = None,
    alert_id: str | None = None,
    incident_id: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    activity_from: datetime | None = None,
    activity_to: datetime | None = None,
    resolved_from: datetime | None = None,
    resolved_to: datetime | None = None,
    sort: Literal["created_at", "last_activity", "severity", "resolved_at"] = "last_activity",
    direction: Literal["asc", "desc"] = "desc",
):
    from appchi.incidents.listing import list_incidents

    if not 1 <= limit <= 200 or len(q) > 256:
        raise AppError("invalid_query", "Invalid incident query.")
    terms = tokens(q)
    if q.strip() and not terms:
        raise AppError("invalid_query", "Search requires text tokens.")
    return list_incidents(
        request,
        tenant_id,
        terms=terms,
        limit=limit,
        cursor=cursor,
        view=view,
        status=status,
        severity=severity,
        assignee=assignee,
        origin=origin,
        rule_id=rule_id,
        alert_id=alert_id,
        incident_id=incident_id,
        created_from=created_from,
        created_to=created_to,
        activity_from=activity_from,
        activity_to=activity_to,
        resolved_from=resolved_from,
        resolved_to=resolved_to,
        sort=sort,
        direction=direction,
    )


@router.get("/{incident_id}", responses=documented(IncidentRead))
def detail(tenant_id: str, incident_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        authorize(conn, request, tenant_id)
        row = get_incident(conn, tenant_id, incident_id)
        from appchi.identity.cleanup import visible_assignee

        row["assignee_id"], row["assignment_cleanup_pending"] = visible_assignee(
            conn, tenant_id, row["assignee_id"]
        )
        from appchi.incidents.counts import linked_counts

        counts = linked_counts(conn, tenant_id, incident_id)
        (data,) = enrich_incidents(conn, tenant_id, [wire({**row, **counts})])
        return {"data": data, "meta": {"revision": str(row["revision"])}}


def lock_linked_incidents(conn, tenant, alert_id):
    lock_contexts(conn, tenant)
    return conn.execute(
        "SELECT i.* FROM incidents i JOIN incident_alert_links l ON l.tenant_id=i.tenant_id AND l.incident_id=i.id WHERE l.tenant_id=%s AND l.alert_id=%s AND l.unlinked_at IS NULL AND i.status<>'resolved' ORDER BY i.id FOR UPDATE OF i",
        (tenant, alert_id),
    ).fetchall()


def linked_transition(conn, incidents, before, after, effective_at):
    if before is None or before["status"] == after["status"]:
        return
    for incident in incidents:
        activity(
            conn,
            incident,
            effective_at,
            None,
            "linked-alert-status",
            {"alert_id": after["id"], "before": before["status"], "after": after["status"]},
        )


@router.post("/move-alerts")
def move(tenant_id: str, body: IncidentMove, request: Request):
    catalog = request_catalog(request, tenant_id)
    if body.source_id == body.destination_id:
        raise AppError("invalid_destination", "Choose a different destination.")
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:incident-move"
        result, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if result is not None:
            return result
        _, now = coordinator(conn, tenant_id)
        lock_contexts(conn, tenant_id)
        lock_catalog(conn, catalog)
        rows = {
            key: get_incident(conn, tenant_id, key, True)
            for key in sorted([body.source_id, body.destination_id])
        }
        source, destination = rows[body.source_id], rows[body.destination_id]
        revision(source, body.source_revision)
        revision(destination, body.destination_revision)
        if source["status"] == "resolved" or destination["status"] == "resolved":
            raise AppError("incident_resolved", "Both incidents must be active.", 409)
        alerts = {key: retained(conn, tenant_id, key, True) for key in sorted(body.alert_ids)}
        for key, row in alerts.items():
            pending(conn, tenant_id, row)
            owner = conn.execute(
                "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
                (tenant_id, key),
            ).fetchone()
            if not owner or str(owner["incident_id"]) != body.source_id:
                raise AppError(
                    "ownership_conflict", "Selection must belong to the source incident.", 409
                )
        for key, row in alerts.items():
            conn.execute(
                "UPDATE incident_alert_links SET unlinked_at=%s WHERE tenant_id=%s AND incident_id=%s AND alert_id=%s",
                (now, tenant_id, body.source_id, key),
            )
            conn.execute(
                "INSERT INTO incident_alert_links(tenant_id,incident_id,alert_id,linked_at) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant_id,incident_id,alert_id) DO UPDATE SET linked_at=EXCLUDED.linked_at,unlinked_at=NULL",
                (tenant_id, body.destination_id, key, now),
            )
            conn.execute(
                "UPDATE alert_active_ownership SET incident_id=%s WHERE tenant_id=%s AND alert_id=%s",
                (body.destination_id, tenant_id, key),
            )
            boundary(conn, tenant_id, key, now)
            alert_link_change(conn, row, now, actor["id"], "incident-move", catalog)
        for incident in (source, destination):
            activity(
                conn, incident, now, actor["id"], "move", body.model_dump(exclude={"command_id"})
            )
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {
                "data": {
                    "source": wire(get_incident(conn, tenant_id, body.source_id)),
                    "destination": wire(get_incident(conn, tenant_id, body.destination_id)),
                },
                "meta": {},
            },
            resources=[
                (tenant_id, "incident", body.source_id),
                (tenant_id, "incident", body.destination_id),
            ],
        )
