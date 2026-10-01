"""Tenant-authorized rule configuration, history and read-only diagnostics."""

import json
from uuid import UUID

from fastapi import APIRouter, Request, Response
from psycopg import sql

from appchi.access import authorize
from appchi.alerts.routes import retained, derived_read
from appchi.cel import CELUnavailableError, CELValidationError
from appchi.cel.compiler import COST_MODEL, PROFILE
from appchi.models import Command
from appchi.shared.cursors import Cursor
from appchi.shared.display_names import (
    ActorPage,
    ActorRead,
    documented,
    enrich_actors,
)
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import command_result, coordinator, revision, save_result, wire
from . import repository as repo
from .cleanup import deleted_definitions, history_parent, retained_revisions, warm_history_names
from .evidence import group_key
from .models import Create, Definition, Replace, TestRequest, grouping, name_key

router = APIRouter(prefix="/api/tenants/{tenant_id}/correlation-rules", tags=["correlation"])


def _snapshot(conn, request, tenant, *, mutation=False, minimum="view"):
    actor, session, role = authorize(conn, request, tenant, minimum, mutation=mutation)
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    return actor, session, role, now


def _codec(request, tenant, session, now, view, **filters):
    return Cursor(
        request.app.state.settings.cipher(),
        wire(
            {
                "tenant": tenant,
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
                "view": view,
                **filters,
            }
        ),
        now,
    )


def _paging(limit, cursor):
    if not 1 <= limit <= 200 or cursor is not None and (not cursor or len(cursor) > 65536):
        raise AppError("invalid_query", "Invalid page size or cursor.", 400)


def _save(request, tenant, body, rule_id=None, intent=None):
    operation = (
        "create"
        if rule_id is None
        else "enable"
        if intent is True
        else "disable"
        if intent is False
        else "replace"
    )
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
        scope = f"{tenant}:{actor['id']}:correlation:{rule_id or 'create'}:{operation}"
        prior, _ = command_result(conn, scope, body.command_id, body.model_dump())
        if prior is not None:
            return prior
        previous = repo.get_rule(conn, tenant, rule_id) if rule_id else None
    submitted = (
        body.model_dump(exclude={"command_id", "expected_revision"})
        if intent is None
        else repo.definition(previous)
    )
    programs = None if intent is False else repo.compile_conditions(submitted)
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
        scope = f"{tenant}:{actor['id']}:correlation:{rule_id or 'create'}:{operation}"
        prior, fingerprint = command_result(conn, scope, body.command_id, body.model_dump())
        if prior is not None:
            return prior
        _, now = coordinator(conn, tenant)
        previous = repo.get_rule(conn, tenant, rule_id, lock=True) if rule_id else None
        if previous:
            revision(previous, body.expected_revision)
        if intent is not None:
            submitted = repo.definition(previous)
        enabled = intent if intent is not None else previous["enabled"] if previous else True
        old_logic = (
            {item["id"]: item["cel"] for item in previous["conditions"]} if previous else None
        )
        new_logic = {item["id"]: item["cel"] for item in submitted["conditions"]}
        reservation = (
            previous is None
            or intent is True
            and not previous["enabled"]
            or intent is None
            and (
                old_logic != new_logic
                or submitted["group_by"] != previous["group_by"]
                or submitted["window_minutes"] != previous["window_minutes"]
            )
        )
        if reservation:
            repo.check_capacity(
                conn,
                tenant,
                submitted,
                programs,
                request.app.state.profile,
                rule_id=rule_id,
                enabled=enabled,
                allow_local_preview=request.app.state.settings.environment == "development",
            )
        row, changed, reason = repo.persist(
            conn,
            tenant,
            actor,
            now,
            submitted,
            programs,
            body.command_id,
            previous=previous,
            enabled=intent,
        )
        return save_result(
            conn,
            scope,
            body.command_id,
            fingerprint,
            {
                "data": repo.public(row),
                "meta": {
                    "revision": str(row["revision"]),
                    "reset_reason": reason,
                    "changed": changed,
                },
            },
            201 if previous is None else 200,
        )


@router.post("", status_code=201)
def create(tenant_id: str, body: Create, request: Request, response: Response):
    result = _save(request, tenant_id, body)
    response.headers["ETag"] = '"' + result["meta"]["revision"] + '"'
    return result


@router.put("/{rule_id}")
def replace_rule(tenant_id: str, rule_id: str, body: Replace, request: Request, response: Response):
    result = _save(request, tenant_id, body, rule_id)
    response.headers["ETag"] = '"' + result["meta"]["revision"] + '"'
    return result


@router.post("/{rule_id}/enable")
def enable(tenant_id: str, rule_id: str, body: Command, request: Request, response: Response):
    result = _save(request, tenant_id, body, rule_id, True)
    response.headers["ETag"] = '"' + result["meta"]["revision"] + '"'
    return result


@router.post("/{rule_id}/disable")
def disable(tenant_id: str, rule_id: str, body: Command, request: Request, response: Response):
    result = _save(request, tenant_id, body, rule_id, False)
    response.headers["ETag"] = '"' + result["meta"]["revision"] + '"'
    return result


@router.delete("/{rule_id}")
def delete(tenant_id: str, rule_id: str, request: Request):
    from .deletion import delete_rule

    return delete_rule(request, tenant_id, rule_id)


@router.get("/deletions/{job_id}")
def deletion_operation(tenant_id: str, job_id: str, request: Request):
    from .deletion import operation

    return operation(request, tenant_id, job_id)


@router.post("/validate")
def validate(tenant_id: str, body: Definition, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
    try:
        programs = repo.compile_conditions(body.model_dump())
    except AppError as exc:
        if exc.status != 422:
            raise
        return {"data": {"valid": False, "diagnostics": exc.fields}, "meta": {"profile": PROFILE}}
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
    cost = sum(program.rule_cost_upper_bound for program in programs.values())
    return {
        "data": {
            "valid": True,
            "diagnostics": [],
            "evaluation_cost": str(cost),
            "cost_model": COST_MODEL,
            "capacity_reserved": False,
        },
        "meta": {"profile": PROFILE},
    }


@router.post("/test")
def test_rule(tenant_id: str, body: TestRequest, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        retained(conn, tenant_id, body.alert_id)
    try:
        programs = repo.compile_conditions(body.model_dump(exclude={"alert_id"}))
    except AppError as exc:
        if exc.status != 422:
            raise
        return {
            "data": {"valid": False, "diagnostics": exc.fields, "qualification_proven": False},
            "meta": {"profile": PROFILE},
        }
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        _, _, _, now = _snapshot(conn, request, tenant_id, mutation=True)
        alert = derived_read(conn, retained(conn, tenant_id, body.alert_id))
        owner = conn.execute(
            "SELECT incident_id FROM alert_active_ownership WHERE tenant_id=%s AND alert_id=%s",
            (tenant_id, body.alert_id),
        ).fetchone()
        alert["active_incident_id"] = owner["incident_id"] if owner else None
        fields = {
            key: str(value) if isinstance(value, UUID) else value for key, value in alert.items()
        }
        results = []
        for condition in body.conditions:
            try:
                matched = programs[condition.id].evaluate(fields, now)
                results.append(
                    {
                        "condition_id": condition.id,
                        "label": condition.label,
                        "matches": matched,
                        "error": None,
                    }
                )
            except (CELValidationError, CELUnavailableError):
                results.append(
                    {
                        "condition_id": condition.id,
                        "label": condition.label,
                        "matches": None,
                        "error": "evaluation_failed",
                    }
                )
        typed_group = group_key(grouping(body.group_by), fields)
        exclusions = []
        if alert["status"] != "firing":
            exclusions.append("not_firing")
        if alert["suppressed"]:
            exclusions.append("suppressed")
        if alert.get("active_incident_id"):
            exclusions.append("active_ownership")
        if typed_group is None:
            exclusions.append("invalid_group")
        return {
            "data": {
                "valid": True,
                "conditions": results,
                "group": json.loads(typed_group.canonical) if typed_group else None,
                "eligibility_exclusions": exclusions,
                "qualification_proven": False,
                "explanation": "Matching now does not prove a new transition or a complete real correlation window.",
            },
            "meta": {
                "profile": PROFILE,
                "as_of": wire(now),
                "alert_revision": str(alert["revision"]),
            },
        }


@router.get("", responses=documented(ActorPage))
def listing(
    tenant_id: str,
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
    name: str = "",
    enabled: bool | None = None,
    health: str | None = None,
    state: str = "active",
    sort: str = "arbitration",
):
    _paging(limit, cursor)
    if (
        len(name) > 200
        or health not in (None, "healthy", "delayed", "blocked", "recovery_needed")
        or state not in ("active", "deleted")
        or sort not in ("arbitration", "name")
    ):
        raise AppError("invalid_query", "Invalid correlation list filter.", 400)
    if state == "deleted":
        with request.app.state.db.transaction() as conn:
            _snapshot(conn, request, tenant_id)
            warm_history_names(conn, tenant_id)
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        _, session, _, now = _snapshot(conn, request, tenant_id)
        generation = conn.execute(
            "SELECT resource_generation FROM tenant_view_state WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()["resource_generation"]
        codec = _codec(
            request,
            tenant_id,
            session,
            now,
            "rule-list",
            name=name,
            enabled=enabled,
            health=health,
            state=state,
            sort=sort,
        )
        old = codec.decode(cursor) if cursor else None
        if old and int(old["generation"]) != generation:
            raise AppError("list_changed", "Rules changed; restart pagination.", 409)
        column = "created_at" if sort == "arbitration" else "name_key"
        source = "correlation_rules"
        source_args = []
        if state == "deleted":
            source, source_args = deleted_definitions(tenant_id, now)
            source = "(" + source + ") retained_deleted"
            if (name or sort == "name") and conn.execute(
                "SELECT 1 FROM " + source + " WHERE name_key IS NULL LIMIT 1", source_args
            ).fetchone():
                raise unavailable("correlation_history_name_index_pending")
        clauses, args = (
            [
                "tenant_id=%s",
                "deleted_at IS " + ("NOT NULL" if state == "deleted" else "NULL"),
            ],
            [tenant_id],
        )
        if name:
            clauses.append("strpos(name_key,%s)>0")
            args.append(name_key(name))
        if enabled is not None:
            clauses.append("enabled=%s")
            args.append(enabled)
        if health is not None:
            clauses.append("health=%s")
            args.append(health)
        if old:
            clauses.append(f"({column},id)>(%s,%s)")
            args.extend(old["position"])
        args.append(limit + 1)
        rows = conn.execute(
            sql.SQL(
                "SELECT * FROM "
                + source
                + " WHERE "
                + " AND ".join(clauses)
                + f" ORDER BY {column},id LIMIT %s"
            ),
            [*source_args, *args],
        ).fetchall()
        next_cursor = (
            codec.encode([rows[limit - 1][column], rows[limit - 1]["id"]], generation=generation)
            if len(rows) > limit
            else None
        )
        return {
            "data": enrich_actors(
                conn,
                [
                    {
                        **row["snapshot"],
                        "deleted_at": wire(row["deleted_at"]),
                        "enabled": False,
                        "health": "blocked",
                        "blocked_reason": "deleted",
                        "history_revision": str(row["history_revision"]),
                        "final_revision": str(row["final_revision"]),
                    }
                    if state == "deleted"
                    else repo.public(
                        repo.get_rule(
                            conn, tenant_id, row["id"], include_deleted=state == "deleted"
                        )
                    )
                    for row in rows[:limit]
                ],
            ),
            "meta": {"as_of": wire(now), "arbitration": "created_at_uuid"},
            "next_cursor": next_cursor,
        }


@router.get("/{rule_id}", responses=documented(ActorRead))
def detail(tenant_id: str, rule_id: str, request: Request, response: Response):
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        _, _, _, now = _snapshot(conn, request, tenant_id)
        row = repo.get_rule(conn, tenant_id, rule_id)
        ready = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='correlation'"
        ).fetchone()["ready"]
        response.headers["ETag"] = '"' + str(row["revision"]) + '"'
        (data,) = enrich_actors(conn, [repo.public(row)])
        return {"data": data, "meta": {"processing_ready": ready, "as_of": wire(now)}}


@router.get("/{rule_id}/history")
def history(
    tenant_id: str, rule_id: str, request: Request, limit: int = 50, cursor: str | None = None
):
    _paging(limit, cursor)
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        _, session, _, now = _snapshot(conn, request, tenant_id)
        row = history_parent(conn, tenant_id, rule_id)
        codec = _codec(request, tenant_id, session, now, "rule-history", rule_id=rule_id)
        old = codec.decode(cursor) if cursor else None
        upper, recorded = (int(old["upper"]), old["recorded"]) if old else (row["revision"], now)
        query, args = retained_revisions(conn, row, now)
        query = "SELECT * FROM (" + query + ") retained WHERE revision<=%s AND recorded_at<=%s"
        args += [upper, recorded]
        if old:
            query += " AND (recorded_at,revision)<(%s,%s)"
            args += old["position"]
        args.append(limit + 1)
        rows = conn.execute(
            query + " ORDER BY recorded_at DESC,revision DESC LIMIT %s", args
        ).fetchall()
        if not rows and row["deleted_at"]:
            raise AppError("not_found", "Rule history unavailable.", 404)
        next_cursor = (
            codec.encode(
                [rows[limit - 1]["recorded_at"], rows[limit - 1]["revision"]],
                upper=upper,
                recorded=recorded,
            )
            if len(rows) > limit
            else None
        )
        data = [
            {
                key: value
                for key, value in repo.history_public(item, now).items()
                if key != "definition"
            }
            for item in rows[:limit]
        ]
        return {
            "data": data,
            "meta": {"recorded_through": wire(recorded)},
            "next_cursor": next_cursor,
        }


@router.get("/{rule_id}/history/{revision_number}")
def history_detail(tenant_id: str, rule_id: str, revision_number: str, request: Request):
    try:
        Command.revision(revision_number)
    except ValueError:
        raise AppError("invalid_revision", "Canonical revision required.", 400) from None
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        _, _, _, now = _snapshot(conn, request, tenant_id)
        row = history_parent(conn, tenant_id, rule_id)
        query, args = retained_revisions(conn, row, now)
        historical = conn.execute(
            "SELECT * FROM (" + query + ") retained WHERE revision=%s",
            args + [int(revision_number)],
        ).fetchone()
        if not historical:
            raise AppError("not_found", "Rule revision unavailable.", 404)
        return {"data": repo.history_public(historical, now), "meta": {"revision": revision_number}}


@router.get("/{rule_id}/diagnostics")
def diagnostics(
    tenant_id: str, rule_id: str, request: Request, limit: int = 50, cursor: str | None = None
):
    _paging(limit, cursor)
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        _, session, _, now = _snapshot(conn, request, tenant_id)
        row = repo.get_rule(conn, tenant_id, rule_id)
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='correlation'"
        ).fetchone()["ready"]
        progress = conn.execute(
            "SELECT * FROM correlation_consumer_state WHERE tenant_id=%s", (tenant_id,)
        ).fetchone()
        codec = _codec(
            request,
            tenant_id,
            session,
            now,
            "rule-diagnostics",
            rule_id=rule_id,
            revision=str(row["revision"]),
            checkpoint=str(progress["change_order"]) if progress else None,
        )
        old = codec.decode(cursor) if cursor else None
        query = """SELECT c.id,c.group_key,c.active_incident_id,
            jsonb_object_agg(counts.condition_id,counts.matches) AS conditions
            FROM correlation_contexts c JOIN (
              SELECT e.context_id,e.condition_id,count(*) AS matches FROM correlation_evidence e
              JOIN alert_identities ai ON ai.tenant_id=e.tenant_id AND ai.id=e.alert_id AND ai.retired_at IS NULL
              JOIN alerts a ON a.tenant_id=e.tenant_id AND a.id=e.alert_id AND a.revision=e.observed_revision
              LEFT JOIN alert_active_ownership own ON own.tenant_id=e.tenant_id AND own.alert_id=e.alert_id
              JOIN correlation_contexts ctx ON ctx.tenant_id=e.tenant_id AND ctx.id=e.context_id
              WHERE e.tenant_id=%s AND e.rule_id=%s AND e.epoch=%s AND e.start_at<=%s AND e.expires_at>%s
                AND a.status='firing' AND NOT a.suppressed AND (own.incident_id IS NULL OR own.incident_id=ctx.active_incident_id)
              GROUP BY e.context_id,e.condition_id) counts ON counts.context_id=c.id
            WHERE c.tenant_id=%s AND c.rule_id=%s AND c.grouping_generation=%s"""
        args = [
            tenant_id,
            rule_id,
            row["epoch"],
            now,
            now,
            tenant_id,
            rule_id,
            row["grouping_generation"],
        ]
        if old:
            query += " AND c.id>%s"
            args += old["position"]
        query += " GROUP BY c.id,c.group_key,c.active_incident_id ORDER BY c.id LIMIT %s"
        args.append(limit + 1)
        rows = conn.execute(query, args).fetchall()
        next_cursor = codec.encode([rows[limit - 1]["id"]]) if len(rows) > limit else None
        groups = [
            {
                "context_id": str(item["id"]),
                "group": json.loads(bytes(item["group_key"])),
                "active_incident_id": wire(item["active_incident_id"]),
                "conditions": [
                    {
                        "condition_id": condition["id"],
                        "matches": str(item["conditions"].get(condition["id"], 0)),
                    }
                    for condition in row["conditions"]
                ],
            }
            for item in rows[:limit]
        ]
        return {
            "data": {
                "health": row["health"],
                "enabled": row["enabled"],
                "processing_ready": gate,
                "last_error": row["blocked_reason"],
                "last_reset_reason": row["last_reset_reason"],
                "epoch": str(row["epoch"]),
                "grouping_generation": str(row["grouping_generation"]),
                "consumer": wire(progress),
                "groups": groups,
            },
            "meta": {"as_of": wire(now)},
            "next_cursor": next_cursor,
        }
