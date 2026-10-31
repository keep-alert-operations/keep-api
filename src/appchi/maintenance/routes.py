from dataclasses import asdict
from datetime import datetime
import hashlib
from uuid import UUID, uuid4

from fastapi import APIRouter, Request, Response
from psycopg import sql
from psycopg.types.json import Jsonb

from appchi.access import authorize
from appchi.cel import CELUnavailableError, CELValidationError, compile_expression
from appchi.models import Command, uuid_string
from appchi.recovery.evidence import Evidence, append_verified
from appchi.shared.cursors import Cursor
from appchi.shared.display_names import ActorPage, ActorRead, documented, enrich_actors
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import command_result, coordinator, revision, save_result
from appchi.serialization import wire

from . import repository as repo
from .models import Create, Definition, Edit, SavedTest, Test
from .timezones import PINNED_TZDATA_VERSION, ScheduleError, supported_zones, zone

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["maintenance"])


def compiled(source):
    try:
        return compile_expression(source, rule=True)
    except CELValidationError:
        raise AppError("invalid_cel", "Maintenance CEL is invalid.", 422) from None
    except CELUnavailableError:
        raise unavailable("cel_compilation_unavailable") from None


def ids(*values):
    for value in values:
        try:
            uuid_string(value)
        except (ValueError, TypeError):
            raise AppError("not_found", "Resource unavailable.", 404) from None


def _preflight(request, tenant, window=None, body=None):
    ids(tenant, *([window] if window else []))
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant, "edit", mutation=True)
        previous = repo.get_window(conn, tenant, window) if window else None
    source = getattr(body, "cel", None) or (previous["cel"] if previous else None)
    return compiled(source)


def _save(request, tenant, body, window=None, enabled=None):
    program = _preflight(request, tenant, window, body)
    payload = body.model_dump()
    operation = (
        "create"
        if window is None
        else "enable"
        if enabled is True
        else "disable"
        if enabled is False
        else "edit"
    )
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant, "edit", mutation=True)
        scope = f"{tenant}:{actor['id']}:maintenance:{window or 'create'}:{operation}"
        prior, fp = command_result(conn, scope, body.command_id, payload)
        if prior is not None:
            return prior
        _, now = coordinator(conn, tenant)
        previous = repo.get_window(conn, tenant, window, lock=True) if window else None
        if previous:
            revision(previous, body.expected_revision)
        if enabled is not None:
            definition = {
                key: previous[key]
                for key in (
                    "name",
                    "reason",
                    "cel",
                    "timezone",
                    "start_at",
                    "end_at",
                    "schedule_evidence",
                )
            }
        else:
            definition = repo.candidate(body, now, previous)
        # The initially compiled source belongs to the submitted revision. A
        # concurrent edit fails expected_revision before its program is used.
        if program.source != definition["cel"]:
            raise AppError("revision_conflict", "Refresh the maintenance definition.", 409)
        reserves = (
            previous is None
            or definition["start_at"] != previous["start_at"]
            or definition["end_at"] > previous["end_at"]
            or definition["cel"] != previous["cel"]
            or enabled is True
            and not previous["enabled"]
        )
        if reserves:
            repo.check_capacity(
                conn, tenant, definition, getattr(request.app.state, "profile", None), now, window
            )
        row, _ = repo.persist(
            conn,
            tenant,
            actor,
            now,
            definition,
            program,
            previous=previous,
            enabled=enabled,
            action=operation,
            profile=getattr(request.app.state, "profile", None),
        )
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {"data": repo.public(row, now), "meta": {"revision": str(row["revision"])}},
            201 if previous is None else 200,
        )


@router.post("/maintenance", status_code=201)
def create(tenant_id: str, body: Create, request: Request, response: Response):
    result = _save(request, tenant_id, body)
    response.headers["ETag"] = '"' + result["meta"]["revision"] + '"'
    return result


@router.patch("/maintenance/{window_id}")
def update(tenant_id: str, window_id: str, body: Edit, request: Request, response: Response):
    result = _save(request, tenant_id, body, window_id)
    response.headers["ETag"] = '"' + result["meta"]["revision"] + '"'
    return result


@router.post("/maintenance/{window_id}/enable")
def enable(tenant_id: str, window_id: str, body: Command, request: Request):
    return _save(request, tenant_id, body, window_id, True)


@router.post("/maintenance/{window_id}/disable")
def disable(tenant_id: str, window_id: str, body: Command, request: Request):
    return _save(request, tenant_id, body, window_id, False)


@router.post("/maintenance/validate")
def validate(tenant_id: str, body: Definition, request: Request):
    ids(tenant_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
    failure = None
    try:
        program = compiled(body.cel)
    except AppError as exc:
        failure = exc
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if failure:
            return _validation_failure(failure)
        try:
            definition = repo.candidate(body, now)
        except AppError as exc:
            return _validation_failure(exc)
        return {"data": _validated_schedule(definition, program.profile), "meta": {}}


def _validation_failure(error):
    if error.status not in (409, 422):
        raise error
    return {
        "data": {
            "valid": False,
            "diagnostics": [{"code": error.code, "message": error.message, "fields": error.fields}],
        },
        "meta": {},
    }


def _validated_schedule(definition, profile):
    return {
        "valid": True,
        "profile": profile,
        "schedule": wire(definition["schedule_evidence"]),
        "start_at": wire(definition["start_at"]),
        "end_at": wire(definition["end_at"]),
        "start_display": wire(
            repo.render_endpoint(
                repo.endpoint(definition["schedule_evidence"]["start"]), definition["timezone"]
            )
        ),
        "end_display": wire(
            repo.render_endpoint(
                repo.endpoint(definition["schedule_evidence"]["end"]), definition["timezone"]
            )
        ),
    }


@router.post("/maintenance/{window_id}/validate")
def validate_edit(tenant_id: str, window_id: str, body: Edit, request: Request):
    """Preview the submitted tagged edit without receipts, controls or reservations."""
    ids(tenant_id, window_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        previous = repo.get_window(conn, tenant_id, window_id)
        revision(previous, body.expected_revision)
    failure = None
    try:
        program = compiled(getattr(body, "cel", None) or previous["cel"])
    except AppError as exc:
        failure = exc
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        current = repo.get_window(conn, tenant_id, window_id)
        revision(current, body.expected_revision)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if failure:
            return _validation_failure(failure)
        try:
            definition = repo.candidate(body, now, current)
            candidate_state = repo.change_window(
                repo.state(current),
                action_time=now,
                start=definition["start_at"],
                end=definition["end_at"],
                cel_digest=hashlib.sha256(definition["cel"].encode()).hexdigest(),
            )
        except repo.MaintenanceConflict as exc:
            return _validation_failure(
                AppError(
                    exc.code, "The maintenance schedule can no longer be changed this way.", 409
                )
            )
        except AppError as exc:
            return _validation_failure(exc)
        return {
            "data": {
                **_validated_schedule(definition, program.profile),
                "phase": candidate_state.phase(now),
                "started_lock": candidate_state.started_lock,
            },
            "meta": {"revision": str(current["revision"])},
        }


@router.post("/maintenance/test")
def test(tenant_id: str, body: Test, request: Request):
    from appchi.alerts.state import retained, with_current_assignee

    ids(tenant_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        retained(conn, tenant_id, body.alert_id)
    program = compiled(body.cel)
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        authorize(conn, request, tenant_id, mutation=True)
        snapshot = with_current_assignee(conn, retained(conn, tenant_id, body.alert_id))
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        definition = repo.candidate(body, now)
        try:
            fields = {
                key: str(value) if isinstance(value, UUID) else value
                for key, value in snapshot.items()
            }
            matches = program.evaluate(fields, now)
        except (CELValidationError, CELUnavailableError):
            raise unavailable("maintenance_evaluation_unavailable") from None
        return {
            "data": {
                "matches": matches,
                "covers_selected_time": definition["start_at"] <= now < definition["end_at"],
                "firing": snapshot["status"] == "firing",
                "qualification_proven": False,
                "explanation": "A current match is not proof of a new qualifying transition. Activation never backfills alerts.",
            },
            "meta": {},
        }


@router.get("/timezones")
def timezones(tenant_id: str, request: Request):
    ids(tenant_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    try:
        values = [
            {
                "id": key,
                "offset_seconds": int(now.astimezone(zone(key)).utcoffset().total_seconds()),
            }
            for key in supported_zones()
        ]
    except ScheduleError:
        raise unavailable("timezone_data_unavailable") from None
    return {"data": values, "meta": {"tzdata_version": PINNED_TZDATA_VERSION, "as_of": wire(now)}}


@router.post("/maintenance/{window_id}/test")
def test_saved(tenant_id: str, window_id: str, body: SavedTest, request: Request):
    """Evaluate persisted UTC endpoints, including ended windows, without rescheduling."""
    from appchi.alerts.state import retained, with_current_assignee

    ids(tenant_id, window_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        previous = repo.get_window(conn, tenant_id, window_id)
        revision(previous, body.expected_revision)
        retained(conn, tenant_id, body.alert_id)
    program = compiled(previous["cel"])
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        authorize(conn, request, tenant_id, mutation=True)
        current = repo.get_window(conn, tenant_id, window_id)
        revision(current, body.expected_revision)
        snapshot = with_current_assignee(conn, retained(conn, tenant_id, body.alert_id))
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        try:
            fields = {
                key: str(value) if isinstance(value, UUID) else value
                for key, value in snapshot.items()
            }
            matches = program.evaluate(fields, now)
        except (CELValidationError, CELUnavailableError):
            raise unavailable("maintenance_evaluation_unavailable") from None
        return {
            "data": {
                "matches": matches,
                "covers_selected_time": current["start_at"] <= now < current["end_at"],
                "firing": snapshot["status"] == "firing",
                "enabled": current["enabled"],
                "qualification_proven": False,
                "explanation": "A current match is not proof of a new qualifying transition. Activation never backfills alerts.",
            },
            "meta": {
                "revision": str(current["revision"]),
                "alert_revision": str(snapshot["revision"]),
                "as_of": wire(now),
            },
        }


def _retained(row, conn):
    from appchi.maintenance.retention import history_retained

    if not history_retained(conn, row):
        raise AppError("not_found", "Maintenance history unavailable.", 404)


@router.get("/maintenance", responses=documented(ActorPage))
def listing(
    tenant_id: str,
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
    name: str = "",
    phase: str = "current",
    enabled: bool | None = None,
    sort: str = "start",
    direction: str = "asc",
    overlap_start: datetime | None = None,
    overlap_end: datetime | None = None,
):
    ids(tenant_id)
    if (
        not 1 <= limit <= 200
        or len(name) > 128
        or phase not in ("current", "scheduled", "active", "ended", "deleted", "all")
        or sort not in ("start", "end", "name", "updated_at")
        or direction not in ("asc", "desc")
    ):
        raise AppError("invalid_query", "Invalid maintenance list query.")
    if (
        (overlap_start is None) != (overlap_end is None)
        or overlap_start
        and (
            overlap_start.tzinfo is None
            or overlap_end.tzinfo is None
            or overlap_end <= overlap_start
        )
    ):
        raise AppError("invalid_query", "Supply an increasing aware schedule-overlap interval.")
    with request.app.state.db.transaction() as conn:
        _, session, _ = authorize(conn, request, tenant_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        column = {
            "start": "start_at",
            "end": "end_at",
            "name": "name_key",
            "updated_at": "updated_at",
        }[sort]
        context = wire(
            {
                "tenant": tenant_id,
                "session": bytes(session["handle_hash"]).hex(),
                "view": "maintenance-list",
                "name": name,
                "phase": phase,
                "enabled": enabled,
                "sort": sort,
                "direction": direction,
                "overlap_start": overlap_start,
                "overlap_end": overlap_end,
                "epoch": request.app.state.settings.deployment_epoch,
            }
        )
        codec = Cursor(request.app.state.settings.cipher(), context, now)
        clauses = ["tenant_id=%s", "strpos(name_key,%s)>0"]
        params = [tenant_id, name.casefold()]
        if phase == "deleted":
            clauses.append("deleted_at IS NOT NULL")
        elif phase != "all":
            clauses.append("deleted_at IS NULL")
        if phase in ("current", "active", "scheduled"):
            clauses.append("end_at>%s")
            params.append(now)
        if phase == "active":
            clauses.append("start_at<=%s")
            params.append(now)
        if phase == "scheduled":
            clauses.append("start_at>%s")
            params.append(now)
        if phase == "ended":
            clauses.append("end_at<=%s")
            params.append(now)
        if enabled is not None:
            clauses.append("enabled=%s")
            params.append(enabled)
        if overlap_start:
            clauses.append("start_at<%s AND end_at>%s")
            params.extend((overlap_end, overlap_start))
        from appchi.maintenance.retention import RETAINED_SQL

        clauses.append(RETAINED_SQL)
        if cursor:
            position = codec.decode(cursor)["position"]
            clauses.append(f"({column},id){'>' if direction == 'asc' else '<'}(%s,%s)")
            params.extend((position["value"], position["id"]))
        query = sql.SQL(
            "SELECT * FROM maintenance_windows w WHERE "
            + " AND ".join(clauses)
            + f" ORDER BY {column} {direction},id {direction} LIMIT %s"
        )
        rows = conn.execute(query, (*params, limit + 1)).fetchall()
        next_cursor = (
            codec.encode({"value": rows[limit - 1][column], "id": rows[limit - 1]["id"]})
            if len(rows) > limit
            else None
        )
        return {
            # Public rows omit actor ids; names come from the stored row's ids.
            "data": enrich_actors(
                conn, [repo.public(row, now) for row in rows[:limit]], rows[:limit]
            ),
            "meta": {},
            "next_cursor": next_cursor,
        }


@router.get("/maintenance/{window_id}", responses=documented(ActorRead))
def detail(tenant_id: str, window_id: str, request: Request, response: Response):
    ids(tenant_id, window_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        row = repo.get_window(conn, tenant_id, window_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        (data,) = enrich_actors(conn, [repo.public(row, now)], [row])
        data["current_causes_count"] = str(
            conn.execute(
                """SELECT count(DISTINCT c.alert_id) AS n FROM alert_maintenance_causes c JOIN maintenance_segments s ON s.tenant_id=c.tenant_id AND s.id=c.segment_id
                    WHERE c.tenant_id=%s AND c.window_id=%s AND c.opened_at<=%s AND (c.closed_at IS NULL OR c.closed_at>%s)
                    """,
                (tenant_id, window_id, now, now),
            ).fetchone()["n"]
        )
        response.headers["ETag"] = '"' + str(row["revision"]) + '"'
        return {"data": data, "meta": {"revision": str(row["revision"])}}


@router.get("/maintenance/{window_id}/history")
def history(
    tenant_id: str, window_id: str, request: Request, limit: int = 50, cursor: str | None = None
):
    ids(tenant_id, window_id)
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Invalid page size.")
    with request.app.state.db.transaction() as conn:
        _, session, _ = authorize(conn, request, tenant_id)
        row = repo.get_window(conn, tenant_id, window_id, include_deleted=True)
        _retained(row, conn)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "window": window_id,
                "session": bytes(session["handle_hash"]).hex(),
                "view": "maintenance-history",
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        prior = codec.decode(cursor) if cursor else None
        upper = prior["upper"] if prior else row["revision"]
        last = prior["position"] if prior else int(upper) + 1
        rows = conn.execute(
            "SELECT * FROM maintenance_revisions WHERE tenant_id=%s AND window_id=%s AND revision<=%s AND revision<%s ORDER BY revision DESC LIMIT %s",
            (tenant_id, window_id, upper, last, limit + 1),
        ).fetchall()
        next_cursor = (
            codec.encode(rows[limit - 1]["revision"], upper=upper) if len(rows) > limit else None
        )
        return {"data": wire(rows[:limit]), "meta": {}, "next_cursor": next_cursor}


@router.get("/maintenance/{window_id}/history/{version}")
def history_detail(tenant_id: str, window_id: str, version: int, request: Request):
    ids(tenant_id, window_id)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        row = repo.get_window(conn, tenant_id, window_id, include_deleted=True)
        _retained(row, conn)
        record = conn.execute(
            "SELECT * FROM maintenance_revisions WHERE tenant_id=%s AND window_id=%s AND revision=%s",
            (tenant_id, window_id, version),
        ).fetchone()
        if not record:
            raise AppError("not_found", "Maintenance revision unavailable.", 404)
        return {"data": wire(record), "meta": {}}


@router.get("/maintenance/{window_id}/alerts")
def affected_alerts(
    tenant_id: str,
    window_id: str,
    request: Request,
    historical: bool = False,
    limit: int = 50,
    cursor: str | None = None,
):
    ids(tenant_id, window_id)
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Invalid page size.")
    with request.app.state.db.transaction() as conn:
        _, session, _ = authorize(conn, request, tenant_id)
        row = repo.get_window(conn, tenant_id, window_id, include_deleted=historical)
        if historical:
            _retained(row, conn)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "window": window_id,
                "view": "maintenance-alerts",
                "session": bytes(session["handle_hash"]).hex(),
                "historical": historical,
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        params = [tenant_id, window_id]
        clauses = ["c.tenant_id=%s", "c.window_id=%s"]
        if not historical:
            clauses.extend(
                [
                    "c.opened_at<=%s",
                    "(c.closed_at IS NULL OR c.closed_at>%s)",
                ]
            )
            params.extend((now, now))
        if cursor:
            clauses.append("c.alert_id>%s")
            params.append(codec.decode(cursor)["position"])
        rows = conn.execute(
            """SELECT DISTINCT c.alert_id,a.tenant_id,a.schema_version,a.key_field,a.name,a.message,a.status,a.severity,a.assignee_id,(a.id IS NULL) AS unavailable
             FROM alert_maintenance_causes c JOIN maintenance_segments s ON s.tenant_id=c.tenant_id AND s.id=c.segment_id
             LEFT JOIN alert_identities i ON i.tenant_id=c.tenant_id AND i.id=c.alert_id AND i.retired_at IS NULL
             LEFT JOIN alerts a ON a.tenant_id=i.tenant_id AND a.id=i.id WHERE """
            + " AND ".join(clauses)
            + " ORDER BY c.alert_id LIMIT %s",
            (*params, limit + 1),
        ).fetchall()
        next_cursor = codec.encode(rows[limit - 1]["alert_id"]) if len(rows) > limit else None
        from appchi.alerts.state import with_current_assignee
        from appchi.alerts.presentation import present_alert

        return {
            "data": wire(
                [
                    present_alert(
                        with_current_assignee(conn, row) if not row["unavailable"] else row
                    )
                    for row in rows[:limit]
                ]
            ),
            "meta": {"coverage": "historical" if historical else "current"},
            "next_cursor": next_cursor,
        }


def _delete_payload(request):
    key = request.headers.get("idempotency-key", "")
    expected = request.headers.get("if-match", "")
    try:
        uuid_string(key)
        if len(expected) < 3 or expected[0] != '"' or expected[-1] != '"':
            raise ValueError()
        body = Command(command_id=key, expected_revision=expected[1:-1])
    except (ValueError, TypeError):
        raise AppError(
            "invalid_precondition", "A command UUID and quoted revision are required."
        ) from None
    return body


def resume_delete(database, store, tenant_id, job_id, program, *, profile=None):
    """Resume an authorized durable deletion; no remote call holds SQL locks."""
    with database.transaction(tenant_id) as conn:
        job = conn.execute(
            "SELECT * FROM maintenance_delete_jobs WHERE tenant_id=%s AND id=%s",
            (tenant_id, job_id),
        ).fetchone()
    if not job:
        raise AppError("not_found", "Deletion operation unavailable.", 404)

    def evidence(kind):
        return Evidence(
            str(job[kind + "_id"]),
            str(job["tenant_id"]),
            "maintenance",
            str(job["window_id"]),
            job["expected_revision"] + 1,
            kind,
            job["digest"],
        )

    if job["state"] == "prepared":
        ack = append_verified(store, evidence("intent"))
        with database.transaction(job["tenant_id"]) as conn:
            conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
            _, now = coordinator(conn, job["tenant_id"])
            job = conn.execute(
                "SELECT * FROM maintenance_delete_jobs WHERE id=%s FOR UPDATE", (job_id,)
            ).fetchone()
            row = repo.get_window(
                conn, job["tenant_id"], job["window_id"], lock=True, include_deleted=True
            )
            if job["state"] == "prepared":
                from appchi.access import ROLE_RANK, effective_role

                principal = conn.execute(
                    "SELECT * FROM principals WHERE id=%s", (job["actor_id"],)
                ).fetchone()
                authorized = bool(
                    principal
                    and principal["kind"] == "user"
                    and principal["verified_at"] is not None
                    and principal["evidence_generation"] > 0
                    and ROLE_RANK.get(effective_role(conn, principal, job["tenant_id"]), 0) >= 2
                )
                gates = conn.execute(
                    "SELECT capability,ready FROM capability_gates WHERE capability IN ('recovery','human_auth') FOR SHARE"
                ).fetchall()
                if len(gates) != 2 or not all(gate["ready"] for gate in gates):
                    raise unavailable("maintenance_deletion_protection_unready")
                if (
                    not authorized
                    or row["revision"] != job["expected_revision"]
                    or row["deleted_at"]
                ):
                    conn.execute(
                        "UPDATE maintenance_delete_jobs SET state='cancelled',intent_ack=%s,updated_at=%s WHERE id=%s",
                        (Jsonb(asdict(ack)), now, job_id),
                    )
                    job["state"] = "cancelled"
                else:
                    definition = {
                        key: row[key]
                        for key in (
                            "name",
                            "reason",
                            "cel",
                            "timezone",
                            "start_at",
                            "end_at",
                            "schedule_evidence",
                        )
                    }
                    deleted, _ = repo.persist(
                        conn,
                        job["tenant_id"],
                        {"id": job["actor_id"], "display_name": job["actor_label"]},
                        now,
                        definition,
                        program,
                        previous=row,
                        deleted=True,
                        action="delete",
                        profile=profile,
                    )
                    receipt = {
                        "data": {
                            "id": str(deleted["id"]),
                            "deleted": True,
                            "revision": str(deleted["revision"]),
                            "refresh_pending": True,
                        },
                        "meta": {"revision": str(deleted["revision"])},
                    }
                    conn.execute(
                        "UPDATE maintenance_delete_jobs SET state='deleted',intent_ack=%s,receipt=%s,updated_at=%s WHERE id=%s",
                        (Jsonb(asdict(ack)), Jsonb(receipt), now, job_id),
                    )
                    job["state"], job["receipt"] = "deleted", receipt
    if job["state"] == "cancelled":
        ack = append_verified(store, evidence("cancel"))
        with database.transaction(job["tenant_id"]) as conn:
            conn.execute(
                "UPDATE maintenance_delete_jobs SET cancel_ack=%s,updated_at=clock_timestamp() WHERE id=%s",
                (Jsonb(asdict(ack)), job_id),
            )
        raise AppError(
            "revision_conflict", "Maintenance changed before protected deletion committed.", 409
        )
    if job["state"] == "deleted":
        ack = append_verified(store, evidence("final"))
        with database.transaction(job["tenant_id"]) as conn:
            conn.execute("SELECT id FROM maintenance_delete_jobs WHERE id=%s FOR UPDATE", (job_id,))
            conn.execute(
                "UPDATE maintenance_delete_jobs SET state='final_protected',final_ack=%s,updated_at=clock_timestamp() WHERE id=%s",
                (Jsonb(asdict(ack)), job_id),
            )
            existing = conn.execute(
                "SELECT 1 FROM command_receipts WHERE scope=%s AND command_id=%s",
                (job["scope"], job["command_id"]),
            ).fetchone()
            if not existing:
                save_result(
                    conn,
                    job["scope"],
                    str(job["command_id"]),
                    bytes(job["fingerprint"]),
                    job["receipt"],
                )
    return job["receipt"]


@router.delete("/maintenance/{window_id}")
def delete(tenant_id: str, window_id: str, request: Request):
    ids(tenant_id, window_id)
    body = _delete_payload(request)
    store = getattr(request.app.state, "recovery_store", None)
    with request.app.state.db.transaction() as conn:
        actor, _, _ = authorize(conn, request, tenant_id, "edit", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:maintenance:{window_id}:delete"
        prior, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if prior is not None:
            return prior
        if store is None:
            raise unavailable("recovery_evidence_required")
        protection = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='recovery'"
        ).fetchone()
        if not protection or not protection["ready"]:
            raise unavailable("recovery_evidence_required")
        _, now = coordinator(conn, tenant_id)
        job = conn.execute(
            "SELECT * FROM maintenance_delete_jobs WHERE scope=%s AND command_id=%s",
            (scope, body.command_id),
        ).fetchone()
        if job:
            if bytes(job["fingerprint"]) != fp:
                raise AppError(
                    "idempotency_conflict", "Command identity has different content.", 409
                )
            row = repo.get_window(conn, tenant_id, window_id, include_deleted=True)
        else:
            row = repo.get_window(conn, tenant_id, window_id, lock=True)
            revision(row, body.expected_revision)
            digest = hashlib.sha256(
                f"{tenant_id}:{window_id}:{row['revision'] + 1}".encode()
            ).hexdigest()
            job = conn.execute(
                """INSERT INTO maintenance_delete_jobs(id,tenant_id,window_id,scope,command_id,fingerprint,expected_revision,actor_id,actor_label,
                intent_id,final_id,cancel_id,digest,state,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'prepared',%s,%s) RETURNING *""",
                (
                    uuid4(),
                    tenant_id,
                    window_id,
                    scope,
                    body.command_id,
                    fp,
                    row["revision"],
                    actor["id"],
                    actor["display_name"],
                    uuid4(),
                    uuid4(),
                    uuid4(),
                    digest,
                    now,
                    now,
                ),
            ).fetchone()
    program = compiled(row["cel"])
    result = resume_delete(
        request.app.state.db,
        store,
        tenant_id,
        job["id"],
        program,
        profile=getattr(request.app.state, "profile", None),
    )
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, "edit", mutation=True)
    return result
