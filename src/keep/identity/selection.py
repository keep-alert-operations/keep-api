"""Authorized directory selectors, ADAPI picker search and save on pick (REV-73).

Requirements: REV-73; tenant access 5 and 12; worker scope 4; plan A11, A12, A14,
A19, A22, A26.

Search reads ADAPI (through the Redis search cache) and merges each row's stored
state from PostgreSQL; it never creates a principal, queues a save or grants
authority. Rows Keep has not saved return ``id: null``. Saving happens only
through ``POST .../permission-principals/resolve`` (save on pick), polled with
``GET .../permission-principals/resolve``.
"""

import hashlib
import unicodedata
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from keep.access import authorize
from keep.identity.adapi import SOURCE, InvalidUsername, normalize_username
from keep.identity.authentication import authenticate
from keep.identity.directory import DirectoryUnavailable, PrincipalKey
from keep.identity.saver import (
    HandOver,
    NotInDirectory,
    Unsaved,
    pending_row,
    principal_row,
    usable,
)
from keep.ingestion.native import canonical
from keep.models import StrictModel
from keep.shared.cursors import Cursor
from keep.shared.errors import AppError, unavailable
from keep.serialization import wire

router = APIRouter(tags=["directory"])


def _query(q):
    if (
        not 2 <= len(q) <= 100
        or not q.strip()
        or any(unicodedata.category(char).startswith("C") for char in q)
    ):
        raise AppError("invalid_query", "Search requires 2–100 plain-text code points.")
    return q


def _authority(conn, request, tenant, mode):
    if tenant is None:
        actor, session = authenticate(conn, request)
        if not actor["super_admin"]:
            raise AppError("forbidden", "Global administration is required.", 403)
        return session
    _, session, _ = authorize(conn, request, tenant, "edit" if mode == "assignees" else "admin")
    return session


def _metadata(conn):
    return conn.execute("""SELECT coalesce(max(semantic_revision),0) AS semantic_revision,
        max(completed_at) FILTER(WHERE complete AND coverage->>'accepted'='true') AS last_successful_verification,
        coalesce((SELECT bool_or(NOT latest.complete OR latest.coverage->>'accepted' IS DISTINCT FROM 'true')
        FROM (SELECT DISTINCT ON(source) complete,coverage FROM directory_verifications ORDER BY source,generation DESC) latest),true) AS directory_degraded
        FROM directory_verifications""").fetchone()


def _present(row):
    verification = (
        "unverified"
        if row["verified_at"] is None
        else "membership_pending"
        if row["kind"] == "team" and not row.get("membership_digest")
        else "verified"
    )
    eligible = bool(row["eligible"] and not row["deleted"])
    return {
        key: row[key]
        for key in (
            "id",
            "directory_source",
            "object_id",
            "kind",
            "display_name",
            "deleted",
            "verified_at",
        )
    } | {
        "eligible": eligible,
        "verification": verification,
        "selectable": eligible and verification == "verified",
    }


def _listing(request, tenant, mode, q, limit, cursor, team=None):
    if not 1 <= limit <= 200:
        raise AppError("invalid_query", "Page size must be between 1 and 200.")
    if mode != "members":
        _query(q)
    # Remote discovery happens after authorization and before the coherent local
    # read transaction; it never writes, publishes identity or grants.
    live, search_failed = None, False
    discovery = getattr(request.app.state, "directory_search", None)
    if mode == "principals" and discovery is not None:
        with request.app.state.db.transaction() as conn:
            _authority(conn, request, tenant, mode)
        try:
            live = discovery(q)
        except DirectoryUnavailable:
            search_failed = True
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        session = _authority(conn, request, tenant, mode)
        metadata = _metadata(conn)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        context = {
            "scope": tenant,
            "mode": mode,
            "team": team,
            "q": q,
            "limit": limit,
            "session": bytes(session["handle_hash"]).hex(),
            "epoch": request.app.state.settings.deployment_epoch,
            "order": "label-id",
        }
        codec = Cursor(request.app.state.settings.cipher(), context, now)
        revision = {"directory": str(metadata["semantic_revision"])}
        if tenant:
            revision["tenant"] = str(
                conn.execute("SELECT revision FROM tenants WHERE id=%s", (tenant,)).fetchone()[
                    "revision"
                ]
            )
        if mode == "assignees":
            revision["administrators"] = conn.execute(
                "SELECT md5(coalesce(string_agg(id::text,',' ORDER BY id),'')) AS digest FROM principals WHERE super_admin"
            ).fetchone()["digest"]
        if team:
            root = conn.execute(
                "SELECT p.kind,r.semantic_digest FROM principals p LEFT JOIN directory_root_checkpoints r ON r.root_id=p.id WHERE p.id=%s",
                (team,),
            ).fetchone()
            if not root or root["kind"] != "team":
                raise AppError("not_found", "Team unavailable.", 404)
            if not root["semantic_digest"]:
                raise unavailable("complete_membership_required")
            revision["membership"] = root["semantic_digest"]
        position = None
        decoded = codec.decode(cursor) if cursor else None
        if live is not None:
            result = _search_rows(conn, live.objects)
            revision["search"] = hashlib.sha256(
                canonical(
                    [
                        (p.key.source, p.key.object_id, p.label, p.kind, p.eligible, p.deleted)
                        for p in live.objects
                    ]
                    + [live.capped]
                )
            ).hexdigest()
            revision["coverage"] = "directory"
        else:
            result = None
            revision["coverage"] = "cache"
        if decoded:
            if decoded["revision"] != revision:
                raise AppError(
                    "list_changed", "Directory selection changed. Restart from the first page.", 409
                )
            position = decoded["position"]
        if result is not None:
            result.sort(
                key=lambda row: (
                    row["display_name"].casefold(),
                    row["directory_source"],
                    row["object_id"],
                )
            )
            if position:
                result = [
                    row
                    for row in result
                    if (row["display_name"].casefold(), row["directory_source"], row["object_id"])
                    > tuple(position)
                ]
            rows = result[: limit + 1]
            next_position = (
                [
                    rows[limit - 1]["display_name"].casefold(),
                    rows[limit - 1]["directory_source"],
                    rows[limit - 1]["object_id"],
                ]
                if len(rows) > limit
                else None
            )
        else:
            rows = _cached_rows(conn, tenant, mode, q, limit, position, team)
            next_position = (
                [rows[limit - 1]["sort_key"], str(rows[limit - 1]["id"])]
                if len(rows) > limit
                else None
            )
            rows = [_present(row) for row in rows]
        # An answer from the search cache may be out of date, and a capped answer is
        # incomplete: neither is presented as the complete company directory.
        metadata.update(
            cached=live is None or live.cached,
            search_complete=live is not None and not live.capped,
            complete_company_directory=live is not None and not live.cached and not live.capped,
            directory_degraded=bool(metadata["directory_degraded"] or search_failed),
            coverage="accepted_cache"
            if live is None
            else "search_cache"
            if live.cached
            else "configured_directory",
            membership_scope="eligible_users" if team else None,
            # ADAPI answered its silent 1,000-row cap: the picker asks to type more.
            type_more=bool(live is not None and live.capped),
        )
        return {
            "data": wire(rows[:limit]),
            "meta": wire(metadata),
            "next_cursor": codec.encode(next_position, revision=revision)
            if next_position
            else None,
        }


def _search_rows(conn, objects):
    """ADAPI matches with each saved principal's stored state merged in; writes nothing.

    A saved row shows what is stored (id, label, eligibility, selectable). A row
    Keep has not saved has ``id: null`` and is not selectable: picking it saves
    it first through ``.../permission-principals/resolve``.
    """
    rows = conn.execute(
        """SELECT p.*,r.semantic_digest AS membership_digest FROM principals p
        LEFT JOIN directory_root_checkpoints r ON r.root_id=p.id
        WHERE (p.directory_source,p.object_id) IN (SELECT * FROM unnest(%s::text[],%s::text[]))""",
        ([obj.key.source for obj in objects], [obj.key.object_id for obj in objects]),
    ).fetchall()
    known = {(row["directory_source"], row["object_id"]): row for row in rows}
    result = []
    for obj in objects:
        stored = known.get((obj.key.source, obj.key.object_id))
        result.append(
            _present(stored)
            if stored
            else {
                "id": None,
                "directory_source": obj.key.source,
                "object_id": obj.key.object_id,
                "kind": obj.kind,
                "display_name": obj.label,
                "deleted": obj.deleted,
                "verified_at": None,
                "eligible": obj.eligible and not obj.deleted,
                "verification": "unverified",
                "selectable": False,
            }
        )
    return result


def _cached_rows(conn, tenant, mode, q, limit, position, team):
    clauses, args = [], []
    if mode == "members":
        clauses.append(
            "EXISTS(SELECT 1 FROM directory_memberships m WHERE m.team_id=%s AND m.user_id=p.id)"
        )
        args.append(team)
    else:
        clauses.append("strpos(lower(p.display_name),lower(%s))>0")
        args.append(q)
    if mode == "assignees":
        clauses.append("""p.kind='user' AND p.eligible AND NOT p.deleted AND p.verified_at IS NOT NULL AND (
            p.super_admin OR EXISTS(SELECT 1 FROM tenants t WHERE t.id=%s AND t.kind='global') OR
            EXISTS(SELECT 1 FROM tenant_grants g WHERE g.tenant_id=%s AND g.role IN ('edit','admin') AND
                (g.principal_id=p.id OR EXISTS(SELECT 1 FROM directory_memberships m WHERE m.team_id=g.principal_id AND m.user_id=p.id))))""")
        args.extend((tenant, tenant))
    if position:
        clauses.append('(lower(p.display_name) COLLATE "C",p.id)>(%s COLLATE "C",%s::uuid)')
        args.extend(position)
    args.append(limit + 1)
    return conn.execute(
        """SELECT p.*,lower(p.display_name) AS sort_key,r.semantic_digest AS membership_digest FROM principals p
        LEFT JOIN directory_root_checkpoints r ON r.root_id=p.id WHERE """
        + " AND ".join(clauses)
        + ' ORDER BY lower(p.display_name) COLLATE "C",p.id LIMIT %s',
        args,
    ).fetchall()


@router.get("/api/tenants/{tenant_id}/permission-principals")
def permission_principals(
    tenant_id: str, request: Request, q: str, limit: int = 50, cursor: str | None = None
):
    return _listing(request, tenant_id, "principals", q, limit, cursor)


@router.get("/api/admin/directory/principals")
def creation_principals(request: Request, q: str, limit: int = 50, cursor: str | None = None):
    return _listing(request, None, "principals", q, limit, cursor)


@router.get("/api/tenants/{tenant_id}/permission-principals/{principal_id}/members")
def members(
    tenant_id: str, principal_id: str, request: Request, limit: int = 50, cursor: str | None = None
):
    return _listing(request, tenant_id, "members", "", limit, cursor, principal_id)


@router.get("/api/tenants/{tenant_id}/assignees")
def assignees(tenant_id: str, request: Request, q: str, limit: int = 50, cursor: str | None = None):
    return _listing(request, tenant_id, "assignees", q, limit, cursor)


# Save on pick (REV-73) ---------------------------------------------------------------


class ResolveBody(StrictModel):
    kind: Literal["user", "team"]
    username: str
    retry: bool = False


def _principal_key(username: str) -> PrincipalKey:
    """Sign-in username rules (identity 2) and no ``*``; lowercase samAccountName."""
    try:
        if "*" in username:
            raise InvalidUsername("username contains a wildcard")
        return PrincipalKey(SOURCE, normalize_username(username))
    except InvalidUsername:
        raise AppError(
            "invalid_username", "Enter a directory username without special characters.", 422
        ) from None


def _saver(request):
    saver = getattr(request.app.state, "pick_saver", None)
    if saver is None:
        # ADAPI or the super-admin group is not configured for this API process.
        raise unavailable("directory_unavailable")
    return saver


def _saved(row):
    return {"data": wire(_present(row)), "meta": {}}


def _pending():
    return JSONResponse({"data": {"status": "pending"}, "meta": {}}, status_code=202)


def _failed(reason):
    return AppError(reason, "Keep couldn't save this from the directory. Try again.", 503)


_NOT_SAVED = {
    "principal_not_in_directory": "The directory has no user or group with this username.",
    "principal_ambiguous": "More than one directory entry has this username.",
    "principal_kind_mismatch": "The directory entry with this username is of another kind.",
}


@router.post("/api/tenants/{tenant_id}/permission-principals/resolve")
def resolve(tenant_id: str, body: ResolveBody, request: Request):
    """Save a picked principal: 200 saved, 202 pending, 422 not in ADAPI, 503 failed.

    Order: a pending row (failed -> 503 unless ``retry``; leased -> 202; otherwise
    hand over -> 202), then a stored usable principal (200, no ADAPI read), then
    an inline save (200, or 202 when it does not fit the request).
    """
    key = _principal_key(body.username)
    db = request.app.state.db

    def admin(conn):
        authorize(conn, request, tenant_id, "admin", mutation=True)

    with db.transaction() as conn:
        admin(conn)
        pending = pending_row(conn, key)
        if pending is None:
            row = principal_row(conn, key)
            if usable(row, body.kind):
                return _saved(row)
            saver = _saver(request)
        elif pending["last_failure"] and not body.retry:
            raise _failed(pending["last_failure"])
        elif pending["leased"]:
            return _pending()
        else:
            # A failure retried, or a save whose process stopped: hand it over again.
            queue = _saver(request).hand_over(
                conn, key, pending["kind"], retry=bool(pending["last_failure"])
            )
    if pending is not None:
        queue()
        return _pending()
    try:
        return _saved(saver.save_inline(key, body.kind, admin))
    except HandOver:
        with db.transaction() as conn:
            admin(conn)
            queue = saver.hand_over(conn, key, body.kind)
        queue()
        return _pending()
    except Unsaved as failure:
        with db.transaction() as conn:
            admin(conn)
            recorded = saver.record_failure(conn, key, body.kind, failure.reason)
        if not recorded:
            # Another request is saving it in the background right now.
            return _pending()
        raise _failed(failure.reason) from None
    except NotInDirectory as missing:
        raise AppError(missing.code, _NOT_SAVED[missing.code], 422) from None


@router.get("/api/tenants/{tenant_id}/permission-principals/resolve")
def resolve_status(tenant_id: str, request: Request, kind: Literal["user", "team"], username: str):
    """Poll a save; reads PostgreSQL only, never ADAPI.

    200 saved and usable; 202 leased or queued (a pending row without a live lease
    is handed over again); 503 failed with its ``last_failure``; 404 no save.
    """
    key = _principal_key(username)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, "admin")
        row = principal_row(conn, key)
        if usable(row, kind):
            return _saved(row)
        pending = pending_row(conn, key)
        if pending is None:
            raise AppError("not_found", "No save is in progress for this username.", 404)
        if pending["last_failure"]:
            raise _failed(pending["last_failure"])
        if pending["leased"]:
            return _pending()
        queue = _saver(request).hand_over(conn, key, pending["kind"])
    queue()
    return _pending()
