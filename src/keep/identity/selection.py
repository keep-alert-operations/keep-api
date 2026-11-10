"""Authorized cached selectors and optional bounded company-directory discovery.

Search never creates a principal or grants authority. Unknown live matches are
queued for the existing complete-verification worker and remain unselectable.
"""

from dataclasses import replace
import hashlib
import time
import unicodedata

from fastapi import APIRouter, Request
from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from keep.access import authorize
from keep.identity.authentication import authenticate
from keep.ingestion.native import canonical
from keep.shared.cursors import Cursor
from keep.shared.errors import AppError, unavailable
from keep.serialization import wire

from .directory import DirectoryObject, DirectoryUnavailable
from .ldap import LDAPDirectoryReader

router = APIRouter(tags=["directory"])


class ConfiguredDirectorySearch:
    """Complete matching search within explicit qualified size/time allocations.

    Bind this callable to app.state.directory_search. TLS/schema/credentials are
    the same explicit LDAPConfig used by the worker. A result is complete only
    after both type filters end with an empty paging cookie; no silent truncation.
    """

    def __init__(
        self,
        config,
        *,
        qualified,
        max_seconds,
        max_matches,
        max_pages,
        reader_factory=LDAPDirectoryReader,
    ):
        if qualified is not True or not config.schema.schema_qualified:
            raise ValueError("Qualified LDAP search schema and capacity are required")
        if type(max_seconds) not in (float, int) or not 0 < max_seconds <= 3:
            raise ValueError("LDAP search allocation must be at most three seconds")
        if any(type(value) is not int or value < 1 for value in (max_matches, max_pages)):
            raise ValueError("Explicit bounded search allocations required")
        if max_matches > config.max_objects or max_pages > config.max_pages:
            raise ValueError("Search cannot exceed the qualified directory allocations")
        self.config = replace(
            config, connect_timeout=min(config.connect_timeout, 1), receive_timeout=1
        )
        self.max_seconds, self.max_matches, self.max_pages = max_seconds, max_matches, max_pages
        self.reader_factory = reader_factory

    def __call__(self, term):
        _query(term)
        deadline = time.monotonic() + self.max_seconds
        found = {}
        try:
            with self.reader_factory(self.config) as reader:
                schema = reader.schema
                for kind, expression in (
                    ("user", schema.user_filter),
                    ("team", schema.team_filter),
                ):
                    cookie, cookies = None, set()
                    query = (
                        f"(&{expression}({schema.label_attribute}=*{escape_filter_chars(term)}*))"
                    )
                    for _ in range(self.max_pages):
                        if time.monotonic() >= deadline:
                            raise DirectoryUnavailable("directory_search_deadline")
                        reader.connection.search(
                            schema.base_dn,
                            query,
                            search_scope=SUBTREE,
                            attributes=[
                                schema.id_attribute,
                                schema.label_attribute,
                                schema.eligibility_attribute,
                            ],
                            time_limit=1,
                            paged_size=min(self.config.page_size, self.max_matches),
                            paged_criticality=True,
                            paged_cookie=cookie,
                        )
                        if (
                            reader.connection.result.get("result") != 0
                            or time.monotonic() >= deadline
                        ):
                            raise DirectoryUnavailable("directory_search_incomplete")
                        for entry in reader.connection.response:
                            if entry.get("type") != "searchResEntry":
                                raise DirectoryUnavailable("directory_search_referral")
                            key = reader._key(entry)
                            label = reader._one(entry, schema.label_attribute).decode("utf-8")
                            eligible = True
                            if kind == "user":
                                status = reader._one(entry, schema.eligibility_attribute).decode(
                                    "utf-8"
                                )
                                eligible = (
                                    not (int(status) & schema.disabled_bitmask)
                                    if schema.disabled_bitmask is not None
                                    else status in schema.eligibility_values
                                )
                            obj = DirectoryObject(key, kind, label, bool(eligible))
                            if key in found and found[key] != obj:
                                raise DirectoryUnavailable("directory_search_identity_conflict")
                            found[key] = obj
                            if len(found) > self.max_matches:
                                raise DirectoryUnavailable("directory_search_allocation_exceeded")
                        control = reader.connection.result.get("controls", {}).get(
                            "1.2.840.113556.1.4.319", {}
                        )
                        cookie = control.get("value", {}).get("cookie")
                        if cookie is None:
                            raise DirectoryUnavailable("directory_search_page_unproven")
                        if not cookie:
                            break
                        if cookie in cookies:
                            raise DirectoryUnavailable("directory_search_page_loop")
                        cookies.add(cookie)
                    else:
                        raise DirectoryUnavailable("directory_search_page_allocation_exceeded")
        except (LDAPException, OSError, UnicodeError, ValueError):
            raise DirectoryUnavailable("directory_search_unavailable") from None
        return tuple(found[key] for key in sorted(found))


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
    # read/queue transaction; it cannot publish accepted identity or grants.
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
            result = _live_rows(conn, live)
            revision["search"] = hashlib.sha256(
                canonical(
                    [
                        (p.key.source, p.key.object_id, p.label, p.kind, p.eligible, p.deleted)
                        for p in live
                    ]
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
        metadata.update(
            cached=live is None,
            search_complete=live is not None,
            complete_company_directory=live is not None,
            directory_degraded=bool(metadata["directory_degraded"] or search_failed),
            coverage="configured_directory" if live is not None else "accepted_cache",
            membership_scope="eligible_users" if team else None,
        )
        return {
            "data": wire(rows[:limit]),
            "meta": wire(metadata),
            "next_cursor": codec.encode(next_position, revision=revision)
            if next_position
            else None,
        }


def _live_rows(conn, live):
    keys = [(obj.key.source, obj.key.object_id) for obj in live]
    rows = conn.execute(
        """SELECT p.*,r.semantic_digest AS membership_digest FROM principals p
        LEFT JOIN directory_root_checkpoints r ON r.root_id=p.id
        WHERE (p.directory_source,p.object_id) IN (SELECT * FROM unnest(%s::text[],%s::text[]))""",
        ([key[0] for key in keys], [key[1] for key in keys]),
    ).fetchall()
    known = {(row["directory_source"], row["object_id"]): row for row in rows}
    result = []
    for obj in live:
        stored = known.get((obj.key.source, obj.key.object_id))
        same = stored and (
            stored["display_name"],
            stored["kind"],
            stored["eligible"],
            stored["deleted"],
        ) == (obj.label, obj.kind, obj.eligible, obj.deleted)
        row = (
            _present(stored)
            if stored
            else {
                "id": None,
                "directory_source": obj.key.source,
                "object_id": obj.key.object_id,
                "kind": obj.kind,
                "display_name": obj.label,
                "eligible": obj.eligible,
                "deleted": obj.deleted,
                "verified_at": None,
                "verification": "verification_pending",
                "selectable": False,
            }
        )
        if not same or row["verification"] != "verified":
            row.update(
                display_name=obj.label,
                eligible=obj.eligible,
                deleted=obj.deleted,
                selectable=False,
                verification="verification_pending",
            )
            conn.execute(
                "INSERT INTO directory_verification_requests(source,object_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",
                (obj.key.source, obj.key.object_id),
            )
        result.append(row)
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
