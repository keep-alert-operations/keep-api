"""Keep password sign-in and PostgreSQL-authoritative human sessions (REV-73).

Requirements: REV-73; identity configuration 2-5, 8-10; plan "Login API".

``POST /auth/login`` checks the password with one LDAP bind (``keep.identity.login``),
reads the person's own ADAPI row and creates a local 24-hour session. ``GET
/auth/session`` returns the signed-in user and ``POST /auth/logout`` revokes the session
locally. There is no provider, callback, refresh, activity heartbeat or idle timeout.

The password is used for the bind only: it is never logged, stored, returned or put in
an exception message. Failures are logged with a fixed reason code, never with the
password or the typed username (people sometimes type a password into that field).
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from keep import request_budget
from keep.identity.adapi import (
    REQUEST_CALL_CAP,
    ADAPIClient,
    ADAPIConfig,
    InvalidUsername,
    normalize_username,
    principal_key,
    user_evidence,
)
from keep.identity.authentication import (
    SESSION_COOKIE as SESSION_COOKIE,
    InvalidReturnPath,
    _cookie as _cookie,
    _guard as _guard,
    _hash as _hash,
    authenticate as authenticate,
    require_human_auth as require_human_auth,
    safe_return_path,
    same_origin as same_origin,
)
from keep.identity.directory import DirectoryUnavailable, PrincipalKey
from keep.identity.login import (
    LDAPBindConfig,
    SignInRejected,
    SignInUnavailable,
    check_password,
)
from keep.identity.publication import allocate_generation, lock_identity, publish, stored_matches
from keep.ingestion.native import parse_json
from keep.shared.errors import AppError

log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["identity"])

# Identity configuration 2: sign-in enforces its own limits, because the request
# middleware exempts POSTs under /auth/ from its body, media type and encoding checks.
LOGIN_BODY_LIMIT = 4096
LOGIN_FIELDS = frozenset({"username", "password", "return_to"})
# Identity configuration 2: before publishing, at least this much request budget remains.
PUBLISH_RESERVE_SECONDS = 1.0
NO_STORE = {"Cache-Control": "private, no-store"}

LOGIN_BODY_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["username", "password"],
    "properties": {
        "username": {"type": "string", "maxLength": 64},
        "password": {"type": "string", "format": "password"},
        "return_to": {"type": ["string", "null"], "maxLength": 2048},
    },
}


def _rejected() -> AppError:
    # One message for a wrong password, a WhoAmI mismatch and a disabled account.
    return AppError("authentication_rejected", "The username or password wasn't accepted.", 401)


def _unavailable() -> AppError:
    return AppError(
        "sign_in_unavailable", "Sign-in is unavailable right now. Try again shortly.", 503
    )


def _refused(reason: str) -> AppError:
    log.info("sign_in_rejected reason=%s", reason)
    return _rejected()


def _down(reason: str) -> AppError:
    log.warning("sign_in_unavailable reason=%s", reason)
    return _unavailable()


@dataclass(frozen=True)
class SignInConfig:
    ldap: LDAPBindConfig
    adapi: ADAPIConfig
    superadmin_group: PrincipalKey


_UNSET = object()


def sign_in_config(app) -> SignInConfig | None:
    """The LDAP, ADAPI and super-admin settings sign-in needs, once per application.

    Missing or invalid settings leave the application running and make sign-in answer
    503 ``sign_in_unavailable``; the problem is logged once, without values.
    """
    cached = getattr(app.state, "sign_in_config", _UNSET)
    if cached is not _UNSET:
        return cached
    settings = app.state.settings
    config = None
    try:
        adapi = ADAPIConfig.from_settings(settings)
        config = SignInConfig(
            LDAPBindConfig.from_settings(settings),
            adapi,
            principal_key(settings.superadmin_group or "", adapi.source),
        )
    except ValueError:
        log.warning(
            "sign_in_configuration_missing: KEEP_LDAP_HOST, KEEP_LDAP_BIND_FORMAT, "
            "KEEP_ADAPI_URL, KEEP_ADAPI_CLIENT_ID and KEEP_SUPERADMIN_GROUP are required"
        )
    app.state.sign_in_config = config
    return config


def _invalid_fields(*fields: tuple[str, str]) -> AppError:
    return AppError(
        "invalid_fields",
        "Invalid request fields.",
        422,
        fields=[{"path": path, "code": code} for path, code in fields],
    )


async def _login_body(request: Request) -> dict:
    """Read and validate the JSON body under sign-in's own encoding and size limits."""
    if request.headers.get("content-encoding", "identity") != "identity":
        raise AppError("unsupported_encoding", "Compressed request bodies are not accepted.", 415)
    media = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media != "application/json":
        raise AppError("unsupported_media_type", "Use application/json.", 415)
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > LOGIN_BODY_LIMIT):
        raise AppError("body_too_large", "Request body exceeds its size limit.", 413)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > LOGIN_BODY_LIMIT:
            raise AppError("body_too_large", "Request body exceeds its size limit.", 413)
        chunks.append(chunk)
    value = parse_json(b"".join(chunks))
    if not isinstance(value, dict):
        raise _invalid_fields(("body", "object_type"))
    problems = [(name, "extra_forbidden") for name in sorted(set(value) - LOGIN_FIELDS)]
    for name in ("username", "password"):
        if name not in value:
            problems.append((name, "missing"))
        elif not isinstance(value[name], str):
            problems.append((name, "string_type"))
    if value.get("return_to") is not None and not isinstance(value["return_to"], str):
        problems.append(("return_to", "string_type"))
    if problems:
        raise _invalid_fields(*problems)
    return value


def _return_path(value: str | None) -> str:
    """Identity configuration 2: a validated local relative path, else the workspace root."""
    if not value:
        return "/"
    try:
        return safe_return_path(value)
    except InvalidReturnPath:
        return "/"


def _budget_left() -> bool:
    try:
        left = request_budget.remaining()
    except AppError:
        return False
    return left is None or left >= PUBLISH_RESERVE_SECONDS


@router.post(
    "/login",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": LOGIN_BODY_SCHEMA}},
        }
    },
)
async def login(request: Request):
    """Sign in with the company username and AD password (identity configuration 2-3)."""
    database = request.app.state.db

    def check_gate():
        with database.transaction() as conn:
            require_human_auth(conn)

    # Identity configuration 2, checks before any bind, in order: the gate, the exact
    # same Origin with this endpoint's body and encoding limits, the username, then
    # the password.
    await run_in_threadpool(check_gate)
    same_origin(request)
    body = await _login_body(request)
    try:
        username = normalize_username(body["username"])
    except InvalidUsername:
        raise _refused("invalid_username") from None
    password = body.pop("password")
    if not password:
        raise _refused("empty_password")
    return_to = _return_path(body.get("return_to"))
    config = sign_in_config(request.app)
    if config is None:
        raise _unavailable()

    # The bind and WhoAmI: LDAP connect 2 s and receive 2 s, in a worker thread.
    try:
        await run_in_threadpool(check_password, config.ldap, username, password)
    except SignInRejected as exc:
        raise _refused(exc.args[0]) from None
    except SignInUnavailable as exc:
        raise _down(exc.args[0]) from None
    finally:
        del password

    # Generations are allocated before reading, so generation order matches read order.
    def allocate():
        with database.transaction() as conn:
            return allocate_generation(conn)

    generation = await run_in_threadpool(allocate)
    started_at = datetime.now(UTC)

    def read_rows():
        # Each call: min(3 s, remaining request budget - 1 s).
        with ADAPIClient(config.adapi, call_cap=REQUEST_CALL_CAP) as client:
            return client.lookup_user_rows(username)

    try:
        rows = await run_in_threadpool(read_rows)
    except DirectoryUnavailable as exc:
        raise _down(exc.args[0] if exc.args else "directory_unavailable") from None
    if not rows:
        log.info("sign_in_rejected reason=account_not_in_directory")
        raise AppError(
            "account_not_in_directory", "Your account isn't in the company directory.", 403
        )
    if len(rows) > 1:
        log.info("sign_in_rejected reason=account_ambiguous")
        raise AppError(
            "account_ambiguous",
            "More than one directory account has this username. Contact your administrator.",
            403,
        )
    try:
        evidence = user_evidence(config.adapi.source, rows[0], generation, started_at)
    except DirectoryUnavailable as exc:
        raise _down(exc.args[0] if exc.args else "directory_unavailable") from None
    person = evidence.objects[next(iter(evidence.roots))]
    if not _budget_left():
        raise _down("request_budget_spent")

    settings = request.app.state.settings
    cipher = settings.cipher()
    handle, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    handle_hash = _hash(handle)
    old_handle = request.cookies.get(SESSION_COOKIE, "")

    def finish():
        """Publish the person's changed row, then create the session, in one transaction.

        Returns the session's absolute deadline, or None when sign-in is refused. A
        refusal still commits the publication, so a confirmed disablement ends the
        person's other sessions (identity configuration 3, 8).
        """
        with database.transaction() as conn:
            lock_identity(conn)
            require_human_auth(conn)
            if not stored_matches(conn, person):
                result = publish(conn, evidence, superadmin_group=config.superadmin_group)
                if result.fenced:
                    # A newer publication holds the person; its stored row decides.
                    log.info("sign_in_publication_fenced")
            if not person.eligible:
                return None
            principal = conn.execute(
                """SELECT id,kind,eligible,deleted,evidence_generation,verified_at FROM principals
                WHERE directory_source=%s AND object_id=%s""",
                (person.key.source, person.key.object_id),
            ).fetchone()
            if (
                principal is None
                or principal["kind"] != "user"
                or not principal["eligible"]
                or principal["deleted"]
                or principal["verified_at"] is None
                or principal["evidence_generation"] < 1
            ):
                return None
            if old_handle and len(old_handle) <= 128:
                # Identity configuration 3, 5: a later sign-in replaces this browser's session.
                conn.execute(
                    """UPDATE auth_sessions SET revoked_at=clock_timestamp()
                    WHERE handle_hash=%s AND revoked_at IS NULL""",
                    (_hash(old_handle),),
                )
            return conn.execute(
                """INSERT INTO auth_sessions(handle_hash,principal_id,csrf_hash,csrf_cipher,
                    auth_time,absolute_at,deployment_epoch)
                SELECT %s,%s,%s,%s,t.signed_in,t.signed_in+interval '24 hours',%s
                FROM (SELECT clock_timestamp() AS signed_in) t
                RETURNING absolute_at""",
                (
                    handle_hash,
                    principal["id"],
                    _hash(csrf),
                    cipher.seal(csrf.encode(), "session-csrf:" + handle_hash.hex()),
                    settings.deployment_epoch,
                ),
            ).fetchone()["absolute_at"]

    absolute_at = await run_in_threadpool(finish)
    if absolute_at is None:
        raise _refused("account_disabled" if not person.eligible else "account_ineligible")
    response = JSONResponse(
        {
            "data": {"return_to": return_to, "absolute_at": absolute_at.isoformat()},
            "meta": {},
        },
        headers=NO_STORE,
    )
    _cookie(response, SESSION_COOKIE, handle)
    return response


@router.get("/session")
async def current_session(request: Request):
    """The signed-in user, effective tenant access and the session's absolute deadline."""
    from keep.access import accessible_tenants

    def session_response():
        with request.app.state.db.transaction() as conn:
            principal, session = authenticate(conn, request)
            csrf = (
                request.app.state.settings.cipher()
                .open(
                    bytes(session["csrf_cipher"]),
                    "session-csrf:" + bytes(session["handle_hash"]).hex(),
                )
                .decode()
            )
            tenants = accessible_tenants(conn, principal)
            public_tenants = [
                {
                    "id": str(t["id"]),
                    "name": t["name"],
                    "kind": t["kind"],
                    "role": t["role"],
                    "revision": str(t["revision"]),
                }
                for t in tenants
            ]
            return JSONResponse(
                {
                    "data": {
                        "principal": {
                            "id": str(principal["id"]),
                            "display_name": principal["display_name"],
                        },
                        "global_super_admin": principal["super_admin"],
                        "tenants": public_tenants,
                        "csrf_token": csrf,
                        "absolute_at": session["absolute_at"].isoformat(),
                        "verified_at": principal["verified_at"].isoformat(),
                        "last_tenant_id": str(session["last_tenant_id"])
                        if session["last_tenant_id"]
                        else None,
                    },
                    "meta": {},
                },
                headers=NO_STORE,
            )

    return await run_in_threadpool(session_response)


@router.post("/logout")
async def logout(request: Request):
    """Revoke the local session before clearing its cookie (identity configuration 10)."""

    def revoke_session():
        with request.app.state.db.transaction() as conn:
            _guard(conn, exclusive=True)
            _, session = authenticate(conn, request, mutation=True)
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE handle_hash=%s",
                (session["handle_hash"],),
            )

    await run_in_threadpool(revoke_session)
    response = JSONResponse({"data": {"signed_out": True}, "meta": {}}, headers=NO_STORE)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response
