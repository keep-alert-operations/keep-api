"""PostgreSQL-authoritative human sessions and backend-only authentication routes."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from appchi.shared.errors import AppError, unavailable

from .oidc import (
    LoginTransaction,
    OIDCClient,
    OIDCConfig,
    OIDCIdentity,
    OIDCInvalid,
    OIDCRevoked,
    OIDCUnavailable,
)

router = APIRouter(prefix="/auth", tags=["identity"])
SESSION_COOKIE = "__Host-appchi_session"
LOGIN_COOKIE = "__Host-appchi_login"


def _hash(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def _guard(conn, *, exclusive=False):
    conn.execute(
        "SELECT scope FROM authorization_guards WHERE scope='identity' FOR "
        + ("UPDATE" if exclusive else "SHARE")
    )


def require_human_auth(conn):
    row = conn.execute(
        "SELECT ready FROM capability_gates WHERE capability='human_auth'"
    ).fetchone()
    if not row or not row["ready"]:
        raise unavailable("human_authorization_gated")


def same_origin(request: Request):
    origin = request.headers.get("origin")
    if origin != request.app.state.settings.public_origin or request.headers.get(
        "sec-fetch-site"
    ) not in (None, "same-origin"):
        raise AppError("origin_rejected", "A same-origin request is required.", 403)


def authenticate(conn, request: Request, mutation: bool = False):
    """Return (principal, session) under the transaction's authorization guard.

    Keep this transaction open through protected reads or mutation commit. A
    mutation guard serializes identity revocation and grant publication; no age test
    is applied to successfully verified cached directory evidence.
    """
    if mutation:
        _guard(conn)
    require_human_auth(conn)
    handle = request.cookies.get(SESSION_COOKIE, "")
    if not handle or len(handle) > 128:
        raise AppError("unauthenticated", "Sign in is required.", 401)
    row = conn.execute(
        """SELECT s.*, p.directory_source,p.object_id,p.kind,p.display_name,p.eligible,p.deleted,
                  p.super_admin,p.evidence_generation,p.verified_at
           FROM auth_sessions s JOIN principals p ON p.id=s.principal_id
           WHERE s.handle_hash=%s AND s.revoked_at IS NULL AND s.absolute_at>clock_timestamp()
           AND s.activity_at>clock_timestamp()-interval '30 minutes' AND s.deployment_epoch=%s""",
        (_hash(handle), request.app.state.settings.deployment_epoch),
    ).fetchone()
    if not row or not row["eligible"] or row["deleted"] or row["kind"] != "user":
        raise AppError("unauthenticated", "Sign in is required.", 401)
    if row["verified_at"] is None or row["evidence_generation"] < 1:
        raise unavailable("directory_evidence_required")
    if mutation:
        same_origin(request)
        csrf = request.headers.get("x-csrf-token", "")
        if (
            not csrf
            or len(csrf) > 128
            or not secrets.compare_digest(_hash(csrf), bytes(row["csrf_hash"]))
        ):
            raise AppError("csrf_rejected", "A valid session CSRF token is required.", 403)
    principal = {
        name: row[name]
        for name in (
            "directory_source",
            "object_id",
            "kind",
            "display_name",
            "eligible",
            "deleted",
            "super_admin",
            "evidence_generation",
            "verified_at",
        )
    }
    principal["id"] = row["principal_id"]
    return principal, row


def oidc_client(request: Request) -> OIDCClient:
    if getattr(request.app.state, "oidc", None) is not None:
        return request.app.state.oidc
    settings = request.app.state.settings
    fields = (
        "oidc_issuer",
        "oidc_client_secret",
        "oidc_directory_source",
        "oidc_directory_id_claim",
        "oidc_directory_scope",
        "oidc_required_acr",
        "oidc_required_amr",
    )
    if not all(getattr(settings, field, None) for field in fields):
        raise unavailable("oidc_configuration_required")
    try:
        config = OIDCConfig(
            settings.oidc_issuer,
            settings.oidc_client_id,
            settings.oidc_client_secret.get_secret_value(),
            settings.public_origin + "/auth/callback",
            settings.public_origin + "/signed-out",
            settings.oidc_directory_source,
            settings.oidc_directory_id_claim,
            settings.oidc_directory_scope,
            settings.oidc_required_acr,
            tuple(settings.oidc_required_amr),
            settings.oidc_ca_file,
        )
        request.app.state.oidc = OIDCClient(config)
    except ValueError:
        raise unavailable("oidc_configuration_invalid") from None
    return request.app.state.oidc


def _protocol_error(exc):
    if isinstance(exc, OIDCUnavailable):
        return unavailable("identity_provider_unavailable")
    return AppError(
        "authentication_rejected", "The authentication response could not be accepted.", 401
    )


def _cookie(response, name, value):
    response.set_cookie(name, value, secure=True, httponly=True, samesite="lax", path="/")
    response.headers["Cache-Control"] = "private, no-store"


@router.get("/login")
async def login(request: Request, return_to: str = "/", fresh: bool = False):
    with request.app.state.db.transaction() as conn:
        require_human_auth(conn)
    client = oidc_client(request)
    browser = secrets.token_urlsafe(32)
    try:
        transaction = client.new_transaction(return_to, browser, fresh=fresh)
        url = await client.authorization_url(transaction)
    except (OIDCInvalid, OIDCUnavailable) as exc:
        raise _protocol_error(exc) from None
    state_hash = _hash(transaction.state)
    ciphertext = request.app.state.settings.cipher().seal(
        json.dumps(asdict(transaction)).encode(), "login:" + state_hash.hex()
    )
    with request.app.state.db.transaction() as conn:
        require_human_auth(conn)
        conn.execute(
            "INSERT INTO login_transactions(state_hash,browser_hash,encrypted_state,expires_at) VALUES(%s,%s,%s,%s)",
            (
                state_hash,
                _hash(browser),
                ciphertext,
                datetime.fromtimestamp(transaction.expires_at, UTC),
            ),
        )
    response = RedirectResponse(url, status_code=302)
    _cookie(response, LOGIN_COOKIE, browser)
    return response


@router.get("/callback")
async def callback(request: Request, state: str = "", code: str = "", error: str | None = None):
    if not state or len(state) > 128 or not code or len(code) > 4096 or error:
        raise AppError("authentication_rejected", "The sign-in transaction was rejected.", 401)
    state_hash = _hash(state)
    # Consume before any external exchange. Failure cannot replay the same code
    # transaction, and no transaction/authorization lock spans a network call.
    with request.app.state.db.transaction() as conn:
        require_human_auth(conn)
        record = conn.execute(
            """UPDATE login_transactions SET consumed=true WHERE state_hash=%s
                              AND consumed=false AND expires_at>clock_timestamp() RETURNING *""",
            (state_hash,),
        ).fetchone()
    if not record:
        if "text/html" in request.headers.get("accept", "").lower():
            return RedirectResponse(
                "/sign-in-expired",
                status_code=303,
                headers={"Cache-Control": "private, no-store"},
            )
        raise AppError(
            "authentication_rejected", "The sign-in transaction expired or was consumed.", 401
        )
    cipher = request.app.state.settings.cipher()
    try:
        transaction = LoginTransaction(
            **json.loads(cipher.open(bytes(record["encrypted_state"]), "login:" + state_hash.hex()))
        )
        transaction.validate_callback(
            state, request.cookies.get(LOGIN_COOKIE, ""), int(datetime.now(UTC).timestamp())
        )
        tokens = await oidc_client(request).exchange(code, transaction)
    except (OIDCInvalid, OIDCUnavailable) as exc:
        raise _protocol_error(exc) from None
    identity = tokens.identity
    needs_evidence = False
    with request.app.state.db.transaction() as conn:
        evidence = conn.execute(
            "SELECT verified_at,evidence_generation FROM principals WHERE directory_source=%s AND object_id=%s",
            (identity.directory_source, identity.directory_object_id),
        ).fetchone()
        needs_evidence = (
            evidence is None
            or evidence["verified_at"] is None
            or evidence["evidence_generation"] < 1
        )
        # Commit a verification request even when admission fails. This also
        # discovers re-enablement of a previously disabled, no-longer-tracked
        # user. Existing trusted evidence remains usable during an outage.
        conn.execute(
            """INSERT INTO directory_verification_requests(source,object_id)
                     VALUES(%s,%s) ON CONFLICT DO NOTHING""",
            (identity.directory_source, identity.directory_object_id),
        )
    if needs_evidence:
        raise unavailable("directory_evidence_required")
    handle, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    handle_hash = _hash(handle)
    with request.app.state.db.transaction() as conn:
        _guard(conn, exclusive=True)
        require_human_auth(conn)
        principal = conn.execute(
            "SELECT * FROM principals WHERE directory_source=%s AND object_id=%s FOR UPDATE",
            (identity.directory_source, identity.directory_object_id),
        ).fetchone()
        if (
            principal is None
            or principal["verified_at"] is None
            or principal["evidence_generation"] < 1
        ):
            raise unavailable("directory_evidence_required")
        if principal["kind"] != "user" or not principal["eligible"] or principal["deleted"]:
            raise AppError("authentication_rejected", "This identity is not eligible.", 401)
        binding = conn.execute(
            "SELECT * FROM oidc_bindings WHERE issuer=%s AND (subject=%s OR principal_id=%s)",
            (identity.issuer, identity.subject, principal["id"]),
        ).fetchall()
        if any(
            b["subject"] != identity.subject or b["principal_id"] != principal["id"]
            for b in binding
        ):
            raise AppError(
                "identity_binding_conflict", "The immutable identity binding conflicts.", 401
            )
        if conn.execute(
            "SELECT 1 FROM logout_fences WHERE issuer=%s AND sid=%s AND expires_at>clock_timestamp()",
            (identity.issuer, identity.sid),
        ).fetchone():
            raise AppError("authentication_rejected", "The provider session was revoked.", 401)
        conn.execute(
            "INSERT INTO oidc_bindings(issuer,subject,principal_id) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING",
            (identity.issuer, identity.subject, principal["id"]),
        )
        old_handle = request.cookies.get(SESSION_COOKIE)
        if old_handle:
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=clock_timestamp(),tokens=NULL WHERE handle_hash=%s",
                (_hash(old_handle),),
            )
        auth_time = datetime.fromtimestamp(identity.auth_time, UTC)
        conn.execute(
            """INSERT INTO auth_sessions(handle_hash,principal_id,issuer,subject,provider_sid,tokens,csrf_hash,
                       csrf_cipher,auth_time,activity_at,absolute_at,deployment_epoch) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,clock_timestamp(),%s,%s)""",
            (
                handle_hash,
                principal["id"],
                identity.issuer,
                identity.subject,
                identity.sid,
                cipher.seal(
                    json.dumps(tokens.tokens).encode(), "session-tokens:" + handle_hash.hex()
                ),
                _hash(csrf),
                cipher.seal(csrf.encode(), "session-csrf:" + handle_hash.hex()),
                auth_time,
                auth_time + timedelta(hours=24),
                request.app.state.settings.deployment_epoch,
            ),
        )
    response = RedirectResponse(transaction.return_path, status_code=302)
    _cookie(response, SESSION_COOKIE, handle)
    response.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response


async def refresh_session(request: Request):
    """Claim once, exchange outside locks, atomically persist rotated credentials."""
    with request.app.state.db.transaction() as conn:
        principal, session = authenticate(conn, request)
        # A worker may die after consuming a rotating provider token. Never
        # retry its old credential after the bounded exchange lease expires.
        conn.execute(
            """UPDATE auth_sessions SET refresh_uncertain=true,refresh_started_at=NULL
                     WHERE handle_hash=%s AND refresh_started_at<clock_timestamp()-interval '30 seconds'""",
            (session["handle_hash"],),
        )
        claimed = conn.execute(
            """UPDATE auth_sessions SET refresh_generation=refresh_generation+1,
                 refresh_started_at=clock_timestamp() WHERE handle_hash=%s AND refresh_uncertain=false
                 AND refresh_started_at IS NULL AND refresh_at<=clock_timestamp()-interval '4 minutes'
                 RETURNING refresh_generation""",
            (session["handle_hash"],),
        ).fetchone()
    if not claimed:
        return
    generation, handle_hash = claimed["refresh_generation"], bytes(session["handle_hash"])
    cipher = request.app.state.settings.cipher()
    stored = json.loads(
        cipher.open(bytes(session["tokens"]), "session-tokens:" + handle_hash.hex())
    )
    identity = OIDCIdentity(
        session["issuer"],
        session["subject"],
        session["provider_sid"],
        principal["directory_source"],
        principal["object_id"],
        int(session["auth_time"].timestamp()),
        principal["display_name"],
    )
    try:
        refreshed = await oidc_client(request).refresh(stored["refresh_token"], identity)
    except (OIDCInvalid, OIDCUnavailable, AppError) as exc:
        with request.app.state.db.transaction() as conn:
            _guard(conn, exclusive=True)
            if isinstance(exc, (OIDCRevoked, OIDCInvalid)):
                conn.execute(
                    """UPDATE auth_sessions SET revoked_at=clock_timestamp(),tokens=NULL,
                             refresh_started_at=NULL WHERE handle_hash=%s AND refresh_generation=%s""",
                    (handle_hash, generation),
                )
            else:
                conn.execute(
                    """UPDATE auth_sessions SET refresh_uncertain=true,refresh_started_at=NULL
                             WHERE handle_hash=%s AND refresh_generation=%s""",
                    (handle_hash, generation),
                )
        return
    with request.app.state.db.transaction() as conn:
        _guard(conn)
        conn.execute(
            """UPDATE auth_sessions SET tokens=%s,refresh_at=clock_timestamp(),refresh_started_at=NULL
                     WHERE handle_hash=%s AND refresh_generation=%s AND revoked_at IS NULL
                     AND absolute_at>clock_timestamp() AND deployment_epoch=%s""",
            (
                cipher.seal(
                    json.dumps(refreshed.tokens).encode(), "session-tokens:" + handle_hash.hex()
                ),
                handle_hash,
                generation,
                request.app.state.settings.deployment_epoch,
            ),
        )


@router.get("/session")
async def current_session(request: Request):
    from appchi.access import accessible_tenants

    await refresh_session(request)
    with request.app.state.db.transaction() as conn:
        principal, session = authenticate(conn, request)
        csrf = (
            request.app.state.settings.cipher()
            .open(
                bytes(session["csrf_cipher"]), "session-csrf:" + bytes(session["handle_hash"]).hex()
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
                    "refresh_uncertain": session["refresh_uncertain"],
                    "last_tenant_id": str(session["last_tenant_id"])
                    if session["last_tenant_id"]
                    else None,
                },
                "meta": {},
            },
            headers={"Cache-Control": "private, no-store"},
        )


@router.post("/activity")
async def activity(request: Request):
    with request.app.state.db.transaction() as conn:
        _, session = authenticate(conn, request, mutation=True)
        conn.execute(
            "UPDATE auth_sessions SET activity_at=clock_timestamp() WHERE handle_hash=%s",
            (session["handle_hash"],),
        )
    await refresh_session(request)
    return JSONResponse(
        {"data": {"accepted": True}, "meta": {}}, headers={"Cache-Control": "private, no-store"}
    )


@router.post("/logout")
async def logout(request: Request):
    with request.app.state.db.transaction() as conn:
        _guard(conn, exclusive=True)
        _, session = authenticate(conn, request, mutation=True)
        conn.execute(
            "UPDATE auth_sessions SET revoked_at=clock_timestamp(),tokens=NULL WHERE handle_hash=%s",
            (session["handle_hash"],),
        )
        conn.execute(
            """INSERT INTO logout_fences(issuer,sid,event_id,expires_at)
                     VALUES(%s,%s,%s,clock_timestamp()+interval '24 hours 5 minutes') ON CONFLICT DO NOTHING""",
            (
                session["issuer"],
                session["provider_sid"],
                "local:" + bytes(session["handle_hash"]).hex(),
            ),
        )
    provider_url = None
    if session["tokens"]:
        try:
            tokens = json.loads(
                request.app.state.settings.cipher().open(
                    bytes(session["tokens"]),
                    "session-tokens:" + bytes(session["handle_hash"]).hex(),
                )
            )
            provider_url = await oidc_client(request).logout_url(tokens["id_token"])
        except (OIDCUnavailable, AppError, KeyError):
            provider_url = None
    response = JSONResponse(
        {
            "data": {
                "signed_out": True,
                "logout_url": provider_url,
                "provider_logout_completed": False,
            },
            "meta": {},
        },
        headers={"Cache-Control": "private, no-store"},
    )
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response


@router.post("/backchannel-logout")
async def backchannel_logout(request: Request):
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip()
        != "application/x-www-form-urlencoded"
    ):
        raise AppError("invalid_logout_request", "Form-encoded logout token is required.", 400)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 65536:
            raise AppError("body_too_large", "The request exceeds the body limit.", 413)
    try:
        values = parse_qs(body.decode("utf-8"), strict_parsing=True, max_num_fields=2)
        if set(values) != {"logout_token"} or len(values["logout_token"]) != 1:
            raise ValueError()
        event = await oidc_client(request).validate_logout_token(values["logout_token"][0])
    except (ValueError, UnicodeError, OIDCInvalid, OIDCUnavailable) as exc:
        raise _protocol_error(exc) from None
    with request.app.state.db.transaction() as conn:
        _guard(conn, exclusive=True)
        if event.subject:
            mismatch = conn.execute(
                "SELECT 1 FROM auth_sessions WHERE issuer=%s AND provider_sid=%s AND subject<>%s",
                (event.issuer, event.sid, event.subject),
            ).fetchone()
            if mismatch:
                raise AppError(
                    "invalid_logout_binding", "Provider session binding does not match.", 400
                )
        conn.execute(
            """INSERT INTO logout_fences(issuer,sid,event_id,expires_at) VALUES(%s,%s,%s,%s)
                     ON CONFLICT DO NOTHING""",
            (event.issuer, event.sid, event.jti, datetime.fromtimestamp(event.fence_until, UTC)),
        )
        conn.execute(
            """UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()),tokens=NULL
                     WHERE issuer=%s AND provider_sid=%s""",
            (event.issuer, event.sid),
        )
    return JSONResponse({}, headers={"Cache-Control": "private, no-store"})
