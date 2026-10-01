"""PostgreSQL-authoritative human sessions and backend-only authentication routes."""

from __future__ import annotations

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
    OIDCInvalid,
    OIDCUnavailable,
)

from appchi.identity.authentication import (
    _hash as _hash,
    _guard as _guard,
    require_human_auth as require_human_auth,
    same_origin as same_origin,
    authenticate as authenticate,
    oidc_client as oidc_client,
    _protocol_error as _protocol_error,
    _cookie as _cookie,
    refresh_session as refresh_session,
)

router = APIRouter(prefix="/auth", tags=["identity"])
SESSION_COOKIE = "__Host-appchi_session"
LOGIN_COOKIE = "__Host-appchi_login"


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
