"""Private, request-owned proof of a fixed and explicitly qualified Kong pool.

No ingestion, migrations, secret decryption, remote writes or background retries.
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import ssl
import time
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from keep.operators.binding import OperatorBinding
from keep.operators.worker import policy_document
from keep.recovery.guard import RESTORE_LOCK


class ProofFailure(Exception):
    def __init__(self, code="proof_unavailable", status=503):
        self.code, self.status = code, status
        super().__init__(code)


def require(value, code="stale_proof", status=409):
    if not value:
        raise ProofFailure(code, status)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProofRequest(Strict):
    operator_id: UUID
    consumer_id: UUID
    credential_id: UUID
    generation: str = Field(pattern=r"^[1-9][0-9]{0,18}$")
    policy_generation: str = Field(pattern=r"^[1-9][0-9]{0,15}$")
    nonce: str = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")
    key: str | None = Field(default=None, pattern=r"^vena_[A-Za-z0-9_-]{43}$", repr=False)
    expected_allowed: StrictBool


class Member(Strict):
    member_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    policy_url: str
    auth_url: str

    @field_validator("policy_url", "auth_url")
    @classmethod
    def endpoint(cls, value):
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port == 0
                or parsed.username
                or parsed.password or parsed.query or parsed.fragment or ".." in parsed.path
                or "\\" in value or any(c.isspace() for c in value) or not parsed.path):
            raise ValueError("Explicit direct HTTPS proof endpoint required")
        return value

    @model_validator(mode="after")
    def same_origin(self):
        first, second = urlsplit(self.policy_url), urlsplit(self.auth_url)
        if first.netloc != second.netloc or first.path == second.path:
            raise ValueError("Distinct proof paths on the same direct member origin required")
        return self


class ProofConfiguration(Strict):
    schema_version: int = Field(default=1, ge=1, le=1)
    ca_file: str = Field(min_length=1)
    members: list[Member] = Field(min_length=1, max_length=16)
    deadline_seconds: float = Field(default=1.5, ge=0.2, le=1.5)
    max_response_bytes: int = Field(default=8192, ge=1024, le=16384)
    max_inflight: int = Field(default=2, ge=1, le=4)

    @model_validator(mode="after")
    def fixed_pool(self):
        if len({m.member_id for m in self.members}) != len(self.members):
            raise ValueError("Duplicate member identity")
        if len({(urlsplit(m.policy_url).hostname, urlsplit(m.policy_url).port or 443)
                for m in self.members}) != len(self.members):
            raise ValueError("Every member needs a distinct direct origin")
        return self


@dataclass(frozen=True)
class Snapshot:
    fence: tuple
    tenant_id: str
    digest: str
    allowed: bool
    state: str
    expires_at: float | None
    routing_names: tuple[str, ...]


def read_snapshot(conn, body, binding_digest, epoch):
    """One bounded read-only snapshot; caller never holds it during network I/O."""
    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    conn.execute("SET LOCAL statement_timeout = '250ms'")
    conn.execute("SET LOCAL lock_timeout = '100ms'")
    locked = conn.execute(
        "SELECT pg_try_advisory_xact_lock_shared(%s) AS acquired", (RESTORE_LOCK,)
    ).fetchone()
    require(locked and locked["acquired"], "restore_fenced", 503)
    control = conn.execute(
        "SELECT deployment_epoch,fenced FROM restore_control WHERE singleton"
    ).fetchone()
    require(control and not control["fenced"]
            and control["deployment_epoch"] in (None, epoch),
            "restore_fenced", 503)
    operator = conn.execute("SELECT * FROM operators WHERE id=%s", (body.operator_id,)).fetchone()
    require(operator and body.operator_id == body.consumer_id
            and str(operator["generation"]) == body.generation)
    job = conn.execute(
        """SELECT id,generation,lease_token,lease_until,state,completed_at,
           progress->'executor'->>'binding_digest' AS binding_digest
           FROM operator_operations WHERE operator_id=%s AND completed_at IS NULL""",
        (body.operator_id,),
    ).fetchone()
    guard = conn.execute(
        "SELECT lease_token,lease_until FROM operator_routing_guard WHERE scope='grafana'"
    ).fetchone()
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    require(job and guard and job["state"] == "running" and job["completed_at"] is None
            and str(job["generation"]) == body.generation and job["lease_token"]
            and job["lease_until"] and job["lease_until"] > now
            and guard["lease_token"] == job["lease_token"]
            and guard["lease_until"] and guard["lease_until"] > now
            and job["binding_digest"] == binding_digest)
    binding = conn.execute(
        "SELECT remote_id FROM operator_remote_bindings WHERE operator_id=%s AND kind='executor_profile'",
        (body.operator_id,),
    ).fetchone()
    require(binding and binding["remote_id"] == binding_digest)
    rows = conn.execute(
        """SELECT id,state,expires_at,verifier FROM operator_credentials
           WHERE operator_id=%s AND tenant_id=%s
           AND (state IN ('prepared','current','retiring') OR id=%s) LIMIT 1001""",
        (body.operator_id, operator["tenant_id"], body.credential_id),
    ).fetchall()
    require(len(rows) <= 1000, "policy_limit_exceeded", 503)
    credential = next((r for r in rows if r["id"] == body.credential_id), None)
    require(credential is not None)
    if body.key is not None:
        require(secrets.compare_digest(sha256(body.key.encode("ascii")).digest(),
                                       bytes(credential["verifier"])), "credential_mismatch", 409)
    policy = conn.execute(
        """SELECT generation,CASE WHEN octet_length(document)<=65536 THEN document END AS document
           FROM operator_gateway_policies WHERE operator_id=%s""",
        (body.operator_id,),
    ).fetchone()
    require(policy and str(policy["generation"]) == body.policy_generation)
    expected_document = policy_document(operator, rows)
    require(policy["document"] == expected_document)
    document = json.loads(expected_document)
    selected = document["credentials"].get(str(body.credential_id), {})
    expiry = selected.get("expires_at")
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    require(job["lease_until"] > now and guard["lease_until"] > now)
    allowed = bool(document["enabled"] and selected.get("state") in ("current", "retiring")
                   and (selected.get("state") != "retiring" or expiry is not None)
                   and (expiry is None or now.timestamp() < expiry))
    require(allowed is body.expected_allowed)
    digest = sha256(expected_document.encode()).hexdigest()
    return Snapshot(
        (str(job["id"]), str(job["lease_token"]), str(operator["revision"]),
         body.generation, body.policy_generation, digest, epoch, control["deployment_epoch"]),
        str(operator["tenant_id"]), digest, allowed, selected.get("state", "inactive"),
        expiry, tuple(document["routing_names"]),
    )


class ProofDatabase:
    """Small read-only pool, without service startup/migration/worker side effects."""
    def __init__(self, url, epoch, binding_digest):
        self.epoch, self.binding_digest = epoch, binding_digest
        self.pool = ConnectionPool(
            url, min_size=1, max_size=2, timeout=0.2, open=True,
            kwargs={"row_factory": dict_row, "connect_timeout": 2,
                    "options": "-c default_transaction_read_only=on"},
        )

    def startup(self):
        self.pool.wait(timeout=10)

    def snapshot(self, body):
        with self.pool.connection(timeout=0.2) as conn, conn.transaction():
            return read_snapshot(conn, body, self.binding_digest, self.epoch)

    def close(self):
        self.pool.close()


class ProofService:
    def __init__(self, configuration, binding, database, token, gateway_token, *, client=None):
        require({m.member_id for m in configuration.members} == set(binding.serving_members),
                "serving_pool_mismatch", 503)
        require(bool(token) and bool(gateway_token), "proof_configuration_invalid", 503)
        self.configuration, self.database = configuration, database
        self.token, self.gateway_token = token, gateway_token
        self.inflight = asyncio.Semaphore(configuration.max_inflight)
        self.client = client or httpx.AsyncClient(
            verify=ssl.create_default_context(cafile=configuration.ca_file),
            trust_env=False, follow_redirects=False,
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        )

    async def close(self):
        try:
            await self.client.aclose()
        finally:
            self.database.close()

    async def remote(self, url, body, deadline, *, key=None):
        require(time.monotonic() < deadline, "proof_deadline", 503)
        headers = {"X-Keep-Probe-Token": self.gateway_token, "Accept": "application/json",
                   "Accept-Encoding": "identity",
                   "Cache-Control": "no-store"}
        if key is not None:
            headers["X-API-Key"] = key
        async with self.client.stream(
            "POST", url, headers=headers, json=body, follow_redirects=False,
            timeout=min(0.5, max(0.001, deadline - time.monotonic())),
        ) as response:
            require(response.headers.get("content-encoding", "identity") == "identity",
                    "member_response_invalid", 503)
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw.extend(chunk)
                require(len(raw) <= self.configuration.max_response_bytes
                        and time.monotonic() < deadline, "member_response_invalid", 503)
            if response.status_code == 401:
                return 401, None
            require(response.status_code == 200, "member_unavailable", 503)
            try:
                parsed = json.loads(raw)
            except ValueError:
                raise ProofFailure("member_response_invalid") from None
            require(isinstance(parsed, dict), "member_response_invalid", 503)
            return 200, parsed

    def verified(self, observed, member, body, snapshot, *, nonce=False):
        required = {
            "member_id": member.member_id, "operator_id": str(body.operator_id),
            "tenant_id": snapshot.tenant_id, "credential_id": str(body.credential_id),
            "generation": body.policy_generation, "policy_digest": snapshot.digest,
            "version": "1.0.0", "expires_at": snapshot.expires_at, "state": snapshot.state,
            "routing_names": list(snapshot.routing_names),
        }
        require(isinstance(observed, dict)
                and all(observed.get(k) == v for k, v in required.items())
                and observed.get("allowed") is snapshot.allowed
                and observed.get("admitted") is False
                and (not nonce or observed.get("nonce") == body.nonce),
                "member_proof_invalid", 503)

    async def member(self, member, body, snapshot, deadline):
        status, observed = await self.remote(member.policy_url, {
            "operator_id": str(body.operator_id), "credential_id": str(body.credential_id),
            "nonce": body.nonce,
        }, deadline)
        require(status == 200, "member_proof_invalid", 503)
        self.verified(observed, member, body, snapshot, nonce=True)
        if body.key is not None:
            status, authenticated = await self.remote(member.auth_url, {}, deadline, key=body.key)
            if snapshot.allowed:
                require(status == 200, "member_auth_proof_invalid", 503)
                self.verified(authenticated, member, body, snapshot)
            else:
                require(status == 401, "member_denial_unproven", 503)
        # Whitelist fields: never forward a remote body, header, error or raw key.
        return {
            "member_id": member.member_id, "ready": True,
            "consumer_id": str(body.operator_id), "operator_id": str(body.operator_id),
            "credential_id": str(body.credential_id), "tenant_id": snapshot.tenant_id,
            "policy_generation": body.policy_generation, "allowed": snapshot.allowed,
            "policy_digest": snapshot.digest, "expires_at": snapshot.expires_at,
            "version": "1.0.0", "authentication_checked": body.key is not None,
        }

    async def prove(self, body):
        # A bounded queue avoids unbounded authenticated resource consumption.
        try:
            async with asyncio.timeout(0.05):
                await self.inflight.acquire()
        except TimeoutError:
            raise ProofFailure("proof_busy") from None
        try:
            async with asyncio.timeout(self.configuration.deadline_seconds):
                deadline = time.monotonic() + self.configuration.deadline_seconds
                before = await asyncio.to_thread(self.database.snapshot, body)
                tasks = [asyncio.create_task(self.member(m, body, before, deadline))
                         for m in self.configuration.members]
                try:
                    members = await asyncio.gather(*tasks)
                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                after = await asyncio.to_thread(self.database.snapshot, body)
                require(before == after)
                result = {"nonce": body.nonce, "generation": body.generation,
                          "admitted": False, "members": members}
                require(len(json.dumps(result).encode()) <= 32768, "proof_response_invalid", 503)
                return result
        finally:
            self.inflight.release()


def create_app(service):
    @asynccontextmanager
    async def lifespan(app):
        try:
            try:
                await asyncio.to_thread(service.database.startup)
            except Exception:
                raise RuntimeError("Operator proof startup unavailable.") from None
            yield
        finally:
            await service.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/readyz")
    async def ready():
        return {"scope": "operator-proof", "configured_members": len(service.configuration.members)}

    @app.post("/operator-check")
    async def proof(request: Request):
        authorization = request.headers.getlist("authorization")
        if len(authorization) != 1 or not secrets.compare_digest(
            authorization[0].encode(), ("Bearer " + service.token).encode()
        ):
            return JSONResponse({"error": "unauthorized"}, 401)
        try:
            raw = bytearray()
            async with asyncio.timeout(0.25):
                async for chunk in request.stream():
                    raw.extend(chunk)
                    require(len(raw) <= 4096, "invalid_proof", 422)
            try:
                body = ProofRequest.model_validate_json(raw)
            except ValueError:
                raise ProofFailure("invalid_proof", 422) from None
            result = await service.prove(body)
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except ProofFailure as exc:
            return JSONResponse({"error": exc.code}, exc.status,
                                headers={"Cache-Control": "no-store"})
        except Exception:
            # Never serialize validation input, HTTP exceptions, SQL errors or secrets.
            return JSONResponse({"error": "proof_unavailable"}, 503,
                                headers={"Cache-Control": "no-store"})

    return app


def load_service():
    configuration = ProofConfiguration.model_validate_json(
        Path(os.environ["KEEP_PROOF_CONFIG_FILE"]).read_text(encoding="utf-8")
    )
    binding = OperatorBinding.model_validate_json(
        Path(os.environ["KEEP_OPERATOR_BINDING"]).read_text(encoding="utf-8")
    )
    token = Path(os.environ["KEEP_PROOF_TOKEN_FILE"]).read_text().strip()
    gateway_token = Path(os.environ["KEEP_PROOF_GATEWAY_TOKEN_FILE"]).read_text().strip()
    require(32 <= len(token) <= 512 and 32 <= len(gateway_token) <= 512
            and token.isascii() and gateway_token.isascii()
            and not any(c.isspace() for c in token + gateway_token),
            "proof_configuration_invalid", 503)
    epoch = os.environ["KEEP_DEPLOYMENT_EPOCH"]
    require(1 <= len(epoch) <= 128, "proof_configuration_invalid", 503)
    database = ProofDatabase(os.environ["KEEP_PROOF_DATABASE_URL"], epoch, binding.digest())
    try:
        return ProofService(configuration, binding, database, token, gateway_token)
    except Exception:
        database.close()
        raise


def main():
    import uvicorn

    from keep.api_http import BoundedHttpToolsProtocol

    try:
        service = load_service()
        cert, key = os.environ["KEEP_PROOF_CERT_FILE"], os.environ["KEEP_PROOF_KEY_FILE"]
        port = int(os.getenv("KEEP_BIND_PORT", "8443"))
    except Exception:
        raise SystemExit("Operator proof configuration is invalid.") from None
    uvicorn.run(create_app(service), host=os.getenv("KEEP_BIND_HOST", "0.0.0.0"), port=port,
                ssl_certfile=cert, ssl_keyfile=key, http=BoundedHttpToolsProtocol,
                proxy_headers=False, access_log=False,
                limit_concurrency=16, timeout_keep_alive=2, timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()
