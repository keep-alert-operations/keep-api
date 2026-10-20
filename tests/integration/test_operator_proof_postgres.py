"""Real SQL/role verification in a uniquely owned disposable PostgreSQL database."""

from hashlib import sha256
import os
import secrets
from types import SimpleNamespace
from uuid import uuid4

import httpx
import psycopg
from pydantic import SecretStr
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
import pytest

from appchi.operators.proof import (
    ProofConfiguration, ProofDatabase, ProofFailure, ProofRequest, ProofService, create_app,
)
from appchi.operators.worker import policy_document
from appchi.recovery.guard import RESTORE_LOCK


pytestmark = pytest.mark.integration


def member_configuration():
    return ProofConfiguration(ca_file="unused-fixture", members=[{
        "member_id": "node", "policy_url": "https://member.test/policy", "auth_url": "https://member.test/auth"}])


@pytest.fixture(scope="module")
def isolated():
    admin_url = os.getenv("APPCHI_PROOF_TEST_POSTGRES_ADMIN_DSN")
    if not admin_url:
        pytest.skip("Bind APPCHI_PROOF_TEST_POSTGRES_ADMIN_DSN to isolated PostgreSQL")
    from appchi.migrate import migrate

    database, login = "proof_test_" + uuid4().hex, "proof_login_" + uuid4().hex
    password = secrets.token_urlsafe(32)
    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    admin_options = conninfo_to_dict(admin_url)
    admin_options["dbname"] = database
    owner_url = make_conninfo(**admin_options)
    try:
        migrate(owner_url)
        with psycopg.connect(owner_url, autocommit=True) as owner:
            owner.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} IN ROLE appchi_worker").format(
                sql.Identifier(login), sql.Literal(password)))
            owner.execute(sql.SQL("ALTER ROLE {} SET default_transaction_read_only=on").format(
                sql.Identifier(login)))
        runtime_options = {**admin_options, "user": login, "password": password}
        yield SecretStr(owner_url), SecretStr(make_conninfo(**runtime_options))
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database)))
            admin.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(login)))


@pytest.fixture
def prepared(isolated):
    owner_url, runtime_url = isolated
    operator, credential, operation, lease = [uuid4() for _ in range(4)]
    key = "vena_" + secrets.token_urlsafe(32)
    with psycopg.connect(owner_url.get_secret_value(), row_factory=dict_row, autocommit=True) as conn:
        tenant = conn.execute("SELECT id FROM tenants WHERE kind='global'").fetchone()["id"]
        conn.execute("UPDATE restore_control SET deployment_epoch=NULL,fenced=false WHERE singleton")
        conn.execute("""INSERT INTO operators(id,tenant_id,name,name_key,lifecycle,generation)
                     VALUES(%s,%s,%s,%s,'setup_pending',7)""", (operator, tenant, str(operator), str(operator)))
        conn.execute("""INSERT INTO operator_credentials(id,tenant_id,operator_id,state,verifier)
                     VALUES(%s,%s,%s,'current',%s)""", (credential, tenant, operator, sha256(key.encode()).digest()))
        conn.execute("""INSERT INTO operator_operations(id,tenant_id,operator_id,kind,generation,state,
                     actor_label,lease_token,lease_until,progress)
                     VALUES(%s,%s,%s,'setup',7,'running','proof-test',%s,
                     clock_timestamp()+interval '45 seconds',%s)""",
                     (operation, tenant, operator, lease, Jsonb({"executor": {"binding_digest": "binding"}})))
        conn.execute("""UPDATE operator_routing_guard SET lease_token=%s,
                     lease_until=clock_timestamp()+interval '45 seconds' WHERE scope='grafana'""", (lease,))
        conn.execute("""INSERT INTO operator_remote_bindings(tenant_id,operator_id,kind,remote_id,generation,verified_at)
                     VALUES(%s,%s,'executor_profile','binding',7,clock_timestamp())""", (tenant, operator))
        op = conn.execute("SELECT * FROM operators WHERE id=%s", (operator,)).fetchone()
        rows = conn.execute("SELECT * FROM operator_credentials WHERE operator_id=%s", (operator,)).fetchall()
        conn.execute("INSERT INTO operator_gateway_policies(operator_id,generation,document) VALUES(%s,12,%s)",
                     (operator, policy_document(op, rows)))
    body = ProofRequest(operator_id=operator, consumer_id=operator, credential_id=credential,
                        generation="7", policy_generation="12", nonce="integration-nonce", key=key,
                        expected_allowed=True)
    db = ProofDatabase(runtime_url.get_secret_value(), "test-epoch", "binding")
    # The runtime startup is intentionally asynchronous; wait only for this private test pool.
    with db.pool.connection(timeout=15):
        pass
    try:
        yield db, body, owner_url
    finally:
        db.close()


def test_real_worker_inherited_role_reads_and_cannot_write(prepared):
    db, body, _ = prepared
    snapshot = db.snapshot(body)
    assert snapshot.allowed and snapshot.fence[-1] is None
    with db.pool.connection() as conn:
        assert conn.execute("SHOW default_transaction_read_only").fetchone()["default_transaction_read_only"] == "on"
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction), conn.transaction():
            conn.execute("UPDATE operator_routing_guard SET lease_until=clock_timestamp() WHERE scope='grafana'")


@pytest.mark.asyncio
async def test_real_startup_establishes_pool_before_readiness(isolated):
    _, runtime_url = isolated
    database = ProofDatabase(runtime_url.get_secret_value(), "test-epoch", "binding")
    service = ProofService(member_configuration(), SimpleNamespace(serving_members=["node"]),
                           database, "fixture-token", "fixture-gateway",
                           client=httpx.AsyncClient(transport=httpx.MockTransport(lambda req: pytest.fail("No startup gateway call"))))
    app = create_app(service)
    async with app.router.lifespan_context(app):
        assert database.pool.get_stats()["pool_available"] == 1
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://proof.test") as client:
            assert (await client.get("/readyz")).status_code == 200
        with database.pool.connection() as conn:
            assert conn.execute("SHOW default_transaction_read_only").fetchone()["default_transaction_read_only"] == "on"
    assert database.pool.closed and service.client.is_closed


@pytest.mark.parametrize("mutation", [
    "UPDATE operators SET generation=generation+1 WHERE id=%s",
    "UPDATE operator_operations SET lease_until=clock_timestamp()-interval '1 second' WHERE operator_id=%s",
    "UPDATE operator_gateway_policies SET document='{}' WHERE operator_id=%s",
    "UPDATE operator_remote_bindings SET remote_id='changed' WHERE operator_id=%s",
])
def test_real_sql_rejects_stale_operation_or_policy(prepared, mutation):
    db, body, owner_url = prepared
    assert db.snapshot(body).allowed
    with psycopg.connect(owner_url.get_secret_value()) as owner:
        owner.execute(mutation, (body.operator_id,))
    with pytest.raises(ProofFailure):
        db.snapshot(body)


def test_real_restore_lock_epoch_and_fence(prepared):
    db, body, owner_url = prepared
    with psycopg.connect(owner_url.get_secret_value(), autocommit=True) as owner:
        owner.execute("SELECT pg_advisory_lock(%s)", (RESTORE_LOCK,))
        try:
            with pytest.raises(ProofFailure, match="restore_fenced"):
                db.snapshot(body)
        finally:
            owner.execute("SELECT pg_advisory_unlock(%s)", (RESTORE_LOCK,))
        owner.execute("UPDATE restore_control SET deployment_epoch='old' WHERE singleton")
        with pytest.raises(ProofFailure, match="restore_fenced"):
            db.snapshot(body)
        owner.execute("UPDATE restore_control SET deployment_epoch='test-epoch',fenced=true WHERE singleton")
        with pytest.raises(ProofFailure, match="restore_fenced"):
            db.snapshot(body)


@pytest.mark.asyncio
async def test_real_sql_change_during_member_probe_invalidates_response(prepared):
    db, body, owner_url = prepared
    before = db.snapshot(body)
    changed = False
    # Establish the fixture writer before starting the HTTP deadline. This test
    # proves an in-flight authority change, not workstation TLS startup latency.
    writer = psycopg.connect(owner_url.get_secret_value(), autocommit=True)

    def gateway(req):
        nonlocal changed
        if not changed:
            writer.execute("UPDATE operators SET revision=revision+1 WHERE id=%s", (body.operator_id,))
            changed = True
        return httpx.Response(200, json={
            "member_id": "node", "operator_id": str(body.operator_id), "tenant_id": before.tenant_id,
            "credential_id": str(body.credential_id), "generation": body.policy_generation,
            "policy_digest": before.digest, "version": "1.0.0", "expires_at": None,
            "state": "current", "routing_names": list(before.routing_names), "allowed": True,
            "admitted": False, "nonce": body.nonce,
        })

    service = ProofService(member_configuration(), SimpleNamespace(serving_members=["node"]), db, "fixture-token", "fixture-gateway",
                           client=httpx.AsyncClient(transport=httpx.MockTransport(gateway)))
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(service)), base_url="https://proof.test") as client:
            response = await client.post("/operator-check", json=body.model_dump(mode="json"),
                                         headers={"Authorization": "Bearer fixture-token"})
    finally:
        await service.client.aclose()
        writer.close()
    assert response.status_code == 409 and response.json() == {"error": "stale_proof"}
