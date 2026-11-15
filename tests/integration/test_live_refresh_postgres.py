"""SSE refresh units against real PostgreSQL grants, sessions, RLS and restore guard."""

from contextlib import contextmanager
import hashlib
import os
import secrets
from types import SimpleNamespace
from uuid import uuid4

import pytest

from keep.db import Database
from keep.identity.authentication import SESSION_COOKIE
from keep.live import LiveRegistry, refresh, state
from keep.shared.errors import AppError

pytestmark = pytest.mark.integration


class ApiDatabase:
    """The guarded API pool, narrowed to the API role so tenant RLS applies."""

    def __init__(self, database):
        self.database = database
        self.units = []

    @contextmanager
    def transaction(self, tenant_id=None, *, read_committed=False):
        self.units.append((tenant_id, read_committed))
        with self.database.transaction(tenant_id, read_committed=read_committed) as conn:
            conn.execute("SET LOCAL ROLE keep_api")
            yield conn


@pytest.fixture
def stream(real_db, tenant):
    principal, handle = uuid4(), secrets.token_urlsafe(32)
    hashed = hashlib.sha256(handle.encode()).digest()
    with real_db.transaction() as conn:
        conn.execute("UPDATE capability_gates SET ready=true WHERE capability='human_auth'")
        conn.execute(
            "INSERT INTO principals(id,directory_source,object_id,kind,display_name,eligible,evidence_generation,verified_at) VALUES(%s,'test',%s,'user','Synthetic user',true,1,clock_timestamp())",
            (principal, str(principal)),
        )
        conn.execute(
            "INSERT INTO tenant_grants(tenant_id,principal_id,role) VALUES(%s,%s,'view')",
            (tenant, principal),
        )
        conn.execute(
            "INSERT INTO auth_sessions(handle_hash,principal_id,csrf_hash,csrf_cipher,auth_time,absolute_at,deployment_epoch) VALUES(%s,%s,%s,%s,clock_timestamp(),clock_timestamp()+interval '1 day','test')",
            (hashed, principal, hashlib.sha256(b"csrf").digest(), b"unused"),
        )
    database = Database(os.environ["KEEP_TEST_DATABASE_URL"], deployment_epoch="test")
    api = ApiDatabase(database)
    registry = LiveRegistry()
    registry.register(str(tenant))
    request = SimpleNamespace(
        cookies={SESSION_COOKIE: handle},
        app=SimpleNamespace(
            state=SimpleNamespace(
                db=api, live_registry=registry, settings=SimpleNamespace(deployment_epoch="test")
            )
        ),
    )
    try:
        yield SimpleNamespace(request=request, api=api, registry=registry, hashed=hashed, principal=principal)
    finally:
        database.close()
        with real_db.transaction() as conn:
            conn.execute("DELETE FROM auth_sessions WHERE handle_hash=%s", (hashed,))
            conn.execute("DELETE FROM tenant_grants WHERE principal_id=%s", (principal,))


def expire(registry, tenant):
    registry.entries[tenant]["expires"] = 0


def test_refresh_reconciles_reauthorizes_and_cuts_off_revocation(stream, real_db, tenant):
    request, api, registry, key = stream.request, stream.api, stream.registry, str(tenant)
    current = state(request, key)
    generation = current["view_generation"]
    assert api.units == [(None, True)]

    # A fresh unchanged vector costs no transaction.
    assert refresh(request, key, generation, False) == (current, False)
    assert len(api.units) == 1

    # Due reconciliation reads through tenant RLS in one guarded, scoped unit.
    expire(registry, key)
    assert refresh(request, key, generation, False) == (current, False)
    assert api.units[1:] == [(key, False)]

    with real_db.transaction() as conn:
        conn.execute(
            "UPDATE tenant_view_state SET view_generation=view_generation+1 WHERE tenant_id=%s",
            (tenant,),
        )
    expire(registry, key)
    changed, reauthorized = refresh(request, key, generation, False)
    assert changed["view_generation"] != generation and reauthorized

    assert refresh(request, key, changed["view_generation"], True) == (changed, True)

    with real_db.transaction() as conn:
        conn.execute("UPDATE auth_sessions SET revoked_at=clock_timestamp() WHERE handle_hash=%s", (stream.hashed,))
    # The cached vector alone never needs authority; the due check ends the stream.
    assert refresh(request, key, changed["view_generation"], False) == (changed, False)
    with pytest.raises(AppError) as error:
        refresh(request, key, changed["view_generation"], True)
    assert error.value.status == 401


def test_lost_grant_stops_delivery_of_a_changed_vector(stream, real_db, tenant):
    request, registry, key = stream.request, stream.registry, str(tenant)
    generation = state(request, key)["view_generation"]
    with real_db.transaction() as conn:
        conn.execute("DELETE FROM tenant_grants WHERE principal_id=%s", (stream.principal,))
        conn.execute(
            "UPDATE tenant_view_state SET view_generation=view_generation+1 WHERE tenant_id=%s",
            (tenant,),
        )
    expire(registry, key)
    with pytest.raises(AppError) as error:
        refresh(request, key, generation, False)
    assert error.value.status == 404
