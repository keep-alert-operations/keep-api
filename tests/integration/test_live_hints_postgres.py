"""Batched hint deletion against real PostgreSQL grants, RLS and the restore guard."""

from contextlib import contextmanager
import os
from threading import Event
import time
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

from appchi.db import Database
from appchi.live import publish_hints

pytestmark = pytest.mark.integration


class ApiDatabase:
    """The guarded API pool, narrowed to the API role that publishes hints."""

    def __init__(self, database):
        self.database = database
        self.units = []

    @contextmanager
    def transaction(self, tenant_id=None, *, read_committed=False):
        self.units.append((tenant_id, read_committed))
        with self.database.transaction(tenant_id, read_committed=read_committed) as conn:
            conn.execute("SET LOCAL ROLE appchi_api")
            yield conn


def create_tenant(conn):
    tenant = uuid4()
    conn.execute(
        "INSERT INTO tenants(id,kind,name,name_key) VALUES(%s,'specific',%s,%s)",
        (tenant, str(tenant), str(tenant)),
    )
    conn.execute("INSERT INTO tenant_work_state(tenant_id) VALUES(%s)", (tenant,))
    conn.execute("INSERT INTO tenant_view_state(tenant_id) VALUES(%s)", (tenant,))
    return tenant


def bump(real_db, tenant):
    with real_db.transaction() as conn:
        conn.execute(
            "UPDATE tenant_view_state SET view_generation=view_generation+1 WHERE tenant_id=%s",
            (tenant,),
        )


def pending(real_db):
    with real_db.transaction() as conn:
        rows = conn.execute("SELECT tenant_id,generation FROM live_hint_outbox").fetchall()
    return {row["tenant_id"]: row["generation"] for row in rows}


def test_batch_delete_removes_only_the_published_generations(real_db):
    with real_db.transaction() as conn:
        conn.execute("DELETE FROM live_hint_outbox")
        tenants = [create_tenant(conn) for _ in range(3)]
        conn.execute("DELETE FROM live_hint_outbox")
    # Separate commits order the outbox: concurrent, published, unpublished.
    for tenant in tenants:
        bump(real_db, tenant)
    concurrent, published, unpublished = tenants
    before = pending(real_db)
    assert set(before) == set(tenants)

    stop = Event()

    class Publisher:
        calls = []

        def publish(self, channel, data):
            self.calls.append((channel, data))
            if str(concurrent) in channel:
                # A newer invalidation commits after its hint was read and sent.
                bump(real_db, concurrent)
            if len(self.calls) == 2:
                stop.set()

    database = Database(os.environ["APPCHI_TEST_DATABASE_URL"], deployment_epoch="test")
    api = ApiDatabase(database)
    try:
        assert publish_hints(api, SimpleNamespace(environment="test"), Publisher(), stop=stop) == 2
    finally:
        database.close()
    assert [channel.rsplit(".", 1)[1] for channel, _ in Publisher.calls] == [
        str(concurrent),
        str(published),
    ]
    # One read unit and one delete unit, both unscoped and READ COMMITTED.
    assert api.units == [(None, True), (None, True)]
    assert pending(real_db) == {
        concurrent: before[concurrent] + 1,
        unpublished: before[unpublished],
    }


def test_locked_published_row_defers_the_delete_within_the_lock_timeout(real_db):
    with real_db.transaction() as conn:
        conn.execute("DELETE FROM live_hint_outbox")
        tenants = [create_tenant(conn) for _ in range(2)]
    for tenant in tenants:
        bump(real_db, tenant)
    before = pending(real_db)
    assert set(before) == set(tenants)

    class Publisher:
        calls = []

        def publish(self, channel, data):
            self.calls.append(channel)

    database = Database(os.environ["APPCHI_TEST_DATABASE_URL"], deployment_epoch="test")
    api = ApiDatabase(database)
    # A multi-tenant view-state writer holds one published row (as the 0020 trigger
    # upsert would) until after the API's DELETE has given up.
    with psycopg.connect(os.environ["APPCHI_TEST_DATABASE_URL"]) as writer:
        writer.execute(
            "SELECT 1 FROM live_hint_outbox WHERE tenant_id=%s FOR UPDATE", (tenants[1],)
        )
        started = time.monotonic()
        try:
            published = publish_hints(api, SimpleNamespace(environment="test"), Publisher())
        finally:
            elapsed = time.monotonic() - started
            writer.rollback()
    try:
        assert published == 2 and len(Publisher.calls) == 2
        # 200 ms lock timeout, far below the 2 s default and the 1 s deadlock_timeout.
        assert elapsed < 1.5
        # The statement is atomic: both rows stay pending for the next turn.
        assert pending(real_db) == before
        Publisher.calls.clear()
        assert publish_hints(api, SimpleNamespace(environment="test"), Publisher()) == 2
        assert pending(real_db) == {}
    finally:
        database.close()
