"""Batched hint deletion against real PostgreSQL grants, RLS and the restore guard."""

from contextlib import contextmanager
import os
from threading import Event, Thread
import time
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest

from appchi.db import Database
from appchi import live
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


def test_batch_delete_removes_only_the_published_generations(real_db, monkeypatch):
    # Only stop may end this pass: on a loaded host the publisher's own commit can
    # outlast the 1 s publication deadline and leave the second row unpublished.
    monkeypatch.setattr(live, "time", SimpleNamespace(monotonic=lambda: 0.0))
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


def test_delete_holds_taken_row_locks_no_longer_than_the_statement_timeout(real_db):
    """A chain of short lock waits must not extend how long the DELETE holds a row.

    Each outside writer holds one published row for under the 200 ms lock_timeout:
    the first releases as soon as the DELETE is seen holding a row, and each next
    one 150 ms after the previous, so every later wait starts at a known time.
    Without a statement bound the DELETE holds that row until the last release
    (at least 600 ms), however slow the setup was.
    """
    # A fresh heap holds the rows in insertion order (no updates, no reused line
    # pointers), so a sequential scan reaches the free rows before the chain.
    with real_db.transaction() as conn:
        conn.execute("TRUNCATE live_hint_outbox")
        tenants = [create_tenant(conn) for _ in range(7)]
    free, chain = tenants[:2], tenants[2:]
    before = pending(real_db)
    assert set(before) == set(tenants)
    dsn = os.environ["APPCHI_TEST_DATABASE_URL"]
    lock = "SELECT 1 FROM live_hint_outbox WHERE tenant_id=%s FOR UPDATE"

    holders = [psycopg.connect(dsn) for _ in chain]
    for holder, tenant in zip(holders, chain):
        holder.execute(lock, (tenant,))

    def release_one_by_one():
        for holder in holders:
            holder.rollback()
            time.sleep(0.15)

    database = Database(dsn, deployment_epoch="test")
    api = ApiDatabase(database)
    outcome = {}

    def publish():
        publisher = SimpleNamespace(publish=lambda channel, data: None)
        try:
            outcome["published"] = publish_hints(
                api, SimpleNamespace(environment="test"), publisher
            )
        except BaseException as error:  # Reported by the assertion below.
            outcome["error"] = error

    worker, releaser = Thread(target=publish), Thread(target=release_one_by_one)
    try:
        with (
            psycopg.connect(dsn, autocommit=True) as monitor,
            psycopg.connect(dsn) as other,
        ):
            worker.start()
            deadline = time.monotonic() + 10
            while not monitor.execute(
                "SELECT 1 FROM pg_stat_activity WHERE pid<>pg_backend_pid() "
                "AND query LIKE 'DELETE FROM live_hint_outbox%' AND wait_event_type='Lock'"
            ).fetchone():
                assert time.monotonic() < deadline, "the DELETE never waited on the chain"
                time.sleep(0.002)
            # Find a published row the DELETE already holds, whatever its plan order.
            held = None
            for tenant in free:
                try:
                    other.execute(lock + " NOWAIT", (tenant,))
                except psycopg.errors.LockNotAvailable:
                    held = tenant
                finally:
                    other.rollback()
                if held:
                    break
            assert held, "the DELETE held no free published row when it first waited"
            releaser.start()
            started = time.monotonic()
            other.execute(lock, (held,))
            waited = time.monotonic() - started
            other.rollback()
    finally:
        worker.join(10)
        if releaser.ident:
            releaser.join(10)
        for holder in holders:
            holder.close()
        database.close()
    assert "error" not in outcome and outcome["published"] == len(tenants)
    # A blocked writer gets the row within the 200 ms statement bound, plus slack.
    assert waited < 0.35
    # The cancelled DELETE rolled back: every row stays pending for the next turn.
    assert pending(real_db) == before
