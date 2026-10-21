"""Redis hint listener pacing and batched outbox deletion, without Redis or PostgreSQL."""

import asyncio
from contextlib import contextmanager
from threading import Event
from types import SimpleNamespace
import time

import pytest

from appchi import live
from appchi.live import publish_hints, redis_listener

TENANTS = [f"00000000-0000-4000-8000-{n:012d}" for n in range(1, 4)]
SETTINGS = SimpleNamespace(
    environment="test", redis_url=SimpleNamespace(get_secret_value=lambda: "redis://unused")
)


def hint(tenant):
    return {"type": "pmessage", "channel": f"appchi.test.tenant.{tenant}".encode("ascii")}


class Subscription:
    """Replays scripted get_message results, then stops the listener."""

    def __init__(self, script):
        self.script = list(script)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def psubscribe(self, pattern):
        assert pattern == "appchi.test.tenant.*"

    async def get_message(self, *, ignore_subscribe_messages, timeout):
        if not self.script:
            raise asyncio.CancelledError
        return self.script.pop(0)


class Registry:
    def __init__(self):
        self.invalidated = []

    def invalidate(self, tenant):
        self.invalidated.append(tenant)


async def listen(monkeypatch, script):
    subscription = Subscription(script)

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def pubsub(self):
            return subscription

    class Redis:
        @staticmethod
        def from_url(*args, **kwargs):
            return Client()

    sleeps = []
    real_sleep = asyncio.sleep

    async def sleep(delay):
        sleeps.append(delay)
        await real_sleep(delay)

    monkeypatch.setattr("redis.asyncio.Redis", Redis)
    monkeypatch.setattr(live.asyncio, "sleep", sleep)
    registry = Registry()
    started = time.monotonic()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(redis_listener(SETTINGS, registry), 5)
    return registry.invalidated, sleeps, time.monotonic() - started


@pytest.mark.asyncio
async def test_back_to_back_hints_are_not_paced(monkeypatch):
    # The former 50 ms sleep after every message needed at least 5 s for 100 hints.
    script = [hint(TENANTS[n % 3]) for n in range(100)]
    invalidated, sleeps, elapsed = await listen(monkeypatch, script)
    assert invalidated == [TENANTS[n % 3] for n in range(100)]
    assert sleeps == []
    assert elapsed < 1


@pytest.mark.asyncio
async def test_empty_poll_still_backs_off(monkeypatch):
    invalidated, sleeps, _ = await listen(monkeypatch, [None, hint(TENANTS[0]), None])
    assert invalidated == [TENANTS[0]]
    assert sleeps == [0.05, 0.05]


class Database:
    def __init__(self, rows):
        self.rows = rows
        self.units = []
        self.deletes = []

    @contextmanager
    def transaction(self, tenant_id=None, *, read_committed=False):
        self.units.append((tenant_id, read_committed))
        yield self

    def execute(self, sql, params=None):
        if sql.startswith("SELECT"):
            return SimpleNamespace(fetchall=lambda: list(self.rows))
        assert sql.startswith("DELETE")
        self.deletes.append(params)


def outbox():
    return [{"tenant_id": tenant, "generation": n + 7} for n, tenant in enumerate(TENANTS)]


def test_publication_deletes_only_published_rows_in_one_statement():
    stop = Event()
    database = Database(outbox())

    class Publisher:
        calls = []

        def publish(self, channel, data):
            self.calls.append((channel, data))
            if len(self.calls) == 2:
                stop.set()  # The third row stays unpublished and pending.

    assert publish_hints(database, SETTINGS, Publisher(), stop=stop) == 2
    assert Publisher.calls == [
        (f"appchi.test.tenant.{TENANTS[0]}", "7"),
        (f"appchi.test.tenant.{TENANTS[1]}", "8"),
    ]
    assert database.deletes == [(TENANTS[:2], [7, 8])]
    assert database.units == [(None, True), (None, True)]


def test_failed_publication_still_deletes_rows_already_sent():
    database = Database(outbox())

    class Publisher:
        def publish(self, channel, data):
            if TENANTS[1] in channel:
                raise ConnectionError()

    with pytest.raises(ConnectionError):
        publish_hints(database, SETTINGS, Publisher())
    assert database.deletes == [(TENANTS[:1], [7])]


def test_nothing_published_deletes_nothing():
    database = Database([])
    assert publish_hints(database, SETTINGS, SimpleNamespace(publish=None)) == 0
    assert database.deletes == []
    assert database.units == [(None, True)]
