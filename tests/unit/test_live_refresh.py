"""SSE wake-up cost and reauthorization timing, without PostgreSQL or Redis."""

import asyncio
from contextlib import contextmanager
import threading
import time
from types import SimpleNamespace

import pytest

from appchi import live
from appchi.live import REAUTHORIZE_SECONDS, LiveRegistry, events, refresh
from appchi.shared.errors import AppError

TENANT = "00000000-0000-4000-8000-000000000001"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


class Database:
    def __init__(self, log):
        self.log = log
        self.units = []
        self.pool_wait = lambda: None

    @contextmanager
    def transaction(self, tenant_id=None, *, read_committed=False):
        self.pool_wait()
        self.units.append((tenant_id, read_committed))
        self.log.append(("transaction", tenant_id))
        yield SimpleNamespace()


class Stack:
    """Fake authority: a view generation and a session that can be revoked."""

    def __init__(self, monkeypatch, clock=None):
        self.monkeypatch = monkeypatch
        self.clock = clock or Clock()
        self.log = []
        self.generation = "1"
        self.revoked_at = None
        self.db = Database(self.log)
        self.registry = LiveRegistry()
        monkeypatch.setattr(live, "time", self.clock)
        monkeypatch.setattr(live, "authorize", self.authorize)
        monkeypatch.setattr(live, "view_state", self.view_state)
        self.request = SimpleNamespace(
            app=SimpleNamespace(
                state=SimpleNamespace(
                    db=self.db,
                    live_registry=self.registry,
                    settings=SimpleNamespace(deployment_epoch="epoch"),
                )
            ),
            headers={},
        )

    def authorize(self, conn, request, tenant):
        self.log.append(("authorize", self.clock.now))
        if self.revoked_at is not None and self.clock.now >= self.revoked_at:
            raise AppError("unauthenticated", "Sign in is required.", 401)

    def view_state(self, conn, tenant):
        self.log.append(("select", tenant))
        return {"view_generation": self.generation}

    def authorizations(self):
        return [entry[1] for entry in self.log if entry[0] == "authorize"]


def test_fresh_unchanged_timeout_wakeup_opens_no_transaction(monkeypatch):
    stack = Stack(monkeypatch)
    stack.registry.register(TENANT)
    stack.registry.read(TENANT, lambda: {"view_generation": "1"})
    value, reauthorized = refresh(stack.request, TENANT, "1", False)
    assert value == {"view_generation": "1"} and not reauthorized
    assert stack.log == []


def test_due_reconciliation_coalesces_one_tenant_scoped_unit_across_streams(monkeypatch):
    stack = Stack(monkeypatch)
    for _ in range(50):
        stack.registry.register(TENANT)
    stack.registry.read(TENANT, lambda: {"view_generation": "1"})
    stack.clock.now += 2
    for _ in range(50):
        assert refresh(stack.request, TENANT, "1", False) == ({"view_generation": "1"}, False)
    # One PostgreSQL reconciliation for the window, without authorization work
    # or the session-lock restore guard of an unscoped unit.
    assert stack.db.units == [(TENANT, False)]
    assert stack.authorizations() == []


def test_changed_vector_from_another_stream_is_reauthorized_before_return(monkeypatch):
    stack = Stack(monkeypatch)
    stack.registry.register(TENANT)
    stack.registry.read(TENANT, lambda: {"view_generation": "2"})
    value, reauthorized = refresh(stack.request, TENANT, "1", False)
    assert value == {"view_generation": "2"} and reauthorized
    assert stack.db.units == [(TENANT, False)] and len(stack.authorizations()) == 1

    stack.revoked_at = stack.clock.now
    with pytest.raises(AppError):
        refresh(stack.request, TENANT, "1", False)


def test_due_interval_reauthorizes_even_when_cache_is_fresh(monkeypatch):
    stack = Stack(monkeypatch)
    stack.registry.register(TENANT)
    stack.registry.read(TENANT, lambda: {"view_generation": "1"})
    assert refresh(stack.request, TENANT, "1", True) == ({"view_generation": "1"}, True)
    assert stack.authorizations() == [stack.clock.now]


async def stream(stack, until, send_seconds=0):
    """Drive one SSE stream where every change wait is a timeout, on the fake clock."""

    async def wait_for(awaitable, timeout):
        if awaitable.__name__ == "wait":
            awaitable.close()
            stack.clock.now += timeout
            raise TimeoutError
        # Other awaits run, then time out as asyncio would if they overran.
        started = stack.clock.now
        try:
            result = await awaitable
        except Exception:
            if stack.clock.now - started <= timeout:
                raise
            result = None
        if stack.clock.now - started > timeout:
            stack.clock.now = started + timeout
            raise TimeoutError
        return result

    async def is_disconnected():
        return stack.clock.now >= until

    stack.request.is_disconnected = is_disconnected
    response = await events(TENANT, stack.request)
    stack.monkeypatch.setattr(
        live, "asyncio", SimpleNamespace(wait_for=wait_for, to_thread=asyncio.to_thread)
    )
    async for chunk in response.body_iterator:
        started = stack.clock.now
        stack.clock.now += send_seconds
        stack.log.append(("sent", started, stack.clock.now))
        if not chunk.startswith(":"):
            stack.log.append(("emit", started, chunk.split("\n")[0]))
    return stack.clock.now


def emits(stack):
    return [entry for entry in stack.log if entry[0] == "emit"]


@pytest.mark.asyncio
async def test_idle_stream_reauthorizes_on_interval_only(monkeypatch):
    stack = Stack(monkeypatch)
    opened = stack.clock.now
    await stream(stack, opened + 60)
    times = stack.authorizations()
    assert times[0] == opened
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    assert gaps and all(REAUTHORIZE_SECONDS <= gap <= REAUTHORIZE_SECONDS + 2 for gap in gaps)
    # Thirty idle 2-second wake-ups reauthorize four times, not thirty.
    assert len(times) == 4
    assert emits(stack) == [("emit", opened, "id: epoch:1")]
    # The open unit stays READ COMMITTED; reconciliation units are tenant scoped.
    assert stack.db.units[0] == (None, True)
    assert all(unit == (TENANT, False) for unit in stack.db.units[1:])


@pytest.mark.asyncio
async def test_change_is_reauthorized_before_it_is_emitted(monkeypatch):
    stack = Stack(monkeypatch)
    opened = stack.clock.now
    original_view_state = stack.view_state

    def view_state(conn, tenant):
        if stack.clock.now >= opened + 6:
            stack.generation = "2"
        return original_view_state(conn, tenant)

    monkeypatch.setattr(live, "view_state", view_state)
    await stream(stack, opened + 10)
    entries = [entry for entry in stack.log if entry[0] != "sent"]
    index = entries.index(("emit", opened + 6, "id: epoch:2"))
    assert entries[index - 1] == ("authorize", opened + 6)


@pytest.mark.asyncio
async def test_revoked_session_is_cut_off_within_the_interval(monkeypatch):
    stack = Stack(monkeypatch)
    opened = stack.clock.now
    stack.revoked_at = opened + 3
    ended = await stream(stack, opened + 600)
    assert ended - stack.revoked_at <= REAUTHORIZE_SECONDS + 2 < 30
    assert all(at < stack.revoked_at for _, at, _ in emits(stack))


@pytest.mark.asyncio
async def test_revoked_session_receives_no_changed_vector(monkeypatch):
    stack = Stack(monkeypatch)
    opened = stack.clock.now
    stack.revoked_at = opened + 4

    def view_state(conn, tenant):
        return {"view_generation": "2" if stack.clock.now >= opened + 4 else "1"}

    monkeypatch.setattr(live, "view_state", view_state)
    ended = await stream(stack, opened + 600)
    assert ended == opened + 4
    assert emits(stack) == [("emit", opened, "id: epoch:1")]


def test_concurrent_misses_wait_for_one_reconciliation_without_a_connection(monkeypatch):
    stack = Stack(monkeypatch)
    streams = 8
    for _ in range(streams):
        stack.registry.register(TENANT)
    barrier = threading.Barrier(streams)
    original_view_state = stack.view_state

    def slow_view_state(conn, tenant):
        time.sleep(0.2)
        return original_view_state(conn, tenant)

    monkeypatch.setattr(live, "view_state", slow_view_state)
    results = []

    def wake():
        barrier.wait(2)
        results.append(refresh(stack.request, TENANT, "1", False))

    threads = [threading.Thread(target=wake) for _ in range(streams)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert results == [({"view_generation": "1"}, False)] * streams
    # Only the winner opened a unit; the others waited on the registry.
    assert stack.db.units == [(TENANT, False)]
    assert stack.authorizations() == []


@pytest.mark.asyncio
async def test_slow_iterations_cannot_exceed_the_30_second_authorization_bound(monkeypatch):
    stack = Stack(monkeypatch)
    opened = stack.clock.now
    stack.revoked_at = opened + 0.001
    original_view_state = stack.view_state

    def slow(seconds):
        if stack.clock.now > opened:
            stack.clock.now += seconds

    def slow_view_state(conn, tenant):
        slow(9)  # A slow SELECT, within the 10 s request budget.
        return original_view_state(conn, tenant)

    stack.db.pool_wait = lambda: slow(3)  # The 3 s pool timeout.
    monkeypatch.setattr(live, "view_state", slow_view_state)
    # Every send takes the full 5 s bound.
    ended = await stream(stack, opened + 600, send_seconds=5)
    sends = [entry for entry in stack.log if entry[0] == "sent"]
    assert sends and all(end - opened <= 30 for _, _, end in sends)
    assert ended - opened <= 30
    # Only the open authorization succeeded; nothing waited on a later one.
    assert [at for at in stack.authorizations() if at < stack.revoked_at] == [opened]
