"""One coalesced vector per connected tenant; Redis hints never authorize delivery."""

import asyncio
from contextlib import suppress
import json
import logging
from threading import Lock, RLock
import time
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from appchi.access import authorize
from appchi.serialization import wire
from appchi.request_budget import request_budget
from appchi.shared.errors import unavailable

log = logging.getLogger(__name__)
router = APIRouter(tags=["live"])


class LiveRegistry:
    def __init__(self):
        self.lock = RLock()
        self.entries = {}

    def register(self, tenant):
        with self.lock:
            entry = self.entries.setdefault(
                tenant,
                {
                    "refs": 0,
                    "expires": 0,
                    "value": None,
                    "event": asyncio.Event(),
                    "load_lock": Lock(),
                    "generation": 0,
                },
            )
            entry["refs"] += 1
            return entry["event"]

    def unregister(self, tenant):
        with self.lock:
            entry = self.entries.get(tenant)
            if entry:
                entry["refs"] -= 1
                if entry["refs"] == 0:
                    del self.entries[tenant]

    def invalidate(self, tenant):
        with self.lock:
            entry = self.entries.get(tenant)
            if entry:
                entry["expires"] = 0
                entry["generation"] += 1
                entry["event"].set()

    def read(self, tenant, load):
        # Only worker threads wait for per-tenant loading. The registry lock
        # protects memory only; Redis callbacks never wait for database I/O.
        with self.lock:
            entry = self.entries.get(tenant)
        if entry is None:
            return load()
        with entry["load_lock"]:
            with self.lock:
                if entry["expires"] > time.monotonic():
                    return entry["value"]
                generation = entry["generation"]
            value = load()
            with self.lock:
                entry["value"] = value
                # An invalidation during the SELECT must force another read.
                if entry["generation"] == generation:
                    entry["expires"] = time.monotonic() + 2
            return value


async def redis_listener(settings, registry):
    from redis.asyncio import Redis

    prefix = f"appchi.{settings.environment}.tenant."
    while True:
        try:
            async with Redis.from_url(
                settings.redis_url.get_secret_value(), socket_connect_timeout=2, socket_timeout=3
            ) as client:
                async with client.pubsub() as subscription:
                    await subscription.psubscribe(prefix + "*")
                    while True:
                        message = await subscription.get_message(
                            ignore_subscribe_messages=True, timeout=1
                        )
                        if message and message.get("type") == "pmessage":
                            channel = message["channel"].decode("ascii")
                            tenant = channel.removeprefix(prefix)
                            if channel.startswith(prefix) and str(UUID(tenant)) == tenant:
                                registry.invalidate(tenant)
                        if message is None:
                            # Back off only on an empty poll; a burst drains back to back.
                            await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise
        except Exception:
            # A broken hint channel cannot make authority unavailable.
            await asyncio.sleep(2)


def state(request, tenant):
    with request_budget(10), request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant)

        def load():
            return wire(
                conn.execute(
                    """SELECT v.*,w.projection_seq AS committed_seq
                FROM tenant_view_state v JOIN tenant_work_state w USING(tenant_id) WHERE tenant_id=%s""",
                    (tenant,),
                ).fetchone()
            )

        return request.app.state.live_registry.read(tenant, load)


class BoundedStream(StreamingResponse):
    def __init__(self, *args, on_close=None, **kwargs):
        self.on_close = on_close
        super().__init__(*args, **kwargs)

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            if self.on_close:
                self.on_close()

    async def stream_response(self, send):
        async def bounded_send(message):
            if len(message.get("body", b"")) > 65536:
                raise RuntimeError("live_vector_exceeds_bound")
            async with asyncio.timeout(5):
                await send(message)

        await super().stream_response(bounded_send)


@router.get("/api/tenants/{tenant_id}/events")
async def events(tenant_id: str, request: Request):
    registry = request.app.state.live_registry
    changed = registry.register(tenant_id)
    try:
        current = await asyncio.to_thread(state, request, tenant_id)
    except BaseException:
        registry.unregister(tenant_id)
        raise
    epoch = request.app.state.settings.deployment_epoch

    async def generate():
        previous = None
        heartbeat = time.monotonic()
        start = heartbeat
        value = current
        try:
            while time.monotonic() - start < 1800:
                if await request.is_disconnected():
                    return
                event_id = f"{epoch}:{value['view_generation']}"
                if previous != event_id:
                    event = (
                        "state"
                        if previous is None and not request.headers.get("last-event-id")
                        else "resync"
                        if previous is None
                        else "invalidate"
                    )
                    yield f"id: {event_id}\nevent: {event}\ndata: {json.dumps(value, separators=(',', ':'))}\n\n"
                    previous = event_id
                if time.monotonic() - heartbeat >= 15:
                    yield ": heartbeat\n\n"
                    heartbeat = time.monotonic()
                with suppress(TimeoutError):
                    await asyncio.wait_for(changed.wait(), timeout=2)
                changed.clear()
                try:
                    value = await asyncio.to_thread(state, request, tenant_id)
                except Exception:
                    return
        finally:
            pass  # Response cleanup also handles failure before the generator starts.

    return BoundedStream(
        generate(),
        on_close=lambda: registry.unregister(tenant_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "private, no-store, no-transform",
            "X-Accel-Buffering": "no",
            "Content-Encoding": "identity",
        },
    )


async def hint_publisher(db, settings, stop, *, interval=1):
    """Product API owns publishing; SQL/Redis calls stay off its event loop."""
    while not stop.is_set():
        try:
            await asyncio.to_thread(publish_hints, db, settings, stop=stop)
        except Exception:
            # Hints are optional; pending work and PG/SSE reconciliation survive.
            log.warning("live_hint_publication_unavailable")
        if not stop.is_set():
            await asyncio.sleep(interval)


def publish_hints(db, settings, client=None, *, stop=None):
    from redis import Redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    if client is None and not settings.redis_url:
        raise unavailable("redis_configuration_required")
    own_client = client is None
    if own_client:
        client = Redis.from_url(
            settings.redis_url.get_secret_value(),
            socket_connect_timeout=2,
            socket_timeout=3,
            retry=Retry(NoBackoff(), 0),
        )
    published = []
    try:
        try:
            # Unscoped and never REPEATABLE READ: the restore guard runs in-transaction.
            with db.transaction(read_committed=True) as conn:
                rows = conn.execute(
                    "SELECT * FROM live_hint_outbox ORDER BY updated_at,tenant_id LIMIT 100"
                ).fetchall()
            deadline = time.monotonic() + 1
            for row in rows:
                if (stop is not None and stop.is_set()) or time.monotonic() >= deadline:
                    break
                client.publish(
                    f"appchi.{settings.environment}.tenant.{row['tenant_id']}",
                    str(row["generation"]),
                )
                published.append(row)
        finally:
            # Also after a failed publish: rows already sent need no second hint.
            if published:
                delete_published(db, published)
        return len(published)
    finally:
        if own_client:
            client.close()


class HintDeleteDeferred(Exception):
    """The published rows were locked by a writer; they stay pending."""


# Below PostgreSQL's 1 s deadlock_timeout, so the optional hint delete yields to
# multi-tenant view-state writers (rebuild cutover, bootstrap) instead of
# deadlocking with them or stalling them.
HINT_DELETE_LOCK_TIMEOUT = "200ms"


def delete_published(db, rows):
    """Delete exactly the published (tenant, generation) pairs in one statement.

    A newer invalidation committed during publication replaced the generation of
    its tenant's row, so that row no longer matches and remains pending. When a
    writer holds one of the rows, the whole delete gives up and every row stays
    pending; the next turn republishes them, and hints are idempotent.
    Returns whether the delete ran.
    """
    from psycopg.errors import LockNotAvailable

    try:
        with db.transaction(read_committed=True) as conn:
            conn.execute(f"SET LOCAL lock_timeout = '{HINT_DELETE_LOCK_TIMEOUT}'")
            try:
                conn.execute(
                    """DELETE FROM live_hint_outbox o
                    USING unnest(%s::uuid[],%s::bigint[]) AS p(tenant_id,generation)
                    WHERE o.tenant_id=p.tenant_id AND o.generation=p.generation""",
                    ([row["tenant_id"] for row in rows], [row["generation"] for row in rows]),
                )
            except LockNotAvailable as error:
                # Only this statement's lock wait is deferred; the unit rolls back.
                raise HintDeleteDeferred() from error
    except HintDeleteDeferred:
        log.info("live_hint_delete_deferred")
        return False
    return True
