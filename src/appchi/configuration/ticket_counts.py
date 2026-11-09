"""ServiceNow ticket counts from the deployment's ticket counting service (REV-65).

The address is the deployment secret ``APPCHI_TICKET_COUNT_URL``; it may carry an
access key in its query string, so neither it nor its query is ever logged, returned
or put in an error. Only the API server calls the service: one GET per
(team, ticket state, detection) with a 5 s total timeout, no redirects and a 64 KiB
reply limit (reliability 8). Each process caches answers in memory for 30 s and
failures for 10 s, shares them across viewers and tenants and sends one request per
key at a time; Redis is not involved (it only carries hints). At most 20 calls run at
once per process; a query that waits more than 3 s for a slot is answered
unavailable without being cached or recorded as a service failure.
"""

import asyncio
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import json
import logging
import ssl
import time
from urllib.parse import unquote_plus, urlencode, urlsplit, urlunsplit

import httpx

log = logging.getLogger(__name__)

TIMEOUT = 5.0
SLOTS = 20
SLOT_WAIT = 3.0
WARNING_INTERVAL = 60.0
MAX_REPLY = 64 * 1024
MAX_COUNT = 2**53 - 1
ANSWER_TTL = 30.0
FAILURE_TTL = 10.0
LAST_COUNT_TTL = 3600.0
MAX_KEYS = 2000
CHECK_TEAM = "__appchi_connection_check__"
NOT_FOUND = "team not found"
STATES = {"open": "new", "in_progress": "in_progress", "both": "all"}
DETECTIONS = {"hamal": "true", "direct": "false", "all": None}
LOOPBACK_NAMES = {"localhost"}


@dataclass(frozen=True)
class Endpoint:
    """A validated counting service address. ``origin`` is safe to show."""

    url: str
    origin: str

    def __repr__(self):
        return f"Endpoint(origin={self.origin!r})"


def _loopback(host):
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_endpoint(raw, *, development=True):
    """The configured address, or None when it is absent or unusable.

    It must be https with a host and no user name or password; plain http is
    accepted only for a loopback host (localhost, 127.0.0.1, ::1) in local
    development. An unusable address is logged without any of its parts.
    """
    value = (raw or "").strip()
    if not value:
        return None
    try:
        if not value.isascii() or any(c.isspace() or not c.isprintable() for c in value):
            raise ValueError
        parts = urlsplit(value)
        port = parts.port
        host = parts.hostname
        if not host or parts.username is not None or parts.password is not None:
            raise ValueError
        if parts.fragment:
            raise ValueError
        local = development and parts.scheme == "http" and _loopback(host)
        if parts.scheme != "https" and not local:
            raise ValueError
    except ValueError:
        log.warning(
            "APPCHI_TICKET_COUNT_URL is not an https address with a host (http only for a "
            "loopback host); ServiceNow ticket panels are not connected"
        )
        return None
    shown = f"[{host}]" if ":" in host else host
    origin = f"{parts.scheme}://{shown}" + (f":{port}" if port is not None else "")
    return Endpoint(value, origin)


def query_url(endpoint, team, ticket_state, detection):
    """The configured address with the panel's parameters replacing same-named ones.

    Configured parameters are kept byte for byte, in order, except those the panel
    sets; for detection All a configured ``system_failure`` is kept, as Keep does.
    """
    parts = urlsplit(endpoint.url)
    params = {"team": team, "state": STATES[ticket_state]}
    if DETECTIONS[detection] is not None:
        params["system_failure"] = DETECTIONS[detection]
    kept = [
        part
        for part in parts.query.split("&")
        if part and unquote_plus(part.split("=", 1)[0]) not in params
    ]
    return urlunsplit(parts._replace(query="&".join(kept + [urlencode(params)])))


def quiet_client_logs():
    """httpx logs each request's full address at INFO; the address carries a key."""
    for name in ("httpx", "httpcore"):
        logger = logging.getLogger(name)
        if logger.level < logging.WARNING:  # NOTSET would follow the root level
            logger.setLevel(logging.WARNING)


def verification(ca_file):
    """TLS verification: the system trust store, or only the configured CA file."""
    return ssl.create_default_context(cafile=str(ca_file)) if ca_file else True


@dataclass(frozen=True)
class Reply:
    """One answer: count, not_found, no_count or unavailable."""

    status: str
    count: int | None = None
    error: str | None = None
    # No slot was free: not an answer from the service, so never cached or recorded.
    busy: bool = False


def _rejected_constant(name):
    raise ValueError(name)


def interpret(body):
    """Map a 2xx reply body to count, not_found or no_count; None when it isn't JSON."""
    try:
        document = json.loads(body, parse_constant=_rejected_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if isinstance(document, dict):
        if "Team not found" in document or any(
            isinstance(value, str) and value.strip().casefold() == NOT_FOUND
            for value in document.values()
        ):
            return Reply("not_found")
        count = document.get("count")
        if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= MAX_COUNT:
            return Reply("count", count)
    return Reply("no_count")


@dataclass
class Answer:
    reply: Reply
    checked_at: datetime
    expires: float


class TicketCounts:
    """The process's counting service client, answer cache and connection status."""

    def __init__(
        self,
        endpoint,
        *,
        transport=None,
        clock=time.monotonic,
        now=lambda: datetime.now(UTC),
        max_keys=MAX_KEYS,
        slots=SLOTS,
        ca_file=None,
    ):
        self.endpoint = endpoint
        self.clock, self.now, self.max_keys = clock, now, max_keys
        self.slots = asyncio.Semaphore(slots)
        self.warned = {}
        self.answers = OrderedDict()
        self.pending = {}
        self.last = OrderedDict()
        self.last_success_at = self.last_failure_at = None
        self.last_error = None
        self.client = (
            httpx.AsyncClient(
                transport=transport,
                timeout=TIMEOUT,
                follow_redirects=False,
                trust_env=False,
                verify=verification(ca_file),
                # The semaphore admits at most ``slots`` calls, so none waits for the pool.
                limits=httpx.Limits(max_connections=slots, max_keepalive_connections=10),
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "User-Agent": "appchi-api",
                },
            )
            if endpoint
            else None
        )

    @classmethod
    def from_settings(cls, settings, **options):
        secret = settings.ticket_count_url
        development = getattr(settings, "environment", "production") == "development"
        raw = secret.get_secret_value() if secret else None
        quiet_client_logs()
        options.setdefault("ca_file", getattr(settings, "ticket_count_ca_file", None))
        return cls(parse_endpoint(raw, development=development), **options)

    @property
    def configured(self):
        return self.endpoint is not None

    async def close(self):
        if self.client:
            await self.client.aclose()

    async def fetch(self, team, ticket_state, detection):
        """One uncached GET; never raises for a failing service."""
        try:
            async with asyncio.timeout(SLOT_WAIT):
                await self.slots.acquire()
        except TimeoutError:
            self._warn("busy", "Ticket counting service at %s is busy: no free call slot", ())
            return Reply("unavailable", error="busy", busy=True)
        try:
            return await self._call(query_url(self.endpoint, team, ticket_state, detection))
        finally:
            self.slots.release()

    async def _call(self, url):
        # The service's 5 s starts once a slot is held.
        try:
            async with asyncio.timeout(TIMEOUT):
                async with self.client.stream("GET", url) as response:
                    status = response.status_code
                    encoding = response.headers.get("content-encoding", "identity")
                    if encoding.strip().lower() not in ("", "identity"):
                        return self._failed("encoding")
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body += chunk
                        if len(body) > MAX_REPLY:
                            return self._failed("reply over 64 KiB")
        except TimeoutError:
            return self._failed("timeout")
        except httpx.TimeoutException:
            return self._failed("timeout")
        except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:
            return self._failed(_transport_kind(exc))
        if 300 <= status < 400:
            return self._failed(f"redirect (status {status}) not followed")
        if 400 <= status < 500:
            # A 4xx reply that says the team isn't known is an answer, not a failure.
            reply = interpret(bytes(body))
            if reply is not None and reply.status == "not_found":
                self.last_success_at = self.now()
                return reply
            return self._failed(f"status {status}")
        if not 200 <= status < 300:
            return self._failed(f"status {status}")
        reply = interpret(bytes(body))
        if reply is None:
            return self._failed("invalid JSON")
        self.last_success_at = self.now()
        return reply

    def _warn(self, kind, message, args):
        """Log at most one warning per kind per minute; never the address."""
        now = self.clock()
        if now - self.warned.get(kind, float("-inf")) >= WARNING_INTERVAL:
            self.warned[kind] = now
            log.warning(message, self.endpoint.origin, *args)

    def _failed(self, kind):
        self._warn(kind, "Ticket counting service at %s failed: %s", (kind,))
        self.last_failure_at = self.now()
        self.last_error = kind
        return Reply("unavailable", error=kind)

    async def lookup(self, team, ticket_state, detection):
        """The cached or fetched answer for one key, as a result dictionary."""
        if not self.configured:
            return result("not_configured")
        key = (team, ticket_state, detection)
        cached = self.answers.get(key)
        if cached is None or cached.expires <= self.clock():
            task = self.pending.get(key)
            if task is None or task.done():
                task = asyncio.ensure_future(self._refresh(key))
                self.pending[key] = task
                task.add_done_callback(self._settled(key))
            # One request's cancellation never cancels the shared lookup.
            cached = await asyncio.shield(task)
        return self._result(key, cached)

    def _settled(self, key):
        def forget(task):
            if self.pending.get(key) is task:
                del self.pending[key]

        return forget

    async def _refresh(self, key):
        reply = await self.fetch(*key)
        if reply.busy:
            # Keep whatever answer is cached; the next viewer tries again.
            return Answer(reply, None, 0.0)
        checked_at = self.now()
        ttl = FAILURE_TTL if reply.status == "unavailable" else ANSWER_TTL
        answer = Answer(reply, checked_at, self.clock() + ttl)
        self.answers[key] = answer
        self.answers.move_to_end(key)
        while len(self.answers) > self.max_keys:
            self.answers.popitem(last=False)
        if reply.status == "count":
            self.last[key] = (reply.count, checked_at, self.clock())
            self.last.move_to_end(key)
            while len(self.last) > self.max_keys:
                self.last.popitem(last=False)
        return answer

    def _result(self, key, answer):
        last = self.last.get(key)
        if last is not None and self.clock() - last[2] > LAST_COUNT_TTL:
            self.last.pop(key, None)
            last = None
        return result(
            answer.reply.status,
            count=answer.reply.count,
            checked_at=answer.checked_at,
            last_count=last[0] if last else None,
            last_counted_at=last[1] if last else None,
        )

    async def lookup_many(self, queries):
        """Results in request order; duplicate queries share one lookup."""
        keys = [(q.team, q.ticket_state, q.detection) for q in queries]
        unique = list(dict.fromkeys(keys))
        answers = await asyncio.gather(*(self.lookup(*key) for key in unique))
        found = dict(zip(unique, answers))
        return [found[key] for key in keys]

    async def check(self):
        """Test the connection without the cache: any valid JSON reply is reachable."""
        if not self.configured:
            return {
                "ok": False,
                "message": "The ticket counting service isn't configured.",
                "elapsed_ms": 0,
            }
        started = time.perf_counter()
        reply = await self.fetch(CHECK_TEAM, "both", "all")
        elapsed = int((time.perf_counter() - started) * 1000)
        if reply.status == "unavailable":
            return {
                "ok": False,
                "message": f"The service didn't answer: {reply.error}.",
                "elapsed_ms": elapsed,
            }
        return {"ok": True, "message": "The service answered.", "elapsed_ms": elapsed}

    def integration(self):
        return {
            "configured": self.configured,
            "host": self.endpoint.origin if self.endpoint else None,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_error": self.last_error,
        }


def result(status, *, count=None, checked_at=None, last_count=None, last_counted_at=None):
    return {
        "status": status,
        "count": count,
        "checked_at": checked_at,
        "last_count": last_count,
        "last_counted_at": last_counted_at,
    }


def _transport_kind(exc):
    if isinstance(exc, httpx.ConnectError):
        return "connection error"
    if isinstance(exc, httpx.TooManyRedirects):
        return "redirect"
    return "transport error"
