"""Redis cache of raw ADAPI picker-search answers (REV-73).

Requirements: REV-73; tenant access 5 (search cache); plan A19.

The cache holds what ADAPI answered to one ``/users`` or ``/groups`` picker search,
including whether the answer hit ADAPI's 1,000-row cap, for
``KEEP_ADAPI_SEARCH_CACHE_TTL_SECONDS`` (two hours by default). The key is a
SHA-256 of the kind and the normalized term, so Redis never holds a raw term.
It feeds picker listings only: save on pick, lookups, members, sign-in and the
refresh always read ADAPI directly. It is never authoritative: a Redis outage,
a timeout or a corrupt value is a miss, and the search then asks ADAPI.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

log = logging.getLogger("keep.identity.search_cache")

FORMAT = 1
# After a Redis error, skip the cache for a short while so an outage does not add
# its connect timeout to every search.
RETRY_AFTER_SECONDS = 5.0
# Short client timeouts: a cache must never hold a picker request up.
SOCKET_TIMEOUT_SECONDS = 0.5


@dataclass(frozen=True)
class CachedAnswer:
    """One raw ADAPI search answer: its rows and whether it hit the 1,000-row cap."""

    rows: tuple[dict, ...]
    capped: bool


def cache_key(prefix: str, kind: str, term: str) -> str:
    """``<prefix>:<sha256(kind, term)>``; the term never appears in the key."""
    digest = hashlib.sha256(f"{kind}\x00{term}".encode("utf-8")).hexdigest()
    return f"{prefix}:{digest}"


def _decode(raw: Any) -> CachedAnswer | None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.get("v") != FORMAT
        or not isinstance(value.get("capped"), bool)
        or not isinstance(value.get("rows"), list)
        or not all(isinstance(row, dict) for row in value["rows"])
    ):
        return None
    return CachedAnswer(tuple(value["rows"]), value["capped"])


class SearchCache:
    """Best-effort get/put over a synchronous Redis client; never raises.

    ``client`` needs ``get(key)``, ``set(key, value, ex=seconds)`` and ``close()``
    (a ``redis.Redis``). ``prefix`` scopes keys per deployment environment.
    """

    def __init__(
        self,
        client: Any,
        *,
        ttl_seconds: int,
        prefix: str = "keep:adapi-search",
        retry_after: float = RETRY_AFTER_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not 1 <= int(ttl_seconds) <= 86400:
            raise ValueError("search cache TTL must be 1-86400 seconds")
        self.client, self.ttl, self.prefix = client, int(ttl_seconds), f"{prefix}:v{FORMAT}"
        self.retry_after, self.monotonic = retry_after, monotonic
        self._down_until = 0.0
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings: Any) -> SearchCache | None:
        """A cache over ``KEEP_REDIS_URL``, or None when Redis isn't configured."""
        if not settings.redis_url:
            return None
        from redis import Redis
        from redis.backoff import NoBackoff
        from redis.retry import Retry

        client = Redis.from_url(
            settings.redis_url.get_secret_value(),
            socket_connect_timeout=SOCKET_TIMEOUT_SECONDS,
            socket_timeout=SOCKET_TIMEOUT_SECONDS,
            retry=Retry(NoBackoff(), 0),
        )
        return cls(
            client,
            ttl_seconds=settings.adapi_search_cache_ttl_seconds,
            prefix=f"keep:{settings.environment}:adapi-search",
        )

    def _available(self) -> bool:
        with self._lock:
            return self.monotonic() >= self._down_until

    def _failed(self, operation: str, error: BaseException) -> None:
        with self._lock:
            self._down_until = self.monotonic() + self.retry_after
        # The exception type only: Redis errors can carry the URL or the key.
        log.warning(
            "adapi_search_cache_unavailable",
            extra={"operation": operation, "error_type": type(error).__name__},
        )

    def get(self, kind: str, term: str) -> CachedAnswer | None:
        """The cached answer, or None for a miss, a corrupt value or a Redis error."""
        if not self._available():
            return None
        try:
            raw = self.client.get(cache_key(self.prefix, kind, term))
        except Exception as error:  # the cache never fails a search
            self._failed("get", error)
            return None
        if raw is None:
            return None
        try:
            return _decode(raw)
        except (ValueError, UnicodeError, TypeError):
            return None

    def put(self, kind: str, term: str, answer: CachedAnswer) -> None:
        """Store an answer for the TTL; errors are logged and ignored."""
        if not self._available():
            return
        value = json.dumps(
            {"v": FORMAT, "capped": answer.capped, "rows": list(answer.rows)},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        try:
            self.client.set(cache_key(self.prefix, kind, term), value, ex=self.ttl)
        except Exception as error:  # the cache never fails a search
            self._failed("put", error)

    def close(self) -> None:
        try:
            self.client.close()
        except Exception as error:  # shutdown continues
            log.warning(
                "adapi_search_cache_close_failed", extra={"error_type": type(error).__name__}
            )
