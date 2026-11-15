"""Save on pick (REV-73): the inline save and the background saver.

Requirements: REV-73; tenant access 5 (save on pick, background save); worker scope
4-6; plan "Save on pick", A12, A22, A26.

An administrator picking a person or group Keep has not saved makes the Product
API read it (and a group's recursive members) from ADAPI and publish it as one
single-root publication. Inline, inside the 10-second request budget, the
verifier gets 7 seconds and at least 1 second must remain before ``publish()``;
a save that does not fit publishes nothing and is handed to the background saver.

The background saver is one thread per API process with a queue of 20. It is not
a poller: it runs only jobs handed to it. The hand-over claims a lease on the
pending ``directory_verification_requests`` row with a conditional update, and
only the claim's winner queues the job. Each job runs in a fresh context under its
own 80-second budget, re-checks and extends its lease when it starts, holds no
database connection while it reads ADAPI, and filters every row update and delete
on its ``lease_owner``. Shutdown stops ADAPI reads between calls, releases this
process's leases and joins the thread before the database pool closes.
"""

from __future__ import annotations

import contextvars
import logging
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Literal
from uuid import UUID, uuid4

import httpx

from keep import request_budget
from keep.identity.adapi import (
    GROUP_ATTRIBUTES,
    INLINE_VERIFY_DEADLINE,
    JOB_CALL_CAP,
    REQUEST_CALL_CAP,
    USER_ATTRIBUTES,
    ADAPIClient,
    ADAPIConfig,
    exact_params,
    job_verification_deadline,
    principal_key,
    verify_root,
)
from keep.identity.directory import (
    FAILURE_BUSY,
    FAILURE_DEADLINE,
    FAILURE_UNAVAILABLE,
    DirectoryEvidence,
    DirectoryUnavailable,
    PrincipalKey,
    failure_reason,
)
from keep.identity.publication import publish_with_retry
from keep.shared.errors import AppError

log = logging.getLogger("keep.identity.saver")

Kind = Literal["user", "team"]
LEASE_SECONDS = 120.0
JOB_BUDGET_SECONDS = 80.0
QUEUE_LIMIT = 20
# Request budget that must remain before an inline publish() starts.
INLINE_PUBLISH_RESERVE = 1.0
# Budget kept back when sizing an inline verifier deadline: the reserve above plus
# the publishing transaction itself.
INLINE_READ_RESERVE = 1.5
# A fenced inline save retries only when another read can still fit.
INLINE_RETRY_MINIMUM = 2.5
# A fenced background save retries only when job_verification_deadline() stays useful.
JOB_RETRY_MINIMUM = 20.0

NOT_IN_DIRECTORY = "principal_not_in_directory"
AMBIGUOUS = "principal_ambiguous"
KIND_MISMATCH = "principal_kind_mismatch"

_PRINCIPAL = """SELECT p.*,r.semantic_digest AS membership_digest,r.root_id IS NOT NULL AS checkpointed
    FROM principals p LEFT JOIN directory_root_checkpoints r ON r.root_id=p.id
    WHERE p.directory_source=%s AND p.object_id=%s"""
_PENDING = """SELECT kind,lease_owner,last_failure,
    lease_until IS NOT NULL AND lease_until>clock_timestamp() AS leased
    FROM directory_verification_requests WHERE source=%s AND object_id=%s"""
# Claim at hand-over: create the pending row or take it over, only when it has no
# failure and no live lease. Exactly one concurrent caller gets a row back.
_CLAIM = """INSERT INTO directory_verification_requests AS r
        (source,object_id,kind,lease_owner,lease_until,updated_at)
    VALUES(%(source)s,%(object_id)s,%(kind)s,%(job)s,
        clock_timestamp()+make_interval(secs=>%(lease)s::double precision),clock_timestamp())
    ON CONFLICT(source,object_id) DO UPDATE SET lease_owner=EXCLUDED.lease_owner,
        lease_until=EXCLUDED.lease_until,updated_at=EXCLUDED.updated_at
    WHERE r.last_failure IS NULL AND (r.lease_until IS NULL OR r.lease_until<clock_timestamp())
    RETURNING r.kind"""
_CLEAR_FAILURE = """UPDATE directory_verification_requests SET last_failure=NULL,
    updated_at=clock_timestamp() WHERE source=%s AND object_id=%s AND last_failure IS NOT NULL"""
# An inline failure is remembered unless another caller holds a live lease.
_RECORD_FAILURE = """INSERT INTO directory_verification_requests AS r
        (source,object_id,kind,last_failure,updated_at)
    VALUES(%(source)s,%(object_id)s,%(kind)s,%(reason)s,clock_timestamp())
    ON CONFLICT(source,object_id) DO UPDATE SET last_failure=EXCLUDED.last_failure,
        lease_owner=NULL,lease_until=NULL,updated_at=EXCLUDED.updated_at
    WHERE r.lease_until IS NULL OR r.lease_until<clock_timestamp()
    RETURNING 1"""
_START = """UPDATE directory_verification_requests
    SET lease_until=clock_timestamp()+make_interval(secs=>%s::double precision),
        updated_at=clock_timestamp()
    WHERE source=%s AND object_id=%s AND lease_owner=%s AND last_failure IS NULL RETURNING kind"""
_OWNED = """SELECT 1 FROM directory_verification_requests
    WHERE source=%s AND object_id=%s AND lease_owner=%s FOR UPDATE"""
_DONE = """DELETE FROM directory_verification_requests
    WHERE source=%s AND object_id=%s AND lease_owner=%s"""
_FAIL = """UPDATE directory_verification_requests SET last_failure=%s,lease_owner=NULL,
    lease_until=NULL,updated_at=clock_timestamp()
    WHERE source=%s AND object_id=%s AND lease_owner=%s"""
_RELEASE = """UPDATE directory_verification_requests SET lease_owner=NULL,lease_until=NULL,
    updated_at=clock_timestamp() WHERE source=%s AND object_id=%s AND lease_owner=%s"""
_RELEASE_ALL = """UPDATE directory_verification_requests SET lease_owner=NULL,lease_until=NULL,
    updated_at=clock_timestamp() WHERE lease_owner=ANY(%s::uuid[])"""


class NotInDirectory(Exception):
    """422: ADAPI does not know the name, two rows match it, or it is the other kind."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Unsaved(Exception):
    """The save failed with a structured reason (``FAILURE_*``)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class HandOver(Exception):
    """The inline save does not fit the request; nothing was published."""


class _LeaseLost(Exception):
    """Another hand-over took the job's lease; this job publishes nothing."""


def principal_row(conn, key: PrincipalKey):
    """The stored principal with ``membership_digest`` and ``checkpointed``, or None."""
    return conn.execute(_PRINCIPAL, (key.source, key.object_id)).fetchone()


def usable(row, kind: str) -> bool:
    """A saved, verified principal of ``kind``; a team also needs its root checkpoint."""
    return bool(
        row is not None
        and row["kind"] == kind
        and row["verified_at"] is not None
        and row["evidence_generation"] >= 1
        and (kind == "user" or row["checkpointed"])
    )


def pending_row(conn, key: PrincipalKey):
    """The pending save (``kind``, ``lease_owner``, ``last_failure``, ``leased``), or None."""
    return conn.execute(_PENDING, (key.source, key.object_id)).fetchone()


def _left() -> float | None:
    try:
        return request_budget.remaining()
    except AppError:
        return 0.0


def _classify_root(config: ADAPIConfig, key: PrincipalKey, kind: Kind, transport, stop) -> None:
    """After the root lookup failed inline, tell an ambiguous name (422) from an outage.

    At most two exact calls on this failure path only; any error keeps the outage.
    """
    attributes = {"user": USER_ATTRIBUTES, "team": GROUP_ATTRIBUTES}
    try:
        with ADAPIClient(
            config, call_cap=REQUEST_CALL_CAP, stop=stop, transport=transport
        ) as client:
            for endpoint in (kind, "team" if kind == "user" else "user"):
                find = client.find_users if endpoint == "user" else client.find_groups
                rows = find(exact_params(key.object_id, attributes[endpoint]))
                if len(rows) > 1:
                    raise NotInDirectory(AMBIGUOUS)
                if rows:
                    return
    except DirectoryUnavailable:
        return


def check_evidence(evidence: DirectoryEvidence, key: PrincipalKey, kind: Kind) -> None:
    """Raise unless ``evidence`` saves exactly the requested principal.

    Incomplete -> Unsaved(reason); unknown name, or the other kind -> NotInDirectory.
    """
    if not evidence.complete:
        raise Unsaved(evidence.failure_reason or FAILURE_UNAVAILABLE)
    root = evidence.objects.get(key)
    if root is None or root.deleted:
        # Both ADAPI endpoints answered without a row for the name.
        raise NotInDirectory(NOT_IN_DIRECTORY)
    if root.kind != kind:
        raise NotInDirectory(KIND_MISMATCH)


@dataclass(frozen=True)
class JobResult:
    """One background job's end, kept for diagnostics and tests (no secrets)."""

    job: UUID
    object_id: str
    outcome: Literal["published", "failed", "dropped", "lease_lost", "stopped"]
    reason: str | None = None


class PickSaver:
    """Inline saves for resolve requests and the per-process background saver.

    ``lease_seconds``, ``job_budget`` and ``queue_limit`` default to the design's
    120 s, 80 s and 20; tests shorten them. ``transport`` is for tests.
    """

    def __init__(
        self,
        db: Any,
        config: ADAPIConfig,
        superadmin_group: str,
        *,
        lease_seconds: float = LEASE_SECONDS,
        job_budget: float = JOB_BUDGET_SECONDS,
        queue_limit: int = QUEUE_LIMIT,
        transport: httpx.BaseTransport | None = None,
    ):
        if lease_seconds <= 0 or job_budget <= 0 or queue_limit < 1:
            raise ValueError("invalid background save allocation")
        self.db, self.config, self.transport = db, config, transport
        self.source = config.source
        self.superadmin = principal_key(superadmin_group, config.source)
        self.lease_seconds, self.job_budget, self.queue_limit = (
            float(lease_seconds),
            float(job_budget),
            queue_limit,
        )
        self.stop = threading.Event()
        self.results: deque[JobResult] = deque(maxlen=200)
        self._lock = threading.Lock()
        self._queued: dict[PrincipalKey, tuple[UUID, Kind]] = {}
        self._owned: set[UUID] = set()
        self._closed = False
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="keep-pick-saver")

    @classmethod
    def from_settings(cls, db: Any, settings: Any) -> PickSaver | None:
        """None unless ADAPI and the super-admin group are configured."""
        if not settings.adapi_url or settings.adapi_client_id is None:
            return None
        if not settings.superadmin_group:
            return None
        return cls(db, ADAPIConfig.from_settings(settings), settings.superadmin_group)

    def key(self, username: str) -> PrincipalKey:
        return principal_key(username, self.source)

    # Inline save (request thread, request budget) -----------------------------------

    def save_inline(self, key: PrincipalKey, kind: Kind, authorize: Callable[[Any], None]):
        """Publish ``key`` inside the request and return its stored row.

        ``authorize(conn)`` runs in the publishing transaction after the exclusive
        identity guard. Raises HandOver (nothing published) when the save does not
        fit, NotInDirectory for a 422, and Unsaved for a structured failure.
        """
        saved: dict[str, Any] = {}

        def read(generation: int) -> DirectoryEvidence:
            left = _left()
            seconds = (
                INLINE_VERIFY_DEADLINE
                if left is None
                else min(INLINE_VERIFY_DEADLINE, left - INLINE_READ_RESERVE)
            )
            if seconds <= 0:
                raise HandOver()
            evidence = verify_root(
                self.config,
                key.object_id,
                kind,
                generation,
                deadline_seconds=seconds,
                call_cap=REQUEST_CALL_CAP,
                transport=self.transport,
            )
            if not evidence.complete:
                if evidence.failure_reason == FAILURE_DEADLINE:
                    raise HandOver()
                if evidence.failure_reason == FAILURE_UNAVAILABLE and key not in evidence.objects:
                    _classify_root(self.config, key, kind, self.transport, None)
            check_evidence(evidence, key, kind)
            return evidence

        def guarded(conn) -> None:
            authorize(conn)
            left = _left()
            if left is not None and left < INLINE_PUBLISH_RESERVE:
                raise HandOver()

        def accepted(conn, evidence) -> None:
            conn.execute(
                "DELETE FROM directory_verification_requests WHERE source=%s AND object_id=%s",
                (key.source, key.object_id),
            )
            saved["row"] = principal_row(conn, key)

        def retry_allowed() -> bool:
            left = _left()
            return left is None or left >= INLINE_RETRY_MINIMUM

        outcome = publish_with_retry(
            self.db,
            read,
            superadmin_group=self.superadmin,
            authorize=guarded,
            on_accepted=accepted,
            attempts=2,
            retry_allowed=retry_allowed,
        )
        if outcome.saved:
            return saved["row"]
        raise Unsaved(outcome.reason or FAILURE_BUSY)

    def record_failure(self, conn, key: PrincipalKey, kind: Kind, reason: str) -> bool:
        """Remember an inline failure; False when another caller holds a live lease."""
        return (
            conn.execute(
                _RECORD_FAILURE,
                {"source": key.source, "object_id": key.object_id, "kind": kind, "reason": reason},
            ).fetchone()
            is not None
        )

    # Hand-over -------------------------------------------------------------------------

    def claim(self, conn, key: PrincipalKey, kind: Kind, *, retry: bool = False):
        """Claim the pending save in the caller's transaction; ``(job, kind)`` or None.

        With ``retry`` a recorded failure is cleared first. Queue the job with
        ``enqueue`` after the caller's transaction commits.
        """
        if retry:
            conn.execute(_CLEAR_FAILURE, (key.source, key.object_id))
        job = uuid4()
        row = conn.execute(
            _CLAIM,
            {
                "source": key.source,
                "object_id": key.object_id,
                "kind": kind,
                "job": job,
                "lease": self.lease_seconds,
            },
        ).fetchone()
        return (job, row["kind"]) if row else None

    def enqueue(self, key: PrincipalKey, kind: Kind, job: UUID) -> bool:
        """Queue a claimed job; a full queue (or shutdown) releases the claim."""
        with self._lock:
            if not self._closed:
                current = self._queued.get(key)
                if current is not None:
                    # Already queued here: it runs once, under the newest lease.
                    self._owned.discard(current[0])
                    self._queued[key] = (job, kind)
                    self._owned.add(job)
                    return True
                if len(self._queued) < self.queue_limit:
                    self._queued[key] = (job, kind)
                    self._owned.add(job)
                    try:
                        self._executor.submit(self._run, key)
                        return True
                    except RuntimeError:
                        self._queued.pop(key, None)
                        self._owned.discard(job)
        self._update(_RELEASE, (key.source, key.object_id, job), "release")
        return False

    def hand_over(self, conn, key: PrincipalKey, kind: Kind, *, retry: bool = False):
        """``claim`` in ``conn``; returns a callable that enqueues after commit."""
        claimed = self.claim(conn, key, kind, retry=retry)
        if claimed is None:
            return lambda: None
        job, row_kind = claimed
        return lambda: self.enqueue(key, row_kind, job)

    def queued(self) -> int:
        with self._lock:
            return len(self._queued)

    # Background jobs (saver thread, own budget) ----------------------------------------

    def _run(self, key: PrincipalKey) -> None:
        with self._lock:
            item = self._queued.pop(key, None)
        if item is None:
            return
        job, kind = item
        try:
            if not self.stop.is_set():
                # A fresh context: no request deadline or other request state leaks in.
                contextvars.Context().run(self._job, key, kind, job)
        finally:
            with self._lock:
                self._owned.discard(job)

    def _job(self, key: PrincipalKey, kind: Kind, job: UUID) -> None:
        outcome, reason = self._attempt(key, kind, job)
        # Result updates run outside the job budget, so a spent budget still records.
        if outcome == "failed":
            self._update(_FAIL, (reason, key.source, key.object_id, job), "fail")
        elif outcome == "stopped":
            self._update(_RELEASE, (key.source, key.object_id, job), "release")
        self.results.append(JobResult(job, key.object_id, outcome, reason))

    def _attempt(self, key: PrincipalKey, kind: Kind, job: UUID):
        try:
            with request_budget.request_budget(self.job_budget):
                with self.db.transaction() as conn:
                    started = conn.execute(
                        _START, (self.lease_seconds, key.source, key.object_id, job)
                    ).fetchone()
                if started is None:
                    return "dropped", None
                outcome = self._publish(key, started["kind"], job)
            if outcome.saved:
                return "published", None
            return "failed", outcome.reason or FAILURE_BUSY
        except _LeaseLost:
            return "lease_lost", None
        except NotInDirectory:
            return ("stopped", None) if self.stop.is_set() else ("failed", FAILURE_UNAVAILABLE)
        except Unsaved as failure:
            return ("stopped", None) if self.stop.is_set() else ("failed", failure.reason)
        except Exception as error:
            if self.stop.is_set():
                return "stopped", None
            # The exception type only: messages can name people or carry secrets.
            log.warning(
                "pick_save_job_failed", extra={"job": str(job), "error_type": type(error).__name__}
            )
            return "failed", FAILURE_UNAVAILABLE

    def _publish(self, key: PrincipalKey, kind: Kind, job: UUID):
        def read(generation: int) -> DirectoryEvidence:
            try:
                seconds = job_verification_deadline()
            except DirectoryUnavailable as error:
                raise Unsaved(failure_reason(error)) from None
            evidence = verify_root(
                self.config,
                key.object_id,
                kind,
                generation,
                deadline_seconds=seconds,
                call_cap=JOB_CALL_CAP,
                stop=self.stop,
                transport=self.transport,
            )
            check_evidence(evidence, key, kind)
            return evidence

        def owned(conn) -> None:
            if conn.execute(_OWNED, (key.source, key.object_id, job)).fetchone() is None:
                raise _LeaseLost()

        def done(conn, evidence) -> None:
            conn.execute(_DONE, (key.source, key.object_id, job))

        def retry_allowed() -> bool:
            left = _left()
            return left is None or left >= JOB_RETRY_MINIMUM

        return publish_with_retry(
            self.db,
            read,
            superadmin_group=self.superadmin,
            authorize=owned,
            on_accepted=done,
            attempts=2,
            retry_allowed=retry_allowed,
        )

    def _update(self, statement: str, params: tuple, action: str) -> None:
        try:
            with self.db.transaction() as conn:
                conn.execute(statement, params)
        except Exception as error:
            # The lease expires on its own; the next poll hands the save over again.
            log.warning(
                "pick_save_update_failed",
                extra={"action": action, "error_type": type(error).__name__},
            )

    # Shutdown --------------------------------------------------------------------------

    def close(self) -> None:
        """Stop reads, release this process's leases, then join the saver thread.

        Call before the database pool closes; the next poll restarts released saves.
        """
        self.stop.set()
        with self._lock:
            self._closed = True
            owned = sorted(self._owned, key=str)
            self._queued.clear()
        if owned:
            self._update(_RELEASE_ALL, (owned,), "release_all")
        self._executor.shutdown(wait=True, cancel_futures=True)
