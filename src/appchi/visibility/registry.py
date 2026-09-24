"""Durable reported view lifecycle. Does not decide measurement eligibility."""

from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

from psycopg.types.json import Jsonb

from appchi.access import authorize
from appchi.ingestion.native import canonical
from appchi.shared.errors import AppError
from appchi.shared.transactions import coordinator

from . import repository
from .authority import capture_authority
from .models import ChangeView, RegisterView, ViewDescriptor


@dataclass(frozen=True)
class RegistryLimits:
    """All allocations supplied explicitly; no telemetry retention default."""

    lease_seconds: int
    max_active_session_views: int  # per session and tenant
    max_active_tenant_views: int
    max_tenant_controls: int
    max_descriptor_bytes: int
    max_request_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError("Positive integer registry allocations required")
        if self.max_request_bytes > 65536 or self.max_descriptor_bytes > self.max_request_bytes:
            raise ValueError("Request allocation cannot exceed 64 KiB")
        if self.max_active_session_views > self.max_active_tenant_views:
            raise ValueError("Session allocation exceeds tenant allocation")
        if max(self.max_tenant_controls, self.max_active_tenant_views) >= 2**63 - 1:
            raise ValueError("Allocation exceeds PostgreSQL bigint range")
        if self.lease_seconds > 86400:
            raise ValueError("A view contact lease cannot exceed one day")


def descriptor_identity(view: ViewDescriptor, limits: RegistryLimits):
    descriptor = view.model_dump(mode="json")
    encoded = canonical({"schema": "appchi-view-intent-v1", "descriptor": descriptor})
    if len(encoded) > limits.max_descriptor_bytes:
        raise AppError("view_too_large", "View exceeds its descriptor allocation.", 413)
    # A syntactic intent digest, deliberately not an evaluated CEL/search digest.
    return descriptor, sha256(encoded).hexdigest()


def _authority(conn, request, tenant):
    principal, session, role = authorize(conn, request, tenant, mutation=True)
    _, now = coordinator(conn, tenant)
    authority = capture_authority(
        conn, tenant=tenant, principal=principal, session=session, role=role, now=now
    )
    return principal, session, now, authority


def register(conn, request, tenant, command: RegisterView, limits: RegistryLimits):
    principal, session, now, authority = _authority(conn, request, tenant)
    fingerprint = sha256(canonical(["register", command.model_dump(mode="json")])).digest()
    existing = repository.replay(
        conn, tenant, session["handle_hash"], command.command_id, fingerprint
    )
    if existing:
        return existing
    descriptor, query_digest = descriptor_identity(command.view, limits)
    repository.check_view_capacity(
        conn, tenant, session["handle_hash"], session["deployment_epoch"], now, limits
    )
    checkpoint = repository.next_checkpoint(conn, tenant, limits.max_tenant_controls)
    row = conn.execute(
        """INSERT INTO visibility_views(tenant_id,id,session_hash,principal_id,deployment_epoch,
        tab_id,revision,view_epoch,query_digest,descriptor,state,recorded_at,lease_until,checkpoint,authority)
        VALUES(%s,%s,%s,%s,%s,%s,1,1,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
        (
            tenant,
            uuid4(),
            session["handle_hash"],
            principal["id"],
            session["deployment_epoch"],
            command.tab_id,
            query_digest,
            Jsonb(descriptor),
            command.state,
            now,
            now + timedelta(seconds=limits.lease_seconds),
            checkpoint,
            Jsonb(authority),
        ),
    ).fetchone()
    return repository.append_control(conn, row, command.command_id, fingerprint)


def change(conn, request, tenant, view_id, command: ChangeView, limits: RegistryLimits):
    _, session, now, authority = _authority(conn, request, tenant)
    row = repository.get_view(
        conn, tenant, view_id, session["handle_hash"], session["deployment_epoch"]
    )
    fingerprint = sha256(
        canonical(["change", str(view_id), command.model_dump(mode="json")])
    ).digest()
    existing = repository.replay(
        conn, tenant, session["handle_hash"], command.command_id, fingerprint
    )
    if existing:
        return existing
    if row["revision"] != int(command.expected_revision):
        raise AppError(
            "revision_conflict", "View lifecycle has changed. Read its current revision.", 409
        )
    if row["state"] == "closed":
        raise AppError("view_closed", "Register a new view after closing.", 409)
    if command.state != "closed" and row["lease_until"] <= now:
        repository.check_view_capacity(
            conn, tenant, session["handle_hash"], session["deployment_epoch"], now, limits
        )
    descriptor, query_digest = (
        descriptor_identity(command.view, limits)
        if command.view is not None
        else (row["descriptor"], row["query_digest"])
    )
    checkpoint = repository.next_checkpoint(conn, tenant, limits.max_tenant_controls)
    # Reopening an expired contact cannot bridge its unknown-presence gap. Each
    # new query or expired contact starts a distinct view epoch for future input.
    epoch = row["view_epoch"] + int(
        query_digest != row["query_digest"] or row["lease_until"] <= now
    )
    changed = conn.execute(
        """UPDATE visibility_views SET revision=revision+1,view_epoch=%s,query_digest=%s,
        descriptor=%s,state=%s,recorded_at=%s,lease_until=%s,checkpoint=%s,authority=%s
        WHERE tenant_id=%s AND id=%s RETURNING *""",
        (
            epoch,
            query_digest,
            Jsonb(descriptor),
            command.state,
            now,
            now if command.state == "closed" else now + timedelta(seconds=limits.lease_seconds),
            checkpoint,
            Jsonb(authority),
            tenant,
            view_id,
        ),
    ).fetchone()
    return repository.append_control(conn, changed, command.command_id, fingerprint)
