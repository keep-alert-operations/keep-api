"""Pure transitions; persistence, locks, ciphertext erasure and audit are caller-owned."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from hashlib import sha256
import secrets
from typing import Literal

from appchi.shared.errors import AppError, unavailable

KeyState = Literal["prepared", "current", "retiring", "revoked", "expired"]


@dataclass(frozen=True)
class SecretMaterial:
    value: str = field(repr=False)
    verifier: bytes = field(repr=False)


def generate_key() -> SecretMaterial:
    value = "vena_" + secrets.token_urlsafe(32)
    return SecretMaterial(value, sha256(value.encode("ascii")).digest())


@dataclass(frozen=True)
class Credential:
    id: str
    state: KeyState
    activated_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    has_ciphertext: bool = True

    def __post_init__(self):
        if self.state not in {"prepared", "current", "retiring", "revoked", "expired"}:
            raise ValueError("Unknown credential state")
        if self.state == "retiring" and self.expires_at is None:
            raise ValueError("Retiring credentials require an immutable deadline")
        if self.state in {"revoked", "expired"} and self.has_ciphertext:
            raise ValueError("Invalidated credentials cannot retain ciphertext")

    def valid_at(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("Authoritative UTC time must have an offset")
        return self.state == "current" or (
            self.state == "retiring" and self.expires_at is not None and now < self.expires_at
        )


@dataclass(frozen=True)
class ReadinessEvidence:
    generation: int
    kong_binding_verified: bool
    grafana_write_acknowledged: bool
    grafana_configuration_verified: bool
    uncertain_write: bool = False

    def complete(self) -> bool:
        return (
            self.kong_binding_verified
            and self.grafana_write_acknowledged
            and self.grafana_configuration_verified
            and not self.uncertain_write
        )


def admission_allowed(
    credential: Credential | None,
    now: datetime,
    *,
    operator_state: str,
    deletion_pending: bool = False,
    grafana: bool = False,
):
    if operator_state == "deleted":
        raise AppError("operator_deleted", "Operator is unavailable", 403)
    if deletion_pending:
        raise AppError("operator_deletion_pending", "Operator deletion is pending", 403)
    if credential is not None and credential.state == "prepared" and grafana:
        raise unavailable("credential_activation_pending")
    if credential is None or not credential.valid_at(now):
        raise AppError("invalid_credential", "Credential is not valid at admission", 401)
    return True


def expire(credentials: tuple[Credential, ...], now: datetime) -> tuple[Credential, ...]:
    return tuple(
        replace(key, state="expired", has_ciphertext=False)
        if key.state == "retiring" and key.expires_at is not None and now >= key.expires_at
        else key
        for key in credentials
    )


def can_prepare(credentials: tuple[Credential, ...], now: datetime, *, rotation: bool):
    live = [key for key in credentials if key.valid_at(now)]
    if any(key.state == "prepared" for key in credentials) or any(
        key.state == "retiring" for key in live
    ):
        raise AppError(
            "credential_operation_conflict",
            "A pending operation or retiring key already exists",
            409,
        )
    if rotation and len([key for key in live if key.state == "current"]) != 1:
        raise AppError("no_current_key", "Rotation requires one current key", 409)
    if not rotation and live:
        raise AppError(
            "active_key_exists", "Create key requires no valid current or retiring key", 409
        )


def activate(
    credentials: tuple[Credential, ...],
    candidate_id: str,
    now: datetime,
    *,
    evidence: ReadinessEvidence,
    expected_generation: int,
    current_generation: int,
    operator_state: str,
    deletion_pending: bool = False,
) -> tuple[Credential, ...]:
    if (
        current_generation != expected_generation
        or evidence.generation != current_generation
        or operator_state == "deleted"
        or deletion_pending
    ):
        raise AppError(
            "stale_provisioning_generation", "Provisioning generation cannot activate", 409
        )
    candidate = next((key for key in credentials if key.id == candidate_id), None)
    if candidate is not None and candidate.state == "current":
        return credentials  # committed activation replay never moves the old deadline
    if candidate is None or candidate.state != "prepared":
        raise AppError("invalid_candidate", "Only a prepared credential can activate", 409)
    if not evidence.complete():
        raise unavailable("operator_readiness_unproven")
    if sum(key.state == "prepared" for key in credentials) != 1:
        raise unavailable("credential_state_inconsistent")
    keys = expire(credentials, now)
    if any(key.state == "retiring" and key.valid_at(now) for key in keys):
        raise AppError(
            "retiring_key_exists", "Retiring key must expire or be revoked before rotation", 409
        )
    if sum(key.state == "current" for key in keys) > 1:
        raise unavailable("credential_state_inconsistent")
    return tuple(
        replace(key, state="current", activated_at=now, expires_at=None)
        if key.id == candidate_id
        else replace(key, state="retiring", expires_at=now + timedelta(hours=24))
        if key.state == "current"
        else key
        for key in keys
    )


def revoke(
    credentials: tuple[Credential, ...], now: datetime, *, key_id: str | None = None
) -> tuple[Credential, ...]:
    if key_id is not None and not any(key.id == key_id for key in credentials):
        raise AppError("not_found", "Credential unavailable", 404)
    cancels_preparation = key_id is None or any(
        key.id == key_id and key.state == "current" for key in credentials
    )
    return tuple(
        replace(key, state="revoked", revoked_at=now, has_ciphertext=False)
        if key.state not in {"revoked", "expired"}
        and (
            key_id is None or key.id == key_id or (cancels_preparation and key.state == "prepared")
        )
        else key
        for key in credentials
    )


def cancel_rotation(
    credentials: tuple[Credential, ...], candidate_id: str, now: datetime
) -> tuple[Credential, ...]:
    candidate = next((key for key in credentials if key.id == candidate_id), None)
    if candidate is None or candidate.state != "prepared":
        raise AppError(
            "rotation_already_activated", "Only an unactivated rotation may be cancelled", 409
        )
    # Caller also fences generation and restores Grafana using the still-current
    # key before completing cancellation; revoked candidates never become valid.
    return revoke(credentials, now, key_id=candidate_id)


def current_for_copy(
    credentials: tuple[Credential, ...], now: datetime, *, deletion_pending: bool = False
) -> Credential:
    current = [
        key
        for key in credentials
        if key.state == "current" and key.valid_at(now) and key.has_ciphertext
    ]
    if deletion_pending or len(current) != 1:
        raise AppError("no_copyable_key", "No current key is available for copy", 409)
    return current[0]
