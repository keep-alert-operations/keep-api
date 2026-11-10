"""Pure durable-job decisions. This module is not a SQL job scheduler."""

from dataclasses import dataclass
from datetime import datetime, timedelta

from keep.shared.errors import AppError


@dataclass(frozen=True)
class ProvisioningProgress:
    generation: int
    kong_verified: bool = False
    grafana_acknowledged: bool = False
    grafana_verified: bool = False
    uncertain_step: str | None = None
    invalidated: bool = False


def next_step(progress: ProvisioningProgress, authoritative_generation: int) -> str:
    if progress.invalidated or progress.generation != authoritative_generation:
        return "reconcile_obsolete_effects"
    if progress.uncertain_step is not None:
        return "reconcile_" + progress.uncertain_step
    if not progress.kong_verified:
        return "provision_and_verify_kong"
    if not progress.grafana_acknowledged:
        return "configure_grafana_same_candidate"
    if not progress.grafana_verified:
        return "verify_grafana"
    return "activate_under_authoritative_locks"


def retry_at(
    now: datetime,
    attempt: int,
    *,
    jitter: float,
    retry_after_seconds: float | None = None,
    needs_attention: bool = False,
) -> datetime:
    if attempt < 0 or not -0.2 <= jitter <= 0.2:
        raise ValueError("Retry attempt and jitter are out of range")
    delay = 3600 if needs_attention else min(300, 5 * 2 ** min(attempt, 6)) * (1 + jitter)
    if retry_after_seconds is not None:
        delay = max(delay, min(max(retry_after_seconds, 0), 3600))
    return now + timedelta(seconds=delay)


def deletion_may_commit(
    *,
    generation_matches: bool,
    retained_alert_count: int,
    pending_input_count: int,
    admission_fenced: bool,
    complete_rule_inventory: bool,
    labels_removed: bool,
    policy_absent: bool,
    receiver_absent: bool,
    uncertain_write: bool,
):
    if retained_alert_count or pending_input_count:
        raise AppError("operator_in_use", "Retained alerts or pending inputs prevent deletion", 409)
    if not (
        generation_matches
        and admission_fenced
        and complete_rule_inventory
        and labels_removed
        and policy_absent
        and receiver_absent
        and not uncertain_write
    ):
        raise AppError(
            "operator_deletion_pending", "Verified Grafana cleanup is required before deletion", 409
        )
    return True
