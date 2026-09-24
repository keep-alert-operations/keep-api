from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from appchi.operators.keys import (
    Credential,
    ReadinessEvidence,
    activate,
    admission_allowed,
    can_prepare,
    cancel_rotation,
    current_for_copy,
    expire,
    generate_key,
    revoke,
)
from appchi.operators.saga import ProvisioningProgress, deletion_may_commit, next_step, retry_at
from appchi.shared.errors import AppError

NOW = datetime(2026, 9, 22, 12, tzinfo=timezone.utc)
PROOF = ReadinessEvidence(7, True, True, True)


def rotation(keys, **kwargs):
    return activate(
        keys,
        "candidate",
        NOW,
        evidence=kwargs.get("evidence", PROOF),
        expected_generation=7,
        current_generation=kwargs.get("generation", 7),
        operator_state="ready",
        deletion_pending=kwargs.get("deleting", False),
    )


def test_key_generation_is_unique_random_and_repr_contains_no_secret():
    a, b = generate_key(), generate_key()
    assert a.value.startswith("vena_") and len(a.value) == 48
    assert a.value != b.value and a.verifier != b.verifier
    assert a.value not in repr(a) and a.verifier.hex() not in repr(a)


def test_prepared_route_and_exact_expiry_boundary():
    prepared = Credential("p", "prepared")
    with pytest.raises(AppError) as failure:
        admission_allowed(prepared, NOW, operator_state="setup_pending", grafana=True)
    assert failure.value.status == 503
    with pytest.raises(AppError) as failure:
        admission_allowed(prepared, NOW, operator_state="setup_pending")
    assert failure.value.status == 401
    retiring = Credential("r", "retiring", expires_at=NOW)
    assert admission_allowed(retiring, NOW - timedelta(microseconds=1), operator_state="ready")
    with pytest.raises(AppError):
        admission_allowed(retiring, NOW, operator_state="ready")
    assert expire((retiring,), NOW)[0].state == "expired"
    assert expire((retiring,), NOW)[0].has_ciphertext is False


def test_rotation_waits_for_grafana_and_overlap_starts_at_activation_once():
    old, prepared = (
        Credential("old", "current", activated_at=NOW - timedelta(days=7)),
        Credential("candidate", "prepared"),
    )
    keys = (old, prepared)
    assert current_for_copy(keys, NOW).id == "old"
    with pytest.raises(AppError):
        rotation(keys, evidence=replace(PROOF, grafana_write_acknowledged=False))
    changed = rotation(keys)
    assert changed[0].state == "retiring" and changed[0].expires_at == NOW + timedelta(hours=24)
    assert changed[1].state == "current"
    replay = activate(
        changed,
        "candidate",
        NOW + timedelta(hours=2),
        evidence=PROOF,
        expected_generation=7,
        current_generation=7,
        operator_state="ready",
    )
    assert replay == changed
    with pytest.raises(AppError):
        can_prepare(changed, NOW, rotation=True)


def test_revoking_current_cancels_prepared_but_does_not_promote_retiring():
    keys = (Credential("old", "current"), Credential("candidate", "prepared"))
    stopped = revoke(keys, NOW, key_id="old")
    assert all(key.state == "revoked" and not key.has_ciphertext for key in stopped)
    with pytest.raises(AppError):
        rotation(stopped)
    overlap = rotation(keys)
    stopped = revoke(overlap, NOW, key_id="candidate")
    assert stopped[0].state == "retiring" and stopped[0].valid_at(NOW)
    with pytest.raises(AppError):
        current_for_copy(stopped, NOW)
    with pytest.raises(AppError):
        can_prepare(stopped, NOW, rotation=False)
    assert all(key.state == "revoked" for key in revoke(stopped, NOW))


def test_cancel_fences_candidate_and_stale_worker_cannot_activate():
    keys = (Credential("old", "current"), Credential("candidate", "prepared"))
    stopped = cancel_rotation(keys, "candidate", NOW)
    assert stopped[0] == keys[0]
    assert stopped[1].state == "revoked" and not stopped[1].has_ciphertext
    with pytest.raises(AppError):
        rotation(keys, generation=8)
    with pytest.raises(AppError):
        rotation(keys, deleting=True)
    with pytest.raises(AppError):
        cancel_rotation(rotation(keys), "candidate", NOW)


def test_saga_unknown_outcomes_never_advance_or_reset_candidate():
    assert next_step(ProvisioningProgress(7), 7) == "provision_and_verify_kong"
    assert next_step(ProvisioningProgress(7, True), 7) == "configure_grafana_same_candidate"
    assert (
        next_step(ProvisioningProgress(7, True, uncertain_step="grafana"), 7) == "reconcile_grafana"
    )
    assert (
        next_step(ProvisioningProgress(7, True, True, True), 7)
        == "activate_under_authoritative_locks"
    )
    assert next_step(ProvisioningProgress(7, True, True, True), 8) == "reconcile_obsolete_effects"
    assert retry_at(NOW, 0, jitter=0) == NOW + timedelta(seconds=5)
    assert retry_at(NOW, 100, jitter=0) == NOW + timedelta(seconds=300)
    assert retry_at(NOW, 0, jitter=0, retry_after_seconds=900) == NOW + timedelta(seconds=900)


def test_deletion_requires_verified_absence_and_preserves_retained_alert_guard():
    evidence = dict(
        generation_matches=True,
        retained_alert_count=0,
        pending_input_count=0,
        admission_fenced=True,
        complete_rule_inventory=True,
        labels_removed=True,
        policy_absent=True,
        receiver_absent=True,
        uncertain_write=False,
    )
    assert deletion_may_commit(**evidence)
    for changed in (
        {"retained_alert_count": 1},
        {"pending_input_count": 1},
        {"uncertain_write": True},
        {"complete_rule_inventory": False},
        {"policy_absent": False},
    ):
        with pytest.raises(AppError):
            deletion_may_commit(**dict(evidence, **changed))
