"""Durable provisioning attempts with no network I/O inside SQL transactions.

The configured adapter supplies verified remote facts, not arbitrary response
bodies. A capability manifest is mandatory; no default remote profile exists.
"""

from dataclasses import dataclass, field
from datetime import timedelta
import random
import math
import json
from typing import Protocol
from uuid import uuid4, UUID
from psycopg.types.json import Jsonb
from appchi.operators import repository as repo, keys
from appchi.operators.remote import CapabilityManifest
from appchi.operators.saga import retry_at, deletion_may_commit
from appchi.shared.errors import AppError, unavailable
from appchi.shared.transactions import coordinator


@dataclass(frozen=True)
class Work:
    operation_id: str
    operator_id: str
    tenant_id: str
    generation: int
    kind: str
    name: str
    pending_name: str | None
    candidate_id: str | None
    current_id: str | None
    reconcile_first: bool
    secret: str | None = field(default=None, repr=False)
    cancel_kind: str | None = None
    policy_generation: int = 0
    policy_document: str = ""
    activation_pending: bool = False
    secret_unavailable: bool = False


@dataclass(frozen=True)
class VerifiedResult:
    kong_verified: bool = False
    grafana_acknowledged: bool = False
    grafana_verified: bool = False
    complete_rule_inventory: bool = False
    labels_verified: bool = False
    policy_verified: bool = False
    receiver_verified: bool = False
    kong_cleanup_verified: bool = False
    consumer_id: str | None = None
    credential_id: str | None = None
    policy_generation: int = 0
    kafka_drain_verified: bool = False


class Provisioner(Protocol):
    manifest: CapabilityManifest

    def execute(self, work: Work) -> VerifiedResult:
        """Perform/reconcile one <=30-second remote attempt using recorded IDs.

        Ownership, complete inventory, CAS/controlled-writer protection and fresh
        readback are mandatory. Reconcile uncertain prior writes before mutation.
        The global database lease serializes Appchi attempts; it does not replace
        the manifest's protection against other Grafana writers.
        """
        ...


def claim(db, *, tenant=None, operation_id=None):
    with db.transaction(tenant) as conn:
        candidate = conn.execute(
            "SELECT tenant_id,operator_id,id FROM operator_operations WHERE completed_at IS NULL AND next_attempt_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp()) "
            "AND (%s::uuid IS NULL OR id=%s) AND (%s::uuid IS NULL OR tenant_id=%s) ORDER BY next_attempt_at,id LIMIT 1",
            (operation_id, operation_id, tenant, tenant),
        ).fetchone()
    if not candidate:
        return None
    with db.transaction(candidate["tenant_id"]) as conn:
        _, now = coordinator(conn, candidate["tenant_id"])
        op = repo.get_operator(
            conn, candidate["tenant_id"], candidate["operator_id"], lock=True, deleted=True
        )
        job = conn.execute(
            "SELECT * FROM operator_operations WHERE id=%s FOR UPDATE", (candidate["id"],)
        ).fetchone()
        if (
            job["completed_at"]
            or (job["lease_until"] and job["lease_until"] > now)
            or job["next_attempt_at"] > now
        ):
            return None
        if job["generation"] != op["generation"]:
            conn.execute(
                "UPDATE operator_operations SET state='superseded',completed_at=%s WHERE id=%s",
                (now, job["id"]),
            )
            return None
        token = uuid4()
        guard = conn.execute(
            "UPDATE operator_routing_guard SET lease_token=%s,lease_until=%s WHERE scope='grafana' AND (lease_until IS NULL OR lease_until<=%s) RETURNING scope",
            (token, now + timedelta(seconds=45), now),
        ).fetchone()
        if not guard:
            return None
        uncertain = job["state"] == "running" or job["progress"].get("uncertain", False)
        conn.execute(
            "UPDATE operator_operations SET state='running',lease_token=%s,lease_until=%s,step='remote-reconcile',attempts=attempts+1 WHERE id=%s",
            (token, now + timedelta(seconds=45), job["id"]),
        )
        return {
            **job,
            "lease_token": token,
            "attempts": job["attempts"] + 1,
            "uncertain": uncertain,
        }, op


def policy_document(current, rows):
    return json.dumps(
        {
            "operator_id": str(current["id"]),
            "tenant_id": str(current["tenant_id"]),
            "enabled": current["lifecycle"] != "deleted" and not current["deletion_pending"],
            "routing_names": [current["name"]]
            + ([current["pending_name"]] if current["pending_name"] else []),
            "credentials": {
                str(r["id"]): {
                    "state": r["state"],
                    **({"expires_at": r["expires_at"].timestamp()} if r["expires_at"] else {}),
                }
                for r in rows
                if r["state"] in ("prepared", "current", "retiring")
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def work_input(db, cipher, job, op):
    with db.transaction(op["tenant_id"]) as conn:
        # A last pre-call fence; a concurrent invalidation after this point still
        # cannot commit activation because completion repeats these checks.
        current = repo.get_operator(conn, op["tenant_id"], op["id"], deleted=True, lock=True)
        if current["generation"] != job["generation"]:
            raise AppError("stale_provisioning_generation", "Operation changed.", 409)
        rows = conn.execute(
            "SELECT * FROM operator_credentials WHERE tenant_id=%s AND operator_id=%s",
            (op["tenant_id"], op["id"]),
        ).fetchall()
        old = next((r for r in rows if r["state"] == "current"), None)
        candidate = next(
            (
                r
                for r in rows
                if r["id"] == job["candidate_id"] and r["state"] in ("prepared", "current")
            ),
            None,
        )
        selected = candidate if job["kind"] in ("setup", "rotate", "create_key") else old
        if (
            job["kind"] == "cancel"
            and job["progress"].get("cancel_kind") == "delete"
            and current["lifecycle"] == "setup_pending"
            and old is None
        ):
            # Deleting an unactivated operator does not destroy its candidate.
            # Cancellation repairs that same remote binding before setup resumes.
            candidate = next((r for r in rows if r["state"] == "prepared"), None)
            selected = candidate
        secret = None
        secret_unavailable = False
        if selected and selected["ciphertext"] is not None:
            try:
                secret = cipher.open(
                    bytes(selected["ciphertext"]), f"operator-key:{op['id']}:{selected['id']}:1"
                ).decode()
            except Exception:
                if job["kind"] in ("setup", "rotate", "create_key"):
                    raise unavailable("credential_decryption_unavailable") from None
                # Gateway denial contains no secrets and must still run when
                # unrelated surviving-key material cannot be decrypted.
                secret_unavailable = True
        document = policy_document(current, rows)
        policy = conn.execute(
            "INSERT INTO operator_gateway_policies(operator_id,generation,document) VALUES(%s,1,%s) "
            "ON CONFLICT(operator_id) DO UPDATE SET generation=operator_gateway_policies.generation + "
            "CASE WHEN operator_gateway_policies.document<>EXCLUDED.document THEN 1 ELSE 0 END,document=EXCLUDED.document "
            "RETURNING generation",
            (op["id"], document),
        ).fetchone()
        return Work(
            str(job["id"]),
            str(op["id"]),
            str(op["tenant_id"]),
            job["generation"],
            job["kind"],
            op["name"],
            op["pending_name"],
            str(candidate["id"]) if candidate else None,
            str(old["id"]) if old else None,
            job["uncertain"],
            secret,
            job["progress"].get("cancel_kind"),
            policy["generation"],
            document,
            bool(job["progress"].get("activation_pending")),
            secret_unavailable,
        )


def complete(db, job, result):
    with db.transaction(job["tenant_id"]) as conn:
        _, now = coordinator(conn, job["tenant_id"])
        op = repo.get_operator(conn, job["tenant_id"], job["operator_id"], lock=True, deleted=True)
        current = conn.execute(
            "SELECT * FROM operator_operations WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if (
            current["completed_at"]
            or current["lease_token"] != job["lease_token"]
            or op["generation"] != job["generation"]
            or not current["lease_until"]
            or now >= current["lease_until"]
        ):
            return False
        guard = conn.execute(
            "SELECT * FROM operator_routing_guard WHERE scope='grafana' FOR UPDATE"
        ).fetchone()
        if guard["lease_token"] != job["lease_token"] or now >= guard["lease_until"]:
            return False
        states = repo.credential_states(repo.credential_rows(conn, op))
        policy = conn.execute(
            "SELECT * FROM operator_gateway_policies WHERE operator_id=%s FOR UPDATE", (op["id"],)
        ).fetchone()
        if (
            not policy
            or policy["generation"] != result.policy_generation
            or not result.kong_verified
        ):
            raise unavailable("kong_policy_unverified")
        conn.execute(
            "UPDATE operator_gateway_policies SET verified_generation=generation,verified_at=%s WHERE operator_id=%s",
            (now, op["id"]),
        )
        kind = job["kind"]
        final_phase = current["progress"].get("final_policy_pending") is True
        restoring = kind == "create_key" and current["progress"].get("restore_cancel") is True
        if final_phase:
            # Domain changes already committed at this point of no return.
            # Only their exact final gateway policy may complete the operation.
            pass
        elif kind in ("setup", "rotate", "create_key"):
            if restoring and not (
                current["progress"].get("cancel_kind") in ("delete", "rename", "rotate")
                and result.complete_rule_inventory
                and result.labels_verified
                and result.policy_verified
                and result.receiver_verified
            ):
                raise unavailable("grafana_verification_required")
            gate = conn.execute(
                "SELECT ready FROM capability_gates WHERE capability='v2_ingress'"
            ).fetchone()
            if not gate or not gate["ready"]:
                raise unavailable("v2_activation_fenced")
            if not result.consumer_id or not result.credential_id:
                raise unavailable("kong_binding_unverified")
            for value in (result.consumer_id, result.credential_id):
                if str(UUID(value)) != value:
                    raise unavailable("kong_binding_unverified")
            evidence = keys.ReadinessEvidence(
                job["generation"],
                result.kong_verified,
                result.grafana_acknowledged,
                result.grafana_verified,
            )
            activated = keys.activate(
                states,
                str(job["candidate_id"]),
                now,
                evidence=evidence,
                expected_generation=job["generation"],
                current_generation=op["generation"],
                operator_state=op["lifecycle"],
                deletion_pending=op["deletion_pending"]
                and not (restoring and current["progress"].get("cancel_kind") == "delete"),
            )
            if op["pending_name"] and not (
                result.complete_rule_inventory and result.labels_verified and result.policy_verified
            ):
                raise unavailable("rename_verification_required")
            repo.persist_credentials(conn, activated)
            conn.execute(
                "UPDATE operator_credentials SET kong_consumer_id=%s,kong_credential_id=%s WHERE id=%s",
                (result.consumer_id, result.credential_id, job["candidate_id"]),
            )
            for binding, identifier in [
                ("kong_consumer", result.consumer_id),
                ("kong_credential", result.credential_id),
            ]:
                conn.execute(
                    "INSERT INTO operator_remote_bindings(tenant_id,operator_id,kind,remote_id,generation,verified_at) VALUES(%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT(operator_id,kind) DO UPDATE SET remote_id=EXCLUDED.remote_id,generation=EXCLUDED.generation,verified_at=EXCLUDED.verified_at",
                    (op["tenant_id"], op["id"], binding, identifier, job["generation"], now),
                )
            if not current["progress"].get("activation_pending"):
                # Activation is durable before distributing the allow policy.
                # Retrying this phase never moves the retiring key's deadline.
                conn.execute(
                    "UPDATE operator_operations SET state='pending',step='gateway-activation',error_code=NULL,progress=%s,lease_token=NULL,lease_until=NULL,next_attempt_at=%s WHERE id=%s",
                    (Jsonb({**current["progress"], "activation_pending": True}), now, job["id"]),
                )
                conn.execute(
                    "UPDATE operator_routing_guard SET lease_token=NULL,lease_until=NULL WHERE scope='grafana' AND lease_token=%s",
                    (job["lease_token"],),
                )
                return False
            conn.execute("UPDATE operators SET lifecycle='ready' WHERE id=%s", (op["id"],))
            if restoring:
                conn.execute(
                    "UPDATE operators SET deletion_pending=false,pending_name=NULL,pending_name_key=NULL WHERE id=%s",
                    (op["id"],),
                )
                conn.execute(
                    "DELETE FROM operator_name_claims WHERE operator_id=%s AND name_key<>%s",
                    (op["id"], op["name_key"]),
                )
        elif kind in ("rename", "cancel", "delete"):
            if not (
                result.grafana_acknowledged
                and result.grafana_verified
                and result.complete_rule_inventory
                and result.labels_verified
                and result.policy_verified
                and result.receiver_verified
            ):
                raise unavailable("grafana_verification_required")
            if kind == "delete":
                if not result.kafka_drain_verified:
                    raise unavailable("operator_kafka_drain_pending")
                repo.in_use(conn, op)
                deletion_may_commit(
                    generation_matches=True,
                    retained_alert_count=0,
                    pending_input_count=0,
                    admission_fenced=op["deletion_pending"],
                    complete_rule_inventory=True,
                    labels_removed=True,
                    policy_absent=True,
                    receiver_absent=True,
                    uncertain_write=False,
                )
                repo.persist_credentials(conn, keys.revoke(states, now))
                conn.execute(
                    "UPDATE operators SET lifecycle='deleted',deleted_at=%s,pending_name=NULL,pending_name_key=NULL WHERE id=%s",
                    (now, op["id"]),
                )
                conn.execute("DELETE FROM operator_name_claims WHERE operator_id=%s", (op["id"],))
            elif kind == "cancel":
                conn.execute(
                    "UPDATE operators SET deletion_pending=false,pending_name=NULL,pending_name_key=NULL WHERE id=%s",
                    (op["id"],),
                )
                conn.execute(
                    "DELETE FROM operator_name_claims WHERE operator_id=%s AND name_key<>%s",
                    (op["id"], op["name_key"]),
                )
        elif kind in ("cleanup", "repair"):
            if not (
                result.kong_cleanup_verified
                and result.grafana_acknowledged
                and result.grafana_verified
            ):
                raise unavailable("remote_cleanup_unverified")
            if op["pending_name"]:
                if not (
                    result.complete_rule_inventory
                    and result.labels_verified
                    and result.policy_verified
                    and result.receiver_verified
                ):
                    raise unavailable("rename_verification_required")
                conn.execute(
                    "UPDATE operators SET pending_name=NULL,pending_name_key=NULL WHERE id=%s",
                    (op["id"],),
                )
                conn.execute(
                    "DELETE FROM operator_name_claims WHERE operator_id=%s AND name_key<>%s",
                    (op["id"], op["name_key"]),
                )
        if (
            not final_phase
            and kind in ("setup", "create_key", "rename")
            and op["pending_name"]
            and not restoring
        ):
            conn.execute(
                "UPDATE operators SET name=pending_name,name_key=pending_name_key,pending_name=NULL,pending_name_key=NULL WHERE id=%s",
                (op["id"],),
            )
            conn.execute(
                "DELETE FROM operator_name_claims WHERE operator_id=%s AND name_key<>%s",
                (op["id"], op["pending_name_key"]),
            )
        final_op = repo.get_operator(conn, job["tenant_id"], job["operator_id"], deleted=True)
        final_document = policy_document(final_op, repo.credential_rows(conn, final_op))
        if final_document != policy["document"]:
            conn.execute(
                "UPDATE operator_operations SET state='pending',step='gateway-final-policy',error_code=NULL,progress=%s,lease_token=NULL,lease_until=NULL,next_attempt_at=%s WHERE id=%s",
                (Jsonb({**current["progress"], "final_policy_pending": True}), now, job["id"]),
            )
            conn.execute(
                "UPDATE operator_routing_guard SET lease_token=NULL,lease_until=NULL WHERE scope='grafana' AND lease_token=%s",
                (job["lease_token"],),
            )
            return False
        conn.execute(
            "UPDATE operators SET revision=revision+1,updated_at=%s,last_reconciled_at=%s,integration_health='in_sync' WHERE id=%s",
            (now, now, op["id"]),
        )
        conn.execute(
            "UPDATE operator_operations SET state='completed',step='complete',completed_at=%s,error_code=NULL,lease_token=NULL,lease_until=NULL WHERE id=%s",
            (now, job["id"]),
        )
        conn.execute(
            "UPDATE operator_routing_guard SET lease_token=NULL,lease_until=NULL WHERE scope='grafana' AND lease_token=%s",
            (job["lease_token"],),
        )
        conn.execute(
            "INSERT INTO operator_steps(id,tenant_id,operator_id,operation_id,generation,step,outcome,recorded_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                op["tenant_id"],
                op["id"],
                job["id"],
                job["generation"],
                "remote-reconcile",
                "verified",
                now,
            ),
        )
        repo.audit(
            conn,
            op,
            {"id": job["actor_id"], "display_name": job["actor_label"]},
            "operator-" + kind + "-completed",
            {"operation_id": job["id"]},
        )
        if kind == "delete" and not result.kong_cleanup_verified:
            fresh = repo.get_operator(conn, op["tenant_id"], op["id"], deleted=True)
            continuation = repo.enqueue(conn, fresh, {}, "cleanup")
            conn.execute(
                "UPDATE operator_operations SET progress=progress||jsonb_build_object('continuation_id',%s::text) WHERE id=%s",
                (str(continuation["id"]), job["id"]),
            )
        if (
            kind == "cancel"
            and job["progress"].get("cancel_kind") == "delete"
            and op["lifecycle"] == "setup_pending"
        ):
            candidate = next((key for key in states if key.state == "prepared"), None)
            if candidate:
                fresh = repo.get_operator(conn, op["tenant_id"], op["id"])
                continuation = repo.enqueue(conn, fresh, {}, "setup", candidate=candidate.id)
                conn.execute(
                    "UPDATE operator_operations SET progress=progress||jsonb_build_object('continuation_id',%s::text) WHERE id=%s",
                    (str(continuation["id"]), job["id"]),
                )
        return True


def failed(db, job, error):
    # Store only a controlled code; never an exception message or remote body.
    allowed = {
        "operator_capabilities_unverified",
        "operator_capability_missing",
        "safe_remote_writer_required",
        "controlled_writer_unverified",
        "remote_needs_attention",
        "adapter_operation_unsupported",
        "credential_decryption_unavailable",
        "remote_outcome_uncertain",
        "remote_version_conflict",
        "operator_readiness_unproven",
        "grafana_verification_required",
        "remote_cleanup_unverified",
        "rename_verification_required",
        "kong_binding_unverified",
        "v2_activation_fenced",
        "kong_policy_unverified",
        "operator_kafka_drain_pending",
        "operator_kafka_drain_unverified",
        "operator_in_use",
    }
    code = (
        error.code
        if isinstance(error, AppError) and error.code in allowed
        else "remote_unavailable"
    )
    attention = code in {
        "operator_capabilities_unverified",
        "operator_capability_missing",
        "safe_remote_writer_required",
        "controlled_writer_unverified",
        "remote_needs_attention",
        "adapter_operation_unsupported",
        "credential_decryption_unavailable",
        "v2_activation_fenced",
    }
    retry_after = (
        error.fields.get("retry_after_seconds")
        if isinstance(error, AppError) and isinstance(error.fields, dict)
        else None
    )
    if type(retry_after) not in (int, float) or not math.isfinite(retry_after):
        retry_after = None
    with db.transaction(job["tenant_id"]) as conn:
        _, now = coordinator(conn, job["tenant_id"])
        op = repo.get_operator(conn, job["tenant_id"], job["operator_id"], lock=True, deleted=True)
        current = conn.execute(
            "SELECT * FROM operator_operations WHERE id=%s FOR UPDATE", (job["id"],)
        ).fetchone()
        if (
            current["completed_at"]
            or current["lease_token"] != job["lease_token"]
            or op["generation"] != job["generation"]
        ):
            return
        due = retry_at(
            now,
            job["attempts"] - 1,
            jitter=random.uniform(-0.2, 0.2),
            needs_attention=attention,
            retry_after_seconds=retry_after,
        )
        progress = {**current["progress"], "uncertain": True}
        conn.execute(
            "UPDATE operator_operations SET state=%s,error_code=%s,next_attempt_at=%s,progress=%s,lease_token=NULL,lease_until=NULL WHERE id=%s",
            ("needs_attention" if attention else "pending", code, due, Jsonb(progress), job["id"]),
        )
        health = (
            "needs_attention"
            if attention or now - job["created_at"] >= timedelta(minutes=15)
            else "pending"
        )
        conn.execute("UPDATE operators SET integration_health=%s WHERE id=%s", (health, op["id"]))
        conn.execute(
            "UPDATE operator_routing_guard SET lease_token=NULL,lease_until=NULL WHERE scope='grafana' AND lease_token=%s",
            (job["lease_token"],),
        )
        conn.execute(
            "INSERT INTO operator_steps(id,tenant_id,operator_id,operation_id,generation,step,outcome,recorded_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                uuid4(),
                op["tenant_id"],
                op["id"],
                job["id"],
                job["generation"],
                "remote-reconcile",
                code,
                now,
            ),
        )


def run_one(db, cipher, adapter: Provisioner | None = None, *, tenant=None, operation_id=None):
    if operation_id is None:
        # Retained future scheduler implementation. HTTP executes only its own job.
        expire_due(db)
        schedule_reconciliation(db)
    claimed = claim(db, tenant=tenant, operation_id=operation_id)
    if not claimed:
        return False
    job, op = claimed
    try:
        if adapter is None:
            raise unavailable("operator_capabilities_unverified")
        adapter.manifest.validate()
        work = work_input(db, cipher, job, op)
        result = adapter.execute(work)
        if not isinstance(result, VerifiedResult):
            raise unavailable("remote_verification_failed")
        return complete(db, job, result)
    except Exception as error:
        failed(db, job, error)
        return False


def expire_due(db):
    """Erase expired material under the same admission coordinator; no remote wait."""
    with db.transaction() as conn:
        due = conn.execute(
            "SELECT tenant_id,operator_id FROM operator_credentials WHERE state='retiring' AND expires_at<=clock_timestamp() ORDER BY expires_at,id LIMIT 100"
        ).fetchall()
    for item in due:
        with db.transaction(item["tenant_id"]) as conn:
            _, now = coordinator(conn, item["tenant_id"])
            op = repo.get_operator(
                conn, item["tenant_id"], item["operator_id"], lock=True, deleted=True
            )
            states = repo.credential_states(repo.credential_rows(conn, op))
            expired = keys.expire(states, now)
            if states == expired:
                continue
            repo.persist_credentials(conn, expired)
            op = repo.bump(conn, op)
            job = repo.active_operation(conn, op)
            if job:
                conn.execute(
                    "UPDATE operator_operations SET generation=%s,state='pending',progress=%s,lease_token=NULL,lease_until=NULL,next_attempt_at=%s WHERE id=%s",
                    (
                        op["generation"],
                        Jsonb({**job["progress"], "uncertain": True}),
                        now,
                        job["id"],
                    ),
                )
            else:
                job = repo.enqueue(conn, op, {}, "cleanup")
            changed = [after.id for before, after in zip(states, expired) if before != after]
            repo.audit(
                conn, op, {}, "keys-expired", {"credential_ids": changed, "operation_id": job["id"]}
            )


def schedule_reconciliation(db):
    """Due scans can be called every30 seconds; successful ready operators reconcile every5 minutes."""
    with db.transaction() as conn:
        due = conn.execute(
            "SELECT tenant_id,id FROM operators o WHERE lifecycle='ready' AND NOT deletion_pending AND (last_reconciled_at IS NULL OR last_reconciled_at<=clock_timestamp()-interval '5 minutes') AND NOT EXISTS(SELECT 1 FROM operator_operations j WHERE j.operator_id=o.id AND j.completed_at IS NULL) ORDER BY last_reconciled_at NULLS FIRST,id LIMIT 100"
        ).fetchall()
    for item in due:
        with db.transaction(item["tenant_id"]) as conn:
            coordinator(conn, item["tenant_id"])
            op = repo.get_operator(conn, item["tenant_id"], item["id"], lock=True)
            if not repo.active_operation(conn, op):
                repo.enqueue(conn, op, {}, "repair")
