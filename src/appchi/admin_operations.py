"""Audited source-head repair using the real reducer and a rollback-only probe."""

import re
import unicodedata

from fastapi import APIRouter, Request
from pydantic import Field, field_validator

from appchi.alerts.processor import _apply_one
from appchi.identity.authentication import authenticate
from appchi.maintenance.runtime import prepare_for_tenant
from appchi.models import StrictModel, uuid_string
from appchi.shared.errors import AppError
from appchi.shared.transactions import audit, command_result, coordinator, save_result
from appchi.serialization import wire

router = APIRouter(tags=["administration"])


@router.get("/api/admin/tenants/{tenant_id}/kafka")
def kafka_health(tenant_id: str, request: Request):
    """Bounded sanitized diagnostics; never a per-delivery status API."""
    with request.app.state.db.transaction() as conn:
        _administrator(conn, request)
        conn.execute("SELECT set_config('appchi.tenant_id',%s,true)", (tenant_id,))
        rejected = conn.execute(
            "SELECT delivery_id,received_at,recorded_at,error_code FROM kafka_source_results WHERE tenant_id=%s AND outcome='rejected' ORDER BY recorded_at DESC,delivery_id LIMIT 100",
            (tenant_id,),
        ).fetchall()
        positions = conn.execute(
            "SELECT * FROM kafka_consumer_positions ORDER BY consumer,topic,partition LIMIT 100"
        ).fetchall()
        faults = conn.execute(
            "SELECT consumer,topic,partition,input_offset,reason,recorded_at FROM kafka_pipeline_faults ORDER BY recorded_at DESC LIMIT 100"
        ).fetchall()
        passes = conn.execute(
            "SELECT index_epoch,boundary_seq,started_at,completed_at,last_page_at FROM search_reconciliation WHERE tenant_id=%s ORDER BY started_at DESC LIMIT 10",
            (tenant_id,),
        ).fetchall()
        return {
            "data": wire(
                {
                    "rejections": rejected,
                    "shared_partition_positions": positions,
                    "shared_partition_faults": faults,
                    "search_passes": passes,
                }
            ),
            "meta": {"limit": 100},
        }


class ProcessingRetry(StrictModel):
    command_id: str
    expected_block_generation: str
    reason: str = Field(min_length=1, max_length=1000)
    _command = field_validator("command_id")(uuid_string)

    @field_validator("expected_block_generation")
    @classmethod
    def generation(cls, value):
        if not re.fullmatch(r"0|[1-9][0-9]{0,18}", value) or int(value) > 2**63 - 1:
            raise ValueError("Decimal bigint generation required")
        return value

    @field_validator("reason")
    @classmethod
    def plain_reason(cls, value):
        if not value.strip() or any(
            unicodedata.category(char).startswith("C") and char not in "\n\t" for char in value
        ):
            raise ValueError("Nonblank plain text without control characters required")
        return value.strip()


def _administrator(conn, request, *, mutation=False):
    actor, _ = authenticate(conn, request, mutation=mutation)
    if not actor["super_admin"]:
        raise AppError("forbidden", "Global administration is required.", 403)
    return actor


def processing_health(conn, tenant):
    """Caller authorizes tenant view or global administration first."""
    if conn.execute("SELECT enabled FROM kafka_pipeline_control WHERE singleton").fetchone()[
        "enabled"
    ]:
        return {
            "transport": "kafka",
            "blocked": None,
            "status": "not_measured",
            "head": None,
            "diagnostics": f"/api/admin/tenants/{tenant}/kafka",
        }
    state = conn.execute(
        """SELECT w.blocked,w.block_generation,w.failures,w.next_attempt_at,
        (SELECT jsonb_build_object('id',h.id,'admission_order',h.admission_order,'received_at',h.received_at,'version',h.version)
         FROM ingest_items h WHERE h.tenant_id=w.tenant_id AND h.disposition='pending' ORDER BY h.admission_order LIMIT 1) AS head,
        (SELECT jsonb_build_object('recorded_at',a.recorded_at,'outcome',a.evidence->>'outcome','proof_code',a.evidence->>'proof_code',
           'block_generation',a.evidence->>'block_generation','head_id',a.evidence->>'head_id')
         FROM audit_events a WHERE a.tenant_id IS NULL AND a.kind='source-processing-retry'
         AND a.evidence->>'target_tenant_id'=w.tenant_id::text ORDER BY a.recorded_at DESC,a.id DESC LIMIT 1) AS last_repair
        FROM tenant_work_state w WHERE w.tenant_id=%s""",
        (tenant,),
    ).fetchone()
    if state is None:
        raise AppError("not_found", "Resource unavailable.", 404)
    return state


def _proof_code(error):
    # Never store exception messages, source values, SQL, or arbitrary error codes.
    known = {
        "capacity_accounting_mismatch",
        "maintenance_proof_unavailable",
        "maintenance_capacity_profile_required",
        "maintenance_gate_changed",
        "maintenance_gate_closed_with_timeline",
        "clock_untrusted",
        "cel_unavailable",
        "correlation_runtime_unready",
        "source_updates_pending",
    }
    code = getattr(error, "code", None)
    return code if code in known else "source_reducer_proof_failed"


def _probe(conn, tenant, catalog, head_id):
    """Always roll back every source/domain/projection/reservation side effect."""
    conn.execute("SAVEPOINT source_repair_probe")
    attempt = {}
    failure = None
    try:
        conn.execute(
            "UPDATE tenant_work_state SET blocked=false,next_attempt_at=clock_timestamp() WHERE tenant_id=%s",
            (tenant,),
        )
        applied = _apply_one(conn, tenant, attempt, catalog)
        row = conn.execute(
            "SELECT disposition FROM ingest_items WHERE tenant_id=%s AND id=%s", (tenant, head_id)
        ).fetchone()
        if (
            not applied
            or attempt.get("item_id") != head_id
            or not row
            or row["disposition"] != "applied"
        ):
            failure = "source_reducer_did_not_apply_head"
    except Exception as error:
        failure = _proof_code(error)
    finally:
        conn.execute("ROLLBACK TO SAVEPOINT source_repair_probe")
        conn.execute("RELEASE SAVEPOINT source_repair_probe")
    return failure


def _outcome(result):
    if "error" in result:
        raise AppError(result["error"]["code"], result["error"]["message"], 409)
    return result


@router.get("/api/admin/tenants/{tenant_id}/processing")
def health(tenant_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        _administrator(conn, request)
        conn.execute("SELECT set_config('appchi.tenant_id',%s,true)", (tenant_id,))
        return {"data": wire(processing_health(conn, tenant_id)), "meta": {}}


@router.post("/api/admin/tenants/{tenant_id}/processing/retry")
def retry(tenant_id: str, body: ProcessingRetry, request: Request):
    database = request.app.state.db
    # Check privilege before catalog access, then again after compilation under
    # the mutation identity guard, including before any stored-result replay.
    with database.transaction() as conn:
        _administrator(conn, request)
        if conn.execute("SELECT enabled FROM kafka_pipeline_control WHERE singleton").fetchone()[
            "enabled"
        ]:
            raise AppError(
                "legacy_pipeline_fenced",
                "Kafka processing requires the partition recovery runbook.",
                409,
            )
        conn.execute("SELECT set_config('appchi.tenant_id',%s,true)", (tenant_id,))
        prepared_head = conn.execute(
            "SELECT * FROM ingest_items WHERE tenant_id=%s AND disposition='pending' ORDER BY admission_order LIMIT 1",
            (tenant_id,),
        ).fetchone()
        claim = (
            conn.execute(
                "SELECT alert_id FROM alert_key_claims WHERE tenant_id=%s AND schema_version=%s AND key_digest=%s",
                (tenant_id, prepared_head["version"], prepared_head["key_digest"]),
            ).fetchone()
            if prepared_head
            else None
        )
    preparation_failure = None
    catalog = None
    try:
        catalog = prepare_for_tenant(
            database,
            tenant_id,
            getattr(request.app.state, "profile", None),
            alert_id=claim["alert_id"] if claim else None,
            effective_at=prepared_head["received_at"] if prepared_head else None,
            source_item=prepared_head,
        )
    except Exception as error:
        preparation_failure = _proof_code(error)
    with database.transaction() as conn:
        actor = _administrator(conn, request, mutation=True)
        conn.execute("SELECT set_config('appchi.tenant_id',%s,true)", (tenant_id,))
        scope = f"{tenant_id}:{actor['id']}:source-processing-retry"
        prior, fingerprint = command_result(
            conn, scope, body.command_id, {"tenant_id": tenant_id, **body.model_dump()}
        )
        if prior is not None:
            return _outcome(prior)
        state, now = coordinator(conn, tenant_id)
        head = conn.execute(
            """SELECT id,admission_order,received_at,version FROM ingest_items WHERE tenant_id=%s
            AND disposition='pending' ORDER BY admission_order LIMIT 1 FOR UPDATE""",
            (tenant_id,),
        ).fetchone()
        proof_code = None
        if state["block_generation"] != int(body.expected_block_generation):
            outcome = "block_generation_conflict"
        elif not state["blocked"]:
            outcome = "source_not_blocked"
        else:
            proof_code = preparation_failure or (
                "source_head_missing" if not head else _probe(conn, tenant_id, catalog, head["id"])
            )
            outcome = "repair_required" if proof_code else "resumed"
        evidence = {
            "target_tenant_id": tenant_id,
            "command_id": body.command_id,
            "expected_block_generation": body.expected_block_generation,
            "block_generation": state["block_generation"],
            "head_id": head["id"] if head else None,
            "reason": body.reason,
            "outcome": outcome,
            "proof_code": proof_code,
        }
        audit(conn, None, actor, "source-processing-retry", evidence)
        if outcome == "resumed":
            conn.execute(
                "UPDATE tenant_work_state SET blocked=false,failures=0,next_attempt_at=%s WHERE tenant_id=%s",
                (now, tenant_id),
            )
            result = {
                "data": {
                    "tenant_id": tenant_id,
                    "resumed": True,
                    "block_generation": state["block_generation"],
                    "head": head,
                },
                "meta": {},
            }
            result = save_result(conn, scope, body.command_id, fingerprint, result)
        else:
            result = {
                "error": {
                    "code": outcome,
                    "message": "The source head requires repair before retry."
                    if outcome == "repair_required"
                    else "The source block changed. Refresh and review.",
                }
            }
            result = save_result(conn, scope, body.command_id, fingerprint, result, status=409)
    return _outcome(result)
