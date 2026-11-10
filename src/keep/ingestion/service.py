import hashlib
import secrets
from datetime import timedelta
from time import monotonic
from uuid import uuid4

from psycopg.types.json import Jsonb

from keep.ingestion.native import (
    RETRY_ID,
    canonical,
    digest,
    format_native_time,
    identity,
    object_slices,
    parse_json,
    validate_native,
)
from keep.shared.errors import AppError, unavailable
from keep.shared.transactions import coordinator
from keep.serialization import wire


class Admission:
    def __init__(self, db, cipher, profile):
        self.db, self.cipher, self.profile = db, cipher, profile

    def admit(self, raw, version, request_key=None, gateway=None, *, receipt_started=None):
        receipt_started = monotonic() if receipt_started is None else receipt_started
        if len(raw) > 4 * 1024 * 1024:
            raise AppError("body_too_large", "Ingestion body exceeds 4 MiB.", 413)
        parsed = parse_json(raw)
        if not isinstance(parsed, dict):
            raise AppError("invalid_envelope", "Expected an object.", 400)
        batch = "alerts" in parsed
        if batch and (set(parsed) != {"alerts"} or not isinstance(parsed["alerts"], list)):
            raise AppError("invalid_envelope", "Expected only an alerts array.", 400)
        if batch and not 1 <= len(parsed["alerts"]) <= 100:
            raise AppError("batch_size", "Batches require 1â€“100 members.", 413)
        if not batch and len(raw) > 65536:
            raise AppError("body_too_large", "Single objects are limited to 64 KiB.", 413)
        if request_key is not None and not RETRY_ID.fullmatch(request_key):
            raise AppError("invalid_retry_id", "Invalid Idempotency-Key.", 422)
        slices = object_slices(raw)
        members = parsed["alerts"] if batch else [{"payload": parsed}]
        validated = []
        for index, member in enumerate(members):
            try:
                if (
                    not isinstance(member, dict)
                    or set(member) - {"payload", "event_id"}
                    or "payload" not in member
                ):
                    raise AppError(
                        "invalid_wrapper", "Each member requires payload and optional event_id."
                    )
                event_id = member.get("event_id")
                if "event_id" in member and (
                    not isinstance(event_id, str) or not RETRY_ID.fullmatch(event_id)
                ):
                    raise AppError("invalid_retry_id", "Invalid event_id.")
                item_raw = slices.get(("alerts", index, "payload") if batch else (), b"")
                payload = validate_native(member["payload"], version, item_raw)
                validated.append((payload, item_raw, event_id, None))
            except AppError as error:
                validated.append(
                    (
                        None,
                        None,
                        None,
                        {"code": error.code, "message": error.message, "fields": error.fields},
                    )
                )
        return self._admit_validated(
            parsed,
            validated,
            version,
            request_key,
            gateway,
            batch,
            receipt_started=receipt_started,
        )

    def admit_grafana(self, raw, request_key, gateway, *, receipt_started=None):
        receipt_started = monotonic() if receipt_started is None else receipt_started
        from keep.operators.grafana import map_webhook, ADAPTER_VERSION
        from keep.operators.repository import routing

        if request_key is not None and not RETRY_ID.fullmatch(request_key):
            raise AppError("invalid_retry_id", "Invalid Idempotency-Key.", 422)
        with self.db.transaction() as conn:
            tenant, operator = self._route(conn, "v2", gateway)
            _, now = coordinator(conn, tenant)
            row = self._credential(conn, tenant, operator, gateway, now, grafana=True)
            route = routing(conn, row)
            expected_revision = row["revision"]
        members = map_webhook(raw, route)
        validated = [
            (member.payload, member.original_bytes, None, member.error) for member in members
        ]
        return self._admit_validated(
            parse_json(raw),
            validated,
            "v2",
            request_key,
            gateway,
            True,
            adapter_version=ADAPTER_VERSION,
            operator_revision=expected_revision,
            receipt_started=receipt_started,
        )

    def _admit_validated(
        self,
        parsed,
        validated,
        version,
        request_key,
        gateway,
        batch,
        *,
        adapter_version=None,
        operator_revision=None,
        receipt_started=None,
    ):
        with self.db.transaction() as conn:
            if conn.execute(
                "SELECT enabled FROM kafka_pipeline_control WHERE singleton"
            ).fetchone()["enabled"]:
                raise unavailable("legacy_pipeline_fenced")
            tenant, operator = self._route(conn, version, gateway)
            state, now = coordinator(conn, tenant)
            # Anchor elapsed server time to the authoritative clock, conservatively
            # including the database round trip. Product admission time stays now.
            receipt_at = (
                now - timedelta(seconds=max(0, monotonic() - receipt_started))
                if receipt_started is not None
                else now
            )
            if version == "v2":
                op = self._credential(
                    conn, tenant, operator, gateway, now, grafana=adapter_version is not None
                )
                if operator_revision is not None and op["revision"] != operator_revision:
                    raise unavailable("operator_binding_changed")
            scope = f"{version}:{tenant}:{operator or ''}"
            if request_key:
                old = conn.execute(
                    "SELECT * FROM ingest_requests WHERE retry_scope=%s AND retry_key=%s AND expires_at>%s",
                    (scope, request_key, now),
                ).fetchone()
                if old:
                    if bytes(old["fingerprint"]) != digest(parsed):
                        raise AppError("idempotency_conflict", "Retry content differs.", 409)
                    return old["response_status"], parse_json(
                        self.cipher.open(bytes(old["response_cipher"]), f"receipt:{old['id']}")
                    )
                conn.execute(
                    "UPDATE ingest_requests SET retry_key=NULL WHERE retry_scope=%s AND retry_key=%s AND expires_at<=%s",
                    (scope, request_key, now),
                )
            request_id = uuid4()
            token = secrets.token_urlsafe(32)
            results = []
            reservations = []
            order = state["admission_order"]
            for index, (payload, item_raw, event_id, error) in enumerate(validated):
                if error:
                    results.append({"index": index, "disposition": "rejected", "error": error})
                    continue
                fingerprint = digest(payload)
                duplicate = None
                if event_id:
                    duplicate = conn.execute(
                        "SELECT k.fingerprint,i.id,i.received_at FROM ingest_retry_keys k JOIN ingest_items i ON i.id=k.item_id WHERE k.scope=%s AND k.event_id=%s AND (k.expires_at IS NULL OR k.expires_at>%s)",
                        (scope, event_id, now),
                    ).fetchone()
                if duplicate:
                    if bytes(duplicate["fingerprint"]) != fingerprint:
                        results.append(
                            {
                                "index": index,
                                "disposition": "rejected",
                                "error": {
                                    "code": "idempotency_conflict",
                                    "message": "Item retry content differs.",
                                },
                            }
                        )
                    else:
                        results.append(
                            {
                                "index": index,
                                "disposition": "duplicate",
                                "event_id": str(duplicate["id"]),
                                "received_at": wire(duplicate["received_at"]),
                            }
                        )
                    continue
                key, key_digest, material = identity(payload, version, operator)
                defaulted = "time_created" not in payload
                if defaulted:
                    payload["time_created"] = format_native_time(now)
                item_id = uuid4()
                order += 1
                conn.execute(
                    "INSERT INTO ingest_items(id,request_id,tenant_id,operator_id,version,admission_order,received_at,key_field,key_digest,identity_material,payload,raw_json,time_defaulted) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        item_id,
                        request_id,
                        tenant,
                        operator,
                        version,
                        order,
                        now,
                        key,
                        key_digest,
                        material,
                        Jsonb(payload),
                        item_raw,
                        defaulted,
                    ),
                )
                if adapter_version:
                    conn.execute(
                        "UPDATE ingest_items SET adapter_version=%s WHERE id=%s",
                        (adapter_version, item_id),
                    )
                from keep.visibility.runtime import record_admission

                record_admission(
                    conn,
                    tenant=tenant,
                    item_id=item_id,
                    received_at=receipt_at,
                    admission_order=order,
                    profile=self.profile,
                )
                if event_id:
                    conn.execute(
                        "DELETE FROM ingest_retry_keys WHERE scope=%s AND event_id=%s AND expires_at<=%s",
                        (scope, event_id, now),
                    )
                    conn.execute(
                        "INSERT INTO ingest_retry_keys(scope,event_id,fingerprint,item_id) VALUES(%s,%s,%s,%s)",
                        (scope, event_id, fingerprint, item_id),
                    )
                from keep.events import received

                envelope = received(
                    tenant=tenant,
                    item=item_id,
                    order=order,
                    native_version=version,
                    payload=payload,
                    at=now,
                )
                conn.execute(
                    "INSERT INTO application_outbox(id,tenant_id,stream,stream_order,envelope) VALUES(%s,%s,%s,%s,%s)",
                    (uuid4(), tenant, "received", order, envelope),
                )
                reservations.append(
                    (
                        item_id,
                        len(item_raw) * self.profile["byte_multiplier"]
                        + self.profile["item_overhead"],
                    )
                )
                results.append(
                    {
                        "index": index,
                        "disposition": "accepted",
                        "event_id": str(item_id),
                        "received_at": wire(now),
                    }
                )
            good = any(item["disposition"] != "rejected" for item in results)
            status = (
                202
                if good
                else 409
                if not batch and results[0]["error"]["code"] == "idempotency_conflict"
                else 422
            )
            response = {
                "request_id": str(request_id),
                "receipt_url": f"/api/ingest/{version}/receipts/{request_id}",
                "receipt_token": token,
                "items": results,
            }
            conn.execute(
                "UPDATE tenant_work_state SET admission_order=%s WHERE tenant_id=%s",
                (order, tenant),
            )
            conn.execute(
                "INSERT INTO ingest_requests(id,tenant_id,operator_id,version,retry_scope,retry_key,fingerprint,receipt_hash,response_cipher,response_status,admitted_at,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    request_id,
                    tenant,
                    operator,
                    version,
                    scope,
                    request_key,
                    digest(parsed),
                    hashlib.sha256(token.encode()).digest(),
                    self.cipher.seal(canonical(response), f"receipt:{request_id}"),
                    status,
                    now,
                    now + timedelta(days=90),
                ),
            )
            self._reserve(conn, tenant, reservations)
            return status, response

    def _route(self, conn, version, gateway):
        if version == "v1":
            row = conn.execute(
                "SELECT id FROM tenants WHERE kind='global' AND name='Global'"
            ).fetchone()
            if not row:
                raise unavailable("global_bootstrap_required")
            return row["id"], None
        # Only the separately verified mTLS gateway adapter may create this server-owned context.
        if not gateway or not gateway.verified:
            raise AppError("invalid_credential", "Trusted gateway authentication required.", 401)
        gate = conn.execute(
            "SELECT ready FROM capability_gates WHERE capability='v2_ingress'"
        ).fetchone()
        if not gate or not gate["ready"]:
            raise unavailable("v2_ingest_not_ready")
        row = conn.execute(
            "SELECT tenant_id,operator_id FROM operator_credentials WHERE kong_consumer_id=%s AND kong_credential_id=%s",
            (gateway.consumer_id, gateway.credential_id),
        ).fetchone()
        if not row:
            raise AppError("invalid_credential", "Invalid ingestion credential.", 401)
        return row["tenant_id"], row["operator_id"]

    def _credential(self, conn, tenant, operator, gateway, now, *, grafana=False):
        op = conn.execute(
            "SELECT * FROM operators WHERE tenant_id=%s AND id=%s FOR UPDATE", (tenant, operator)
        ).fetchone()
        credential = conn.execute(
            "SELECT * FROM operator_credentials WHERE operator_id=%s AND kong_credential_id=%s FOR UPDATE",
            (operator, gateway.credential_id),
        ).fetchone()
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if grafana and credential["state"] == "prepared":
            raise unavailable("credential_activation_pending")
        if op["deletion_pending"]:
            raise AppError("operator_deletion_pending", "Operator deletion is pending.", 403)
        if (
            op["lifecycle"] != "ready"
            or credential["state"] not in ("current", "retiring")
            or (credential["state"] == "retiring" and now >= credential["expires_at"])
        ):
            raise AppError("invalid_credential", "Invalid ingestion credential.", 401)
        return op

    def _reserve(self, conn, tenant, reservations):
        if not reservations:
            return
        count = len(reservations)
        charge = sum(cost for _, cost in reservations)
        rows = []
        for scope in ("global", str(tenant)):
            row = conn.execute(
                "SELECT * FROM admission_capacity WHERE scope=%s FOR UPDATE", (scope,)
            ).fetchone()
            if not row or row["blocked"]:
                raise unavailable("capacity_accounting_unavailable")
            prefix = "global" if scope == "global" else "tenant"
            if (
                row["pending_items"] + count > self.profile[prefix + "_items"]
                or row["pending_bytes"] + charge > self.profile[prefix + "_bytes"]
            ):
                raise AppError("capacity_exceeded", "Durable backlog capacity is full.", 429)
            rows.append(scope)
        for scope in rows:
            conn.execute(
                "UPDATE admission_capacity SET pending_items=pending_items+%s,pending_bytes=pending_bytes+%s WHERE scope=%s",
                (count, charge, scope),
            )
        for item, cost in reservations:
            conn.execute(
                "INSERT INTO admission_reservations(item_id,tenant_id,bytes,profile) VALUES(%s,%s,%s,%s)",
                (item, tenant, cost, self.profile["id"]),
            )

    def receipt(self, request_id, token, version, gateway=None):
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM ingest_requests WHERE id=%s AND version=%s AND expires_at>clock_timestamp()",
                (request_id, version),
            ).fetchone()
            if (
                not row
                or not token
                or not secrets.compare_digest(
                    bytes(row["receipt_hash"]), hashlib.sha256(token.encode()).digest()
                )
            ):
                raise AppError("not_found", "Receipt unavailable.", 404)
            if version == "v2":
                tenant, operator = self._route(conn, version, gateway)
                if operator != row["operator_id"]:
                    raise AppError("not_found", "Receipt unavailable.", 404)
                _, now = coordinator(conn, tenant)
                self._credential(conn, tenant, operator, gateway, now)
            result = parse_json(
                self.cipher.open(bytes(row["response_cipher"]), f"receipt:{row['id']}")
            )
            result.pop("receipt_token", None)
            for item in result["items"]:
                if "event_id" in item:
                    outcome = conn.execute(
                        "SELECT disposition AS processing_status,error_code,alert_id,occurrence_id FROM ingest_items WHERE id=%s",
                        (item["event_id"],),
                    ).fetchone()
                    item.update(wire(outcome))
            return result
