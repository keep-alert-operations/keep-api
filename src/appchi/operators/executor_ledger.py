"""Short SQL fences and reversible nonsecret label journals for remote attempts."""

from copy import deepcopy
from uuid import UUID

from psycopg.types.json import Jsonb

from appchi.shared.errors import AppError, unavailable


class PostgresLedger:
    def __init__(self, db):
        self.db = db

    def begin(self, work, binding_digest):
        return AttemptLedger(self.db, work, binding_digest)


class AttemptLedger:
    def __init__(self, db, work, binding_digest):
        self.db, self.work = db, work
        self.token = self.revision = None
        with db.transaction(work.tenant_id) as conn:
            op, job = self._rows(conn)
            conn.execute(
                "SELECT id FROM operators WHERE tenant_id=%s AND id=%s FOR UPDATE",
                (work.tenant_id, work.operator_id),
            )
            conn.execute(
                "SELECT id FROM operator_operations WHERE id=%s FOR UPDATE", (work.operation_id,)
            )
            op, job = self._rows(conn)
            binding = conn.execute(
                "SELECT remote_id FROM operator_remote_bindings WHERE tenant_id=%s AND operator_id=%s AND kind='executor_profile'",
                (work.tenant_id, work.operator_id),
            ).fetchone()
            if binding and binding["remote_id"] != binding_digest:
                raise unavailable("operator_capabilities_unverified")
            if not binding:
                conn.execute(
                    "INSERT INTO operator_remote_bindings(tenant_id,operator_id,kind,remote_id,generation,verified_at) VALUES(%s,%s,'executor_profile',%s,%s,clock_timestamp())",
                    (work.tenant_id, work.operator_id, binding_digest, work.generation),
                )
            progress = job["progress"].get("executor", {})
            if progress.get("binding_digest", binding_digest) != binding_digest:
                raise unavailable("operator_capabilities_unverified")
            self.token, self.revision = job["lease_token"], op["revision"]
            self.deleted = op["lifecycle"] == "deleted"
            self.known_operators = {
                str(r["id"]) for r in conn.execute("SELECT id FROM operators").fetchall()
            }
            rows = conn.execute(
                "SELECT id,state,expires_at FROM operator_credentials WHERE tenant_id=%s AND operator_id=%s",
                (work.tenant_id, work.operator_id),
            ).fetchall()
            now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
            self.valid_ids = {
                str(r["id"])
                for r in rows
                if r["state"] in ("prepared", "current")
                or r["state"] == "retiring"
                and r["expires_at"] > now
            }
            self.invalid_ids = {str(r["id"]) for r in rows} - self.valid_ids
            self.edits = deepcopy(progress.get("labels", []))
            self.restore_edits = []
            if (
                work.kind == "cancel"
                or work.kind == "cleanup"
                and work.pending_name
                or work.kind == "create_key"
                and job["progress"].get("restore_cancel")
            ):
                # Current job identity cannot recover arbitrary old platform edits.
                previous = conn.execute(
                    "SELECT progress FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND id<>%s AND kind=%s AND completed_at IS NOT NULL AND (%s::uuid IS NULL OR id=%s::uuid) ORDER BY created_at DESC LIMIT 1",
                    (
                        work.tenant_id,
                        work.operator_id,
                        work.operation_id,
                        work.cancel_kind or "setup",
                        job["progress"].get("cancel_operation_id"),
                        job["progress"].get("cancel_operation_id"),
                    ),
                ).fetchone()
                if previous:
                    self.restore_edits = deepcopy(
                        previous["progress"].get("executor", {}).get("labels", [])
                    )
                if work.cancel_kind == "delete" and work.pending_name:
                    # Delete may supersede a partially applied rename. Undo
                    # delete first, then that rename, before releasing its name.
                    renamed = conn.execute(
                        "SELECT progress FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND kind IN ('setup','rename') AND state IN ('superseded','cancelled') ORDER BY created_at DESC LIMIT 1",
                        (work.tenant_id, work.operator_id),
                    ).fetchone()
                    if renamed:
                        self.restore_edits = (
                            deepcopy(renamed["progress"].get("executor", {}).get("labels", []))
                            + self.restore_edits
                        )
            self.binding_digest = binding_digest
            conn.execute(
                "UPDATE operator_operations SET progress=%s WHERE id=%s",
                (
                    Jsonb(
                        {
                            **job["progress"],
                            "executor": {"binding_digest": binding_digest, "labels": self.edits},
                        }
                    ),
                    work.operation_id,
                ),
            )

    def _rows(self, conn):
        job = conn.execute(
            "SELECT * FROM operator_operations WHERE tenant_id=%s AND operator_id=%s AND id=%s",
            (self.work.tenant_id, self.work.operator_id, self.work.operation_id),
        ).fetchone()
        op = conn.execute(
            "SELECT * FROM operators WHERE tenant_id=%s AND id=%s",
            (self.work.tenant_id, self.work.operator_id),
        ).fetchone()
        guard = conn.execute(
            "SELECT * FROM operator_routing_guard WHERE scope='grafana'"
        ).fetchone()
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        if (
            not op
            or not job
            or not guard
            or job["state"] != "running"
            or job["completed_at"]
            or job["generation"] != self.work.generation
            or op["generation"] != self.work.generation
            or not job["lease_token"]
            or not job["lease_until"]
            or job["lease_until"] <= now
            or guard["lease_token"] != job["lease_token"]
            or not guard["lease_until"]
            or guard["lease_until"] <= now
            or (
                self.token is not None
                and (job["lease_token"] != self.token or op["revision"] != self.revision)
            )
        ):
            raise AppError("stale_provisioning_generation", "Provisioning authority changed.", 409)
        return op, job

    def check(self):
        with self.db.transaction(self.work.tenant_id) as conn:
            self._rows(conn)

    def owns(self, kind, identifier):
        with self.db.transaction(self.work.tenant_id) as conn:
            self._rows(conn)
            return (
                conn.execute(
                    "SELECT 1 FROM operator_remote_bindings WHERE tenant_id=%s AND operator_id=%s AND kind=%s AND remote_id=%s",
                    (
                        self.work.tenant_id,
                        self.work.operator_id,
                        "executor_intent:" + kind,
                        identifier,
                    ),
                ).fetchone()
                is not None
            )

    def claim_resource(self, kind, identifier):
        # Call only after verified remote absence, before the first create. The
        # explicit intent kind is not an acknowledgement of remote readiness.
        with self.db.transaction(self.work.tenant_id) as conn:
            conn.execute(
                "SELECT id FROM operator_operations WHERE id=%s FOR UPDATE",
                (self.work.operation_id,),
            )
            self._rows(conn)
            row = conn.execute(
                "INSERT INTO operator_remote_bindings(tenant_id,operator_id,kind,remote_id,generation,verified_at) VALUES(%s,%s,%s,%s,%s,clock_timestamp()) ON CONFLICT(operator_id,kind) DO UPDATE SET generation=EXCLUDED.generation WHERE operator_remote_bindings.remote_id=EXCLUDED.remote_id RETURNING remote_id",
                (
                    self.work.tenant_id,
                    self.work.operator_id,
                    "executor_intent:" + kind,
                    identifier,
                    self.work.generation,
                ),
            ).fetchone()
            if not row:
                raise unavailable("remote_ownership_conflict")

    def record(self, edit):
        if edit in self.edits:
            return
        # Only UUID-ish rule IDs, routing-label keys and their explicit string
        # values enter progress. Never credentials, rule bodies or HTTP responses.
        if len(self.edits) >= 10000 or set(edit) != {
            "uid",
            "old_key",
            "old_value",
            "new_key",
            "new_value",
        }:
            raise unavailable("operator_capabilities_unverified")
        for key in ("old_key", "new_key"):
            if edit[key] is not None and not edit[key].startswith("Appchi - "):
                raise unavailable("operator_capabilities_unverified")
        with self.db.transaction(self.work.tenant_id) as conn:
            self._rows(conn)
            row = conn.execute(
                "SELECT progress FROM operator_operations WHERE id=%s FOR UPDATE",
                (UUID(self.work.operation_id),),
            ).fetchone()
            self._rows(conn)
            self.edits.append(deepcopy(edit))
            progress = {
                **row["progress"],
                "executor": {"binding_digest": self.binding_digest, "labels": self.edits},
            }
            conn.execute(
                "UPDATE operator_operations SET progress=%s WHERE id=%s",
                (Jsonb(progress), self.work.operation_id),
            )
