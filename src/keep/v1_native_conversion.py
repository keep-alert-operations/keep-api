"""Convert Global's saved definitions, then its stored v1 alerts, to v1 as sent (REV-77).

Run after migration 0071, once every source processor runs a REV-77 release:

    python -m keep.v1_native_conversion --actor PRINCIPAL_ID [--dry-run] [--reverse]

It reads KEEP_DATABASE_URL (and the optional capacity profile) like the API.
Definitions go first, through the same writes as a user's save: each changed
preset, maintenance window and correlation rule gets a new revision, history
entry, digest, epoch or grouping generation. Saved CEL is rewritten by parse
positions only (keep.cel.v1_rewrite); expressions it cannot prove safe, and
windows that have already started (their expression is locked), are listed and
left unchanged. Then each v1 alert still in the old words is converted in its
own transaction in the writers' lock order (keep.alerts.v1_native). Only the
Global tenant is touched, and immutable history, proof and old revisions are
never rewritten. `--reverse` restores the old words, definitions first.
A rerun changes nothing. `--dry-run` reports the plan and writes nothing. The
output is one JSON document without secrets.
"""

from __future__ import annotations

import argparse
import json
from uuid import UUID, uuid4

from keep.alerts.v1_native import as_legacy, as_sent, convert_alert, held_by, legacy, sent
from keep.cel import CELUnavailableError, CELValidationError, compile_expression
from keep.cel.v1_rewrite import Unprovable, rename_field, rewrite
from keep.configuration.models import PresetDefinition
from keep.shared.errors import AppError
from keep.shared.transactions import coordinator

BATCH = 100


def global_tenant(db):
    with db.transaction() as conn:
        row = conn.execute("SELECT id FROM tenants WHERE kind='global'").fetchone()
    if row is None:
        raise SystemExit("No Global tenant")
    return row["id"]


def principal(db, actor_id):
    with db.transaction() as conn:
        row = conn.execute(
            "SELECT id,display_name FROM principals WHERE id=%s", (actor_id,)
        ).fetchone()
    if row is None:
        raise SystemExit("--actor must name an existing principal")
    return {"id": row["id"], "display_name": row["display_name"]}


def _expression(source, reverse, *, rule):
    """(new source, None) or (None, reason); the result recompiles in its context."""
    try:
        result = rewrite(source, reverse=reverse)
    except Unprovable as exc:
        return None, str(exc)
    if result.changed:
        try:
            compile_expression(result.source, rule=rule)
        except CELValidationError:
            return None, "rewritten_cel_invalid"
        except CELUnavailableError:
            return None, "cel_compilation_unavailable"
    return result.source, None


class Report:
    def __init__(self, dry_run, reverse):
        self.data = {
            "v1_native_conversion": {
                "direction": "reverse" if reverse else "forward",
                "dry_run": dry_run,
                "definitions": {"preset": [], "maintenance": [], "correlation": []},
                "skipped": [],
                "alerts": {"planned": 0, "converted": 0, "held": [], "failed": []},
            }
        }
        self.root = self.data["v1_native_conversion"]

    def definition(self, kind, resource_id, name, changes, applied, revision=None):
        self.root["definitions"][kind].append(
            {
                "id": str(resource_id),
                "name": name,
                "changes": changes,
                "applied": applied,
                **({"revision": str(revision)} if revision is not None else {}),
            }
        )

    def skip(self, kind, resource_id, name, reason):
        self.root["skipped"].append(
            {"kind": kind, "id": str(resource_id), "name": name, "reason": reason}
        )

    def counts(self):
        definitions = self.root["definitions"]
        self.root["counts"] = {
            **{kind: len(items) for kind, items in definitions.items()},
            "skipped": len(self.root["skipped"]),
            "alerts": self.root["alerts"]["converted"]
            if not self.root["dry_run"]
            else self.root["alerts"]["planned"],
        }
        return self.data


def convert_presets(db, tenant, actor, reverse, dry_run, report):
    from keep.configuration.routes import get_definition, public, write_revision

    with db.transaction(tenant) as conn:
        rows = conn.execute(
            "SELECT * FROM presets WHERE tenant_id=%s AND deleted_at IS NULL ORDER BY id", (tenant,)
        ).fetchall()
    for row in rows:
        cel, reason = _expression(row["cel"], reverse, rule=False)
        if reason:
            report.skip("preset", row["id"], row["name"], reason)
            continue
        current = public(row)
        definition = {
            "name": row["name"],
            "cel": cel,
            "sort": [dict(item, field=rename_field(item["field"], reverse=reverse)) for item in current["sort"]],
            "columns": [rename_field(column, reverse=reverse) for column in current["columns"]],
            "group_by": rename_field(row["group_by"], reverse=reverse) if row["group_by"] else None,
            "noisy": row["noisy"],
        }
        try:
            definition = PresetDefinition(**definition).model_dump()
        except ValueError:
            report.skip("preset", row["id"], row["name"], "rewritten_preset_invalid")
            continue
        changes = {
            key: {"before": current[key], "after": definition[key]}
            for key in definition
            if current[key] != definition[key]
        }
        if not changes:
            continue
        revision = None
        if not dry_run:
            with db.transaction(tenant) as conn:
                conn.execute(
                    "SELECT tenant_id FROM tenant_configuration_guard WHERE tenant_id=%s FOR UPDATE",
                    (tenant,),
                )
                previous = get_definition(conn, tenant, "presets", str(row["id"]), True)
                if previous["revision"] != row["revision"]:
                    report.skip("preset", row["id"], row["name"], "revision_conflict")
                    continue
                _, revision = write_revision(
                    conn, tenant, "presets", actor, previous, definition, str(uuid4()), str(row["id"])
                )
        report.definition("preset", row["id"], row["name"], changes, not dry_run, revision)


def convert_windows(db, tenant, actor, reverse, dry_run, report, profile):
    from keep.maintenance import repository as repo

    with db.transaction(tenant) as conn:
        rows = conn.execute(
            "SELECT *,clock_timestamp() AS now FROM maintenance_windows WHERE tenant_id=%s AND deleted_at IS NULL ORDER BY id",
            (tenant,),
        ).fetchall()
    for row in rows:
        cel, reason = _expression(row["cel"], reverse, rule=True)
        if reason:
            report.skip("maintenance", row["id"], row["name"], reason)
            continue
        if cel == row["cel"]:
            continue
        if row["started_lock"] or row["now"] >= row["start_at"]:
            # A started window's expression is locked (maintenance_start_locked).
            report.skip("maintenance", row["id"], row["name"], "maintenance_start_locked")
            continue
        changes = {"cel": {"before": row["cel"], "after": cel}}
        revision = None
        if not dry_run:
            program = compile_expression(cel, rule=True)
            with db.transaction(tenant) as conn:
                _, now = coordinator(conn, tenant)
                previous = repo.get_window(conn, tenant, row["id"], lock=True)
                if previous["revision"] != row["revision"]:
                    report.skip("maintenance", row["id"], row["name"], "revision_conflict")
                    continue
                definition = {
                    key: previous[key]
                    for key in ("name", "reason", "cel", "timezone", "start_at", "end_at", "schedule_evidence")
                }
                definition["cel"] = cel
                try:
                    repo.check_capacity(conn, tenant, definition, profile, now, row["id"])
                    stored, _ = repo.persist(
                        conn, tenant, actor, now, definition, program,
                        previous=previous, action="edit", profile=profile,
                    )
                except AppError as exc:
                    report.skip("maintenance", row["id"], row["name"], exc.code)
                    continue
                revision = stored["revision"]
        report.definition("maintenance", row["id"], row["name"], changes, not dry_run, revision)


def convert_rules(db, tenant, actor, reverse, dry_run, report, profile):
    from keep.correlation import repository as repo

    with db.transaction(tenant) as conn:
        rows = conn.execute(
            "SELECT id,revision FROM correlation_rules WHERE tenant_id=%s AND deleted_at IS NULL ORDER BY id",
            (tenant,),
        ).fetchall()
        rows = [repo.get_rule(conn, tenant, row["id"]) for row in rows]
    for row in rows:
        submitted = repo.definition(row)
        conditions, reason = [], None
        for condition in submitted["conditions"]:
            cel, reason = _expression(condition["cel"], reverse, rule=True)
            if reason:
                break
            conditions.append(dict(condition, cel=cel))
        if reason:
            report.skip("correlation", row["id"], row["name"], reason)
            continue
        submitted = dict(
            submitted,
            conditions=conditions,
            group_by=[rename_field(name, reverse=reverse) for name in submitted["group_by"]],
        )
        changes = {
            key: {"before": row[key], "after": submitted[key]}
            for key in ("conditions", "group_by")
            if submitted[key] != row[key]
        }
        if not changes:
            continue
        changes = json.loads(json.dumps(changes, default=str))
        revision = None
        if not dry_run:
            try:
                programs = repo.compile_conditions(submitted)
            except AppError as exc:
                report.skip("correlation", row["id"], row["name"], exc.code)
                continue
            with db.transaction(tenant) as conn:
                _, now = coordinator(conn, tenant)
                previous = repo.get_rule(conn, tenant, row["id"], lock=True)
                if previous["revision"] != row["revision"]:
                    report.skip("correlation", row["id"], row["name"], "revision_conflict")
                    continue
                try:
                    repo.check_capacity(
                        conn, tenant, submitted, programs, profile,
                        rule_id=str(row["id"]), enabled=previous["enabled"],
                    )
                    stored, _, _ = repo.persist(
                        conn, tenant, actor, now, submitted, programs, str(uuid4()), previous=previous
                    )
                except AppError as exc:
                    report.skip("correlation", row["id"], row["name"], exc.code)
                    continue
                revision = stored["revision"]
        report.definition("correlation", row["id"], row["name"], changes, not dry_run, revision)


def convert_alerts(db, tenant, reverse, dry_run, report, profile, batch=BATCH):
    """Each alert in its own transaction, in the writers' lock order."""
    from keep.alerts.state import retained
    from keep.incidents.state import lock_linked_incidents
    from keep.maintenance.runtime import flush_inline_effects, lock_catalog, prepare_for_tenant

    pending = sent if reverse else legacy
    after = None
    while True:
        with db.transaction(tenant) as conn:
            rows = conn.execute(
                "SELECT a.* FROM alerts a JOIN alert_identities i ON i.tenant_id=a.tenant_id AND i.id=a.id"
                " WHERE a.tenant_id=%s AND a.schema_version='v1' AND i.retired_at IS NULL"
                " AND (%s::uuid IS NULL OR a.id>%s::uuid) ORDER BY a.id LIMIT %s",
                (tenant, after, after, batch),
            ).fetchall()
        if not rows:
            return
        after = rows[-1]["id"]
        for candidate in rows:
            if not pending(candidate):
                continue
            report.root["alerts"]["planned"] += 1
            if dry_run:
                continue
            try:
                catalog = prepare_for_tenant(db, tenant, profile, alert_id=str(candidate["id"]))
                with db.transaction(tenant) as conn:
                    _, now = coordinator(conn, tenant)
                    lock_catalog(conn, catalog, targets=[candidate["id"]])
                    lock_linked_incidents(conn, tenant, candidate["id"], contexts_locked=True)
                    row = retained(conn, tenant, candidate["id"], True)
                    windows = held_by(
                        catalog, row, as_legacy(row) if reverse else as_sent(row), now, 0
                    )
                    if windows:
                        # A started window in the other words would change its
                        # match; the row waits until that window ends.
                        report.root["alerts"]["held"].append(
                            {"id": str(row["id"]), "windows": windows}
                        )
                        continue
                    if convert_alert(conn, row, now, catalog, reverse=reverse) is not None:
                        report.root["alerts"]["converted"] += 1
                    flush_inline_effects(conn)
            except AppError as exc:
                report.root["alerts"]["failed"].append(
                    {"id": str(candidate["id"]), "reason": exc.code}
                )


def run(db, actor_id, *, reverse=False, dry_run=False, profile=None, batch=BATCH):
    """Convert Global; return the machine-readable report."""
    tenant = global_tenant(db)
    actor = principal(db, actor_id)
    report = Report(dry_run, reverse)
    convert_presets(db, tenant, actor, reverse, dry_run, report)
    convert_windows(db, tenant, actor, reverse, dry_run, report, profile)
    convert_rules(db, tenant, actor, reverse, dry_run, report, profile)
    convert_alerts(db, tenant, reverse, dry_run, report, profile, batch)
    return report.counts()


def main():
    from keep.alert_notifications import configure
    from keep.config import Settings
    from keep.db import Database

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actor", type=UUID, required=True, help="Principal recorded on new revisions")
    parser.add_argument("--dry-run", action="store_true", help="Report the plan; write nothing")
    parser.add_argument("--reverse", action="store_true", help="Restore the old v1 words")
    parser.add_argument("--batch", type=int, default=BATCH, help="Alerts read per page")
    args = parser.parse_args()
    if not 1 <= args.batch <= 1000:
        parser.error("--batch must be 1 through 1000")
    settings = Settings()
    db = Database(
        settings.database_url.get_secret_value(), 1, deployment_epoch=settings.deployment_epoch
    )
    try:
        # Search hints are best effort; reconciliation repairs a missed one.
        configure(settings)
        path = settings.capacity_profile
        profile = json.loads(path.read_text()) if path else None
        result = run(
            db, args.actor, reverse=args.reverse, dry_run=args.dry_run, profile=profile,
            batch=args.batch,
        )
        print(json.dumps(result, indent=2, default=str))
    finally:
        db.close()


if __name__ == "__main__":
    main()
