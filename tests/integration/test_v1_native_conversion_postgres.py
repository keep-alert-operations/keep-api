"""The REV-77 conversion command against real PostgreSQL proof, revisions and locks."""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import os
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

import keep.alerts.processor as processor
from keep.alerts.lifecycle import apply_source as current_apply_source
from keep.alerts.v1_native import as_legacy, as_sent
from keep.cel import compile_expression
from keep.correlation import repository as rules
from keep.db import Database
from keep.ingestion.native import canonical
from keep.ingestion.service import Admission
from keep.maintenance import repository as windows
from keep.maintenance.processing import derive_current
from keep.maintenance.timezones import local_to_utc
from keep.migrate import migrate
from keep.serialization import wire
from keep.shared.transactions import coordinator
from keep.v1_native_conversion import run

pytestmark = pytest.mark.integration
PROFILE = {
    "id": "v1-native",
    "global_items": 10000,
    "tenant_items": 10000,
    "global_bytes": 10**8,
    "tenant_bytes": 10**8,
    "byte_multiplier": 4,
    "item_overhead": 2048,
}


@pytest.fixture
def db():
    admin = os.environ.get("KEEP_MAINTENANCE_TEST_ADMIN_URL") or os.environ.get(
        "KEEP_IDENTITY_TEST_ADMIN_URL"
    )
    if not admin:
        pytest.skip("Set KEEP_MAINTENANCE_TEST_ADMIN_URL to an isolated test cluster")
    name = "keep_v1conv_test_" + uuid4().hex
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    params = conninfo_to_dict(admin)
    params["dbname"] = name
    dsn = make_conninfo(**params)
    try:
        migrate(dsn)
        database = Database(dsn)
        yield database
        database.close()
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


@pytest.fixture
def cipher():
    from keep.shared.crypto import EnvelopeCipher

    return EnvelopeCipher({"test": b"k" * 32}, "test")


def old_words(monkeypatch):
    """Make the source processor store v1 in the pre-REV-77 words, like old releases."""

    def apply_source(previous, item):
        current, changed = current_apply_source(
            as_sent(previous) if previous is not None else None, item
        )
        return (as_legacy(current) if item["version"] == "v1" else current), changed

    monkeypatch.setattr(processor, "apply_source", apply_source)
    monkeypatch.setattr(processor, "source_prior", lambda previous, *args: (previous, False))


def send(db, cipher, tenant, payload):
    status, _ = Admission(db, cipher, PROFILE).admit(canonical(payload), "v1")
    assert status == 202
    while processor.process_one(db, tenant):
        pass
    with db.transaction(tenant) as conn:
        head = conn.execute(
            "SELECT disposition,error_code,alert_id FROM ingest_items WHERE tenant_id=%s ORDER BY admission_order DESC LIMIT 1",
            (tenant,),
        ).fetchone()
    assert head["disposition"] == "applied", head["error_code"]
    return head["alert_id"]


def alert(db, tenant, alert_id):
    with db.transaction(tenant) as conn:
        return conn.execute("SELECT * FROM alerts WHERE id=%s", (alert_id,)).fetchone()


def suppressed(db, tenant, alert_id):
    with db.transaction(tenant) as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=%s", (alert_id,)).fetchone()
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        return row["suppressed"], derive_current(conn, row, now)[0]


def count(db, tenant, query, *args):
    with db.transaction(tenant) as conn:
        return conn.execute(query, (tenant, *args)).fetchone()["count"]


def window(db, tenant, actor, cel, start, end):
    def endpoint(at):
        return local_to_utc("UTC", at.strftime("%Y-%m-%dT%H:%M:%S"))

    first, last = endpoint(start), endpoint(end)
    definition = {
        "name": "w-" + uuid4().hex[:8],
        "reason": "",
        "cel": cel,
        "timezone": "UTC",
        "start_at": first.utc,
        "end_at": last.utc,
        "schedule_evidence": wire({"start": asdict(first), "end": asdict(last)}),
    }
    with db.transaction(tenant) as conn:
        _, now = coordinator(conn, tenant)
        row, _ = windows.persist(
            conn, tenant, actor, now, definition, compile_expression(cel, rule=True)
        )
    return row


def preset(db, tenant, actor, cel, field="component"):
    from keep.configuration.routes import write_revision

    definition = {
        "name": "p-" + uuid4().hex[:8],
        "cel": cel,
        "sort": [{"field": field, "direction": "asc"}],
        "columns": [field, "severity"],
        "group_by": field,
        "noisy": False,
    }
    with db.transaction(tenant) as conn:
        row, _ = write_revision(conn, tenant, "presets", actor, None, definition, str(uuid4()))
    return row


def rule(db, tenant, actor, cel):
    body = {
        "name": "r-" + uuid4().hex[:8],
        "description": "",
        "severity": "high",
        "window_minutes": 10,
        "group_by": ["component"],
        "conditions": [{"id": str(uuid4()), "label": "Database", "cel": cel}],
    }
    programs = rules.compile_conditions(body)
    with db.transaction(tenant) as conn:
        _, now = coordinator(conn, tenant)
        row, _, _ = rules.persist(conn, tenant, actor, now, body, programs, str(uuid4()))
    return row


def read(db, tenant, table, resource_id):
    with db.transaction(tenant) as conn:
        return conn.execute(
            sql.SQL("SELECT * FROM {} WHERE id=%s").format(sql.Identifier(table)), (resource_id,)
        ).fetchone()


def test_conversion_keeps_proof_suppression_and_is_reversible(db, cipher, monkeypatch):
    """Requirements: REV-77; plan A4, A5 and A10; maintenance 6; alert operations 6."""
    with db.transaction() as conn:
        tenant = conn.execute("SELECT id FROM tenants WHERE kind='global'").fetchone()["id"]
        actor_id = uuid4()
        conn.execute(
            "INSERT INTO principals(id,directory_source,object_id,kind,display_name,eligible) VALUES(%s,'test',%s,'user','Conversion operator',true)",
            (actor_id, str(actor_id)),
        )
        specific = uuid4()
        conn.execute(
            "INSERT INTO tenants(id,kind,name,name_key) VALUES(%s,'specific',%s,%s)",
            (specific, str(specific), str(specific)),
        )
        for table in ("tenant_work_state", "tenant_view_state", "tenant_configuration_guard"):
            conn.execute(
                sql.SQL("INSERT INTO {}(tenant_id) VALUES(%s)").format(sql.Identifier(table)),
                (specific,),
            )
    actor = {"id": actor_id, "display_name": "Conversion operator"}
    now = datetime.now(UTC).replace(microsecond=0)
    # A started window in the old words suppresses the "db" alert; its CEL is locked.
    started = window(db, tenant, actor, 'severity == "critical"', now - timedelta(minutes=5), now + timedelta(hours=2))
    later = window(db, tenant, actor, 'severity == "critical"', now + timedelta(days=1), now + timedelta(days=2))
    saved = preset(db, tenant, actor, 'component == "db" && severity in ["critical","high"]')
    odd = preset(db, tenant, actor, 'string(severity).startsWith("c")')
    other = preset(db, specific, actor, 'component == "db"')
    correlated = rule(db, tenant, actor, 'component == "db"')

    old_words(monkeypatch)
    base = {"node_name": "n1", "operator": "legacy", "time_created": "01-01-2026 00:00:00"}
    db_alert = send(db, cipher, tenant, dict(base, application="pay", object="db", message="down", severity="error"))
    web_alert = send(db, cipher, tenant, dict(base, application="pay", object="web", message="slow", severity="major"))
    assert alert(db, tenant, db_alert)["severity"] == "critical"
    assert alert(db, tenant, web_alert)["component"] == "web"
    assert suppressed(db, tenant, db_alert) == (True, True)
    monkeypatch.undo()
    activity = count(db, tenant, "SELECT count(*) FROM alert_activity WHERE tenant_id=%s")
    journal = count(db, tenant, "SELECT count(*) FROM correlation_journal WHERE tenant_id=%s")

    dry = run(db, actor_id, dry_run=True)["v1_native_conversion"]
    assert dry["alerts"]["planned"] == 2 and dry["alerts"]["converted"] == 0
    assert read(db, tenant, "presets", saved["id"])["revision"] == 1
    assert alert(db, tenant, web_alert)["component"] == "web"

    report = run(db, actor_id)["v1_native_conversion"]
    skipped = {(item["id"], item["reason"]) for item in report["skipped"]}
    assert (str(started["id"]), "maintenance_start_locked") in skipped
    assert (str(odd["id"]), "severity_use_not_provable") in skipped
    converted = read(db, tenant, "presets", saved["id"])
    assert converted["revision"] == 2
    assert converted["cel"] == 'object == "db" && severity in ["error","major"]'
    assert converted["columns"] == ["object", "severity"] and converted["group_by"] == "object"
    assert converted["sort"] == [{"field": "object", "direction": "asc"}]
    assert converted["updated_by"] == actor_id
    assert read(db, tenant, "presets", odd["id"])["cel"] == 'string(severity).startsWith("c")'
    assert read(db, specific, "presets", other["id"])["revision"] == 1
    rewritten = read(db, tenant, "maintenance_windows", later["id"])
    assert rewritten["revision"] == 2 and rewritten["cel"] == 'severity == "error"'
    import hashlib

    assert rewritten["cel_digest"] == hashlib.sha256(rewritten["cel"].encode()).hexdigest()
    assert read(db, tenant, "maintenance_windows", started["id"])["revision"] == 1
    new_rule = read(db, tenant, "correlation_rules", correlated["id"])
    assert new_rule["revision"] == 2 and new_rule["group_by"] == ["object"]
    with db.transaction(tenant) as conn:
        stored = rules.get_rule(conn, tenant, correlated["id"])
    assert [item["cel"] for item in stored["conditions"]] == ['object == "db"']
    assert stored["grouping_generation"] > correlated["grouping_generation"]
    with db.transaction(tenant) as conn:
        assert conn.execute(
            "SELECT count(*) FROM preset_revisions WHERE id=%s", (saved["id"],)
        ).fetchone()["count"] == 2

    # The web alert is converted without activity or a correlation journal row; the
    # db alert stays in the old words while the locked window would release it.
    assert report["alerts"]["converted"] == 1
    assert [item["id"] for item in report["alerts"]["held"]] == [str(db_alert)]
    web = alert(db, tenant, web_alert)
    assert (web["object"], web["component"], web["severity"]) == ("web", None, "major")
    assert web["revision"] == 1
    assert count(db, tenant, "SELECT count(*) FROM alert_activity WHERE tenant_id=%s") == activity
    assert count(db, tenant, "SELECT count(*) FROM correlation_journal WHERE tenant_id=%s") == journal
    with db.transaction(tenant) as conn:
        latest = conn.execute(
            "SELECT snapshot FROM projection_work WHERE tenant_id=%s AND alert_id=%s ORDER BY seq DESC LIMIT 1",
            (tenant, web_alert),
        ).fetchone()["snapshot"]
        kinds = [
            row["kind"]
            for row in conn.execute(
                "SELECT kind FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s ORDER BY original_order",
                (tenant, web_alert),
            ).fetchall()
        ]
    assert latest["object"] == "web" and latest["severity"] == "major"
    assert kinds == ["source", "v1-native-conversion"]
    assert suppressed(db, tenant, db_alert) == (True, True)

    # Source updates after the conversion apply with continuous proof.
    send(db, cipher, tenant, dict(base, application="pay", object="web", message="slower", severity="major"))
    web = alert(db, tenant, web_alert)
    assert (web["object"], web["severity"], web["message"]) == ("web", "major", "slower")
    send(db, cipher, tenant, dict(base, application="pay", object="db", message="still down", severity="error"))
    held = alert(db, tenant, db_alert)
    assert (held["component"], held["severity"], held["message"]) == ("db", "critical", "still down")
    assert suppressed(db, tenant, db_alert) == (True, True)
    assert count(db, tenant, "SELECT count(*) FROM incidents WHERE tenant_id=%s") == 0
    # The rewritten definitions match a new v1 alert in the v1 words.
    fresh = alert(db, tenant, send(db, cipher, tenant, dict(base, application="new", object="db", message="m", severity="error")))
    assert compile_expression(converted["cel"]).evaluate(fresh, now)
    assert compile_expression(rewritten["cel"], rule=True).evaluate(fresh, now)
    assert compile_expression('object == "db"', rule=True).evaluate(fresh, now)

    again = run(db, actor_id)["v1_native_conversion"]
    assert again["alerts"]["converted"] == 0
    assert all(not items for items in again["definitions"].values())

    back = run(db, actor_id, reverse=True)["v1_native_conversion"]
    assert read(db, tenant, "presets", saved["id"])["cel"] == (
        'component == "db" && severity in ["critical","high"]'
    )
    assert read(db, tenant, "presets", saved["id"])["revision"] == 3
    assert read(db, tenant, "correlation_rules", correlated["id"])["group_by"] == ["component"]
    web = alert(db, tenant, web_alert)
    assert (web["component"], web["object"], web["severity"]) == ("web", None, "high")
    assert back["alerts"]["converted"] >= 1
    assert suppressed(db, tenant, db_alert) == (True, True)
    twice = run(db, actor_id, reverse=True)["v1_native_conversion"]
    assert twice["alerts"]["converted"] == 0
    assert all(not items for items in twice["definitions"].values())


def test_source_update_converts_an_old_row_on_touch(db, cipher, monkeypatch):
    """Requirements: REV-77; plan A2 and A4; alert operations 6; maintenance 6."""
    with db.transaction() as conn:
        tenant = conn.execute("SELECT id FROM tenants WHERE kind='global'").fetchone()["id"]
    base = {"application": "pay", "object": "db", "node_name": "n1", "operator": "legacy",
            "time_created": "01-01-2026 00:00:00", "severity": "error"}
    old_words(monkeypatch)
    alert_id = send(db, cipher, tenant, dict(base, message="down"))
    send(db, cipher, tenant, dict(base, message="down"))
    monkeypatch.undo()
    stored = alert(db, tenant, alert_id)
    assert (stored["component"], stored["severity"], stored["revision"]) == ("db", "critical", 1)
    activity = count(db, tenant, "SELECT count(*) FROM alert_activity WHERE tenant_id=%s")
    # The same delivery after REV-77: stored in the v1 words, no semantic change.
    send(db, cipher, tenant, dict(base, message="down"))
    touched = alert(db, tenant, alert_id)
    assert (touched["object"], touched["component"], touched["severity"]) == ("db", None, "error")
    assert touched["revision"] == 1
    assert count(db, tenant, "SELECT count(*) FROM alert_activity WHERE tenant_id=%s") == activity
    # A real change records only that change: no "Critical -> Error" in its evidence.
    send(db, cipher, tenant, dict(base, message="worse"))
    with db.transaction(tenant) as conn:
        evidence = conn.execute(
            "SELECT evidence FROM alert_activity WHERE tenant_id=%s AND alert_id=%s ORDER BY change_order DESC LIMIT 1",
            (tenant, alert_id),
        ).fetchone()["evidence"]
        inputs = conn.execute(
            "SELECT before_snapshot,after_snapshot FROM maintenance_alert_inputs WHERE tenant_id=%s AND alert_id=%s ORDER BY original_order",
            (tenant, alert_id),
        ).fetchall()
    assert evidence["before"]["severity"] == evidence["after"]["severity"] == "error"
    assert evidence["before"]["message"] == "down" and evidence["after"]["message"] == "worse"
    # Proof is one continuous chain from the old words into the v1 words.
    for previous, following in zip(inputs, inputs[1:]):
        assert following["before_snapshot"] == previous["after_snapshot"]
    assert "object" not in inputs[1]["after_snapshot"]
    assert inputs[2]["after_snapshot"]["object"] == "db"
    with pytest.raises(AssertionError):
        send(db, cipher, tenant, dict(base, severity="major", message="x"))
    rejected = count(
        db, tenant, "SELECT count(*) FROM ingest_items WHERE tenant_id=%s AND error_code=%s",
        "identity_conflict",
    )
    assert rejected == 1
