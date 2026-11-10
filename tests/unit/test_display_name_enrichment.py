"""Read-time display-name enrichment: batching, fallbacks and published contract."""

from uuid import uuid4

from keep.shared.display_names import (
    actor_names,
    enrich_actors,
    enrich_alerts,
    enrich_assignees,
    enrich_incidents,
)


class Rows:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class RecordingConnection:
    """Answers batched name lookups from in-memory tables and records queries."""

    def __init__(self, principals=None, incidents=None, contexts=None, operators=None):
        self.principals = principals or {}
        self.contexts = contexts or {}
        self.incidents = incidents or {}
        self.operators = operators or {}
        self.queries = []

    def execute(self, query, args):
        self.queries.append((" ".join(query.split()), args))
        if "FROM principals" in query:
            (ids,) = args
            return Rows(
                [
                    {"id": key, "display_name": self.principals[key]}
                    for key in ids
                    if key in self.principals
                ]
            )
        if "FROM incidents" in query:
            tenant, ids = args
            return Rows(
                [
                    {"id": key, "title": title}
                    for key in ids
                    for owner, title in [self.incidents.get(key, (None, None))]
                    if owner == tenant
                ]
            )
        if "FROM operators" in query:
            tenant, ids = args
            return Rows(
                [
                    {"id": key, "name": name}
                    for key in ids
                    for owner, name in [self.operators.get(key, (None, None))]
                    if owner == tenant
                ]
            )
        if "FROM correlation_contexts" in query:
            tenant, ids = args
            return Rows(
                [
                    {"id": key, "rule_id": rule, "name": name}
                    for key in ids
                    for owner, rule, name in [self.contexts.get(key, (None, None, None))]
                    if owner == tenant
                ]
            )
        raise AssertionError("unexpected query " + query)


def test_alert_rows_use_one_batched_lookup_per_source_and_never_cross_tenants():
    tenant, other = str(uuid4()), str(uuid4())
    alice, bob = str(uuid4()), str(uuid4())
    own, foreign = str(uuid4()), str(uuid4())
    conn = RecordingConnection(
        {alice: "Alice", bob: "Bob (deleted)"},
        {own: (tenant, "Database outage"), foreign: (other, "Other tenant incident")},
    )
    rows = [
        {"id": "1", "assignee_id": alice, "acknowledged_by": bob, "active_incident_id": own},
        {"id": "2", "assignee_id": alice, "acknowledged_by": None, "active_incident_id": foreign},
        {"id": "3", "assignee_id": None, "active_incident_id": None},
        {"id": "4", "assignee_id": "not-a-uuid", "acknowledged_by": str(uuid4())},
    ]
    result = enrich_alerts(conn, tenant, rows)
    assert len(conn.queries) == 2  # one principal query, one incident query: no N+1
    principal_ids = conn.queries[0][1][0]
    assert principal_ids == [alice]
    assert conn.queries[1][1] == (tenant, sorted([own, foreign]))
    assert [(r["assignee_display_name"], r["active_incident_title"]) for r in result] == [
        ("Alice", "Database outage"),
        ("Alice", None),
        (None, None),
        (None, None),
    ]
    # Every other field is carried unchanged; the input rows are not mutated.
    assert [
        {
            k: v
            for k, v in r.items()
            if not k.endswith(("_display_name", "_title")) and k != "display_status"
        }
        for r in result
    ] == [{k: v for k, v in r.items() if k != "acknowledged_by"} for r in rows]
    assert "assignee_display_name" not in rows[0]


def test_empty_pages_do_not_query():
    conn = RecordingConnection()
    assert enrich_alerts(conn, str(uuid4()), []) == []
    assert enrich_assignees(conn, [{"id": "x", "assignee_id": None}]) == [
        {"id": "x", "assignee_id": None, "assignee_display_name": None}
    ]
    assert conn.queries == []


def test_alert_operator_name_is_current_tenant_scoped_and_legacy_value_is_exact():
    tenant, other = str(uuid4()), str(uuid4())
    managed, foreign, missing = (str(uuid4()) for _ in range(3))
    conn = RecordingConnection(
        operators={managed: (tenant, "Payments"), foreign: (other, "Other tenant")}
    )
    rows = [
        {"schema_version": "v2", "operator": managed},
        {"schema_version": "v2", "operator": foreign},
        {"schema_version": "v2", "operator": missing},
        {"schema_version": "v1", "operator": " Legacy sender "},
    ]
    labelled = enrich_alerts(conn, tenant, rows)
    assert [row["operator_display_name"] for row in labelled] == [
        "Payments", None, None, " Legacy sender "
    ]
    assert [row["operator"] for row in labelled] == [row["operator"] for row in rows]
    assert len(conn.queries) == 1
    assert conn.queries[0][1] == (tenant, sorted([managed, foreign, missing]))
    conn.operators[managed] = (tenant, "Payments East")
    assert enrich_alerts(conn, tenant, rows)[0]["operator_display_name"] == "Payments East"


def test_incident_origins_are_batched_tenant_scoped_and_correlation_only():
    tenant, other = str(uuid4()), str(uuid4())
    live, deleted, foreign = (str(uuid4()) for _ in range(3))
    rule, gone, alien = (str(uuid4()) for _ in range(3))
    conn = RecordingConnection(
        contexts={
            live: (tenant, rule, "Checkout errors"),
            deleted: (tenant, gone, None),
            foreign: (other, alien, "Other tenant rule"),
        }
    )
    rows = [
        {"id": "1", "origin": "correlation", "context_id": live, "assignee_id": None},
        {"id": "2", "origin": "correlation", "context_id": deleted},
        {"id": "3", "origin": "correlation", "context_id": foreign},
        {"id": "4", "origin": "manual", "context_id": live},
    ]
    result = enrich_incidents(conn, tenant, rows)
    assert len(conn.queries) == 1  # no principal ids, one origin query
    assert conn.queries[0][1] == (tenant, sorted([live, deleted, foreign]))
    assert [(r["origin_rule_id"], r["origin_rule_name"]) for r in result] == [
        (rule, "Checkout errors"),
        (gone, None),
        (None, None),
        (None, None),
    ]
    assert all(r["assignee_display_name"] is None for r in result)


def test_actor_names_follow_the_ids_each_row_carries():
    creator, editor = str(uuid4()), str(uuid4())
    conn = RecordingConnection({creator: "Creator", editor: "Editor"})
    rows = [
        {"id": "a", "created_by": creator, "updated_by": editor},
        {"id": "b", "updated_by": str(uuid4())},
        {"id": "c"},
    ]
    assert enrich_actors(conn, rows) == [
        {**rows[0], "created_by_display_name": "Creator", "updated_by_display_name": "Editor"},
        {**rows[1], "updated_by_display_name": None},
        rows[2],
    ]
    assert len(conn.queries) == 1
    # Public rows that omit ids can take them from their stored source rows.
    public = [{"id": "m"}]
    assert enrich_actors(conn, public, [{"created_by": creator, "updated_by": creator}]) == [
        {"id": "m", "created_by_display_name": "Creator", "updated_by_display_name": "Creator"}
    ]
    assert actor_names(conn, [{}]) == [{}]


def test_openapi_publishes_optional_display_fields_for_changed_reads():
    from keep.main import app

    spec = app.openapi()
    schemas = spec["components"]["schemas"]

    def response(path, method="get"):
        body = spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]
        return body["schema"]["$ref"].rsplit("/", 1)[1]

    root = "/api/tenants/{tenant_id}"
    assert response(root + "/alerts") == "AlertPage"
    assert response(root + "/presets/preview", "post") == "AlertPage"
    assert response(root + "/alerts/{alert_id}") == "AlertRead"
    assert response(root + "/incidents") == "IncidentPage"
    assert response(root + "/incidents/{incident_id}") == "IncidentRead"
    for path in (
        "/presets",
        "/dashboards",
        "/maintenance",
        "/correlation-rules",
    ):
        assert response(root + path) == "ActorPage"
    for path in (
        "/presets/{resource_id}",
        "/dashboards/{resource_id}",
        "/maintenance/{window_id}",
        "/correlation-rules/{rule_id}",
    ):
        assert response(root + path) == "ActorRead"
    # History revisions keep their recorded actor labels; today's directory name
    # is never presented as historical attribution (REV-10).
    for path in (
        "/presets/{resource_id}/history/{revision}",
        "/dashboards/{resource_id}/history/{revision}",
        "/correlation-rules/{rule_id}/history/{revision_number}",
    ):
        assert "$ref" not in str(spec["paths"][root + path]["get"]["responses"]["200"])
    alert = schemas["AlertDisplayNames"]
    assert alert["additionalProperties"] is True and "required" not in alert
    assert set(alert["properties"]) == {
        "assignee_display_name",
        "operator_display_name",
        "display_status",
        "active_incident_title",
        # REV-49: the timed dismissal end, already reflected in `suppressed`.
        "dismissed_until",
    }
    detail = schemas["AlertRead"]["properties"]["data"]["$ref"].rsplit("/", 1)[1]
    assert set(schemas[detail]["properties"]) == set(alert["properties"]) | {"active_incident_id", "dismissal"}
    assert "required" not in schemas[detail]
    assert set(schemas["IncidentDisplayNames"]["properties"]) == {
        "assignee_display_name",
        "origin_rule_id",
        "origin_rule_name",
        # REV-56: link counts, on list rows as well as the detail.
        "total_linked",
        "suppressed",
        "unavailable",
    }
    assert set(schemas["ActorDisplayNames"]["properties"]) == {
        "created_by_display_name",
        "updated_by_display_name",
    }
