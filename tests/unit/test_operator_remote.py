from contextlib import nullcontext
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest

from appchi.operators.policy import (
    ManagedRoute,
    migrate_rule_labels,
    normalized_name,
    routing_intent,
)
from appchi.operators.remote import (
    CapabilityManifest,
    Endpoint,
    REQUIRED_CAPABILITIES,
    RemoteAdapter,
)
from appchi.shared.errors import AppError


def manifest(**changes):
    # These are deliberately unit-test profile values, not claimed company versions.
    value = CapabilityManifest(
        "test",
        "test-grafana",
        "test-kong",
        "test-org",
        "test-evidence",
        REQUIRED_CAPABILITIES,
        "cas",
        None,
        {"tree": Endpoint("/supplied/tree", "/supplied/tree", "PUT", "ETag", "If-Match")},
    )
    return replace(value, **changes)


def test_company_branch_and_default_preserved_and_routes_continue():
    defaults = {"receiver": "company-default", "group_by": ["team"]}
    company = {
        **defaults,
        "routes": [{"receiver": "critical-team", "matchers": ["severity=critical"]}],
    }
    first, second = str(uuid4()), str(uuid4())
    intent = routing_intent(
        defaults, company, (ManagedRoute(second, "B"), ManagedRoute(first, "A"))
    )
    assert intent["root_defaults"] == defaults
    assert intent["children"][-1]["company_branch"] == company
    assert all(route["continue"] for route in intent["children"][:-1])
    assert all(route["group_by"] == ["..."] for route in intent["children"][:-1])
    intent["children"][-1]["company_branch"]["receiver"] = "changed"
    assert company["receiver"] == "company-default"


def test_rule_label_migration_changes_only_exact_label_and_preserves_expression():
    rule = {
        "labels": {"Appchi - Old": "{{ $values.A.Value }}", "team": "payments"},
        "query": {"x": [1, 2]},
    }
    migrated = migrate_rule_labels(rule, "Old", "NEW")
    assert migrated["labels"] == {"Appchi - NEW": "{{ $values.A.Value }}", "team": "payments"}
    assert migrated["query"] == rule["query"]
    assert "Appchi - Old" in rule["labels"]
    assert migrate_rule_labels(rule, "Old", None)["labels"] == {"team": "payments"}
    rule["labels"]["Appchi - NEW"] = "conflict"
    with pytest.raises(AppError):
        migrate_rule_labels(rule, "Old", "NEW")


def test_names_nfc_casefold_and_control_rejection():
    assert normalized_name("  Cafe\u0301  ") == ("Café", "café")
    with pytest.raises(AppError):
        normalized_name("A\u200bB")


def test_cas_header_fresh_read_and_verified_readback():
    calls = []

    def transport(request):
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(
                200, json={"owner": "appchi", "value": len(calls) > 1}, headers={"ETag": '"7"'}
            )
        assert request.headers["If-Match"] == '"7"'
        return httpx.Response(200, json={})

    adapter = RemoteAdapter(
        httpx.Client(transport=httpx.MockTransport(transport)), "https://test.invalid", manifest()
    )
    result = adapter.update(
        "tree",
        {},
        coordinator=nullcontext(),
        ownership=lambda doc: doc["owner"] == "appchi",
        merge=lambda doc: dict(doc, value=True),
        matches=lambda wanted, actual: wanted == actual,
    )
    assert result.body["value"] is True
    assert [request.method for request in calls] == ["GET", "PUT", "GET"]


def test_no_safe_writer_or_missing_precondition_blocks_before_write():
    with pytest.raises(AppError):
        RemoteAdapter(
            httpx.Client(), "https://test.invalid", manifest(safe_mode="controlled_writer")
        )
    methods = []

    def transport(request):
        methods.append(request.method)
        return httpx.Response(200, json={"owner": "appchi"})

    adapter = RemoteAdapter(
        httpx.Client(transport=httpx.MockTransport(transport)), "https://test.invalid", manifest()
    )
    with pytest.raises(AppError) as failure:
        adapter.update(
            "tree",
            {},
            coordinator=nullcontext(),
            ownership=lambda doc: True,
            merge=lambda doc: doc,
            matches=lambda a, b: True,
        )
    assert failure.value.code == "remote_version_precondition_missing"
    assert methods == ["GET"]


def test_uncertain_write_never_automatically_retries_or_claims_success():
    calls = []

    def transport(request):
        calls.append(request.method)
        if request.method == "GET":
            return httpx.Response(200, json={}, headers={"ETag": "7"})
        raise httpx.ReadTimeout("Unit-test uncertainty")

    adapter = RemoteAdapter(
        httpx.Client(transport=httpx.MockTransport(transport)), "https://test.invalid", manifest()
    )
    with pytest.raises(AppError) as failure:
        adapter.update(
            "tree",
            {},
            coordinator=nullcontext(),
            ownership=lambda doc: True,
            merge=lambda doc: doc,
            matches=lambda a, b: True,
        )
    assert failure.value.code == "remote_outcome_uncertain"
    assert calls == ["GET", "PUT"]
