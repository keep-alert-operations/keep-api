"""HTTP contract fixtures test executable control flow, not private compatibility."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, UTC
from email.utils import format_datetime
import json
from hashlib import sha256
from unittest.mock import MagicMock
from uuid import uuid4

import httpx
import pytest

from appchi.operators.binding import OperatorBinding, EXTRA_CAPABILITIES
from appchi.operators.executor import PlatformCredentials, ProvisioningExecutor
from appchi.operators.policy import resource_identity
from appchi.operators.remote import REQUIRED_CAPABILITIES
from appchi.operators.worker import Work
from appchi.shared.errors import AppError


class Ledger:
    def __init__(self, work):
        self.deleted = False
        self.known_operators = {work.operator_id}
        self.valid_ids = {work.candidate_id, work.current_id} - {None}
        self.invalid_ids = set()
        self.edits = []
        self.restore_edits = []
        self.stale = False
        self.owned = set()

    def begin(self, work, digest):
        return self

    def check(self):
        if self.stale:
            raise AppError("stale_provisioning_generation", "Changed", 409)

    def record(self, edit):
        if edit not in self.edits:
            self.edits.append(deepcopy(edit))

    def owns(self, kind, identifier):
        return (kind, identifier) in self.owned

    def claim_resource(self, kind, identifier):
        self.check()
        self.owned.add((kind, identifier))


class Remote:
    def __init__(self, work):
        self.work = work
        self.calls = []
        self.consumers = {}
        self.keys = {}
        self.receivers = []
        self.rules = [
            {
                "uid": "rule1",
                "orgID": 1,
                "labels": {"Appchi - Old Ω": "{{ $values.A }}", "team": "existing"},
                "title": "Unchanged",
                "data": [{"model": {"expr": "up"}}],
            }
        ]
        self.company = {
            "receiver": "company-default",
            "group_by": ["team"],
            "routes": [
                {"receiver": "company-team", "object_matchers": [["team", "=", "existing"]]}
            ],
        }
        self.policy = {"receiver": "company-default", "routes": [deepcopy(self.company)]}
        self.timeout_path = None
        self.bad_probe = False
        self.callback = None
        self.gateway_policy = None

    def __call__(self, request):
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.url.host, method, path, deepcopy(body)))
        if self.callback:
            callback, self.callback = self.callback, None
            callback(request)
        if request.url.host == "probe.test":
            document = json.loads(self.gateway_policy["document"])
            key = document["credentials"].get(body["credential_id"], {})
            return httpx.Response(
                200,
                json={
                    "nonce": body["nonce"],
                    "generation": body["generation"],
                    "admitted": False,
                    "members": [
                        {
                            "member_id": "gateway1",
                            "consumer_id": body["consumer_id"],
                            "credential_id": "wrong" if self.bad_probe else body["credential_id"],
                            "ready": True,
                            "policy_generation": str(self.gateway_policy["generation"]),
                            "allowed": body["expected_allowed"],
                            "tenant_id": document["tenant_id"],
                            "version": "1.0.0",
                            "policy_digest": sha256(self.gateway_policy["document"].encode()).hexdigest(),
                            "expires_at": key.get("expires_at"),
                        }
                    ],
                },
            )
        if request.url.host == "kong.test":
            if path == "/":
                return httpx.Response(200, json={"version": "fixture-kong"})
            parts = path.strip("/").split("/")
            if parts[0] == "appchi-policies":
                if method == "PUT":
                    self.gateway_policy = body
                return httpx.Response(200, json=self.gateway_policy)
            if parts[0] == "key-auths":
                row = self.keys.get(parts[-1])
            elif len(parts) == 2:
                if method == "PUT":
                    self.consumers[parts[1]] = body
                if method == "DELETE":
                    self.consumers.pop(parts[1], None)
                    return httpx.Response(204)
                row = self.consumers.get(parts[1])
            elif len(parts) == 3:
                row = {"data": list(self.keys.values()), "next": None}
            else:
                identifier = parts[-1]
                if method == "PUT":
                    self.keys[identifier] = {**body, "consumer": {"id": parts[1]}}
                if method == "DELETE":
                    self.keys.pop(identifier, None)
                    return httpx.Response(204)
                row = self.keys.get(identifier)
            return httpx.Response(200, json=row) if row is not None else httpx.Response(404)
        if path == "/api/health":
            return httpx.Response(200, json={"version": "fixture-grafana"})
        if path == "/api/org":
            return httpx.Response(200, json={"id": 1})
        if path.endswith("/policies"):
            if method == "PUT":
                self.policy = body
            return httpx.Response(200, json=self.policy)
        if "/contact-points" in path:
            if method == "GET":
                redacted = deepcopy(self.receivers)
                for r in redacted:
                    r["settings"]["authorization_credentials"] = "[REDACTED]"
                return httpx.Response(200, json=redacted)
            if method == "DELETE":
                self.receivers = [r for r in self.receivers if r["uid"] != path.split("/")[-1]]
                return httpx.Response(204)
            self.receivers = [r for r in self.receivers if r["uid"] != body["uid"]] + [body]
            if self.timeout_path == path:
                self.timeout_path = None
                raise httpx.ReadTimeout("synthetic secret response body", request=request)
            return httpx.Response(202, json={})
        if path.endswith("/alert-rules"):
            return httpx.Response(200, json=self.rules)
        uid = path.split("/")[-1]
        if method == "PUT":
            self.rules = [r for r in self.rules if r["uid"] != uid] + [body]
        return httpx.Response(200, json=next(r for r in self.rules if r["uid"] == uid))


@pytest.fixture
def executor(monkeypatch):
    monkeypatch.setattr("appchi.operators.kafka_drain.require_drain", lambda *args, **kwargs: None)
    monkeypatch.setattr("appchi.operators.repository.in_use", lambda *args: None)
    work = Work(
        str(uuid4()),
        str(uuid4()),
        str(uuid4()),
        1,
        "setup",
        "Old Ω",
        None,
        str(uuid4()),
        None,
        False,
        "vena_" + "a" * 43,
    )
    binding = OperatorBinding(
        profile="grafana-provisioning-v1-kong-appchi-policy-v1",
        grafana_url="https://grafana.test",
        kong_url="https://kong.test",
        probe_url="https://probe.test/check",
        webhook_url="https://ingress.test/api/ingest/v2/grafana",
        grafana_version="fixture-grafana",
        kong_version="fixture-kong",
        organization=1,
        verified_evidence_id="fixture",
        controlled_writer_evidence_id="fixture",
        wrapper_evidence_id="fixture",
        inventory_evidence_id="fixture",
        namespace_evidence_id="fixture",
        serving_pool_evidence_id="fixture",
        serving_members=["gateway1"],
        capabilities=sorted(REQUIRED_CAPABILITIES | EXTRA_CAPABILITIES),
    )
    work = replace(work, policy_generation=1, policy_document=json.dumps({
        "operator_id":work.operator_id,"tenant_id":work.tenant_id,"enabled":True,
        "routing_names":[work.name],"credentials":{work.candidate_id:{"state":"prepared"}},
    }, sort_keys=True, separators=(",",":")))
    remote, ledger = Remote(work), Ledger(work)
    adapter = ProvisioningExecutor(
        binding,
        MagicMock(),
        PlatformCredentials(
            "grafana-management-secret", "kong-management-secret", "probe-management-secret"
        ),
        transport=httpx.MockTransport(remote),
        ledger=ledger,
    )
    yield adapter, remote, ledger, work
    adapter.close()


def test_setup_requires_matching_probe_and_keeps_company_routes(executor):
    adapter, remote, ledger, work = executor
    result = adapter.execute(work)
    assert (
        result.kong_verified
        and result.grafana_verified
        and result.credential_id == work.candidate_id
    )
    assert remote.policy["routes"][-1] == remote.company
    route = remote.policy["routes"][0]
    assert route["object_matchers"] == [["Appchi - Old Ω", "=", "true"]]
    assert route["continue"] is True and route["group_by"] == ["..."]
    assert remote.receivers[0]["settings"]["authorization_credentials"] == work.secret
    assert ledger.edits == []
    assert work.secret not in repr(work) and "management-secret" not in repr(adapter.credentials)


def test_timeout_reconciles_same_ids_and_rewrites_redacted_secret(executor):
    adapter, remote, ledger, work = executor
    remote.timeout_path = "/api/v1/provisioning/contact-points"
    with pytest.raises(AppError, match="remote_outcome_uncertain") as caught:
        adapter.execute(work)
    assert "synthetic secret" not in str(caught.value)
    assert len(remote.receivers) == 1
    result = adapter.execute(replace(work, reconcile_first=True))
    assert result.credential_id == work.candidate_id
    writes = [
        call for call in remote.calls if call[1] in ("POST", "PUT") and "/contact-points" in call[2]
    ]
    assert len(writes) == 2 and writes[0][3]["uid"] == writes[1][3]["uid"]


@pytest.mark.parametrize("activated", [False, True])
def test_rotation_does_not_authenticate_old_credential_with_candidate_key(executor, activated):
    adapter, remote, ledger, work = executor
    current_id = str(uuid4())
    document = json.loads(work.policy_document)
    document["credentials"][current_id] = (
        {"state": "retiring", "expires_at": (datetime.now(UTC) + timedelta(days=1)).timestamp()}
        if activated else {"state": "current"}
    )
    if activated:
        document["credentials"][work.candidate_id] = {"state": "current"}
    rotation = replace(
        work, kind="rotate", current_id=current_id,
        policy_document=json.dumps(document, sort_keys=True, separators=(",", ":")),
    )
    ledger.valid_ids.add(current_id)
    ledger.owned.add(("kong_key", current_id))
    remote.keys[current_id] = {
        "id": current_id, "key": "vena_" + "b" * 43,
        "consumer": {"id": work.operator_id},
    }
    result = adapter.execute(rotation)
    proofs = [body for host, _, _, body in remote.calls if host == "probe.test"]
    assert result.credential_id == work.candidate_id
    assert all(body["key"] is None for body in proofs if body["credential_id"] == current_id)
    assert all(body["key"] == work.secret for body in proofs if body["credential_id"] == work.candidate_id)
    assert all(body["expected_allowed"] is activated for body in proofs if body["credential_id"] == work.candidate_id)


@pytest.mark.parametrize("restore_kind", ["cancel", "create_key"])
def test_rename_and_cancel_restore_only_journaled_labels(executor, restore_kind):
    adapter, remote, ledger, work = executor
    renamed = replace(
        work, kind="rename", pending_name="New Ω", current_id=work.candidate_id, candidate_id=None
    )
    adapter.execute(renamed)
    assert remote.rules[0]["labels"] == {"Appchi - New Ω": "{{ $values.A }}", "team": "existing"}
    assert len(ledger.edits) == 1
    remote.rules[0]["title"] = "Fresh unrelated edit"
    ledger.restore_edits = deepcopy(ledger.edits)
    adapter.execute(replace(renamed, kind=restore_kind, cancel_kind="rename"))
    assert remote.rules[0]["labels"] == {"Appchi - Old Ω": "{{ $values.A }}", "team": "existing"}
    assert remote.rules[0]["title"] == "Fresh unrelated edit"
    assert remote.policy["routes"][0]["object_matchers"][0][0] == "Appchi - Old Ω"


def test_delete_proves_grafana_absence_before_kong_cleanup(executor):
    adapter, remote, ledger, work = executor
    adapter.execute(work)
    result = adapter.execute(replace(work, kind="delete"))
    assert result.receiver_verified and not result.kong_cleanup_verified
    assert remote.receivers == [] and remote.policy["routes"] == [remote.company]
    assert remote.rules[0]["labels"] == {"team": "existing"}
    assert work.candidate_id in remote.keys
    ledger.deleted, ledger.invalid_ids, ledger.valid_ids = True, {work.candidate_id}, set()
    result = adapter.execute(replace(work, kind="cleanup", candidate_id=None, secret=None))
    assert result.kong_cleanup_verified and remote.keys == {} and remote.consumers == {}


def test_probe_mismatch_never_returns_readiness(executor):
    adapter, remote, ledger, work = executor
    remote.bad_probe = True
    with pytest.raises(AppError, match="operator_readiness_unproven"):
        adapter.execute(work)


def test_generation_change_stops_before_next_remote_write(executor):
    adapter, remote, ledger, work = executor
    remote.callback = lambda request: setattr(ledger, "stale", True)
    with pytest.raises(AppError, match="stale_provisioning_generation"):
        adapter.execute(work)
    assert not any(call[1] != "GET" for call in remote.calls)


def test_unmanaged_reference_and_conflicting_rule_label_block(executor):
    adapter, remote, ledger, work = executor
    remote.company["routes"].append({"receiver": resource_identity(work.operator_id)["receiver"]})
    remote.policy["routes"][-1] = deepcopy(remote.company)
    with pytest.raises(AppError, match="remote_ownership_conflict"):
        adapter.execute(replace(work, kind="delete"))
    assert not any(call[1] == "DELETE" for call in remote.calls)


def test_profile_requires_capabilities_https_and_controlled_writer(executor):
    adapter, *_ = executor
    body = adapter.binding.model_dump()
    for patch in (
        {"capabilities": []},
        {"grafana_url": "http://grafana.test"},
        {"controlled_writer_evidence_id": ""},
        {"profile": "unimplemented-app-platform"},
    ):
        with pytest.raises(ValueError):
            OperatorBinding.model_validate({**body, **patch})


def test_foreign_credential_collision_is_never_overwritten(executor):
    adapter, remote, _, work = executor
    remote.keys[work.candidate_id] = {
        "id": work.candidate_id,
        "consumer": {"id": str(uuid4())},
        "key": "foreign",
    }
    with pytest.raises(AppError, match="remote_ownership_conflict"):
        adapter.execute(work)
    assert remote.keys[work.candidate_id]["key"] == "foreign"
    assert not any(call[1] == "PUT" and "/key-auth/" in call[2] for call in remote.calls)


def test_missing_plaintext_never_recreates_a_credential(executor):
    adapter, remote, ledger, work = executor
    adapter.execute(work)
    ledger.invalid_ids, ledger.valid_ids = {work.candidate_id}, set()
    remote.calls.clear()
    result = adapter.execute(replace(work, kind="cleanup", candidate_id=None, secret=None))
    assert result.kong_cleanup_verified
    assert remote.keys == {}
    assert not any(call[1] == "PUT" and "/key-auth/" in call[2] for call in remote.calls)


def test_delete_cancel_reverses_superseded_rename_then_delete(executor):
    adapter, remote, ledger, work = executor
    renamed = replace(work, kind="rename", pending_name="New Ω")
    adapter.execute(renamed)
    rename_edits = deepcopy(ledger.edits)
    ledger.edits = []
    adapter.execute(replace(renamed, kind="delete"))
    ledger.restore_edits = rename_edits + deepcopy(ledger.edits)
    adapter.execute(replace(renamed, kind="cancel", cancel_kind="delete"))
    assert remote.rules[0]["labels"] == {"Appchi - Old Ω": "{{ $values.A }}", "team": "existing"}
    assert remote.policy["routes"][0]["object_matchers"] == [["Appchi - Old Ω", "=", "true"]]


def test_supported_version_mismatch_blocks_all_writes(executor):
    adapter, remote, _, work = executor
    adapter.binding = adapter.binding.model_copy(update={"grafana_version": "different"})
    with pytest.raises(AppError, match="operator_capabilities_unverified"):
        adapter.execute(work)
    assert not any(call[0] == "grafana.test" and call[1] != "GET" for call in remote.calls)


def test_preexisting_receiver_without_durable_ownership_is_not_adopted(executor):
    adapter, remote, _, work = executor
    identity = resource_identity(work.operator_id)
    remote.receivers = [
        {
            "uid": identity["uid"],
            "name": identity["receiver"],
            "type": "webhook",
            "settings": {"authorization_credentials": "foreign"},
        }
    ]
    with pytest.raises(AppError, match="remote_ownership_conflict"):
        adapter.execute(work)
    assert remote.receivers[0]["settings"]["authorization_credentials"] == "foreign"
    assert not any(call[1] != "GET" and "/contact-points" in call[2] for call in remote.calls)


@pytest.mark.parametrize(
    "header,expected",
    [
        ("1200", 1200),
        ("9999999999999999", 3600),
        ("0", 0),
        ("invalid-secret-header", None),
        ("-10", None),
        ("1.5", None),
    ],
)
def test_remote_retry_after_is_bounded_and_header_not_retained(executor, header, expected):
    adapter, remote, _, work = executor
    adapter.client.close()
    adapter.client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                429, headers={"Retry-After": header}, content=b"sensitive remote body"
            )
        )
    )
    with pytest.raises(AppError) as caught:
        adapter.execute(work)
    assert caught.value.code == "remote_unavailable"
    assert caught.value.fields == (
        {"retry_after_seconds": expected} if expected is not None else None
    )
    assert "sensitive" not in str(caught.value) and "invalid-secret-header" not in str(
        caught.value.fields
    )


def test_remote_retry_after_http_date(executor):
    adapter, _, _, work = executor
    header = format_datetime(datetime.now(UTC) + timedelta(minutes=20), usegmt=True)
    adapter.client.close()
    adapter.client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(503, headers={"Retry-After": header})
        )
    )
    with pytest.raises(AppError) as caught:
        adapter.execute(work)
    assert 1198 <= caught.value.fields["retry_after_seconds"] <= 1200


def test_denial_runs_before_unrelated_cipher_failure_or_grafana(executor):
    adapter, remote, ledger, work = executor
    adapter.execute(work)
    document = json.loads(work.policy_document)
    document["credentials"] = {}
    ledger.invalid_ids, ledger.valid_ids = {work.candidate_id, str(uuid4())}, set()
    remote.calls.clear()
    with pytest.raises(AppError, match="credential_decryption_unavailable"):
        adapter.execute(replace(work, kind="cleanup", candidate_id=None, secret=None,
            secret_unavailable=True, policy_generation=2, policy_document=json.dumps(document)))
    proofs = [body for host, _, _, body in remote.calls if host == "probe.test"]
    assert {proof["credential_id"] for proof in proofs} == ledger.invalid_ids
    assert all(proof["key"] is None and proof["expected_allowed"] is False for proof in proofs)
    assert remote.keys == {}
    assert not any(host == "grafana.test" for host, _, _, _ in remote.calls)
