"""Executable, explicitly qualified legacy Grafana/Kong provisioning profile.

No platform endpoint is discovered from tenant data. Remote facts are verified
by fresh reads, explicit writes and a non-ingesting serving-pool proof contract.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, UTC
from email.utils import parsedate_to_datetime
import json
import math
import secrets
import time
from hashlib import sha256
from urllib.parse import quote

import httpx

from appchi.operators.binding import OperatorBinding
from appchi.operators.executor_ledger import PostgresLedger
from appchi.operators.policy import resource_identity
from appchi.operators.remote import RemoteAdapter
from appchi.operators.worker import VerifiedResult
from appchi.shared.errors import AppError, unavailable


@dataclass(frozen=True)
class PlatformCredentials:
    grafana: str = field(repr=False)
    kong: str = field(repr=False)
    probe: str = field(repr=False)


def _id(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 128
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for c in value
        )
    ):
        raise unavailable("remote_schema_unsupported")
    return quote(value, safe="")


def _require(condition, code="remote_verification_failed"):
    if not condition:
        raise unavailable(code)


def _retry_fields(response):
    value = response.headers.get("Retry-After", "").strip()
    if not value or len(value) > 128:
        return None
    try:
        if value.isascii() and value.isdigit():
            delay = int(value)
        else:
            deadline = parsedate_to_datetime(value)
            if deadline.tzinfo is None:
                return None
            delay = math.ceil((deadline - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None
    # Preserve only a bounded delay, never a remote header/body in job errors.
    return {"retry_after_seconds": min(3600, max(0, delay))}


def _route(operator, name):
    return {
        "receiver": resource_identity(operator)["receiver"],
        "object_matchers": [["Appchi - " + name, "=", "true"]],
        "continue": True,
        "group_by": ["..."],
        "group_wait": "0s",
        "group_interval": "1m",
        "repeat_interval": "1h",
    }


class ProvisioningExecutor:
    def __init__(
        self,
        binding: OperatorBinding,
        db,
        credentials: PlatformCredentials,
        *,
        transport=None,
        ledger=None,
        settings=None,
    ):
        if not all((credentials.grafana, credentials.kong, credentials.probe)):
            raise unavailable("operator_capabilities_unverified")
        self.binding, self.manifest = binding, binding.manifest()
        self.credentials = credentials
        self.db, self.settings = db, settings
        self.ledger = ledger or PostgresLedger(db)
        self.client = httpx.Client(
            verify=binding.ca_file or True,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )
        # Reuse the existing profile/origin validator; this executor adds list,
        # creation, absence, strict profile schemas and a whole-attempt deadline.
        self.grafana = RemoteAdapter(self.client, binding.grafana_url, self.manifest)
        self.kong = RemoteAdapter(self.client, binding.kong_url, self.manifest)

    def close(self):
        self.client.close()

    def execute(self, work):
        # Attempts have independent clients' requests/ledger state; the durable
        # worker's global lease supplies single Appchi routing-writer ownership.
        attempt = _Attempt(self, work)
        return attempt.run()


class _Attempt:
    def __init__(self, executor, work):
        self.executor, self.binding, self.work = executor, executor.binding, work
        self.deadline = time.monotonic() + 27
        self.ledger = executor.ledger.begin(work, executor.binding.digest())
        self.identity = resource_identity(work.operator_id)
        self.receiver_path = "/api/v1/provisioning/contact-points/" + self.identity["uid"]

    def http(self, service, method, path="", body=None, *, absent=False):
        self.ledger.check()
        remaining = self.deadline - time.monotonic()
        _require(remaining > 0.1, "remote_outcome_uncertain")
        origins = {
            "grafana": self.binding.grafana_url,
            "kong": self.binding.kong_url,
            "probe": self.binding.probe_url,
        }
        headers = {"Accept": "application/json"}
        if service == "grafana":
            headers.update(
                {
                    "Authorization": "Bearer " + self.executor.credentials.grafana,
                    "X-Grafana-Org-Id": str(self.binding.organization),
                }
            )
        elif service == "kong":
            headers["Kong-Admin-Token"] = self.executor.credentials.kong
        else:
            headers["Authorization"] = "Bearer " + self.executor.credentials.probe
        try:
            # Streaming bounds bytes and rejects trickle responses at the shared
            # deadline. Every blocking phase receives only a fraction of it.
            with self.executor.client.stream(
                method,
                origins[service] + path,
                headers=headers,
                json=body,
                timeout=min(2.0, remaining / 4),
                follow_redirects=False,
            ) as response:
                if response.status_code == 404 and absent:
                    self.ledger.check()
                    return None
                if response.status_code in (401, 403):
                    raise AppError(
                        "remote_needs_attention",
                        "Remote authorization failed.",
                        503,
                        fields=_retry_fields(response),
                    )
                if response.status_code in (409, 412):
                    raise AppError(
                        "remote_version_conflict",
                        "Remote state changed; reconcile again.",
                        409,
                        fields=_retry_fields(response),
                    )
                if not 200 <= response.status_code < 300:
                    raise AppError(
                        "remote_unavailable",
                        "Remote service is unavailable.",
                        503,
                        fields=_retry_fields(response),
                    )
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    _require(
                        len(raw) <= self.binding.max_response_bytes
                        and time.monotonic() < self.deadline,
                        "remote_schema_unsupported",
                    )
                result = json.loads(raw) if raw else {}
        except (httpx.HTTPError, ValueError):
            raise unavailable(
                "remote_outcome_uncertain" if method != "GET" else "remote_unavailable"
            ) from None
        self.ledger.check()
        return result

    def inventory(self):
        rules = self.http("grafana", "GET", "/api/v1/provisioning/alert-rules")
        _require(
            isinstance(rules, list) and len(rules) <= self.binding.max_rules,
            "operator_capability_missing",
        )
        seen = set()
        for rule in rules:
            _require(
                isinstance(rule, dict) and isinstance(rule.get("labels"), dict),
                "remote_schema_unsupported",
            )
            uid = _id(rule.get("uid"))
            _require(uid not in seen, "remote_schema_unsupported")
            seen.add(uid)
            _require(
                rule.get("orgID", rule.get("orgId", self.binding.organization))
                == self.binding.organization,
                "remote_ownership_conflict",
            )
        return rules

    def policy(self, names):
        tree = self.http("grafana", "GET", "/api/v1/provisioning/policies")
        _require(
            isinstance(tree, dict)
            and isinstance(tree.get("routes"), list)
            and len(tree["routes"]) >= 1,
            "operator_capabilities_unverified",
        )
        company = tree["routes"][-1]
        _require(
            isinstance(company, dict)
            and not any(
                company.get(k) for k in ("matchers", "object_matchers", "match", "match_re")
            )
            and company.get("receiver"),
            "operator_capabilities_unverified",
        )
        managed = []
        for route in tree["routes"][:-1]:
            _require(isinstance(route, dict), "remote_schema_unsupported")
            receiver = route.get("receiver", "")
            _require(receiver.startswith("vena-operator-"), "remote_ownership_conflict")
            owner = receiver[len("vena-operator-") :]
            _require(owner in self.ledger.known_operators, "remote_ownership_conflict")
            if owner != self.work.operator_id:
                managed.append(deepcopy(route))
        if not names:

            def references(node):
                return isinstance(node, dict) and (
                    node.get("receiver") == self.identity["receiver"]
                    or any(references(child) for child in node.get("routes", []))
                )

            _require(
                not any(references(route) for route in [company, *managed])
                and tree.get("receiver") != self.identity["receiver"],
                "remote_ownership_conflict",
            )
        desired = deepcopy(tree)
        managed.extend(_route(self.work.operator_id, name) for name in names)
        managed.sort(
            key=lambda route: (
                route["receiver"],
                json.dumps(route.get("object_matchers", []), ensure_ascii=False),
            )
        )
        desired["routes"] = [*managed, deepcopy(company)]
        if desired != tree:
            self.http("grafana", "PUT", "/api/v1/provisioning/policies", desired)
        actual = self.http("grafana", "GET", "/api/v1/provisioning/policies")
        _require(actual == desired)

    def receiver(self, secret, *, remove=False):
        rows = self.http("grafana", "GET", "/api/v1/provisioning/contact-points")
        _require(
            isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
            "remote_schema_unsupported",
        )
        found = [
            r
            for r in rows
            if r.get("uid") == self.identity["uid"] or r.get("name") == self.identity["receiver"]
        ]
        _require(
            len(found) <= 1
            and all(
                r.get("uid") == self.identity["uid"]
                and r.get("name") == self.identity["receiver"]
                and r.get("type") == "webhook"
                for r in found
            ),
            "remote_ownership_conflict",
        )
        if found:
            _require(
                self.ledger.owns("grafana_receiver", self.identity["uid"]),
                "remote_ownership_conflict",
            )
        if remove:
            if found:
                self.http("grafana", "DELETE", self.receiver_path, absent=True)
            rows = self.http("grafana", "GET", "/api/v1/provisioning/contact-points")
            _require(
                isinstance(rows, list)
                and not any(
                    r.get("uid") == self.identity["uid"]
                    or r.get("name") == self.identity["receiver"]
                    for r in rows
                )
            )
            return
        _require(
            isinstance(secret, str) and secret.startswith("vena_"),
            "credential_decryption_unavailable",
        )
        settings = {
            "url": self.binding.webhook_url,
            "httpMethod": "POST",
            "authorization_scheme": "Bearer",
            "authorization_credentials": secret,
            "maxAlerts": "0",
            "tlsConfig": {"insecureSkipVerify": False},
        }
        desired = {
            "uid": self.identity["uid"],
            "name": self.identity["receiver"],
            "type": "webhook",
            "disableResolveMessage": False,
            "settings": settings,
        }
        if not found:
            self.ledger.claim_resource("grafana_receiver", self.identity["uid"])
        # Repeat the intended secret write even if its readback is redacted;
        # a redacted response alone is never proof of the candidate secret.
        self.http(
            "grafana",
            "PUT" if found else "POST",
            self.receiver_path if found else "/api/v1/provisioning/contact-points",
            desired,
        )
        rows = self.http("grafana", "GET", "/api/v1/provisioning/contact-points")
        actual = (
            next((r for r in rows if r.get("uid") == self.identity["uid"]), None)
            if isinstance(rows, list)
            else None
        )
        _require(
            actual
            and all(
                actual.get(k) == desired[k]
                for k in ("uid", "name", "type", "disableResolveMessage")
            )
        )
        redacted = deepcopy(actual.get("settings", {}))
        redacted.pop("authorization_credentials", None)
        public_settings = {k: v for k, v in settings.items() if k != "authorization_credentials"}
        _require(redacted == public_settings)

    def kong(self):
        consumer = self.http("kong", "GET", "/consumers/" + self.work.operator_id, absent=True)
        desired = {
            "id": self.work.operator_id,
            "username": self.identity["kong_username"],
            "custom_id": self.work.operator_id,
        }
        if consumer is None and not self.ledger.deleted:
            self.ledger.claim_resource("kong_consumer", self.work.operator_id)
            self.http("kong", "PUT", "/consumers/" + self.work.operator_id, desired)
            consumer = self.http("kong", "GET", "/consumers/" + self.work.operator_id)
        if consumer is not None:
            _require(
                self.ledger.owns("kong_consumer", self.work.operator_id),
                "remote_ownership_conflict",
            )
            _require(
                all(consumer.get(k) == v for k, v in desired.items()), "remote_ownership_conflict"
            )
        credential = self.work.candidate_id or self.work.current_id
        if self.work.secret is not None:
            _require(
                consumer is not None and credential in self.ledger.valid_ids,
                "kong_binding_unverified",
            )
            path = f"/consumers/{self.work.operator_id}/key-auth/{credential}"
            existing = self.http("kong", "GET", path, absent=True)
            global_credential = self.http("kong", "GET", "/key-auths/" + credential, absent=True)
            if global_credential is not None:
                _require(
                    global_credential.get("id") == credential
                    and global_credential.get("consumer", {}).get("id") == self.work.operator_id,
                    "remote_ownership_conflict",
                )
            if existing is not None:
                _require(
                    existing.get("id") == credential
                    and existing.get("consumer", {}).get("id") == self.work.operator_id,
                    "remote_ownership_conflict",
                )
            self.http("kong", "PUT", path, {"id": credential, "key": self.work.secret})
            actual = self.http("kong", "GET", path)
            _require(
                actual.get("id") == credential
                and actual.get("consumer", {}).get("id") == self.work.operator_id,
                "kong_binding_unverified",
            )
        for identifier in sorted(self.ledger.invalid_ids):
            path = f"/consumers/{self.work.operator_id}/key-auth/{identifier}"
            existing = self.http("kong", "GET", path, absent=True)
            if existing is not None:
                _require(
                    existing.get("id") == identifier
                    and existing.get("consumer", {}).get("id") == self.work.operator_id,
                    "remote_ownership_conflict",
                )
                self.http("kong", "DELETE", path, absent=True)
            _require(
                self.http("kong", "GET", path, absent=True) is None, "remote_cleanup_unverified"
            )
        if self.ledger.deleted and consumer is not None:
            # Never delete a Consumer while an untracked credential might remain.
            inventory = self.http("kong", "GET", f"/consumers/{self.work.operator_id}/key-auth")
            _require(
                isinstance(inventory, dict)
                and inventory.get("data") == []
                and not inventory.get("next"),
                "remote_ownership_conflict",
            )
            self.http("kong", "DELETE", "/consumers/" + self.work.operator_id, absent=True)
            _require(
                self.http("kong", "GET", "/consumers/" + self.work.operator_id, absent=True)
                is None,
                "remote_cleanup_unverified",
            )
        return credential

    def labels(self, rules, names, destination):
        for rule in rules:
            source_keys = [
                "Appchi - " + name for name in names if "Appchi - " + name in rule["labels"]
            ]
            for key in source_keys:
                new_key = "Appchi - " + destination if destination is not None else None
                if key == new_key:
                    continue
                fresh = self.http(
                    "grafana", "GET", "/api/v1/provisioning/alert-rules/" + _id(rule["uid"])
                )
                _require(
                    isinstance(fresh, dict) and isinstance(fresh.get("labels"), dict),
                    "remote_schema_unsupported",
                )
                if key not in fresh["labels"]:
                    continue
                old_value = fresh["labels"][key]
                _require(
                    isinstance(old_value, str) and len(old_value.encode()) <= 16384,
                    "remote_schema_unsupported",
                )
                _require(
                    new_key is None
                    or new_key not in fresh["labels"]
                    or fresh["labels"][new_key] == old_value,
                    "routing_label_conflict",
                )
                edit = {
                    "uid": fresh["uid"],
                    "old_key": key,
                    "old_value": old_value,
                    "new_key": new_key,
                    "new_value": fresh["labels"].get(new_key) if new_key else None,
                }
                self.ledger.record(edit)
                desired = deepcopy(fresh)
                del desired["labels"][key]
                if new_key:
                    desired["labels"][new_key] = old_value
                self.write_rule(fresh["uid"], desired)
        actual = self.inventory()
        for rule in actual:
            _require(
                not any(
                    "Appchi - " + name in rule["labels"] for name in names if name != destination
                ),
                "grafana_verification_required",
            )

    def write_rule(self, uid, desired):
        path = "/api/v1/provisioning/alert-rules/" + _id(uid)
        self.http("grafana", "PUT", path, desired)
        actual = self.http("grafana", "GET", path)
        # Server recording metadata may change; everything writable is preserved.
        ignored = {"id", "updated", "provenance"}
        _require(
            {k: v for k, v in actual.items() if k not in ignored}
            == {k: v for k, v in desired.items() if k not in ignored}
        )

    def restore(self):
        for edit in reversed(self.ledger.restore_edits):
            fresh = self.http(
                "grafana", "GET", "/api/v1/provisioning/alert-rules/" + _id(edit["uid"])
            )
            labels = fresh.get("labels")
            _require(isinstance(labels, dict), "remote_schema_unsupported")
            old, new = edit["old_key"], edit["new_key"]
            if old in labels:
                _require(labels[old] == edit["old_value"], "routing_label_conflict")
            else:
                _require(
                    new is None or labels.get(new) == edit["old_value"], "routing_label_conflict"
                )
            desired = deepcopy(fresh)
            desired["labels"][old] = edit["old_value"]
            if new:
                _require(
                    labels.get(new) in (None, edit["old_value"], edit["new_value"]),
                    "routing_label_conflict",
                )
                if edit["new_value"] is None:
                    desired["labels"].pop(new, None)
                else:
                    desired["labels"][new] = edit["new_value"]
            if desired != fresh:
                self.write_rule(edit["uid"], desired)

    def probe(self, credential):
        nonce = secrets.token_urlsafe(24)
        document = json.loads(self.work.policy_document)
        key = document["credentials"].get(credential, {})
        allowed = (
            document["enabled"]
            and key.get("state") in ("current", "retiring")
            and (not key.get("expires_at") or datetime.now(UTC).timestamp() < key["expires_at"])
        )
        payload = {
            "operator_id": self.work.operator_id,
            "consumer_id": self.work.operator_id,
            "credential_id": credential,
            "generation": str(self.work.generation),
            "nonce": nonce,
            "key": self.work.secret
            if credential in (self.work.candidate_id, self.work.current_id)
            else None,
            "policy_generation": str(self.work.policy_generation),
            "expected_allowed": bool(allowed),
        }
        actual = self.http("probe", "POST", body=payload)
        _require(
            isinstance(actual, dict)
            and actual.get("nonce") == nonce
            and actual.get("generation") == str(self.work.generation)
            and actual.get("admitted") is False,
            "operator_readiness_unproven",
        )
        members = actual.get("members")
        _require(
            isinstance(members, list) and len(members) == len(self.binding.serving_members),
            "operator_readiness_unproven",
        )
        _require(
            all(isinstance(m, dict) for m in members)
            and {m.get("member_id") for m in members} == set(self.binding.serving_members)
            and all(
                m.get("ready") is True
                and m.get("consumer_id") == self.work.operator_id
                and m.get("credential_id") == credential
                and m.get("policy_generation") == str(self.work.policy_generation)
                and m.get("allowed") is bool(allowed)
                and m.get("tenant_id") == self.work.tenant_id
                and m.get("version") == "1.0.0"
                and m.get("policy_digest") == sha256(self.work.policy_document.encode()).hexdigest()
                and m.get("expires_at") == key.get("expires_at")
                for m in members
            ),
            "operator_readiness_unproven",
        )

    def run(self):
        _require(
            self.work.kind
            in {"setup", "create_key", "rotate", "rename", "delete", "cancel", "cleanup", "repair"},
            "adapter_operation_unsupported",
        )
        self.executor.manifest.validate()
        _require(
            bool(self.work.policy_document) and self.work.policy_generation > 0,
            "kong_policy_unverified",
        )
        kong = self.http("kong", "GET", "/")
        _require(
            kong.get("version") == self.binding.kong_version, "operator_capabilities_unverified"
        )
        # Denial distribution is independent of Grafana and never needs a revoked secret.
        path = "/appchi-policies/" + self.work.operator_id
        policy = {"generation": self.work.policy_generation, "document": self.work.policy_document}
        self.http("kong", "PUT", path, policy)
        actual = self.http("kong", "GET", path)
        _require(all(actual.get(k) == v for k, v in policy.items()), "kong_policy_unverified")
        credential = self.kong()
        for identifier in sorted(self.ledger.valid_ids | self.ledger.invalid_ids):
            self.probe(identifier)
        if self.work.kind == "delete" and not self.ledger.deleted:
            from appchi.operators.kafka_drain import require_drain

            require_drain(
                self.executor.db,
                self.executor.settings,
                self.work,
                self.ledger.check,
                deadline=self.deadline,
            )
            from appchi.operators import repository as repo

            with self.executor.db.transaction(self.work.tenant_id) as conn:
                operator = repo.get_operator(conn, self.work.tenant_id, self.work.operator_id)
                repo.in_use(conn, operator)
        if self.work.secret_unavailable:
            raise unavailable("credential_decryption_unavailable")
        health = self.http("grafana", "GET", "/api/health")
        org = self.http("grafana", "GET", "/api/org")
        _require(
            health.get("version") == self.binding.grafana_version
            and org.get("id") == self.binding.organization
            and kong.get("version") == self.binding.kong_version,
            "operator_capabilities_unverified",
        )
        names = [self.work.name] + ([self.work.pending_name] if self.work.pending_name else [])
        rules = self.inventory()
        deleting = self.work.kind == "delete" or self.ledger.deleted
        if deleting:
            self.labels(rules, names, None)
            self.policy([])
            # Direct receivers bypass the policy tree and are live blockers.
            _require(
                not any(
                    (rule.get("notification_settings") or {}).get("receiver")
                    == self.identity["receiver"]
                    for rule in self.inventory()
                ),
                "remote_ownership_conflict",
            )
            self.receiver(None, remove=True)
            if self.ledger.deleted:
                self.kong()
            return VerifiedResult(
                kong_verified=True,
                grafana_acknowledged=True,
                grafana_verified=True,
                complete_rule_inventory=True,
                labels_verified=True,
                policy_verified=True,
                receiver_verified=True,
                kong_cleanup_verified=self.ledger.deleted,
                policy_generation=self.work.policy_generation,
                kafka_drain_verified=True,
            )
        cancelling = (
            self.work.kind == "cancel"
            or self.work.kind == "cleanup"
            and self.work.pending_name
            or self.work.kind == "create_key"
            and self.work.cancel_kind is not None
        )
        target = self.work.name if cancelling else self.work.pending_name or self.work.name
        if self.work.secret is None:
            # Credential-free cleanup cannot manufacture or revive a key. It can
            # remove invalid Kong material, but Grafana repair stays visible.
            self.policy([])
            self.receiver(None, remove=True)
            return VerifiedResult(
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                True,
                self.work.operator_id,
                credential,
                self.work.policy_generation,
            )
        self.receiver(self.work.secret)
        self.policy(names if self.work.pending_name else [target])
        if cancelling:
            self.restore()
            restored = self.inventory()
            _require(
                not self.work.pending_name
                or not any(
                    "Appchi - " + self.work.pending_name in rule["labels"] for rule in restored
                ),
                "grafana_verification_required",
            )
        elif self.work.pending_name:
            self.labels(rules, [self.work.name], target)
        self.policy([target])
        self.probe(credential)
        self.ledger.check()
        return VerifiedResult(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            self.work.operator_id,
            credential,
            self.work.policy_generation,
        )


def configured_executor(path, db, credentials, *, settings=None):
    """Load an explicitly supplied JSON binding; no fallback or default fleet."""
    try:
        binding = OperatorBinding.model_validate_json(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise unavailable("operator_capabilities_unverified") from None
    return ProvisioningExecutor(binding, db, credentials, settings=settings)
