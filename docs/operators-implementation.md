# Operator implementation and supplied-platform binding

The application now has durable operator APIs, encrypted key state, request-owned
provisioning with durable SQL operation progress, and an executable HTTPS
Grafana/Kong adapter. Private company compatibility and readiness remain
unqualified. No company Grafana receiver, policy, rule, Kong Consumer or key was
changed during this implementation.

## Implemented paths

`operators/routes.py` and `repository.py` implement tenant-authorized create,
list/detail, rename, key preparation/rotation, current-key copy, revocation,
delete, retry and supported cancellation. Accepted work persists in PostgreSQL;
operator generations fence stale completion. Copy is a separately authorized,
audited response; ciphertext and secrets never appear in list/history payloads.
Revocation immediately erases ciphertext and authoritative admission eligibility.

Provisioning is request-owned (REV-34; [worker scope 3](https://github.com/appchi-alert-operations/appchi-design/blob/main/specs/spec-worker-scope.md#3-request-owned-operator-provisioning)).
No operator worker or background retry loop runs. The API commits the command and
its operation first; `operators/synchronous.py` then runs that operation inside the
same HTTP request, within a 90-second budget that starts no attempt with less than
35 seconds left. Creation returns 201, and other provisioning mutations 200, only
after verified completion. A failed or incomplete request returns 503 (or an
applicable 409, such as a cancelled or superseded operation) with the operator and
operation IDs, `outcome_may_be_partial: true` and `retry_action: "retry"`. Partial
progress stays for the explicit retry endpoint; replaying the original command
inspects its original operation and never creates another key. A restart or
disconnected caller leaves recoverable progress but schedules no continuation.

For each attempt, `run_one` in `operators/worker.py` (the module keeps the deferred
worker's name) claims that operation's 45-second lease and the global Grafana writer
lease; a competing request never steals a held lease. `operators/executor.py` makes
external calls outside SQL transactions, with a 27-second attempt budget and
bounded response sizes. `executor_ledger.py` checks the operation token, both lease
deadlines, generation and operator revision before and after HTTP calls. It pins
the supplied profile digest per operator and persists only reversible routing-label
edits, never key material or rule bodies.
A durable resource-creation intent is recorded after confirmed absence and before
the first remote write. A preexisting same-UUID Consumer or receiver without that
ownership record is a conflict; a reserved name alone does not permit adoption.
A changed destination/profile requires a deliberate platform migration; changing
the binding file does not silently move existing operator resources.

Create, rotate and replacement preparation reuse the existing prepared credential
UUID and plaintext on uncertain retries. Activation needs acknowledged Grafana
secret write, verified public receiver settings, Kong ownership/readback and the
serving-pool proof below. Redacted receiver readback is never evidence that its
secret equals the candidate: each attempt acknowledges the intended secret write.
Expiry/revocation never generates or revives a key. A keyless live operator can
clean invalid Kong credentials but remains visibly pending for Grafana repair
until an authorized usable replacement exists.
Create key can supersede pending cleanup after revocation. That transaction
advances the generation and audits the superseded operation; the replacement
attempt still removes invalid remote credentials. Late cleanup cannot commit.
If initial setup had a proposed name, replacement activation commits it only
after the same full inventory, label and policy verification used by setup.

Rename preserves the exact rule-label expression/value and unrelated rule fields.
The route matcher is exactly `Appchi - {operator name}` = literal string `true`.
Both old and proposed names remain claimed until verified completion. Cancellation
reverses the persisted edits using fresh rule reads and checks for conflicts.
Cancelling deletion of initial setup reuses its original prepared credential.
Cancelling deletion that superseded a partial rename reverses delete edits and
then rename edits before removing the temporary route/name claim.
If the final usable key is revoked during cancellation, an explicit Create key
can prepare a fresh replacement for that restoration. Its durable progress retains
the original cancelled operation ID/kind. It restores the old name and label
changes rather than completing the abandoned rename. The deletion admission fence,
where present, remains until full restoration evidence and replacement activation
commit together. Revoking that replacement preserves the restoration lineage for
another explicit command; revoked plaintext is never recovered. Public operation
fields `restoring_cancellation` and `cancellation_kind` let the UI explain this state.

Deletion removes exact old/proposed routing labels, the owned managed policy
entries and receiver, checks for direct receiver references, and verifies absence
before the completion transaction may logically retire the operator. Retained-alert
and pending input eligibility are rechecked at commit. Only then are remaining keys
revoked, name claims released and a durable Kong cleanup operation recorded, which
the same request continues. Cleanup refuses to delete a Consumer with untracked
credentials. Local authoritative admission rejects a retired or revoked identity
while remote cleanup is pending.

## Supported executable profile

The only encoded profile is `grafana-provisioning-v1-kong-key-auth-v1`:

- Grafana legacy provisioning API: complete alert-rule inventory and individual
  rule GET/PUT, contact point GET/POST/PUT/DELETE, whole notification-policy tree
  GET/PUT, plus `/api/health` and `/api/org` verification.
- Kong database-backed Admin API: `/consumers/{id}` and deterministic credential
  `/consumers/{id}/key-auth/{credential_id}`, with `/key-auths/{credential_id}`
  ownership checking, credential inventory and root version read.
- An explicitly supplied private readiness proof service. This is an Appchi
  integration contract, **not an invented Kong Admin API endpoint**.

The profile follows the official [Grafana legacy provisioning API](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/alerting_provisioning/),
[Grafana webhook configuration](https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/),
[webhook settings schema](https://github.com/grafana/alerting/blob/main/receivers/webhook/v1/config.go)
and [Kong Key Auth](https://developer.konghq.com/plugins/key-auth/) /
[Kong Admin API](https://developer.konghq.com/api/gateway/admin-ee/3.16/) contracts.
These references establish API shape, not the installed company versions.
Grafana App Platform APIs and alternative Kong modes are not encoded profiles.

This legacy profile requires a platform-enforced **controlled writer**, covering
both the shared policy tree and affected rules. Direct competing UI/API writers
must be restricted or routed through that coordinator. The Appchi SQL lease does
not establish this prerequisite. Complete inventory, bounded uncertain-write
reconciliation, reserved resource namespaces, exact Unicode labels, secret fields,
resolved delivery and pool proof must be qualified in the supplied environment.

The company must first establish and verify the normative policy wrapper: managed
Appchi routes followed by the preserved catch-all company branch, including its
original defaults and complete ordered subtree. The executor rejects an absent
wrapper and never bootstraps it speculatively. It reads fresh state, preserves the
whole company branch and other operators' entries, updates only its own entries,
and verifies the resulting tree. Managed routes continue sibling evaluation,
use `group_by: ["..."]`, `group_wait: 0s`, `group_interval: 1m`, `repeat_interval: 1h`.
The receiver sends POST webhook notifications with resolved messages enabled,
Bearer authorization, no maximum-alert truncation and TLS verification enabled.

## Required binding and credentials

Load a UTF-8 JSON file with `OperatorBinding` (`operators/binding.py`). All URLs
must be explicit HTTPS URLs without embedded credentials, query or fragment.
No remote host, version, organization, pool or evidence identifier is guessed.
The following illustrates field names only; placeholders are not qualification:

```json
{
  "profile": "grafana-provisioning-v1-kong-key-auth-v1",
  "grafana_url": "https://grafana.example.invalid",
  "kong_url": "https://kong-admin.example.invalid",
  "probe_url": "https://readiness.example.invalid/operator-check",
  "webhook_url": "https://appchi-ingress.example.invalid/api/ingest/v2/grafana",
  "grafana_version": "SUPPLIED-EXACT-VERSION",
  "kong_version": "SUPPLIED-EXACT-VERSION",
  "organization": 1,
  "verified_evidence_id": "SUPPLIED-QUALIFICATION-RECORD",
  "controlled_writer_evidence_id": "SUPPLIED-ENFORCEMENT-RECORD",
  "wrapper_evidence_id": "SUPPLIED-PRESERVED-COMPANY-ROUTING-RECORD",
  "inventory_evidence_id": "SUPPLIED-COMPLETE-INVENTORY-RECORD",
  "namespace_evidence_id": "SUPPLIED-RESERVED-NAMESPACE-RECORD",
  "serving_pool_evidence_id": "SUPPLIED-SERVING-POOL-RECORD",
  "serving_members": ["SUPPLIED-MEMBER-ID"],
  "capabilities": [
    "secret_webhook_authorization", "resolved_notifications",
    "receiver_read_write_delete", "routing_read_write",
    "deterministic_resource_identity", "exact_unicode_labels",
    "kong_database_control_plane", "kong_credential_identity",
    "private_readiness_probe", "complete_rule_inventory",
    "wrapper_bootstrap_verified", "reserved_resource_namespace",
    "kong_explicit_credential_uuid"
  ],
  "max_rules": 2000,
  "max_response_bytes": 8388608
}
```

Optional `ca_file` selects the platform CA bundle; default is normal HTTPS
certificate verification. The rule inventory limit is explicit (1–10000); an
exceeded or unsupported inventory blocks work instead of accepting a subset.
Qualification must prove that the selected all-rules endpoint is complete under
the supplied account and organization, without silent pagination/truncation.

Credentials are separate from this nonsecret binding: Grafana service-account
Bearer token, Kong Admin `Kong-Admin-Token`, and a distinct proof-service Bearer
token. Supply them through the deployment secret mechanism. For each provisioning
request, `operators/synchronous.py` instantiates the adapter:

```python
from appchi.operators.executor import configured_executor, PlatformCredentials

adapter = configured_executor(
    settings.operator_binding, operator_db,
    PlatformCredentials(grafana_token, kong_token, probe_token),
    settings=settings,
)
# The request passes adapter to operators.worker.run_one(operator_db,
# envelope_cipher, adapter, tenant=..., operation_id=...) for its own
# operation only, then closes the adapter.
```

The factory provides `.manifest`, `.execute(Work)` and `.close()`. A missing or
unsupported binding or capability fails the provisioning request with 503;
unrelated APIs are unaffected.

The Product API mounts the binding and management credentials. It wires this
factory from `APPCHI_OPERATOR_BINDING` (the JSON file path),
`APPCHI_OPERATOR_DATABASE_URL`, `APPCHI_OPERATOR_GRAFANA_TOKEN`,
`APPCHI_OPERATOR_KONG_TOKEN` and `APPCHI_OPERATOR_PROBE_TOKEN`, alongside the
normal database/envelope-key settings. The operator database URL uses the
provisioning-role privileges through one shared connection per API process;
ordinary API SQL keeps its RLS connection. Never mount these credentials into
ingress or frontend. Supply secrets through the platform mechanism, without shell
tracing. There is no operator worker to start: the `operators` role is deferred
(REV-34) and `appchi.worker` rejects it.

## Private readiness proof contract and security

The supplied service must authenticate only the provisioning role, validate its
current operator/generation/credential authorization, and exercise authentication
on every serving Kong member without admitting an alert. It must never expose a
public candidate-key bypass, echo the key, log request bodies or persist plaintext.
It must verify the supplied key resolves to the exact Consumer and credential on
each member; reading the control-plane row alone is insufficient propagation proof.
The fleet membership and service implementation are platform qualification inputs.
This repository does not claim that such a company service is already deployed.

The executor POSTs JSON to the exact `probe_url`:

```json
{
  "operator_id": "OPERATOR-UUID", "consumer_id": "OPERATOR-UUID",
  "credential_id": "CREDENTIAL-UUID", "generation": "DECIMAL-STRING",
  "nonce": "FRESH-ATTEMPT-NONCE", "key": "SECRET-IN-TRANSIT-ONLY"
}
```

A successful response must match nonce/generation, contain exactly the configured
member IDs with no duplicates, confirm `admitted: false` and identify the exact
Consumer/credential for every member:

```json
{
  "nonce": "SAME-NONCE", "generation": "SAME-DECIMAL-STRING", "admitted": false,
  "members": [{"member_id": "CONFIGURED-MEMBER-ID", "ready": true,
               "consumer_id": "OPERATOR-UUID", "credential_id": "CREDENTIAL-UUID"}]
}
```

Missing members, stale IDs, authentication errors, timeouts and mismatches never
activate the candidate. HTTPS redirects are disabled for all three services.
Exceptions and durable job errors contain controlled codes, not remote bodies.
A timed-out write is reconciled by fresh reads of the same deterministic identity;
no timeout produces an optimistic success or a second random candidate.
Failed HTTP responses preserve only a sanitized retry delay. Delta-seconds and
HTTP-date `Retry-After` values can extend the durable backoff up to one hour;
malformed values are ignored, and shorter values never reduce normal backoff.

## Grafana ingress and evidence

`map_webhook` validates the 4 MiB/100-member envelope, rejects truncation, preserves
member order/original JSON bytes and records `appchi-grafana-v1` provenance with
native-equivalent mapped payloads. The HTTP ingress integration derives routing
from authenticated PostgreSQL operator ownership and retained old/new name claims;
labels never select authenticated tenancy. Grafana fingerprint/groupKey/startsAt
are not external delivery IDs. Invalid members retain indexed error outcomes.

Executed on Windows Python 3.13, 2026-09-23: **21 executor HTTP contract tests passed**
and **28 actual PostgreSQL repository/ledger tests passed** in a newly migrated,
disposable database that was dropped afterward. Tests cover uncertain secret writes,
exact routing and preservation, rename/delete cancellation, foreign credential
ownership, keyless cleanup, proof mismatch, version/profile gates, key reuse,
SQL generation/revision/lease fences, durable ownership/journals, and keyless
rename/rotation/deletion cancellation replacement including repeated revocation.
Failed restoration evidence retains the admission fence and prepared state. HTTP responses
are explicit fixtures; these are not live Grafana/Kong compatibility tests.
Ruff check passed for the changed implementation and test files.
Frontend typecheck and a focused Chromium test passed for creating a replacement
while revoked-key cleanup is pending; Copy remains unavailable until activation.

That run used the monorepo layout. The executor tests now live in this repository
and the repository/ledger tests in delivery; rerun them with:

```powershell
# From appchi-api, after poetry sync --all-extras:
poetry run python -m pytest tests/unit/test_operator_executor.py -q
# From appchi-delivery, with APPCHI_TEST_DATABASE_URL set to an isolated migrated test database:
.venv/Scripts/python.exe -m pytest tests/integration/test_operator_repository.py tests/integration/test_operator_executor_ledger.py -q
```

Before enabling the profile, execute the operator verification-plan scenarios
against the supplied private platforms, including controlled-writer enforcement,
full inventory, policy wrapper equivalence, Unicode label round trips, redacted
secret writes, uncertain late outcomes, credential propagation across the actual
serving pool, rotation overlap, revocation, rename restoration and deletion races.
No capacity, private version compatibility or production-readiness claim follows
from the local fixture and PostgreSQL results.
