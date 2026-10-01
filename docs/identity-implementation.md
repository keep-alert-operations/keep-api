# Identity implementation and private-environment checks

**2026-09-30 directory scope (REV-35):** the directory worker is nice-to-have and is not started by current launchers. Explicit trusted publication remains required for bootstrap and identity changes; automatic five-minute LDAP propagation is deferred. See [current worker scope](../spec-worker-scope.md#4-directory-synchronization-is-nice-to-have). Historical runtime evidence below does not describe a rollout of this later change.

This implementation follows [the identity contract](../spec-identity-configuration.md)
and [tenant access](../spec-tenant-access.md). Provider and directory qualification
must be executed on the user's private nonproduction network. No company host,
directory schema, credential, installed release or successful integration is implied.

## Implemented boundaries

- `backend/appchi/identity/oidc.py`: Authlib RS256 verification, exact issuer and
  audience/authorized-party checks, nonce, authentication time and explicit password
  evidence; confidential code flow with S256 PKCE; unknown-key refresh once;
  signed backchannel logout; identity-preserving refresh; bounded HTTPS clients.
- `session.py`: PostgreSQL one-use encrypted login transactions and browser
  bindings; hashed opaque session handles, encrypted provider tokens and CSRF
  material; strict origin/CSRF checks; idle/absolute/deployment-epoch enforcement;
  atomic refresh claims and generation fencing; local and backchannel revocation
  fences. Browser activity, not provider refresh or incoming SSE, extends idle time.
- `directory.py`: immutable source/object keys, bounded cycle-safe traversal,
  alternate-path deduplication, complete coverage evidence, semantic digests,
  independent negative facts and a reference last-known-data publication policy.
- `ldap.py`: read-only ldap3 TLS connection with supplied trust bundle; escaped
  literal filters; complete paged searches; configurable immutable ID, eligibility,
  group-member DN and primary-group attribute mappings. Referrals, size limits,
  missing page controls, repeated page cookies and unsupported ranged membership
  fail as incomplete, never as an empty team.
- `publication.py`: PostgreSQL publication under the authorization guard;
  generation-fenced object/edge proof and complete-root checkpoints; immediate
  known disablement/session revocation even in partial cycles; persisted graph
  closure, global privilege changes, tenant role changes and vacancy audit.
- `worker.py`: explicit sanitized LDAP configuration loader and one verification
  cycle covering global-admin team, grants, active users, assignees and pending
  verified-OIDC login requests. It also destroys expired session token material,
  expired login transactions and expired logout fences. The workload scheduler
  calls `run_cycle` every 60 seconds with jitter on failures.

The directory worker must allocate a generation with `allocate_generation(conn)`
before collecting evidence outside a database transaction, then call
`publish(conn, evidence, superadmin_group=PrincipalKey(source, immutable_id))`
inside one transaction. Refresh every tracked dependency at least every 60 seconds
and retry failures with small jitter. The reader's object/page allocation is a
bounded development default, not a qualified company-directory allocation.

`PublicationResult.changed_access` and `.revoked_principals` expose the identities
requiring domain-owned assignment reconciliation. Alert and incident workers must
perform that cleanup through their aggregate/coordinator contracts; this adapter
does not bypass domain tables. End-to-end assignment and SSE propagation evidence
must be included in the private-environment run.

## Required configuration

Supply through the approved secret/configuration mechanism:

| Setting | Required binding |
|---|---|
| `APPCHI_PUBLIC_ORIGIN` | Exact application HTTPS origin, no wildcard. |
| `APPCHI_OIDC_ISSUER` | Exact dedicated environment realm issuer URL. |
| `APPCHI_OIDC_CLIENT_ID` | Confidential client; default `appchi-web`. |
| `APPCHI_OIDC_CLIENT_SECRET` | Environment-specific secret, server-side only. |
| `APPCHI_OIDC_DIRECTORY_SOURCE` | Stable configured company directory source identifier. |
| `APPCHI_OIDC_DIRECTORY_ID_CLAIM` | Protected, read-only immutable directory ID claim. |
| `APPCHI_OIDC_DIRECTORY_SCOPE` | Scope supplying that protected claim. |
| `APPCHI_OIDC_REQUIRED_ACR` | Exact protected claim value for the configured password sign-in policy. |
| `APPCHI_OIDC_REQUIRED_AMR` | JSON array of required protected password methods; local Keycloak uses `["pwd"]`, without `otp`. |
| `APPCHI_OIDC_CA_FILE` | Optional approved private-CA PEM path; system trust otherwise. |
| `APPCHI_SUPERADMIN_GROUP` | Supplied immutable designated team identity; worker binds its source explicitly. |
| Database, wrapping key and deployment epoch | Shared configuration described in delivery instructions. |

Register exact `${APPCHI_PUBLIC_ORIGIN}/auth/callback`,
`${APPCHI_PUBLIC_ORIGIN}/signed-out` and
`${APPCHI_PUBLIC_ORIGIN}/auth/backchannel-logout` routes with Keycloak. Disable
wildcards, local-user claim spoofing, direct grants, offline access and unsupported
client flows. Require provider session IDs in backchannel notifications. Use the
realm/client authentication, rotation and synchronization settings in the normative document.

The LDAP adapter's `LDAPConfig` requires hostname, TLS port, read-only bind DN,
secret, CA file and `LDAPSchema`. Supply actual base DN, user/team filters,
immutable-ID attribute/encoding, label and DN membership attributes, explicit
eligibility values or disabled-bit mask, and primary-group semantics. Selecting
`primary_group_mode="none"` requires evidence that no primary-group path is omitted.
`attribute` mode maps a user's primary-group attribute to a group's corresponding
attribute. Schemas needing computed primary-group IDs or ranged membership need
a verified schema adapter extension before those teams can be considered complete.
DNs, usernames, emails and group labels never replace immutable grant keys.
For `load_directory_config(Path(...))`, the JSON configuration uses the
`LDAPConfig` field names with nested `schema` fields from `LDAPSchema`; replace
the password field with `password_env`, the name of a secret-injected environment
variable. Set `schema_qualified` only after verifying complete visibility and the
actual mapping. `run_cycle(database, config, PrincipalKey(config.source, group_id),
bootstrap_qualified=True)` may lift initial bootstrap only with that qualification
and a complete nonempty eligible team; ordinary cycles leave integrity gates intact.

A valid first-time OIDC callback queues its immutable identity for verification
and returns `503 directory_evidence_required` while that evidence is absent. The
user retries sign-in after the directory cycle completes. No LDAP username guess,
local test login or provider claim alone can create an authorized session.

## Consequential implementation choices

These are assistant-selected implementation details, not changes to product scope:

- Require explicit protected `acr` and `amr` mappings so the backend can reject
  authentication that lacks evidence of the configured password method. Configure and test the
  supplied Keycloak release's protocol mappers; no claim values are guessed.
- Discovery endpoints must be HTTPS under the configured realm origin/path.
  Redirect-following and environment proxy inheritance are disabled. Metadata and
  token responses are bounded at one MiB; token strings at 32 KiB. Network calls
  use a five-second default total request deadline and bounded connect/read waits.
- A transport-ambiguous rotating-token exchange marks the session's refresh state
  uncertain and does not retry the possibly consumed token. The local session
  remains usable until its ordinary deadlines or a known revocation; fresh SSO
  reconciles uncertainty. A refresh worker lost after claiming its token is treated
  as uncertain after 30 seconds. Definitive `invalid_grant` revokes immediately.
- Complete results arriving after newer covered observations cannot overwrite
  them. Negative facts are independently generation-fenced. An unchanged complete
  re-verification updates its checkpoint without incrementing semantic revision.
- Initial human-authorization bootstrap requires complete, nonempty eligible
  super-admin evidence plus an explicit configuration-qualification signal from
  the controlled worker/deployment command. It cannot lift a restore-integrity gate.

## Tests and private-network qualification

From the workspace root, after `uv sync --project backend --frozen --group dev`:

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/tests/unit/test_identity_directory.py backend/tests/unit/test_identity_ldap.py backend/tests/unit/test_identity_oidc.py -q
backend/.venv/Scripts/python.exe -m ruff check backend/appchi/identity backend/tests/unit/test_identity*.py
```

The adapter suite uses real Authlib RSA signatures and controlled HTTP/LDAP failure
doubles. It does not establish company Keycloak or LDAP compatibility. Authlib and
ldap3 currently emit upstream deprecation warnings; their selected interfaces are
locked by the repository dependencies and must be checked before upgrades.

The PostgreSQL tests require an isolated test cluster and a role allowed to create
and drop a uniquely named temporary database. They run all migrations and exercise
the real production auth router and SQL transactions; only provider responses are
controlled doubles. They do not modify shared company services.

Executed locally: 42 adapter tests passed; 8 real PostgreSQL auth/publication tests
passed in an automatically created and removed database; identity Ruff checks
passed. Windows `localhost` initially exceeded the three-second pool acquisition
deadline during IPv6 fallback; the successful local run used `127.0.0.1` with a
two-second connection deadline. No company Keycloak/LDAP compatibility run occurred.

```powershell
$env:APPCHI_IDENTITY_TEST_ADMIN_URL = '<isolated-test-cluster-admin-DSN>'
backend/.venv/Scripts/python.exe -m pytest backend/tests/unit/test_identity_sessions.py -q
```

On the private nonproduction deployment, record actual versions/configuration and
execute the full [identity acceptance list](../verification-plan.md#identity):

1. Fresh username/password login without OTP enrollment or challenge, SSO reuse, exact redirects, code/state/nonce
   replay rejection, same-origin CSRF, cookie properties and protected mapper rules.
2. Full direct/nested/cyclic/alternate-path and primary-group membership; disabled
   and recreated users; immutable rename behavior; unknown-user evidence denial.
3. Paged LDAP failure, inaccessible subtrees and directory visibility delay. Measure
   source change to open API/SSE revocation against the five-minute target.
4. Keycloak and LDAP independent outages, valid cached sessions without an identity
   age cutoff, new-user admission restrictions and verified recovery publication.
5. Concurrent tab refresh, rotation crash/ambiguity, signed logout replay and racing
   callbacks; no stale session survives verified disablement or deployment restore.
6. Last-local-admin vacancy/restoration, global group replacement/empty recovery,
   current role/assignment enforcement, product audit and protected recovery gates.

Keep `human_auth` gated until immutable mapping, password authentication and complete bootstrap evidence
are verified. A working local test suite does not qualify production identity,
directory propagation, recovery evidence or company-service availability.

## Assignment and audit cleanup

`identity/cleanup.py` provides `cleanup_assignment` for one resource and
`cleanup_assignments` for a bounded page (maximum 100, optional tenant and keyset
cursor). Recheck accepted effective edit access under the identity guard and
tenant coordinator before clearing the still-current assignee. Alternate direct,
nested-team or global-super-admin access preserves assignment. Verification age
and an unavailable refresh never independently establish loss. A replaced or
requalified assignee is preserved. Alert cleanup uses the maintenance reducer,
semantic revision and common projection/live publisher. Incident cleanup writes
immutable activity with `qualifying=False`. Neither resets inactivity. Activity
captures the former principal label and accepted identity/tenant proof. The
read-only `visible_assignee` helper immediately presents confirmed losses as
unassigned while persisted cleanup catches up; alert detail uses it. Hosts must
apply the helper to other authoritative product views and preserve sweep cursors.

Migration `0019_identity_cleanup.sql` adds explicit audit retention holds, durable
retirement attempts and minimal expiry fences. `hold_audit`/`release_audit_hold`
are trusted command/reference/recovery-owner interfaces, not user editing APIs.
`retire_audit` and `purge_audit_batch` use 365 elapsed days, recheck dependencies
after the external intent acknowledgment, and retain stable distinct intent,
final and cancel UUIDs. No network operation holds a SQL transaction. A failed
final acknowledgment leaves the audit payload physically present, a durable
retired job and a logical API fence; retry uses the same evidence UUID. Physical
deletion runs only after a verified final acknowledgment is persisted. Fences
retain event identity/time, scope and digest, not
actor labels or audit payload. Platform events use immutable Global solely as
their external evidence scope. The audit API includes explicitly protected expired
events and excludes fenced events, including stale restored copies.

Both `audit_retention` and `recovery` gates must be qualified before physical
deletion. The supplied independent store must support resource kind `audit`.
Restore must apply these independent expiry fences before exposing audit content.
Dependency owners must register explicit holds before publishing references.
Daily scheduling, bounded backlog completion within 24 hours and actual external
storage/restore qualification remain deployment work; missing protection fails
closed. Current grants, tenants, directory objects and command/revocation fences
are untouched by audit expiry.

Eight real PostgreSQL cleanup tests passed, covering alternate/cached access,
replacement rechecks, revisions and inactivity preservation, bounded scans,
elapsed expiry and holds, a hold racing external intent, final-ack retry, platform
scope, protection gates, protected-history visibility and stale-copy fencing.
These use controlled independent-store doubles and database-only identities.

## Directory selection

Mount `identity.selection.router` for tenant-admin company search at
`/api/tenants/{tenant_id}/permission-principals`, global-super-admin search at
`/api/admin/directory/principals`, the tenant-admin team `/members` preview and
editor-only `/api/tenants/{tenant_id}/assignees`. Search uses literal 2–100-code-point
terms, default 50/max 200 results, and current authorization before each page.
Assignee access filtering happens in SQL before ordering/limits, including nested
teams, direct grants and current global privilege. Assignment still revalidates
at command commit and never confers access.

Opaque 15-minute cursors bind session, tenant, query, order and deployment epoch.
Directory semantic revision, tenant revision and relevant team proof invalidate
changed rosters; freshness-only verification does not. Assignee cursors additionally
bind the current global-admin membership digest. Team previews expose the complete
accepted flattened **eligible-user** membership, deduplicated by immutable ID,
and fail unavailable without a complete tracked-root checkpoint. Cached searches
are explicitly incomplete company search, with degradation and last successful
verification metadata. Verification age alone never removes a cached choice.

For qualified live discovery, supply `app.state.directory_search` with
`ConfiguredDirectorySearch(config, qualified=True, max_seconds=..., max_matches=...,
max_pages=...)`. The `LDAPConfig` must have a qualified explicit schema and TLS
trust/secret binding. Search uses separate configured user/team filters, escaped
literal labels, read-only TLS, no referrals, required complete LDAP paging, and
explicit size/page/deadline bounds. The search budget is at most three seconds
between bounded one-second network operations and cannot exceed directory
allocation limits; deployed latency still needs measurement. Any partial result,
budget exhaustion or transport failure falls back to explicitly incomplete cached
results. A live continuation also binds the full matching-result digest and
requires restart if discovery or coverage changes.

Discovery does not create principals, publish accepted authorization or modify
LDAP. Unknown/changed matches and incomplete teams remain unselectable and enqueue
immutable verification requests awaiting explicit trusted publication under REV-35.
After complete manual publication, repeating the search makes eligible matches selectable.
Thus a live complete matching search and complete authorization evidence remain
distinct. API health/logs do not receive LDAP credentials or raw exceptions.

`frontend/src/components/directory-picker.tsx` exports `DirectoryPicker` and
`PermissionGrantEditor`. The latter edits an explicit bounded batch, preserves its
captured revision and uncertain command identity, and requires explicit review
before adopting a newer revision. Mount it with `key=tenantId`, current authorized
grant rows/revision, and an `onCommitted` callback that refreshes session/access
before reloading protected data. The picker clears rows on failed authorization
and aborts old-scope requests. Parent screens own integration, Global's immutable
policy and their unsaved-draft navigation guard.

Eight selection tests passed: seven real PostgreSQL API cases and one controlled
LDAP adapter case, including non-owner API-role discovery queue writes, current
role enforcement, literal wildcard characters, filtering before pagination,
outage cache behavior, semantic/freshness cursor distinctions, expiration/tamper,
complete-team requirements and no user creation during discovery. TypeScript and
Ruff checks passed. These do not qualify the company's live LDAP schema, service
allocation, nested-team coverage or normal-operation five-minute propagation.
