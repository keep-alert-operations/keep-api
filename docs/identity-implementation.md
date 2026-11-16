# Identity implementation and private-environment checks

**2026-11-15 sign-in and directory (REV-73):** Keep's own password sign-in (one LDAP bind against Active Directory) and the ADAPI directory replace the earlier identity provider; Keycloak, OIDC and Keep's LDAP directory reader were removed by REV-73. This document describes the current code. See [REV-73](https://github.com/keep-alert-operations/keep-design/blob/main/decisions/design-register.md#rev-73--keep-password-sign-in-and-adapi-directory-replace-keycloak-2026-11-15).

**2026-09-30 directory scope (REV-35):** automatic directory refresh is nice-to-have and is not started by current launchers. Bootstrap and identity changes come from explicit publications: the manual refresh command, sign-in and save on pick. The five-minute automatic propagation target is deferred. See [current worker scope](https://github.com/keep-alert-operations/keep-design/blob/main/specs/spec-worker-scope.md#4-directory-synchronization-is-nice-to-have).

This implementation follows [the identity contract](https://github.com/keep-alert-operations/keep-design/blob/main/specs/spec-identity-configuration.md)
and [tenant access](https://github.com/keep-alert-operations/keep-design/blob/main/specs/spec-tenant-access.md). Active Directory and ADAPI
qualification must be executed on the user's private nonproduction network. No company host,
directory response, credential, installed release or successful integration is implied.

## Implemented boundaries

The shared modules live in keep-domain's `keep.identity` package. This repository's
`src/keep/identity` adds the HTTP routes, picker search, its cache and the save-on-pick saver.

keep-domain:

- `login.py`: `LDAPBindConfig` and `check_password`. One read-only ldap3 simple bind,
  run in a worker thread, as `KEEP_LDAP_BIND_FORMAT` filled with the username, with the
  password sent as UTF-8 bytes, 2-second connect and receive timeouts and no referrals.
  LDAP WhoAmI must then name the typed username (`u:DOMAIN\name`) or equal the bind DN
  (`dn:…`). An empty password is refused before connecting. Rejecting LDAP results raise
  `SignInRejected`; anything else raises `SignInUnavailable`. Errors carry fixed reason
  codes, and ldap3 is told to strip credentials from anything it logs.
- `adapi.py`: `ADAPIConfig`, `ADAPIClient` (httpx with the `ClientId` header and an
  explicit per-call timeout from the caller's cap and the request budget), username
  normalization (lowercase samAccountName, 1–64 characters, no AD-forbidden characters,
  `@` or `\`), RFC 4515 escaping for `customFilter`, and `ADAPIDirectoryReader`:
  kind-hinted lookups, deletion only when both endpoints answer 200 with no rows,
  ambiguity failing closed, recursive group members and member display names in batches
  of `KEEP_ADAPI_LOOKUP_BATCH`. `verify_root`, `verify_roots` and `user_evidence` build
  the evidence that save on pick, the refresh and sign-in publish.
- `authentication.py`: the `__Host-keep_session` cookie, `authenticate` (stored handle
  hash, absolute deadline, deployment epoch, an eligible verified user, and CSRF and the
  exact Origin for mutations), the human-authorization gate and `safe_return_path`.
- `directory.py`: vendor-independent traversal with complete coverage evidence, a
  10,000-object cap per evidence and structured failure reasons. Failure never turns an
  incomplete roster into an empty one.
- `publication.py`: `allocate_generation`, `lock_identity`, `stored_matches`, `publish`
  and `publish_with_retry`. Generations are allocated before reading. Publication runs
  under the exclusive identity guard with set-based statements; an evidence is rejected
  only when a covered root or team has a newer generation, and confirmed disablement
  revokes that person's sessions immediately.
- `worker.py`: the manual refresh, `python -m keep.identity.worker --once [--bootstrap]`
  (also delivery's `python -m keep.worker directory --once`). It publishes one evidence
  for all user roots and one per team root, each with its own generation; a fenced
  publication retries once; it lists every failed root and exits non-zero if any failed.
- `cleanup.py`: assignment and audit cleanup, described below.

This repository:

- `session.py`: `POST /auth/login`, `GET /auth/session` and `POST /auth/logout`. Sign-in
  checks, before any bind, the human-authorization gate, the exact Origin, its own 4 KiB
  body limit and identity-only `Content-Encoding`, the username and a non-empty password.
  It then binds, reads the person's own ADAPI row (403 `account_not_in_directory` or
  `account_ambiguous` for zero or two rows), publishes a single-object evidence only when
  the stored row differs, revokes the session of any cookie the browser sent and creates a
  session whose absolute deadline is 24 hours after sign-in. At least 1 second of the
  request budget must remain before publishing; otherwise it answers 503
  `sign_in_unavailable`. Logs carry reason codes only, never the password or the typed
  username. Logout revokes the local session and returns no provider URL.
- `selection_config.py`: `ADAPISearch` and `configured_search`. A picker search asks
  `/users` and `/groups` with `samAccountName=*term*` and `customFilter=(displayName=*term*)`
  (escaped), with no security-group filter, and reports a 1,000-row answer as capped.
- `search_cache.py`: `SearchCache`, a best-effort Redis cache of raw search answers for
  `KEEP_ADAPI_SEARCH_CACHE_TTL_SECONDS` under a SHA-256 key of the kind and the normalized
  term. A Redis outage, timeout or corrupt value is a miss. It feeds picker listings only.
- `selection.py`: picker, member and assignee listings and save on pick (below).
- `saver.py`: `PickSaver`, the inline save and the per-process background saver.

`main.py` builds the search cache, the picker search and the saver in the application
lifespan. On shutdown it closes the saver (stopping ADAPI reads, releasing this process's
leases and joining its thread) before the database pool, and then the cache.

## Required configuration

Supply through the approved secret/configuration mechanism:

| Setting | Required binding |
|---|---|
| `KEEP_PUBLIC_ORIGIN` | Exact application HTTPS origin, no wildcard. Sign-in requires this exact Origin. |
| `KEEP_LDAP_HOST`, `KEEP_LDAP_PORT` | The LDAP server that checks passwords; the port defaults to 389. |
| `KEEP_LDAP_USE_TLS`, `KEEP_LDAP_CA_FILE` | Encryption, off by default (user decision for the private network). When on, the server certificate is validated, optionally against the CA file. |
| `KEEP_LDAP_BIND_FORMAT` | Bind name containing `{username}` exactly once, for example `{username}@corp.example`; locally `uid={username},ou=people,dc=keep,dc=local`. |
| `KEEP_ADAPI_URL` | ADAPI origin without credentials, query or fragment. |
| `KEEP_ADAPI_CLIENT_ID` | Secret `ClientId` header value. |
| `KEEP_ADAPI_LOOKUP_BATCH` | Member display names per lookup call; default 50 (1–200). |
| `KEEP_ADAPI_SEARCH_CACHE_TTL_SECONDS` | Picker search cache lifetime; default 7,200 (1–86,400). The cache needs `KEEP_REDIS_URL`. |
| `KEEP_SUPERADMIN_GROUP` | samAccountName of the global-super-admin AD group, read by the Product API and the refresh command. |
| `KEEP_DIRECTORY_BOOTSTRAP_QUALIFIED` | `true` (or `--bootstrap`) on the refresh that may open the initial bootstrap gate. |
| Database, wrapping key and deployment epoch | Shared configuration described in delivery instructions. |

Missing or invalid sign-in settings leave the API running: sign-in answers 503
`sign_in_unavailable` and logs the problem once without values. Without ADAPI settings,
pickers list Keep's saved principals only, labelled as cached, and save on pick answers
503 `directory_unavailable`.

The refresh run with the bootstrap flag may lift the initial human-authorization
bootstrap gate only with a complete, nonempty eligible super-admin group; ordinary runs
leave integrity gates intact, and no run can open a restore-integrity gate.

A first sign-in saves the person from their own ADAPI row in the same request, so no
refresh is needed before a new person can sign in. No local test login,
browser-supplied principal or successful bind alone creates an authorized session: the
session needs a stored, eligible, verified user principal.

## Consequential implementation choices

These are assistant-selected implementation details recorded in REV-73, not changes to product scope:

- AD resolves `name@domain` by an explicit userPrincipalName before
  `sAMAccountName@domain`, so the WhoAmI check stops a bind as one account from signing
  in as another. The domain part of `u:DOMAIN\name` is not checked.
- LDAP results 48, 49, 50 and 53 are 401 `authentication_rejected`; any other result,
  timeout or referral is 503. A wrongly shaped login body is 422 `invalid_fields`.
- A refused sign-in for a disabled account still commits that person's changed row, so
  their other sessions end. When the publication fence rejects the sign-in's evidence, the
  newer stored row decides.
- Complete results arriving after newer covered observations cannot overwrite them.
  Negative facts are independently generation-fenced. An unchanged complete
  re-verification updates its checkpoint without incrementing semantic revision.
- Initial human-authorization bootstrap requires complete, nonempty eligible
  super-admin evidence plus the explicit qualification signal from the controlled
  refresh command. It cannot lift a restore-integrity gate.

## Tests and private-network qualification

From `keep-api`, after `poetry check --lock` and `poetry sync --all-extras`:

```powershell
poetry run python -m pytest tests/unit/test_password_login.py -q
poetry run python -m ruff check src/keep/identity tests/unit/test_password_login.py
```

`test_password_login.py` drives `POST /auth/login` through the real HTTP middleware with
a fake ldap3 connection, a fake ADAPI client and a recording database double. The shared
modules are tested in keep-domain (`tests/unit/test_identity_login.py`,
`test_identity_adapi.py`, `test_identity_directory.py` and `test_identity_worker.py`).

Real PostgreSQL and service tests are in keep-delivery: `tests/unit/test_identity_sessions.py`
and `test_identity_selection.py`, and `tests/integration/test_password_login.py`
(the OpenLDAP container and the mock ADAPI), `test_save_on_pick.py` and
`test_adapi_publication.py`. They need `KEEP_IDENTITY_TEST_ADMIN_URL` set to an isolated
test cluster with a role allowed to create and drop a uniquely named temporary
database; the OpenLDAP tests also need Docker. They do not modify shared company
services. Results recorded earlier in this document covered the OIDC and LDAP-reader
adapters removed by REV-73 and are not evidence for this code; current results belong
in delivery's implementation status.

On the private nonproduction deployment, record actual versions/configuration and
execute the full [identity acceptance list](https://github.com/keep-alert-operations/keep-design/blob/main/verification/verification-plan.md#identity):

1. Fresh username/password sign-in without OTP enrollment or challenge; one real sign-in
   confirms the bind name format and the WhoAmI answer; wrong password, disabled,
   unknown and ambiguous accounts; exact Origin, CSRF, cookie properties and replacement
   of an old cookie's session.
2. One real call per ADAPI route confirms the response shapes the local mock copies;
   direct, nested and distribution-group membership; disabled and recreated users and
   username reuse.
3. ADAPI non-200 and timeout handling, the 1,000-row search cap and the picker search
   cache. Verify that an explicit `directory --once` publication of a disablement revokes
   open API/SSE access; the five-minute automatic propagation target is deferred with
   the directory worker (REV-35).
4. Independent LDAP and ADAPI outages, valid cached sessions without an identity age
   cutoff, sign-in 503 and verified recovery publication.
5. Save on pick inline and in the background (pending, failure and Try again) racing a
   refresh; no stale session survives verified disablement or deployment restore.
6. Last-local-admin vacancy/restoration, global group replacement/empty recovery,
   current role/assignment enforcement, product audit and protected recovery gates.

Keep `human_auth` gated until password authentication, the ADAPI mapping and complete
bootstrap evidence are verified. A working local test suite does not qualify production
identity, directory propagation, recovery evidence or company-service availability.

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
`/api/admin/directory/principals`, the tenant-admin team `/members` preview,
editor-only `/api/tenants/{tenant_id}/assignees` and save on pick at
`/api/tenants/{tenant_id}/permission-principals/resolve`. Search uses literal
2–100-code-point terms, default 50/max 200 results, and current authorization before
each page. Assignee access filtering happens in SQL before ordering/limits, including
nested teams, direct grants and current global privilege. Assignment still revalidates
at command commit and never confers access.

Principal search calls `app.state.directory_search` (ADAPI through the search cache)
after authorization and outside the read transaction, then merges each row's stored
state from PostgreSQL. A saved row shows what is stored; a row Keep has not saved
returns `id: null` and is not selectable. A search never creates a principal, queues a
save, publishes identity or grants authority. Listing metadata says whether the answer
came from the search cache (`cached`, `coverage`), whether it is complete, and sets
`type_more` when ADAPI hit its 1,000-row cap. Without ADAPI, or when it fails, the
listing falls back to Keep's saved principals, marked as cached; a failure also marks
it degraded. Members and assignees read PostgreSQL only. API health and logs never
receive the `ClientId`, ADAPI response text or raw exceptions.

Opaque 15-minute cursors bind session, tenant, query, order and deployment epoch.
Directory semantic revision, tenant revision and relevant team proof invalidate
changed rosters; freshness-only verification does not. A live search cursor also binds
a digest of the matching ADAPI rows, and assignee cursors bind the current global-admin
membership digest. Team previews expose the complete accepted flattened
**eligible-user** membership, deduplicated by principal, and fail unavailable without a
complete tracked-root checkpoint.

Save on pick: `POST …/permission-principals/resolve` with `{kind, username, retry}` is
the only route that saves a principal, for tenant admins and global super-admins. It
checks, in order: a pending row (failed without `retry: true` → 503 with its
`last_failure`; failed with `retry: true`, or without a live lease → handed over again,
202; leased → 202); then a stored, usable principal → 200 without reading ADAPI;
otherwise an inline save with a 7-second verifier deadline and at least 1 second left
before publishing → 200, or, when it does not fit, nothing published, a pending row, a
hand-over and 202 `{status: "pending"}`. A fence rejection retries once within the
budget, then 503 `directory_busy`. A name ADAPI does not know, that two rows match or
that is the other kind returns 422 with nothing saved. `GET …/resolve?kind=&username=`
polls PostgreSQL only: 200 saved, 202 pending (a pending row without a live lease is
handed over again), 503 failed with its `last_failure`, 404 when no save exists.

The background saver is one thread per API process with a queue of 20; it is not a
poller and runs only jobs handed to it. The hand-over claims a 120-second lease on the
`directory_verification_requests` row with a conditional update, only the winner queues
the job, and a full queue releases the claim. Each job runs under its own 80-second
budget, re-checks and extends its lease when it starts, holds no database connection
while it reads ADAPI and filters every row update on its `lease_owner`. Failures are
recorded as `directory_unavailable`, `directory_group_too_large`,
`directory_verification_deadline` or `directory_busy`.

REV-73 has the keep-frontend directory picker save an unsaved row through `resolve`
when it is picked, show "Saving from the directory…" while a save is pending, poll
3 seconds after each response and offer Try again (`retry: true`) after a 503. Grants
still accept only saved principals.
