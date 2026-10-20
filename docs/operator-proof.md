# Private operator serving-pool proof

The API image provides `python -m appchi.operators.proof` as a separate, internal
HTTPS process for the synchronous operator executor. It has no background
provisioning loop, retry scheduler, alert-admission route, migration runner or key
decryption capability. Deployment composition and qualification belong to
`appchi-delivery`; this document defines the executable interface.

## Configuration and startup

Mount the [configuration example](operator-proof.example.json) and the same
`OperatorBinding` JSON used by the Product API. Replace the example node identity
with the observed `kong.node.get_id()` value from the qualified member. The member
list must exactly match `OperatorBinding.serving_members`; duplicates, empty lists,
HTTP URLs, URL credentials/query strings/fragments, shared origins and distinct
origins for the two routes of one member are rejected.

| Environment | Required value |
| --- | --- |
| `APPCHI_PROOF_CONFIG_FILE` | Path to the JSON configuration below. |
| `APPCHI_OPERATOR_BINDING` | Path to the API's exact, qualified `OperatorBinding` JSON. |
| `APPCHI_PROOF_DATABASE_URL` | Secret PostgreSQL DSN for the dedicated proof login. |
| `APPCHI_DEPLOYMENT_EPOCH` | Same nonempty deployment epoch as the API. |
| `APPCHI_PROOF_TOKEN_FILE` | Mounted secret text file: same bearer token as the API executor's probe credential. |
| `APPCHI_PROOF_GATEWAY_TOKEN_FILE` | Mounted secret text file: shared private probe token configured on both Kong proof routes. |
| `APPCHI_PROOF_CERT_FILE` | Mounted PEM server certificate, including its chain, for the helper's internal Service DNS. |
| `APPCHI_PROOF_KEY_FILE` | Mounted PEM server private key. |
| `APPCHI_BIND_HOST` | Optional listener address; default `0.0.0.0`. |
| `APPCHI_BIND_PORT` | Optional HTTPS port; default `8443`. |

Both token files contain 32–512 ASCII characters without whitespace, apart from an
optional surrounding newline. Do not pass tokens or keys as command-line arguments.
The helper does not need API cookie secrets, operator encryption keys, Grafana
credentials or Kafka access. Never mount those secrets into this process.

The config's `ca_file` contains trusted CA roots for the direct member HTTPS
endpoints. Each member certificate must cover its direct DNS name. The API's
binding CA bundle must trust the helper's certificate. Verification is mandatory;
there is no insecure TLS switch. Environment proxy configuration is ignored for
outbound member calls, and redirects are rejected.

```sh
python -m appchi.operators.proof
```

The server provides `GET /readyz` and authenticated `POST /operator-check`; there
is no public route or generated API documentation. Before application startup
completes, the helper establishes one read-only database-pool connection with a
bounded 10-second startup wait off the event loop. Failure closes the client and
pool and reports a fixed, sanitized startup error. Readiness confirms a loaded
configuration, that initial connection, and a responsive process. It does not
continually recheck database availability, current policy agreement, complete
serving-pool coverage or successful provisioning.
Only an operation-bound `/operator-check` result supplies that evidence.

## Fixed pool and gateway routes

This initial helper supports an explicitly qualified, fixed pool of 1–16 members.
Every `policy_url` and `auth_url` must target its member directly. A load-balanced
Service URL cannot establish complete pool coverage. The isolated OpenShift
example uses one StatefulSet member at
`https://appchi-kong-0.appchi-kong-members:8443` and these existing plugin routes:

| Route | Qualified configuration and behavior |
| --- | --- |
| `/__appchi/operator-check` | `appchi-policy` with `probe=true` and the private probe token; returns current policy, node identity and caller nonce. |
| `/__appchi/operator-auth-check` | Real KeyAuth followed by `appchi-policy` with `probe_active=true` and the same private probe token; allowed credentials return policy/member evidence, inactive credentials return 401. |

Both routes must terminate in the plugin. Neither may forward a request to alert
admission. They need the same KeyAuth and policy behavior as the qualified workload
route, with plugin version `1.0.0`. The parent deployment supplies their routes;
the helper does not create or change Kong resources. The active probe sends `{}`,
never an alert envelope. A successful proof requires explicit `admitted:false` on
policy and successful authentication responses.

Qualification must demonstrate these direct endpoints correspond to **all**
members that serve the workload route. Matching configured member IDs cannot
discover an unadvertised serving node. Do not autoscale or change routing behind
this fixed binding. A restart with a new node ID, replacement, scale operation or
topology change requires re-observation, full pool requalification and coordinated
updates to the helper config, API binding and their evidence IDs before resuming
operator operations. Unknown or duplicated actual node identities fail closed.

## Operation-bound checks

The request is the existing executor protocol: operator/consumer/credential UUIDs,
operator generation, policy generation, fresh nonce, exact boolean
`expected_allowed`, and the selected raw `key` when available. Authentication uses
one exact `Authorization: Bearer …` header. The Product API invokes it during a
live operator attempt; a made-up operation cannot produce a proof.

Before and after contacting every member, the helper opens a short **read-only**
PostgreSQL transaction and checks:

1. The restore advisory fence, restore status and deployment epoch. As in the
   normal runtime guard, a fresh database's NULL epoch is permitted; a non-NULL
   epoch must match `APPCHI_DEPLOYMENT_EPOCH`. A transition from NULL to an epoch
   during a proof invalidates the response. No manual epoch initialization is used.
2. The current operator generation/revision, unfinished running operation, live
   operation lease, matching live global routing lease, and recorded executor
   binding digest in both operation progress and remote bindings.
3. The selected SQL credential state and expiry, and the exact canonical policy
   document/generation. Its SHA-256 digest, tenant, credential, state, expiry,
   routing names and disposition must match every member's current policy reply.
4. When a raw key is supplied, its SHA-256 verifier must match SQL **before** a
   KeyAuth request. A wrong key's 401 cannot stand in for prepared-key denial.
5. The same operation identity, lease token, operator revision, policy digest,
   deployment authority and credential disposition still hold after remote calls.

The role contract is a dedicated `appchi_proof_login` with `INHERIT` membership in
the existing `appchi_worker` role so existing worker RLS policies permit the
required reads. Configure `default_transaction_read_only=on` on the login. The
helper independently sets that connection option and starts each snapshot as
`REPEATABLE READ READ ONLY`; it never assumes a migration/superuser identity and
does not run migrations on startup. The inherited role has broader grants than
this helper uses; the read-only session/transaction mode is an execution guard,
not a new database role whose SQL grants are read-only. Provisioning the identity
and grants belongs to the deployment's database bootstrap, using the dedicated
migration/administration identity before the helper starts.

The existing executor supplies its selected candidate/current key. Allowed keys
must authenticate successfully with matching member evidence; prepared/inactive
keys must receive 401. Old keys during rotation and revoked/deleted keys can have
`key:null`, because their raw secrets are not available. For those requests the
helper verifies current policy disposition on every node and reports
`authentication_checked:false`; it does not claim a KeyAuth request was made.
This follows the executor's per-credential protocol, which separately probes the
selected credential through KeyAuth. No ciphertext is read or decrypted.

## Bounds and failure behavior

| Bound | Default / hard limit |
| --- | --- |
| Request body | 4,096 bytes, 250 ms to read. |
| Complete proof | `deadline_seconds=1.5`, configurable 0.2–1.5 seconds, including both SQL snapshots. |
| Individual member HTTP operation | At most 500 ms and the remaining overall deadline. |
| Member response | `max_response_bytes=8192`, configurable 1,024–16,384 bytes; compressed responses rejected. |
| Final response | At most 32,768 encoded bytes. |
| Concurrent proofs | `max_inflight=2`, configurable 1–4, with at most 50 ms waiting. |
| Server concurrent requests | 16; idle HTTP keepalive 2 seconds. |
| SQL connections | 1 warmed before startup, at most 2; pool checkout 200 ms; connect timeout 2 seconds; initial pool wait 10 seconds. |
| SQL statement / lock | 250 ms / 100 ms. |
| SQL policy read | At most 65,536 encoded document bytes and 1,000 selected/active credential rows; otherwise reject. |

SQL transactions are released before network calls. An expired asynchronous
deadline cancels member calls and returns no proof. An already running synchronous
SQL snapshot may finish its bounded database calls after request cancellation;
the connection pool still limits it to two connections. It cannot turn a timed-out
request into success or change SQL data. No request is retried automatically.
The initial connection is warmed before readiness, while later connection loss or
an exhausted pool can still fail checkout. Connection establishment may continue
in the pool, but a failed operator request needs an explicit retry of its recorded
operation. Qualify cold startup and reconnection in the actual cluster; readiness
is not an instruction to relax these deadlines.

Unauthorized callers receive 401; invalid request bodies receive 422; stale SQL
authority receives 409; unavailable/malformed members, capacity limits, restore
fences and deadlines receive 503. Errors contain a small fixed code, never
validation input, remote response bodies, exception text, raw operator keys or
tokens. Successful replies whitelist public proof fields. Access logging is
disabled, request bodies must not be captured by infrastructure logs, and the
endpoint should be reachable only from the Product API. Allow outbound access
only to the direct Kong HTTPS members and PostgreSQL (plus cluster DNS).

## Verification and remaining qualification

```sh
python -m pytest tests/unit/test_operator_proof.py tests/unit/test_operator_executor.py -q
python -m ruff check src tests
```

`tests/integration/test_operator_proof_postgres.py` creates and drops a uniquely
named database and login on an **isolated disposable** PostgreSQL cluster when
`APPCHI_PROOF_TEST_POSTGRES_ADMIN_DSN` is set. It uses the real migration chain,
worker RLS inheritance and read-only connection pool, checks restore/lease/policy
fences, and changes SQL authority during a mocked member call. Without that
binding it skips. Keep its admin DSN outside logs and version control.
Use the coordinated workspace environment with `appchi-migrations` installed for
this optional suite; the API runtime itself does not depend on that package.
The fixture prewarms its private pool with a bounded 15-second acquisition and
establishes its mutation writer before the HTTP check. These checks establish SQL
fencing behavior, not cold-connection or full-gateway latency qualification.

```sh
python -m pytest tests/integration/test_operator_proof_postgres.py -q
```

Unit HTTP fixtures and real PostgreSQL checks do not qualify the private Kong
deployment. In the target cluster, verify certificate trust/hostname rejection,
each real member ID, KeyAuth allow and prepared denial, revoked policy denial,
stale policy, missing member, replacement/duplicate member, clock distrust,
lease/restore changes, timeout and outage behavior, plus no Kafka admission from
either proof route. Run normal synchronous create/activate/rotate/delete flows
with the actual qualified binding. Until those checks pass, serving-pool proof
and operator lifecycle readiness remain unqualified.
