# keep-api

Product HTTP API, password sign-in and local sessions, ADAPI picker search and save on pick, scoped commands, operator provisioning and live/SSE updates.

See [system design](https://github.com/keep-alert-operations/keep-design), [workspace setup](https://github.com/keep-alert-operations/keep-delivery) and [source provenance](SOURCE.md).

## Development

Use Python 3.13, Poetry 2.3.1 and the committed `poetry.lock`. Configure Git authentication for the
private organization repositories before resolving internal dependencies.

```powershell
poetry check --lock
poetry sync --all-extras
poetry run ruff check src tests
poetry run pytest
poetry build --format wheel
```

Shared `keep` modules use namespace packaging; each module has exactly one owning
distribution. Dependencies resolve immutable Git revisions in Python dependency metadata and `poetry.lock`.
For coordinated local edits use the delivery workspace setup, which installs local
packages without changing release dependency pins.

## Execution

`poetry run keep-api` is the entrypoint. Supply the documented environment
bindings; package installation does not start services or migrate data.

For an isolated cluster's fixed Kong serving pool, the same image can run the
private HTTPS proof process with `python -m keep.operators.proof`. See the
[operator proof interface](docs/operator-proof.md) and
[configuration example](docs/operator-proof.example.json) for authentication,
TLS, read-only SQL fences, limits and required target-cluster qualification.
This is an operation-bound helper for the API's synchronous executor.

ServiceNow ticket panels (REV-65) read counts from the ticket counting service named
by the optional secret `KEEP_TICKET_COUNT_URL`, mounted only into this API. It must
be `https://` with a host (plain `http://` only for a loopback host in local
development) and may carry an access key in its query string; it is never logged or
returned. Without a usable address the panels show that ServiceNow isn't connected.
Each process caches answers for 30 s (failures for 10 s), sends one request per
team, state and detection at a time and runs at most 20 calls at once; see
`keep.configuration.ticket_counts`. The optional `KEEP_TICKET_COUNT_CA_FILE`
names a CA bundle that alone verifies the service's certificate. Startup sets the
`httpx` and `httpcore` loggers to WARNING so request addresses are never logged.

Grafana panels (REV-68) frame single Grafana panels from the Grafana instances
listed in the optional setting `KEEP_GRAFANA_PANEL_ORIGINS`, mounted into this API
(and the UI server). It is a comma-separated list of `https://` Grafana addresses,
each an origin with an optional base path for a Grafana served under a sub-path,
such as `https://grafana.example.com,https://tools.example.com/grafana`; plain
`http://` is accepted only for a loopback host in local development. It is not a
secret. Empty or unset turns Grafana panels off. Unusable entries, including Keep's
own address, are ignored with one startup warning each and never fail startup; see
`keep.configuration.grafana`. Saving a dashboard checks each new or changed Grafana
panel address against the list (422 `grafana_url_invalid`); an unchanged address
still saves after its Grafana is removed from the list. Tenant readers see the
allowed list at `GET /api/tenants/{tenant_id}/grafana-panels/status`; super admins
also see the ignored entries at `GET /api/admin/integrations/grafana-panels`.
