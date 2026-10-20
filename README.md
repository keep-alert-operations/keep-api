# appchi-api

Product HTTP API, OIDC sessions, scoped commands, operator provisioning and live/SSE updates.

See [system design](https://github.com/appchi-alert-operations/appchi-design), [workspace setup](https://github.com/appchi-alert-operations/appchi-delivery) and [source provenance](SOURCE.md).

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

Shared `appchi` modules use namespace packaging; each module has exactly one owning
distribution. Dependencies resolve immutable Git revisions in Python dependency metadata and `poetry.lock`.
For coordinated local edits use the delivery workspace setup, which installs local
packages without changing release dependency pins.

## Execution

`poetry run appchi-api` is the entrypoint. Supply the documented environment
bindings; package installation does not start services or migrate data.

For an isolated cluster's fixed Kong serving pool, the same image can run the
private HTTPS proof process with `python -m appchi.operators.proof`. See the
[operator proof interface](docs/operator-proof.md) and
[configuration example](docs/operator-proof.example.json) for authentication,
TLS, read-only SQL fences, limits and required target-cluster qualification.
This is an operation-bound helper for the API's synchronous executor.
