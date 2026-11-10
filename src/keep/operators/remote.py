"""Capability-bound HTTP attempts. No company URL or version is guessed here."""

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass, field
import re
from typing import Callable, Literal
from urllib.parse import quote, urlsplit

import httpx

from keep.shared.errors import AppError, unavailable

REQUIRED_CAPABILITIES = frozenset(
    (
        "secret_webhook_authorization",
        "resolved_notifications",
        "receiver_read_write_delete",
        "routing_read_write",
        "deterministic_resource_identity",
        "exact_unicode_labels",
        "kong_database_control_plane",
        "kong_credential_identity",
        "private_readiness_probe",
    )
)


@dataclass(frozen=True)
class Endpoint:
    read_path: str
    write_path: str
    write_method: Literal["POST", "PUT", "PATCH", "DELETE"]
    version_header: str | None = None
    precondition_header: str | None = None


@dataclass(frozen=True)
class CapabilityManifest:
    profile_id: str
    grafana_version: str
    kong_version: str
    organization: str
    verified_evidence_id: str
    capabilities: frozenset[str]
    safe_mode: Literal["cas", "controlled_writer"]
    controlled_writer_evidence_id: str | None
    endpoints: dict[str, Endpoint]

    def validate(self):
        if not all(
            (
                self.profile_id,
                self.grafana_version,
                self.kong_version,
                self.organization,
                self.verified_evidence_id,
            )
        ):
            raise unavailable("operator_capabilities_unverified")
        if not REQUIRED_CAPABILITIES <= self.capabilities:
            raise unavailable("operator_capability_missing")
        if self.safe_mode not in {"cas", "controlled_writer"}:
            raise unavailable("safe_remote_writer_required")
        if self.safe_mode == "controlled_writer" and not self.controlled_writer_evidence_id:
            raise unavailable("controlled_writer_unverified")


@dataclass(frozen=True)
class RemoteObservation:
    body: dict = field(repr=False)
    version: str | None


class RemoteAdapter:
    """Use a separately configured authenticated/TLS-verifying HTTP client.

    The manifest is deployment evidence, not proof fabricated by this class.
    A missing safe concurrency mode blocks writes. Attempts never automatically
    retry a timeout, because the remote outcome may already have committed.
    """

    def __init__(self, client: httpx.Client, base_url: str, manifest: CapabilityManifest):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "An explicit HTTPS management base URL without embedded credentials is required"
            )
        manifest.validate()
        self.client, self.base_url, self.manifest = client, base_url.rstrip("/"), manifest

    def _url(self, path: str, bindings: dict[str, str]) -> str:
        if (
            not path.startswith("/")
            or path.startswith("//")
            or ".." in path
            or "?" in path
            or "#" in path
        ):
            raise unavailable("unsafe_adapter_endpoint")
        if any(
            not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", value)
            or value in {".", ".."}
            for value in bindings.values()
        ):
            raise unavailable("unsafe_adapter_binding")
        try:
            expanded = path.format_map(
                {key: quote(value, safe="") for key, value in bindings.items()}
            )
        except (KeyError, ValueError) as exc:
            raise unavailable("adapter_endpoint_binding_missing") from exc
        return self.base_url + expanded

    def _request(self, method: str, url: str, **kwargs):
        try:
            response = self.client.request(
                method, url, timeout=30, follow_redirects=False, **kwargs
            )
        except httpx.HTTPError as exc:
            code = "remote_outcome_uncertain" if method != "GET" else "remote_unavailable"
            raise unavailable(code) from exc
        if response.status_code in {401, 403}:
            raise AppError(
                "remote_needs_attention",
                "Remote management authorization requires platform repair",
                503,
            )
        if response.status_code in {409, 412}:
            raise AppError(
                "remote_version_conflict",
                "Remote configuration changed; reconcile fresh state",
                409,
            )
        if not 200 <= response.status_code < 300:
            raise unavailable("remote_unavailable")
        return response

    def read(self, operation: str, bindings: dict[str, str]) -> RemoteObservation:
        endpoint = self.manifest.endpoints.get(operation)
        if endpoint is None:
            raise unavailable("adapter_operation_unsupported")
        if endpoint.write_method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise unavailable("adapter_method_unsupported")
        response = self._request("GET", self._url(endpoint.read_path, bindings))
        try:
            body = response.json()
            if not isinstance(body, dict):
                raise ValueError("object required")
        except ValueError as exc:
            raise unavailable("remote_schema_unsupported") from exc
        return RemoteObservation(
            body, response.headers.get(endpoint.version_header) if endpoint.version_header else None
        )

    def update(
        self,
        operation: str,
        bindings: dict[str, str],
        *,
        coordinator: AbstractContextManager,
        ownership: Callable[[dict], bool],
        merge: Callable[[dict], dict],
        matches: Callable[[dict, dict], bool],
    ) -> RemoteObservation:
        self.manifest.validate()
        endpoint = self.manifest.endpoints.get(operation)
        if endpoint is None:
            raise unavailable("adapter_operation_unsupported")
        with coordinator:
            observed = self.read(operation, bindings)
            if not ownership(observed.body):
                raise AppError(
                    "remote_ownership_conflict",
                    "Remote resource is not owned by this operation",
                    409,
                )
            desired = merge(deepcopy(observed.body))
            headers = {}
            if self.manifest.safe_mode == "cas":
                if not endpoint.precondition_header or not observed.version:
                    raise unavailable("remote_version_precondition_missing")
                headers[endpoint.precondition_header] = observed.version
            # Controlled-writer mode is allowed only with independently supplied
            # enforcement evidence; a local coordinator alone is insufficient.
            self._request(
                endpoint.write_method,
                self._url(endpoint.write_path, bindings),
                json=desired,
                headers=headers,
            )
            actual = self.read(operation, bindings)
            if not ownership(actual.body) or not matches(desired, actual.body):
                raise unavailable("remote_verification_failed")
            return actual
