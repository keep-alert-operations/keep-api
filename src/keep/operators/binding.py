"""Explicitly qualified legacy API binding; credentials are supplied separately."""

from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from keep.models import StrictModel
from keep.operators.remote import CapabilityManifest, REQUIRED_CAPABILITIES

EXTRA_CAPABILITIES = frozenset(
    {
        "complete_rule_inventory",
        "wrapper_bootstrap_verified",
        "reserved_resource_namespace",
        "kong_explicit_credential_uuid",
        "keep_policy_v1",
        "monotonic_policy_generation",
        "serving_pool_allow_and_deny_proof",
    }
)


class OperatorBinding(StrictModel):
    profile: Literal["grafana-provisioning-v1-kong-keep-policy-v1"]
    grafana_url: str
    kong_url: str
    probe_url: str
    webhook_url: str
    grafana_version: str = Field(min_length=1, max_length=128)
    kong_version: str = Field(min_length=1, max_length=128)
    organization: int = Field(ge=1)
    verified_evidence_id: str = Field(min_length=1, max_length=512)
    controlled_writer_evidence_id: str = Field(min_length=1, max_length=512)
    wrapper_evidence_id: str = Field(min_length=1, max_length=512)
    inventory_evidence_id: str = Field(min_length=1, max_length=512)
    namespace_evidence_id: str = Field(min_length=1, max_length=512)
    serving_pool_evidence_id: str = Field(min_length=1, max_length=512)
    serving_members: list[str] = Field(min_length=1, max_length=100)
    capabilities: list[str]
    ca_file: str | None = None
    max_rules: int = Field(default=2000, ge=1, le=10000)
    max_response_bytes: int = Field(default=8388608, ge=1024, le=33554432)

    @field_validator("grafana_url", "kong_url", "probe_url", "webhook_url")
    @classmethod
    def https(cls, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or ".." in parsed.path
            or "\\" in value
        ):
            raise ValueError("Explicit HTTPS URL without credentials/query/fragment required")
        return value.rstrip("/")

    @field_validator("capabilities")
    @classmethod
    def qualified(cls, value):
        if not REQUIRED_CAPABILITIES | EXTRA_CAPABILITIES <= set(value):
            raise ValueError("The complete verified profile capability set is required")
        return value

    @field_validator("serving_members")
    @classmethod
    def members(cls, value):
        if len(set(value)) != len(value) or any(not 1 <= len(v) <= 128 for v in value):
            raise ValueError("Distinct explicit serving member IDs required")
        return value

    def manifest(self):
        return CapabilityManifest(
            self.profile,
            self.grafana_version,
            self.kong_version,
            str(self.organization),
            self.verified_evidence_id,
            frozenset(self.capabilities),
            "controlled_writer",
            self.controlled_writer_evidence_id,
            {},
        )

    def digest(self):
        return sha256(self.model_dump_json().encode()).hexdigest()
