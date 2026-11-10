"""API-independent owned policy intent; version-specific encoding is external."""

from copy import deepcopy
from dataclasses import dataclass
import unicodedata
from uuid import UUID

from keep.shared.errors import AppError, unavailable


def normalized_name(value: str) -> tuple[str, str]:
    if unicodedata.unidata_version != "15.1.0":
        raise unavailable("operator_name_profile_unavailable")
    if not isinstance(value, str):
        raise AppError("invalid_operator_name", "Operator name must be a string")
    name = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(name) <= 128 or any(
        unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in name
    ):
        raise AppError(
            "invalid_operator_name", "Operator names require 1–128 allowed Unicode characters"
        )
    return name, unicodedata.normalize("NFC", name.casefold())


def resource_identity(operator_id: str) -> dict:
    parsed = UUID(operator_id)
    if str(parsed) != operator_id:
        raise AppError("invalid_operator_id", "Operator ID must be a canonical UUID")
    return {
        "receiver": "vena-operator-" + operator_id,
        "uid": "vena-" + parsed.hex,
        "kong_custom_id": operator_id,
        "kong_username": "vena-operator-" + operator_id,
    }


@dataclass(frozen=True)
class ManagedRoute:
    operator_id: str
    name: str

    def intent(self) -> dict:
        return {
            "receiver": resource_identity(self.operator_id)["receiver"],
            "matcher": {"name": "Keep - " + self.name, "operator": "=", "value": "true"},
            "continue": True,
            "group_by": ["..."],
            "group_wait": "0s",
            "group_interval": "1m",
            "repeat_interval": "1h",
        }


def routing_intent(
    root_defaults: dict, company_branch: dict, routes: tuple[ManagedRoute, ...]
) -> dict:
    """Return a logical intent, NOT an assumed installed Grafana API schema.

    root_defaults/company_branch come from the verified bootstrap wrapper's
    fresh state. The final company branch includes its old defaults and entire
    ordered child tree, so existing fallback delivery is not lost.
    """
    seen = set()
    managed = []
    for route in sorted(routes, key=lambda value: (value.operator_id, value.name)):
        key = (route.operator_id, route.name)
        if key in seen:
            raise AppError("duplicate_managed_route", "Duplicate owned routing entry", 409)
        seen.add(key)
        managed.append(route.intent())
    return {
        "root_defaults": deepcopy(root_defaults),
        "children": [*managed, {"company_branch": deepcopy(company_branch)}],
    }


def migrate_rule_labels(rule: dict, old_name: str, new_name: str | None) -> dict:
    """Change only the operator's routing-label key, preserving arbitrary rule data."""
    result = deepcopy(rule)
    labels = result.get("labels")
    if not isinstance(labels, dict):
        raise AppError(
            "unsupported_rule_schema", "Selected profile must supply a label-map rule view"
        )
    old_key = "Keep - " + old_name
    if old_key not in labels:
        return result
    if new_name is not None:
        new_key = "Keep - " + new_name
        if new_key == old_key:
            return result
        if new_key in labels and labels[new_key] != labels[old_key]:
            raise AppError(
                "routing_label_conflict", "Destination routing label has a conflicting value", 409
            )
        labels[new_key] = labels[old_key]
    del labels[old_key]
    return result
