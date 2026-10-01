from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from appchi.alerts.lifecycle import apply_command, apply_source
from appchi.alerts.presentation import display_status, present_alert, present_command_result
from appchi.cel import CELValidationError, compile_expression
from appchi.cel.routes import describe_profile
from appchi.models import AlertCommand, BulkCommand
from appchi.search.projection import index_mapping
from appchi.search.reader import sort_spec
from appchi.shared.errors import AppError

NOW = datetime(2026, 9, 27, tzinfo=UTC)


@pytest.mark.parametrize(
    "status,assigned,expected",
    [
        ("firing", False, "firing"),
        ("firing", True, "acknowledged"),
        ("resolved", False, "resolved"),
        ("resolved", True, "resolved"),
    ],
)
@pytest.mark.parametrize("legacy_ack", [False, True])
def test_current_status_and_filters_depend_only_on_lifecycle_and_assignment(
    status, assigned, expected, legacy_ack
):
    row = {
        "status": status,
        "assignee_id": str(uuid4()) if assigned else None,
        "acknowledged": legacy_ack,
    }
    assert display_status(row) == expected
    current = present_alert(row)
    assert current["display_status"] == expected and "acknowledged" not in current
    for value in ("firing", "acknowledged", "resolved"):
        expr = compile_expression(f'alert.display_status == "{value}"')
        assert expr.evaluate(row, NOW) is (value == expected)
        # This field must work against the existing physical mapping.
        assert "display_status" not in str(expr.to_elasticsearch(NOW))
    assert compile_expression('alert.display_status in ["firing", "acknowledged"]').evaluate(
        row, NOW
    ) is (status == "firing")
    assert compile_expression('alert.display_status != "resolved"').evaluate(row, NOW) is (
        status == "firing"
    )
    assert compile_expression("has(alert.display_status)").evaluate(row, NOW)


def test_assignment_resolution_and_next_occurrence(v1):
    actor, other = uuid4(), uuid4()
    item = dict(
        payload=v1,
        received_at=NOW,
        version="v1",
        tenant_id=uuid4(),
        id=uuid4(),
        key_field="ownership",
    )
    row, _ = apply_source(None, item)
    assert display_status(row) == "firing"
    assigned, changed = apply_command(row, "set_assignee", str(actor), actor, NOW)
    assert changed and display_status(assigned) == "acknowledged"
    assert assigned["status"] == "firing" and assigned["occurrence_id"] == row["occurrence_id"]
    assert apply_command(assigned, "set_assignee", str(actor), actor, NOW) == (assigned, False)
    reassigned, _ = apply_command(assigned, "set_assignee", str(other), actor, NOW)
    assert reassigned["assignee_id"] == other and display_status(reassigned) == "acknowledged"
    unassigned, _ = apply_command(reassigned, "set_assignee", None, actor, NOW)
    assert display_status(unassigned) == "firing"
    resolved, _ = apply_command(reassigned, "set_status", "resolved", actor, NOW)
    assert display_status(resolved) == "resolved" and resolved["assignee_id"] == other
    repeated, _ = apply_source(reassigned, {**item, "received_at": NOW + timedelta(seconds=1)})
    assert (
        display_status(repeated) == "acknowledged"
        and repeated["occurrence_number"] == row["occurrence_number"]
    )
    reopened, _ = apply_source(resolved, {**item, "received_at": NOW + timedelta(seconds=2)})
    assert display_status(reopened) == "firing" and reopened["assignee_id"] is None
    assert reopened["occurrence_number"] == row["occurrence_number"] + 1
    manually_reopened, _ = apply_command(resolved, "set_status", "firing", actor, NOW)
    assert (
        display_status(manually_reopened) == "firing" and manually_reopened["assignee_id"] is None
    )


def test_retired_commands_are_rejected_and_history_is_not_rewritten():
    command = dict(
        command_id=str(uuid4()), expected_revision="1", kind="set_acknowledged", value=True
    )
    with pytest.raises(ValidationError):
        AlertCommand(**command)
    with pytest.raises(ValidationError):
        BulkCommand(
            **{k: v for k, v in command.items() if k != "expected_revision"},
            items=[dict(alert_id=str(uuid4()), expected_revision="1")],
        )
    with pytest.raises(ValidationError):
        AlertCommand(**{**command, "kind": "set_status", "value": "acknowledged"})
    stored = {
        "data": {
            "status": "firing",
            "assignee_id": str(uuid4()),
            "acknowledged": False,
            "acknowledged_by": None,
        },
        "meta": {"revision": "2"},
    }
    original = deepcopy(stored)
    result = present_command_result(stored)
    assert result["data"]["display_status"] == "acknowledged"
    assert stored == original and "acknowledged" not in result["data"]
    assert present_command_result({**stored, "data": [stored["data"]]})["data"] == [result["data"]]


def test_virtual_catalog_preserves_legacy_execution_and_mapping():
    names = {field.name for field in describe_profile("feed").fields}
    assert "display_status" in names
    assert not names.intersection({"acknowledged", "acknowledged_by", "acknowledged_at"})
    assert "display_status" not in index_mapping()["properties"]
    assert "acknowledged" in index_mapping()["properties"]
    assert compile_expression("alert.acknowledged", rule=True).evaluate({"acknowledged": True}, NOW)
    with pytest.raises(CELValidationError):
        compile_expression('alert.display_status == "acknowledged"', rule=True)
    with pytest.raises(AppError):
        sort_spec("display_status", "asc")
