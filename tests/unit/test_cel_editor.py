from datetime import UTC, datetime

import pytest

from keep.cel import compiler
from keep.cel.routes import describe_profile, diagnostic


def test_advertised_operators_and_functions_compile_with_native_runtime():
    profile = describe_profile("feed")
    examples = {
        "&&": "true && false",
        "||": "true || false",
        "!": "!true",
        "==": 'alert.status == "firing"',
        "!=": 'alert.status != "firing"',
        "<": "alert.occurrence_number < 2",
        "<=": "alert.occurrence_number <= 2",
        ">": "alert.occurrence_number > 2",
        ">=": "alert.occurrence_number >= 2",
        "+": 'alert.time_created < now() + duration("1s")',
        "-": 'alert.time_created < now() - duration("1s")',
        "in": 'alert.status in ["firing"]',
        "startsWith": 'alert.message.startsWith("x")',
        "endsWith": 'alert.message.endsWith("x")',
        "contains": 'alert.message.contains("x")',
        "timestamp": 'alert.time_created < timestamp("2026-01-01T00:00:00Z")',
        "duration": 'alert.time_created < now() - duration("1s")',
        "now": "alert.time_created < now()",
        "has": "has(alert.node_name)",
    }
    advertised = set(profile.operators) | {fn.name for fn in profile.functions}
    assert advertised == set(examples)
    for token in advertised:
        compiled = compiler.compile_expression(examples[token])
        assert compiled.to_elasticsearch(datetime(2026, 9, 23, tzinfo=UTC))


def test_native_diagnostic_offset_counts_unicode_codepoints():
    source = 'alert.message == "😀" &&\nalert.private_field == "x"'
    with pytest.raises(compiler.CELValidationError) as error:
        compiler.compile_expression(source)
    result = diagnostic(error.value, source)
    assert result.position == source.index(".private_field")
    assert (result.line, result.column) == (2, 6)
    assert "private_field" not in result.message


def test_byte_limit_remains_enforced_by_compiler():
    with pytest.raises(compiler.CELValidationError, match="UTF-8"):
        compiler.compile_expression('alert.message == "' + "😀" * 5000 + '"')
