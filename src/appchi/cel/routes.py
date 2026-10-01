"""Assistant-selected editor discovery/validation APIs; no expression execution.

These additive read workflows use the existing profile and compiler. Validation
does not reserve deployment rule capacity or certify Elasticsearch equivalence.
"""

from typing import Literal

from fastapi import APIRouter, Request
from pydantic import Field

from appchi.access import authorize
from appchi.models import StrictModel
from appchi.shared.errors import unavailable
from . import compiler
from .catalog import FIELDS, RULE_FIELDS, CORRELATION_FIELDS, LEGACY_ACK_FIELDS

router = APIRouter(prefix="/api/tenants/{tenant_id}/cel", tags=["CEL"])
Context = Literal["feed", "rule", "correlation"]


class ValidationRequest(StrictModel):
    cel: str = Field(max_length=compiler.MAX_SOURCE_BYTES)
    context: Context


class CatalogField(StrictModel):
    name: str
    type: str
    nullable: bool
    values: list[str]


class Function(StrictModel):
    name: str
    signature: str
    description: str
    insert_text: str


class Limits(StrictModel):
    source_bytes: int
    ast_nodes: int
    depth: int
    list_members: int
    compile_timeout_ms: int


class Profile(StrictModel):
    profile: str
    context: Context
    cost_model: str
    fields: list[CatalogField]
    operators: list[str]
    functions: list[Function]
    limits: Limits


class ProfileResponse(StrictModel):
    data: Profile


class Diagnostic(StrictModel):
    code: str
    message: str
    position: int | None
    line: int | None
    column: int | None


class Validation(StrictModel):
    valid: bool
    profile: str
    context: Context
    diagnostics: list[Diagnostic]
    position_encoding: Literal["unicode_codepoints"] = "unicode_codepoints"
    ast_nodes: int | None = None
    rule_cost_upper_bound: str | None = None
    relative: bool | None = None


class ValidationResponse(StrictModel):
    data: Validation


def describe_profile(context: Context) -> Profile:
    fields = {
        name: spec
        for name, spec in FIELDS.items()
        if name not in LEGACY_ACK_FIELDS
        and (
            context == "feed"
            or name in (CORRELATION_FIELDS if context == "correlation" else RULE_FIELDS)
        )
    }
    functions = [
        Function(
            name=name,
            signature=f'string_field.{name}("literal")',
            description="Case-sensitive literal string predicate; false on null.",
            insert_text=f'{name}("")',
        )
        for name in compiler.STRING_METHODS
    ]
    for name in compiler.TIME_LITERAL_FUNCTIONS:
        functions.append(
            Function(
                name=name,
                signature=f'{name}("literal")',
                insert_text=f'{name}("")',
                description=(
                    "RFC3339 instant with explicit offset and at most six fractional digits."
                    if name == "timestamp"
                    else "Nonnegative literal hours, minutes and seconds."
                ),
            )
        )
    functions.append(
        Function(
            name="has",
            signature="has(field)",
            description="True when an approved scalar field is non-null.",
            insert_text="has(",
        )
    )
    if context == "feed":
        functions.append(
            Function(
                name=compiler.NOW_FUNCTION,
                signature="now()",
                description="Clock frozen for the query snapshot; feed only.",
                insert_text="now()",
            )
        )
    operators = [
        name.strip("_")
        for name in (
            *compiler.BOOLEAN_OPERATORS,
            *compiler.COMPARISON_OPERATORS,
            *compiler.TIME_OPERATORS,
        )
    ] + [compiler.MEMBERSHIP_OPERATOR.removeprefix("@")]
    return Profile(
        profile=compiler.PROFILE,
        context=context,
        cost_model=compiler.COST_MODEL,
        fields=[
            CatalogField(
                name=name, type=spec.kind, nullable=spec.nullable, values=list(spec.values)
            )
            for name, spec in sorted(fields.items())
        ],
        operators=operators,
        functions=functions,
        limits=Limits(
            source_bytes=compiler.MAX_SOURCE_BYTES,
            ast_nodes=compiler.MAX_AST_NODES,
            depth=compiler.MAX_DEPTH,
            list_members=compiler.MAX_LIST_MEMBERS,
            compile_timeout_ms=int(compiler.COMPILE_TIMEOUT_SECONDS * 1000),
        ),
    )


# Only fixed application messages may cross the HTTP boundary. Native parser
# errors and unknown-field/function errors can contain the caller's source.
SAFE_MESSAGES = frozenset(
    (
        "Expression contains invalid Unicode",
        "Expression must contain 1–16384 UTF-8 bytes",
        "Expression exceeds 256 nodes or depth 32",
        "Only signed integers, strings, booleans and null are literals",
        "Only approved alert fields may be referenced",
        "Only direct approved field references are allowed",
        "has() requires a scalar field",
        "Lists permit at most 100 nonoptional literal members",
        "Membership lists must contain homogeneous scalar literals",
        "Unsupported CEL construct",
        "Unsupported string method or argument",
        "Boolean operators require booleans",
        "Nested time arithmetic is not supported",
        "Time arithmetic outside supported years",
        "Incident membership requires a UUID literal",
        "Membership requires a scalar field and literal list",
        "Constant comparison types differ",
        "Unsupported ordered constant comparison",
        "Comparisons require a scalar field and compatible literal",
        "Ordered comparisons require integers or timestamps",
        "Null comparison requires a nullable field",
        "Invalid enum literal",
        "Literal does not match field type",
        "Expression must return bool",
        "Timestamp requires RFC3339 with explicit offset and microsecond precision",
        "Invalid timestamp offset",
        "Invalid timestamp",
        "Timestamp outside years 0001–9999",
        "Duration must be nonnegative literal hours/minutes/seconds",
        "Duration exceeds 3,652,500 days",
        "Resulting time bound outside supported years",
    )
)


def diagnostic(error, source):
    message = str(error)
    if message.startswith("Unsupported field:"):
        message = "This field is unavailable in the selected CEL context."
    elif message.startswith("Unsupported function or operator:"):
        message = "This function or operator is outside the supported CEL profile."
    elif message not in SAFE_MESSAGES:
        message = "Invalid CEL syntax. Check the expression and supported language profile."
    position = error.position
    if type(position) is not int or not 0 <= position <= len(source):
        position = None
    prefix = source[:position] if position is not None else None
    return Diagnostic(
        code="invalid_cel",
        message=message,
        position=position,
        line=prefix.count("\n") + 1 if prefix is not None else None,
        column=len(prefix.rsplit("\n", 1)[-1]) + 1 if prefix is not None else None,
    )


@router.get("/profile", response_model=ProfileResponse)
def cel_profile(request: Request, tenant_id: str, context: Context = "feed"):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
    profile = describe_profile(context)
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
    return ProfileResponse(data=profile)


@router.post("/validate", response_model=ValidationResponse)
def validate_cel(request: Request, tenant_id: str, body: ValidationRequest):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
        evaluated_at = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    result = Validation(valid=False, profile=compiler.PROFILE, context=body.context, diagnostics=[])
    failed = False
    try:
        compiled = compiler.compile_expression(body.cel, rule=body.context != "feed")
        if body.context == "correlation" and "assignee_id" in compiled.fields:
            raise compiler.CELValidationError("Unsupported field: assignee_id")
        compiled.to_elasticsearch(evaluated_at)
        result.valid = True
        result.ast_nodes = compiled.ast_nodes
        result.rule_cost_upper_bound = str(compiled.rule_cost_upper_bound)
        result.relative = compiled.relative
    except compiler.CELValidationError as error:
        result.diagnostics = [diagnostic(error, body.cel)]
    except compiler.CELUnavailableError:
        failed = True
    # Reauthorize invalid and unavailable results too; no SQL lock spans native
    # compilation, process startup, or translator work.
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id, mutation=True)
    if failed:
        raise unavailable("cel_unavailable")
    return ValidationResponse(data=result)
