from uuid import uuid4
from typing import Literal
from fastapi import APIRouter, Request
from pydantic import Field, field_validator, model_validator
from keep.models import StrictModel, Command, uuid_string
from keep.configuration.models import name, name_key
from keep.access import authorize, accessible_tenants, effective_role
from keep.identity.authentication import authenticate
from keep.shared.errors import AppError, unavailable
from keep.shared.transactions import command_result, revision, save_result, audit
from keep.serialization import wire

router = APIRouter(tags=["tenants"])


class Grant(StrictModel):
    principal_id: str
    role: Literal["view", "edit", "admin"]
    _principal = field_validator("principal_id")(uuid_string)


class TenantCreate(StrictModel):
    command_id: str
    name: str
    initial_grants: list[Grant] = Field(min_length=1, max_length=100)
    _name = field_validator("name")(name)
    _command = field_validator("command_id")(uuid_string)


class TenantRename(Command):
    name: str
    _name = field_validator("name")(name)


class GrantChange(StrictModel):
    principal_id: str
    action: Literal["set", "remove"]
    role: Literal["view", "edit", "admin"] | None = None
    _principal = field_validator("principal_id")(uuid_string)

    @model_validator(mode="after")
    def shape(self):
        if (self.action == "set") != (self.role is not None):
            raise ValueError("Set requires a role; remove does not accept one")
        return self


class GrantBatch(Command):
    operations: list[GrantChange] = Field(min_length=1, max_length=100)


def guard(conn):
    conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR UPDATE")


def valid_grants(conn, grants):
    if len({g.principal_id for g in grants}) != len(grants):
        raise AppError("duplicate_principal", "A principal appears more than once.")
    for grant in grants:
        principal = conn.execute(
            "SELECT * FROM principals WHERE id=%s", (grant.principal_id,)
        ).fetchone()
        if not principal or principal["verified_at"] is None:
            raise unavailable("directory_evidence_required")
        if principal["deleted"] or (principal["kind"] == "user" and not principal["eligible"]):
            raise AppError("ineligible_principal", "Principal is not eligible.")
        if (
            principal["kind"] == "team"
            and not conn.execute(
                "SELECT 1 FROM directory_root_checkpoints WHERE root_id=%s", (grant.principal_id,)
            ).fetchone()
        ):
            raise unavailable("complete_membership_required")


def require_local_admin(conn, tenant):
    row = conn.execute(
        "SELECT count(DISTINCT p.id) AS n FROM principals p WHERE p.kind='user' AND p.eligible AND NOT p.deleted AND EXISTS(SELECT 1 FROM tenant_grants g WHERE g.tenant_id=%s AND g.role='admin' AND (g.principal_id=p.id OR g.principal_id IN(SELECT team_id FROM directory_memberships WHERE user_id=p.id)))",
        (tenant,),
    ).fetchone()
    if row["n"] == 0:
        raise AppError(
            "last_admin_required", "At least one eligible local administrator is required.", 409
        )


@router.get("/api/tenants")
def listing(request: Request):
    with request.app.state.db.transaction() as conn:
        principal, _ = authenticate(conn, request)
        return {"data": wire(accessible_tenants(conn, principal)), "meta": {}, "next_cursor": None}


@router.post("/api/tenants", status_code=201)
def create(body: TenantCreate, request: Request):
    with request.app.state.db.transaction() as conn:
        guard(conn)
        principal, _ = authenticate(conn, request, True)
        if not principal["super_admin"]:
            raise AppError("forbidden", "Global administration is required.", 403)
        scope = f"{principal['id']}:tenant-create"
        result, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if result is not None:
            return result
        valid_grants(conn, body.initial_grants)
        if conn.execute(
            "SELECT 1 FROM tenants WHERE name_key=%s", (name_key(body.name),)
        ).fetchone():
            raise AppError("name_unavailable", "Name is unavailable.", 409)
        tenant = uuid4()
        conn.execute(
            "INSERT INTO tenants(id,kind,name,name_key) VALUES(%s,'specific',%s,%s)",
            (tenant, body.name, name_key(body.name)),
        )
        # Authorization above covers creation. Scope all child writes, including
        # the durable live hint emitted by the initial view-state insertion.
        conn.execute("SELECT set_config('keep.tenant_id',%s,true)", (str(tenant),))
        for grant in body.initial_grants:
            conn.execute(
                "INSERT INTO tenant_grants(tenant_id,principal_id,role) VALUES(%s,%s,%s)",
                (tenant, grant.principal_id, grant.role),
            )
        require_local_admin(conn, tenant)
        conn.execute("INSERT INTO tenant_work_state(tenant_id) VALUES(%s)", (tenant,))
        conn.execute("INSERT INTO tenant_view_state(tenant_id) VALUES(%s)", (tenant,))
        conn.execute("INSERT INTO tenant_configuration_guard(tenant_id) VALUES(%s)", (tenant,))
        conn.execute("INSERT INTO admission_capacity(scope) VALUES(%s)", (str(tenant),))
        audit(conn, tenant, principal, "tenant-created", body.model_dump(exclude={"command_id"}))
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {
                "data": {
                    "id": str(tenant),
                    "kind": "specific",
                    "name": body.name,
                    "revision": "1",
                    "role": "admin",
                },
                "meta": {"revision": "1"},
            },
            201,
        )


@router.get("/api/tenants/{tenant_id}")
def detail(tenant_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        _, _, role = authorize(conn, request, tenant_id)
        row = conn.execute("SELECT * FROM tenants WHERE id=%s", (tenant_id,)).fetchone()
        return {"data": wire({**row, "role": role}), "meta": {"revision": str(row["revision"])}}


@router.patch("/api/tenants/{tenant_id}")
def rename(tenant_id: str, body: TenantRename, request: Request):
    with request.app.state.db.transaction() as conn:
        guard(conn)
        actor, _, _ = authorize(conn, request, tenant_id, "admin", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:tenant-rename"
        result, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if result is not None:
            return result
        row = conn.execute("SELECT * FROM tenants WHERE id=%s FOR UPDATE", (tenant_id,)).fetchone()
        if row["kind"] == "global":
            raise AppError("fixed_global_policy", "Global cannot be renamed.")
        revision(row, body.expected_revision)
        if row["name"] != body.name:
            if conn.execute(
                "SELECT 1 FROM tenants WHERE name_key=%s AND id<>%s",
                (name_key(body.name), tenant_id),
            ).fetchone():
                raise AppError("name_unavailable", "Name is unavailable.", 409)
            conn.execute(
                "UPDATE tenants SET name=%s,name_key=%s,revision=revision+1,updated_at=clock_timestamp() WHERE id=%s",
                (body.name, name_key(body.name), tenant_id),
            )
            audit(
                conn,
                tenant_id,
                actor,
                "tenant-renamed",
                {"before": row["name"], "after": body.name},
            )
        row = conn.execute("SELECT * FROM tenants WHERE id=%s", (tenant_id,)).fetchone()
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {"data": wire(row), "meta": {"revision": str(row["revision"])}},
        )


@router.get("/api/tenants/{tenant_id}/permissions")
def permissions(tenant_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        conn.execute("SELECT scope FROM authorization_guards WHERE scope='identity' FOR SHARE")
        authorize(conn, request, tenant_id, "admin")
        tenant = conn.execute(
            "SELECT revision FROM tenants WHERE id=%s FOR SHARE", (tenant_id,)
        ).fetchone()
        rows = conn.execute(
            "SELECT g.principal_id,g.role,p.display_name,p.kind,p.eligible,p.deleted FROM tenant_grants g JOIN principals p ON p.id=g.principal_id WHERE g.tenant_id=%s ORDER BY p.display_name,p.id",
            (tenant_id,),
        ).fetchall()
        return {
            "data": wire(rows),
            "meta": {"revision": str(tenant["revision"])},
            "next_cursor": None,
        }


@router.patch("/api/tenants/{tenant_id}/permissions")
def change_permissions(tenant_id: str, body: GrantBatch, request: Request):
    if len({g.principal_id for g in body.operations}) != len(body.operations):
        raise AppError("duplicate_principal", "Repeated principals are invalid.")
    with request.app.state.db.transaction() as conn:
        guard(conn)
        actor, _, _ = authorize(conn, request, tenant_id, "admin", mutation=True)
        scope = f"{tenant_id}:{actor['id']}:permissions"
        result, fp = command_result(conn, scope, body.command_id, body.model_dump())
        if result is not None:
            return result
        row = conn.execute("SELECT * FROM tenants WHERE id=%s FOR UPDATE", (tenant_id,)).fetchone()
        if row["kind"] == "global":
            raise AppError("fixed_global_policy", "Global has a fixed access policy.")
        revision(row, body.expected_revision)
        before = {
            str(g["principal_id"]): g["role"]
            for g in conn.execute(
                "SELECT principal_id,role FROM tenant_grants WHERE tenant_id=%s", (tenant_id,)
            )
        }
        changed = []
        for item in body.operations:
            if item.action == "set" and before.get(item.principal_id) != item.role:
                rank = {"view": 1, "edit": 2, "admin": 3}
                if rank[item.role] > rank.get(before.get(item.principal_id), 0):
                    valid_grants(conn, [item])
                conn.execute(
                    "INSERT INTO tenant_grants(tenant_id,principal_id,role) VALUES(%s,%s,%s) ON CONFLICT(tenant_id,principal_id) DO UPDATE SET role=EXCLUDED.role",
                    (tenant_id, item.principal_id, item.role),
                )
                changed.append(item.model_dump())
            elif item.action == "remove" and item.principal_id in before:
                conn.execute(
                    "DELETE FROM tenant_grants WHERE tenant_id=%s AND principal_id=%s",
                    (tenant_id, item.principal_id),
                )
                changed.append(item.model_dump())
        require_local_admin(conn, tenant_id)
        if changed:
            conn.execute(
                "UPDATE tenants SET revision=revision+1,updated_at=clock_timestamp() WHERE id=%s",
                (tenant_id,),
            )
            audit(
                conn,
                tenant_id,
                actor,
                "permissions-changed",
                {"changes": changed, "before": before},
            )
        current = conn.execute("SELECT revision FROM tenants WHERE id=%s", (tenant_id,)).fetchone()
        return save_result(
            conn,
            scope,
            body.command_id,
            fp,
            {
                "data": {
                    "revision": str(current["revision"]),
                    "role": effective_role(conn, actor, tenant_id),
                },
                "meta": {},
            },
        )


@router.get("/api/tenants/{tenant_id}/view-state")
@router.get("/api/tenants/{tenant_id}/health")
def health(tenant_id: str, request: Request):
    with request.app.state.db.transaction() as conn:
        authorize(conn, request, tenant_id)
        row = conn.execute(
            "SELECT v.*,w.projection_seq AS committed_seq,w.blocked AS source_blocked FROM tenant_view_state v JOIN tenant_work_state w USING(tenant_id) WHERE tenant_id=%s",
            (tenant_id,),
        ).fetchone()
        if conn.execute("SELECT enabled FROM kafka_pipeline_control WHERE singleton").fetchone()[
            "enabled"
        ]:
            row = dict(
                row, source_blocked=None, source_transport="kafka", source_status="not_measured"
            )
        return {"data": wire(row), "meta": {}}


@router.get("/api/admin/health")
def admin_health(request: Request):
    with request.app.state.db.transaction() as conn:
        actor, _ = authenticate(conn, request)
        if not actor["super_admin"]:
            raise AppError("forbidden", "Global administration is required.", 403)
        return {
            "data": {
                "capabilities": conn.execute(
                    "SELECT * FROM capability_gates ORDER BY capability"
                ).fetchall()
            },
            "meta": {},
        }


def audit_page(
    request,
    tenant_id,
    limit,
    cursor,
    *,
    period="recent",
    from_at=None,
    to_at=None,
    action=None,
    actor_id=None,
    affected_principal_id=None,
    resource_id=None,
    platform_tenant_id=None,
):
    from datetime import UTC, datetime, timedelta
    from uuid import UUID
    from psycopg.types.json import Jsonb
    from keep.shared.cursors import Cursor

    if not 1 <= limit <= 200 or period not in {"recent", "retained"}:
        raise AppError(
            "invalid_query", "Choose recent or retained history and a page size of 1–200."
        )

    def instant(value):
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError()
            return parsed.astimezone(UTC)
        except (TypeError, ValueError):
            raise AppError(
                "invalid_query", "Audit times require ISO 8601 instants with a timezone."
            ) from None

    def identifier(value):
        if value is None:
            return None
        try:
            return str(UUID(value))
        except (TypeError, ValueError, AttributeError):
            raise AppError("invalid_query", "Audit references require immutable UUIDs.") from None

    start, end = instant(from_at), instant(to_at)
    if start and end and start >= end:
        raise AppError("invalid_query", "The audit start time must precede the end time.")
    if action is not None and (not action.strip() or len(action) > 128):
        raise AppError("invalid_query", "Choose a nonblank action of at most 128 characters.")
    actor_id = actor_id if actor_id == "system" else identifier(actor_id)
    affected_principal_id = identifier(affected_principal_id)
    resource_id, platform_tenant_id = identifier(resource_id), identifier(platform_tenant_id)
    filters = {
        "period": period,
        "from_at": wire(start),
        "to_at": wire(end),
        "action": action,
        "actor_id": actor_id,
        "affected_principal_id": affected_principal_id,
        "resource_id": resource_id,
        "tenant_id": platform_tenant_id,
    }
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        if tenant_id:
            actor, session, _ = authorize(conn, request, tenant_id, "admin")
        else:
            actor, session = authenticate(conn, request)
            if not actor["super_admin"]:
                raise AppError("forbidden", "Global administration is required.", 403)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            {
                "tenant": tenant_id,
                "collection": "access-audit",
                "filters": filters,
                "order": "recorded-desc-id-desc",
                "actor": str(actor["id"]),
                "session": bytes(session["handle_hash"]).hex(),
                "epoch": request.app.state.settings.deployment_epoch,
            },
            now,
        )
        old = codec.decode(cursor) if cursor else None
        upper = old["upper"] if old else min(now, end) if end else now
        lower = (
            old["lower"]
            if old
            else start
            if start
            else now - timedelta(days=30)
            if period == "recent"
            else None
        )
        held = "EXISTS(SELECT 1 FROM audit_retention_holds h WHERE h.event_id=a.id AND h.released_at IS NULL)"
        query = f"""SELECT a.*,{held} AS dependency_protected FROM audit_events a
            WHERE a.tenant_id IS NOT DISTINCT FROM %s
            AND (a.recorded_at>%s OR {held}) AND a.recorded_at<=%s
            AND NOT EXISTS(SELECT 1 FROM audit_expiry_fences f WHERE f.event_id=a.id)"""
        args = [tenant_id, now - timedelta(days=365), upper]
        if lower:
            query += " AND a.recorded_at>=%s"
            args.append(lower)
        if end:
            query += " AND a.recorded_at<%s"
            args.append(end)
        if action:
            query += " AND a.kind=%s"
            args.append(action)
        if actor_id == "system":
            query += " AND a.actor_id IS NULL"
        elif actor_id:
            query += " AND a.actor_id=%s"
            args.append(actor_id)
        if affected_principal_id:
            # These are the writer-owned shapes; a prior complete grant roster
            # is context, not proof that every roster member was affected.
            query += " AND (a.evidence @> %s OR a.evidence @> %s OR a.evidence @> %s)"
            args += [
                Jsonb({"principal_id": affected_principal_id}),
                Jsonb({"changes": [{"principal_id": affected_principal_id}]}),
                Jsonb({"initial_grants": [{"principal_id": affected_principal_id}]}),
            ]
        if resource_id:
            # Tenant lifecycle changes affect the scope tenant; source repair
            # records identify their actual queued source item as head_id.
            query += " AND (a.tenant_id=%s OR a.evidence->>'target_tenant_id'=%s OR a.evidence->>'head_id'=%s)"
            args += [resource_id, resource_id, resource_id]
        if platform_tenant_id:
            query += " AND a.evidence->>'target_tenant_id'=%s"
            args.append(platform_tenant_id)
        if old:
            query += " AND (a.recorded_at,a.id)<(%s,%s)"
            args += old["position"]
        rows = conn.execute(
            query + " ORDER BY a.recorded_at DESC,a.id DESC LIMIT %s", args + [limit + 1]
        ).fetchall()
        # Resolve only IDs actually recorded by current writers. Minimal
        # existence checks never reconstruct source or resource content.
        source_groups = {}
        for row in rows[:limit]:
            row["references"] = []
            target = row["tenant_id"] or row["evidence"].get("target_tenant_id")
            if target:
                row["references"].append({"kind": "tenant", "id": str(target)})
            head = row["evidence"].get("head_id")
            if head and target:
                try:
                    key = str(UUID(str(target)))
                    source_groups.setdefault(key, set()).add(str(UUID(str(head))))
                except ValueError:
                    continue
                row["references"].append({"kind": "source-item", "id": str(head)})
        available_sources = set()
        for target, heads in source_groups.items():
            conn.execute("SELECT set_config('keep.tenant_id',%s,true)", (target,))
            available_sources.update(
                str(row["id"])
                for row in conn.execute(
                    "SELECT id FROM ingest_items WHERE tenant_id=%s AND id=ANY(%s::uuid[])",
                    (target, sorted(heads)),
                ).fetchall()
            )
        for row in rows[:limit]:
            for reference in row["references"]:
                if reference["kind"] == "source-item":
                    reference["available"] = reference["id"] in available_sources
        return {
            "data": wire(rows[:limit]),
            "meta": {"filters": filters, "from_at": wire(lower), "upper_recorded_at": wire(upper)},
            "next_cursor": codec.encode(
                [rows[limit - 1]["recorded_at"], rows[limit - 1]["id"]], upper=upper, lower=lower
            )
            if len(rows) > limit
            else None,
        }


@router.get("/api/tenants/{tenant_id}/audit")
def tenant_audit(
    tenant_id: str,
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
    period: str = "recent",
    from_at: str | None = None,
    to_at: str | None = None,
    action: str | None = None,
    actor_id: str | None = None,
    affected_principal_id: str | None = None,
    resource_id: str | None = None,
):
    return audit_page(
        request,
        tenant_id,
        limit,
        cursor,
        period=period,
        from_at=from_at,
        to_at=to_at,
        action=action,
        actor_id=actor_id,
        affected_principal_id=affected_principal_id,
        resource_id=resource_id,
    )


@router.get("/api/admin/access-audit")
def platform_audit(
    request: Request,
    limit: int = 50,
    cursor: str | None = None,
    period: str = "recent",
    from_at: str | None = None,
    to_at: str | None = None,
    action: str | None = None,
    actor_id: str | None = None,
    affected_principal_id: str | None = None,
    resource_id: str | None = None,
    tenant_id: str | None = None,
):
    return audit_page(
        request,
        None,
        limit,
        cursor,
        period=period,
        from_at=from_at,
        to_at=to_at,
        action=action,
        actor_id=actor_id,
        affected_principal_id=affected_principal_id,
        resource_id=resource_id,
        platform_tenant_id=tenant_id,
    )
