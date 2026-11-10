"""Authorized live incident queries with deterministic, query-bound keyset pages."""

import hashlib
from datetime import datetime
from uuid import UUID

from keep.access import authorize
from keep.identity.cleanup import visible_assignee
from keep.incidents.counts import page_linked_counts
from keep.shared.cursors import Cursor
from keep.shared.display_names import enrich_incidents
from keep.shared.errors import AppError
from keep.serialization import wire

SORTS = {
    "created_at": "i.created_at",
    "last_activity": "i.last_activity",
    "resolved_at": "i.resolved_at",
    "severity": "CASE i.severity WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 END",
}

# Match current assignment presentation, including pending durable cleanup.
ASSIGNEE_QUALIFIES = """EXISTS(SELECT 1 FROM principals p JOIN tenants t ON t.id=i.tenant_id
 WHERE p.id=i.assignee_id AND p.kind='user' AND p.eligible AND NOT p.deleted
 AND (p.super_admin OR t.kind='global' OR EXISTS(SELECT 1 FROM tenant_grants g
 WHERE g.tenant_id=t.id AND g.role IN ('edit','admin') AND (g.principal_id=p.id OR
 EXISTS(SELECT 1 FROM directory_memberships m WHERE m.team_id=g.principal_id AND m.user_id=p.id)))))"""


def validate_identifiers(query):
    for key in ("rule_id", "alert_id", "incident_id", "assignee"):
        value = query[key]
        if value is None or key == "assignee" and value in ("me", "unassigned"):
            continue
        try:
            if str(UUID(value)) != value:
                raise ValueError
        except (TypeError, ValueError):
            raise AppError("invalid_query", "Filters require canonical UUIDs.") from None


def list_incidents(request, tenant_id, *, terms, limit, cursor, **query):
    validate_identifiers(query)
    for prefix in ("created", "activity", "resolved"):
        lower, upper = query[prefix + "_from"], query[prefix + "_to"]
        if any(value is not None and value.tzinfo is None for value in (lower, upper)) or (
            lower is not None and upper is not None and lower >= upper
        ):
            raise AppError(
                "invalid_query", "Time ranges require aware instants and an increasing interval."
            )
    with request.app.state.db.transaction() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        actor, session, _ = authorize(conn, request, tenant_id)
        now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
        codec = Cursor(
            request.app.state.settings.cipher(),
            wire(
                {
                    "tenant": tenant_id,
                    "collection": "incidents",
                    "filters": query,
                    "q": sorted(terms),
                    "actor": str(actor["id"]),
                    "session": bytes(session["handle_hash"]).hex(),
                    "epoch": request.app.state.settings.deployment_epoch,
                }
            ),
            now,
        )
        old = codec.decode(cursor) if cursor else None
        clauses, args = ["i.tenant_id=%s", "ident.retired_at IS NULL"], [tenant_id]
        view = query["view"]
        if view != "all":
            clauses.append("i.status" + ("<>" if view == "active" else "=") + "'resolved'")
        for key in ("status", "severity", "origin"):
            if query[key] is not None:
                clauses.append(f"i.{key}=%s")
                args.append(query[key])
        if query["incident_id"]:
            clauses.append("i.id=%s")
            args.append(query["incident_id"])
        if query["rule_id"]:
            clauses.append(
                "EXISTS(SELECT 1 FROM correlation_contexts c WHERE c.tenant_id=i.tenant_id AND c.id=i.context_id AND c.rule_id=%s)"
            )
            args.append(query["rule_id"])
        if query["alert_id"]:
            clauses.append(
                "EXISTS(SELECT 1 FROM incident_alert_links l WHERE l.tenant_id=i.tenant_id AND l.incident_id=i.id AND l.alert_id=%s AND l.unlinked_at IS NULL)"
            )
            args.append(query["alert_id"])
        assignment = query["assignee"]
        if assignment == "unassigned":
            clauses.append("(i.assignee_id IS NULL OR NOT " + ASSIGNEE_QUALIFIES + ")")
        elif assignment is not None:
            clauses.extend(["i.assignee_id=%s", ASSIGNEE_QUALIFIES])
            args.append(actor["id"] if assignment == "me" else assignment)
        for prefix, column in (
            ("created", "created_at"),
            ("activity", "last_activity"),
            ("resolved", "resolved_at"),
        ):
            for suffix, operator in (("from", ">="), ("to", "<")):
                value = query[prefix + "_" + suffix]
                if value is not None:
                    clauses.append(f"i.{column}{operator}%s")
                    args.append(value)
        for token in sorted(terms):
            clauses.append(
                "EXISTS(SELECT 1 FROM incident_search_tokens t WHERE t.tenant_id=i.tenant_id AND t.incident_id=i.id AND t.token_digest=%s AND t.token_text=%s)"
            )
            args.extend([hashlib.sha256(token.encode()).digest(), token])
        expression = SORTS[query["sort"]]
        direction = query["direction"]
        if old:
            value, identifier = old["position"]
            if value is None:
                clauses.append(f"({expression} IS NULL AND i.id>%s)")
                args.append(identifier)
            else:
                if query["sort"] != "severity":
                    value = datetime.fromisoformat(value)
                op = ">" if direction == "asc" else "<"
                clauses.append(
                    f"({expression}{op}%s OR ({expression}=%s AND i.id>%s) OR {expression} IS NULL)"
                )
                args.extend([value, value, identifier])
        rows = conn.execute(
            "SELECT i.*, "
            + expression
            + " AS sort_value FROM incidents i JOIN incident_identities ident ON ident.tenant_id=i.tenant_id AND ident.id=i.id WHERE "
            + " AND ".join(clauses)
            + f" ORDER BY {expression} {direction} NULLS LAST,i.id ASC LIMIT %s",
            (*args, limit + 1),
        ).fetchall()
        next_cursor = (
            codec.encode([rows[limit - 1]["sort_value"], rows[limit - 1]["id"]])
            if len(rows) > limit
            else None
        )
        counts = page_linked_counts(conn, tenant_id, [item["id"] for item in rows[:limit]])
        for item in rows[:limit]:
            item.pop("sort_value")
            item["assignee_id"], item["assignment_cleanup_pending"] = visible_assignee(
                conn, tenant_id, item["assignee_id"]
            )
            item.update(counts[str(item["id"])])
        return {
            "data": enrich_incidents(conn, tenant_id, wire(rows[:limit])),
            "meta": {},
            "next_cursor": next_cursor,
        }
