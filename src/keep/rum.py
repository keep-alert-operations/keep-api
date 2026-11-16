"""Real user monitoring: browser events become metrics and browser log records.

The browser posts bounded batches of events it collected (observability 9). This
endpoint requires the session and its CSRF token, limits each session's rate, and
is excluded from the Product API's own service level indicators. Nothing a browser sends becomes a metric label unless it belongs
to a closed set held here: sections of the UI, the application's own route
templates, and fixed outcome, state and reason lists.
"""

from collections import OrderedDict
import logging
import re
from time import monotonic

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from keep.identity.authentication import authenticate
from keep.models import RumBatch
from keep.observability import log_event
from keep.observability.http import actor
from keep.observability.metrics import FAST, LONG, counter, histogram
from keep.shared.errors import AppError
from keep.workload import RUM_PATH

log = logging.getLogger(__name__)
router = APIRouter(tags=["rum"])

VIEWS = frozenset(
    {
        "alerts",
        "alert",
        "incidents",
        "incident",
        "presets",
        "dashboards",
        "rules",
        "maintenance",
        "reports",
        "admin",
        "sign_in",
        "other",
    }
)
VITALS = frozenset({"ttfb", "fcp", "lcp", "inp"})
API_OUTCOMES = frozenset(
    {"ok", "rejected", "conflict", "denied", "server_error", "network", "unreadable"}
)
API_FAILURES = frozenset({"server_error", "network", "unreadable"})
LIVE_STATES = frozenset({"connecting", "connected", "degraded", "hidden", "denied"})
DISCONNECTS = frozenset(
    {"watchdog", "stream_end", "http_status", "invalid_response", "network", "denied"}
)
ERROR_KINDS = frozenset({"error", "unhandled_rejection"})
VISIBILITY = frozenset({"visible", "hidden"})
# The upper bounds, in seconds, of the buckets the browser counts API calls into;
# the last is everything slower.
API_BOUNDS = (0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0)
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_FRAME = re.compile(r"[^\w.:/@$<>\[\]() \n-]")

BATCHES = counter("keep_rum_batches_total", "Browser event batches, by outcome.", ("outcome",))
EVENTS = counter("keep_rum_events_total", "Browser events, by kind and outcome.", ("kind", "outcome"))
WEB_VITAL = histogram(
    "keep_rum_web_vital_seconds",
    "Page load timings as users experience them: time to first byte, first and largest "
    "contentful paint, and interaction delay.",
    ("name", "view"),
    buckets=FAST,
)
LAYOUT_SHIFT = histogram(
    "keep_rum_layout_shift",
    "Cumulative layout shift of a page view (no unit).",
    ("view",),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1),
)
PAGE_VIEWS = counter("keep_rum_page_views_total", "Views opened, by section.", ("view",))
API_REQUESTS = counter(
    "keep_rum_api_requests_total",
    "Product API calls as the browser saw them, including those that never reached the server.",
    ("route", "method", "outcome"),
)
API_SECONDS = histogram(
    "keep_rum_api_request_seconds",
    "Product API call duration as the browser saw it.",
    ("route", "method"),
    buckets=LONG,
)
LIVE_SECONDS = counter(
    "keep_rum_live_state_seconds_total",
    "Time browsers spent in each state of the live update connection.",
    ("state",),
)
LIVE_DISCONNECTS = counter(
    "keep_rum_live_disconnects_total", "Live update connections lost, by cause.", ("reason",)
)
JS_ERRORS = counter(
    "keep_rum_js_errors_total", "JavaScript errors nothing handled.", ("kind", "view")
)
TAB_SECONDS = counter(
    "keep_rum_tab_seconds_total", "Time the UI was open, by tab visibility.", ("state",)
)
DROPPED = counter(
    "keep_rum_events_dropped_total", "Events a browser dropped because its buffer was full."
)

# At most this many batches a minute from one session; the collector sends about two.
BATCHES_PER_MINUTE = 12
_SESSIONS = 5000
_recent = OrderedDict()


def within_rate(session, now=None):
    """Whether this session may send another batch now."""
    now = monotonic() if now is None else now
    stamps = [at for at in _recent.pop(session, ()) if now - at < 60.0]
    allowed = len(stamps) < BATCHES_PER_MINUTE
    if allowed:
        stamps.append(now)
    _recent[session] = stamps
    while len(_recent) > _SESSIONS:
        _recent.popitem(last=False)
    return allowed


def route_templates(app):
    """The application's own route templates, keyed as a browser can name them.

    A browser knows a path, not the template behind it, so it replaces each
    identifier with ``{id}``; the same is done to the templates here.
    """
    known = getattr(app.state, "rum_routes", None)
    if known is None:
        known = {}
        # The contract document lists every route, including those of included routers.
        for path in app.openapi()["paths"]:
            if path.startswith(("/api/", "/auth/")):
                known.setdefault(re.sub(r"\{[^}]+\}", "{id}", path), path)
        app.state.rum_routes = known
    return known


def _frames(stack):
    """Stack frames only: control characters and anything unusual are removed."""
    lines = [_FRAME.sub("", line).strip()[:200] for line in stack.splitlines()[:30]]
    return "\n".join(line for line in lines if line)[:2000] or None


def record(events, *, principal_id, routes):
    """Turn one batch into metrics and browser log records; return how many were used."""
    used = 0
    for event in events:
        if _apply(event, principal_id, routes):
            EVENTS.labels(event.kind, "accepted").inc()
            used += 1
        else:
            EVENTS.labels(event.kind, "invalid").inc()
    return used


def _apply(event, principal_id, routes):
    kind, view = event.kind, event.view if event.view in VIEWS else None
    if kind == "web_vital":
        if view is None or event.value is None:
            return False
        if event.name == "cls":
            LAYOUT_SHIFT.labels(view).observe(float(event.value))
        elif event.name in VITALS:
            WEB_VITAL.labels(event.name, view).observe(float(event.value))
        else:
            return False
    elif kind == "page_view":
        if view is None:
            return False
        PAGE_VIEWS.labels(view).inc()
    elif kind == "api":
        route = routes.get(event.route or "")
        if route is None or event.method is None or event.outcome not in API_OUTCOMES:
            return False
        counts = event.buckets or []
        if len(counts) != len(API_BOUNDS) or event.count != sum(counts):
            return False
        API_REQUESTS.labels(route, event.method, event.outcome).inc(event.count)
        timings = API_SECONDS.labels(route, event.method)
        for bound, calls in zip(API_BOUNDS, counts):
            for _ in range(min(calls, 500)):
                timings.observe(bound)
    elif kind == "api_error":
        route = routes.get(event.route or "")
        if route is None or event.method is None or event.outcome not in API_FAILURES:
            return False
        log_event(
            log,
            "rum_api_error",
            service="browser",
            principal_id=principal_id,
            method=event.method,
            route=route,
            reason=event.outcome,
            status=event.status,
            request_id=event.request_id,
            view=view,
        )
    elif kind == "live":
        if event.state not in LIVE_STATES or event.value is None:
            return False
        LIVE_SECONDS.labels(event.state).inc(float(event.value))
    elif kind == "live_disconnect":
        if event.reason not in DISCONNECTS:
            return False
        LIVE_DISCONNECTS.labels(event.reason).inc()
        log_event(
            log,
            "rum_live_disconnect",
            service="browser",
            principal_id=principal_id,
            reason=event.reason,
            status=event.status,
            view=view,
        )
    elif kind == "js_error":
        if event.name not in ERROR_KINDS or view is None:
            return False
        JS_ERRORS.labels(event.name, view).inc()
        named = event.error_name if event.error_name and _NAME.match(event.error_name) else None
        log_event(
            log,
            "rum_js_error",
            service="browser",
            principal_id=principal_id,
            kind=event.name,
            view=view,
            error_class=named or "Error",
            stack=_frames(event.stack) if event.stack else None,
            alert_id=event.alert_id,
            incident_id=event.incident_id,
        )
    elif kind == "tab":
        if event.state not in VISIBILITY or event.value is None:
            return False
        TAB_SECONDS.labels(event.state).inc(float(event.value))
    elif kind == "dropped":
        if event.count is None:
            return False
        DROPPED.inc(event.count)
    return True


@router.post(RUM_PATH, status_code=202)
def rum_events(body: RumBatch, request: Request):
    """Accept one batch of browser monitoring events."""
    if not request.app.state.settings.rum_enabled:
        # Off unless configured: the browser stops sending when it sees this.
        raise AppError("not_found", "Resource unavailable.", 404)
    with request.app.state.db.transaction(read_committed=True) as conn:
        principal, session = authenticate(conn, request, mutation=True)
    actor(request, principal["id"])
    if not within_rate(bytes(session["handle_hash"])):
        BATCHES.labels("rate_limited").inc()
        raise AppError("rate_limited", "Too many monitoring batches; send fewer.", 429)
    used = record(body.events, principal_id=principal["id"], routes=route_templates(request.app))
    BATCHES.labels("accepted").inc()
    return JSONResponse(
        {"data": {"accepted": used}, "meta": {"request_id": request.state.request_id}}, 202
    )
