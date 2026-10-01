import json
import asyncio
from time import monotonic
from datetime import UTC, datetime
from contextlib import suppress
from contextlib import asynccontextmanager
from uuid import UUID, uuid4
from threading import Event

from fastapi import FastAPI, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from appchi.config import Settings
from appchi.db import Database
from appchi.ingestion.native import parse_json
from appchi.ingestion.kafka_admission import KafkaAdmission, KafkaPublisher
from appchi.ingestion.schemas import request_schema, admission_responses
from appchi.shared.errors import AppError, unavailable


def create_app(settings=None, db=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings()
        from appchi.workload import HTTP_ROLES

        if app.state.settings.role not in HTTP_ROLES:
            raise RuntimeError("This role does not expose an HTTP application")
        ingress = app.state.settings.role in ("ingestion-api", "private-ingestion")
        app.state.db = None if ingress else db or Database(
            app.state.settings.database_url.get_secret_value(),
            app.state.settings.pool_size,
            deployment_epoch=app.state.settings.deployment_epoch,
        )
        app.state.operator_db = (
            Database(app.state.settings.operator_database_url.get_secret_value(), 1,
                     deployment_epoch=app.state.settings.deployment_epoch)
            if not ingress and app.state.settings.operator_database_url else None
        )
        app.state.kafka_publisher = KafkaPublisher(app.state.settings) if app.state.settings.kafka_bootstrap else None
        if not ingress:
            from appchi.alert_notifications import configure
            configure(app.state.settings)
        path = app.state.settings.capacity_profile
        app.state.profile = json.loads(path.read_text()) if path else None
        from appchi.visibility.runtime import capture_profile

        capture = capture_profile(
            app.state.profile, deployment_epoch=app.state.settings.deployment_epoch
        )
        app.state.visibility_registry_limits = capture.registry if capture else None
        if (
            app.state.profile
            and app.state.settings.environment != "development"
            and not app.state.profile.get("qualified")
        ):
            raise RuntimeError("A qualified capacity profile is required outside development")
        from appchi.live import LiveRegistry, hint_publisher, redis_listener
        from appchi.identity.selection_config import configured_search

        app.state.directory_search = configured_search(app.state.settings)

        app.state.recovery_store = None
        if app.state.settings.recovery_binding or app.state.settings.recovery_credential:
            from appchi.recovery.runtime import configured_store

            app.state.recovery_store = configured_store(app.state.settings)
        owned_recovery_store = app.state.recovery_store
        app.state.live_registry = LiveRegistry()
        listener = (
            asyncio.create_task(redis_listener(app.state.settings, app.state.live_registry))
            if not ingress and app.state.settings.redis_url
            else None
        )
        publisher_stop = Event()
        publisher = (
            asyncio.create_task(hint_publisher(app.state.db, app.state.settings, publisher_stop))
            if not ingress and app.state.settings.redis_url
            else None
        )
        try:
            yield
        finally:
            # Drain the bounded thread turn before closing its shared SQL pool.
            publisher_stop.set()
            if publisher:
                await publisher
            if listener:
                listener.cancel()
                with suppress(asyncio.CancelledError):
                    await listener
            if owned_recovery_store:
                owned_recovery_store.close()
            if app.state.kafka_publisher:
                app.state.kafka_publisher.close()
            if app.state.operator_db:
                app.state.operator_db.close()
            if not db and app.state.db:
                app.state.db.close()

    def validate_path(request: Request):
        if request.url.path.startswith("/api/"):
            route = request.scope.get("route")
            query_fields = getattr(getattr(route, "dependant", None), "query_params", ())
            allowed = {field.alias for field in query_fields}
            if set(request.query_params) - allowed:
                raise AppError("invalid_query", "Unknown query parameter.", 422)
            for field in query_fields:
                if (
                    field.field_info.annotation is bool
                    and field.alias in request.query_params
                    and request.query_params[field.alias] not in ("true", "false")
                ):
                    raise AppError(
                        "invalid_query", "Boolean query parameters require true or false.", 422
                    )
        for key, value in request.path_params.items():
            if key.endswith("_id"):
                try:
                    if str(UUID(value)) != value:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise AppError("invalid_identifier", "Canonical UUID required.", 422) from None

    app = FastAPI(
        dependencies=[Depends(validate_path)],
        title="Appchi",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def error_response(request, error):
        content = {
            "code": error.code,
            "message": error.message,
            "request_id": getattr(request.state, "request_id", str(uuid4())),
        }
        if error.fields:
            content["fields"] = error.fields
        headers = {"Cache-Control": "private, no-store"}
        if error.status in (429, 503):
            delay = 10 if error.status == 429 else 5
            headers["Retry-After"] = str(delay)
            content["retry_after_seconds"] = delay
        return JSONResponse({"error": content}, error.status, headers=headers)

    @app.exception_handler(AppError)
    async def app_error(request, error):
        return error_response(request, error)

    from appchi.cel import CELValidationError, CELUnavailableError

    @app.exception_handler(CELValidationError)
    async def cel_invalid(request, error):
        return error_response(request, AppError("invalid_cel", "CEL expression is invalid.", 422))

    @app.exception_handler(CELUnavailableError)
    async def cel_unavailable(request, error):
        return error_response(request, unavailable("cel_unavailable"))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        return error_response(
            request,
            AppError(
                "invalid_fields",
                "Invalid request fields.",
                422,
                fields=[
                    {"path": ".".join(map(str, item["loc"])), "code": item["type"]}
                    for item in error.errors()
                ],
            ),
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request, error):
        return error_response(
            request, AppError("internal_error", "Unexpected application error.", 500)
        )

    @app.exception_handler(DatabaseError)
    @app.exception_handler(PoolTimeout)
    async def database_error(request, error):
        return error_response(request, unavailable("database_unavailable"))

    @app.middleware("http")
    async def protocol(request, call_next):
        request.state.request_id = str(uuid4())
        request.state.received_at = datetime.now(UTC)
        try:
            async with asyncio.timeout(5 if "/ingest/" in request.url.path else None):
                from appchi.workload import permits_http

                if not permits_http(request.app.state.settings, request.url.path):
                    raise AppError("not_found", "Resource unavailable.", 404)
                if "/ingest/" in request.url.path or (request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api/")):
                    from appchi.clock_health import require_clock_health
                    require_clock_health(request.app.state.settings, now=request.state.received_at)
                for key in request.query_params:
                    if len(request.query_params.getlist(key)) > 1:
                        raise AppError(
                            "duplicate_parameter", "Repeated query parameters are invalid.", 400
                        )
                for key in (
                    "idempotency-key",
                    "x-receipt-token",
                    "x-api-key",
                    "authorization",
                    "if-match",
                    "origin",
                    "x-csrf-token",
                ):
                    if len(request.headers.getlist(key)) > 1:
                        raise AppError(
                            "duplicate_header", "Repeated security headers are invalid.", 400
                        )
                if request.method in ("POST", "PUT", "PATCH") and not request.url.path.startswith(
                    "/auth/"
                ):
                    if request.headers.get("content-encoding", "identity") != "identity":
                        raise AppError(
                            "unsupported_encoding", "Compressed request bodies are not accepted.", 415
                        )
                    if (
                        request.headers.get("content-type", "").split(";")[0].lower()
                        != "application/json"
                    ):
                        raise AppError("unsupported_media_type", "Use application/json.", 415)
                    limit = (
                        4 * 1024 * 1024
                        if "/ingest/" in request.url.path
                        else 1024 * 1024
                        if "/correlation-rules" in request.url.path
                        else 256 * 1024
                        if "/maintenance" in request.url.path
                        else 65536
                    )
                    chunks = []
                    size = 0
                    async for chunk in request.stream():
                        size += len(chunk)
                        if size > limit:
                            raise AppError(
                                "body_too_large", "Request body exceeds its size limit.", 413
                            )
                        chunks.append(chunk)
                    request._body = b"".join(chunks)
                    request.state.receipt_started = monotonic()
                    parse_json(request._body)
                response = await call_next(request)
        except TimeoutError:
            response = error_response(request, unavailable("ingress_timeout"))
        except AppError as error:
            response = error_response(request, error)
        response.headers.update(
            {
                "Cache-Control": (
                    "private, no-store, no-transform"
                    if response.headers.get("content-type", "").split(";")[0] == "text/event-stream"
                    else "private, no-store"
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Request-ID": request.state.request_id,
            }
        )
        return response

    @app.get("/livez", tags=["health"])
    def livez():
        return {"status": "alive"}

    @app.get("/readyz", tags=["health"])
    def readyz(request: Request):
        from appchi.probes import check_readiness

        configured = request.app.state.settings
        check_readiness(configured, request.app.state.db)
        return {"status": "ready", "scope": configured.role, "environment": configured.environment}

    def admission(request):
        settings = request.app.state.settings
        if not settings.kafka_admission_enabled:
            raise unavailable("kafka_cutover_required")
        if not request.app.state.kafka_publisher or not settings.global_tenant_id:
            raise unavailable("kafka_admission_unconfigured")
        return KafkaAdmission(request.app.state.kafka_publisher, environment=settings.environment, global_tenant_id=settings.global_tenant_id)

    @app.post(
        "/api/ingest/v1/alerts",
        tags=["ingestion"],
        status_code=202, responses=admission_responses(),
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": request_schema("v1")}},
            }
        },
    )
    async def ingest_v1(request: Request):
        status, result = await admission(request).admit(
            await request.body(),
            "v1",
            request.headers.get("idempotency-key"),
            received_at=request.state.received_at,
        )
        result["request_id"] = request.state.request_id
        return JSONResponse(result, status)

    @app.post(
        "/api/ingest/v2/alerts",
        tags=["ingestion"],
        status_code=202, responses=admission_responses(),
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {"application/json": {"schema": request_schema("v2")}},
            }
        },
    )
    async def ingest_v2(request: Request):
        from appchi.ingestion.gateway import gateway_identity

        gateway = gateway_identity(request)
        status, result = await admission(request).admit(
            await request.body(),
            "v2",
            request.headers.get("idempotency-key"),
            gateway,
            received_at=request.state.received_at,
        )
        result["request_id"] = request.state.request_id
        return JSONResponse(result, status)

    @app.post("/api/ingest/v2/grafana", tags=["ingestion"], status_code=202, responses=admission_responses())
    async def ingest_grafana(request: Request):
        from appchi.ingestion.gateway import gateway_identity

        gateway = gateway_identity(request)
        status, result = await admission(request).admit_grafana(
            await request.body(),
            request.headers.get("idempotency-key"),
            gateway,
            received_at=request.state.received_at,
        )
        result["request_id"] = request.state.request_id
        return JSONResponse(result, status)

    from appchi.alerts.routes import router as alerts
    import appchi.alerts.history  # noqa: F401 -- registers authoritative history routes
    from appchi.identity.session import router as auth

    app.include_router(auth)
    app.include_router(alerts)
    from appchi.configuration.routes import router as configuration
    from appchi.incidents.routes import router as incidents
    import appchi.incidents.history  # noqa: F401 -- registers incident child routes
    from appchi.tenant_routes import router as tenants

    app.include_router(configuration)
    from appchi.configuration.deletion import router as configuration_deletion

    app.include_router(configuration_deletion)
    from appchi.configuration.read_routes import router as configuration_reads

    app.include_router(configuration_reads)
    from appchi.configuration.count_routes import router as configuration_counts

    app.include_router(configuration_counts)
    from appchi.maintenance.routes import router as maintenance

    app.include_router(maintenance)
    from appchi.correlation.routes import router as correlation

    app.include_router(correlation)
    from appchi.operators.routes import router as operators

    app.include_router(operators)
    app.include_router(incidents)
    app.include_router(tenants)
    from appchi.identity.selection import router as directory_selection

    app.include_router(directory_selection)
    from appchi.admin_operations import router as administration

    app.include_router(administration)
    from appchi.search_routes import router as search

    app.include_router(search)
    from appchi.cel.routes import router as cel_tools

    app.include_router(cel_tools)
    from appchi.live import router as live

    app.include_router(live)
    from appchi.visibility.routes import router as visibility_registry

    app.include_router(visibility_registry)
    return app


app = create_app()
