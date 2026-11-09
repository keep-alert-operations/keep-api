import json
import asyncio
from contextlib import suppress
from contextlib import asynccontextmanager
from threading import Event


from appchi.config import Settings
from appchi.db import Database


from appchi.http import create_http_app


def create_app(settings=None, db=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings()
        from appchi.workload import HTTP_ROLES

        if app.state.settings.role not in HTTP_ROLES:
            raise RuntimeError("This role does not expose an HTTP application")
        if app.state.settings.role != "product-api":
            raise RuntimeError("Use the ingestion application for ingestion roles")
        app.state.db = db or Database(
            app.state.settings.database_url.get_secret_value(),
            app.state.settings.pool_size,
            deployment_epoch=app.state.settings.deployment_epoch,
        )
        app.state.operator_db = (
            Database(
                app.state.settings.operator_database_url.get_secret_value(),
                1,
                deployment_epoch=app.state.settings.deployment_epoch,
            )
            if app.state.settings.operator_database_url
            else None
        )
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

        from elasticsearch import Elasticsearch
        from appchi.service_clients import elasticsearch_options

        app.state.search_client = (
            Elasticsearch(
                app.state.settings.elasticsearch_url,
                **elasticsearch_options(app.state.settings),
            )
            if app.state.settings.elasticsearch_url
            else None
        )
        owned_search_client = app.state.search_client

        app.state.recovery_store = None
        if app.state.settings.recovery_binding or app.state.settings.recovery_credential:
            from appchi.recovery.runtime import configured_store

            app.state.recovery_store = configured_store(app.state.settings)
        owned_recovery_store = app.state.recovery_store
        from appchi.configuration.ticket_counts import TicketCounts

        # REV-65: an invalid address is logged here and leaves ticket panels unconnected.
        app.state.ticket_counts = TicketCounts.from_settings(app.state.settings)
        app.state.live_registry = LiveRegistry()
        listener = (
            asyncio.create_task(redis_listener(app.state.settings, app.state.live_registry))
            if app.state.settings.redis_url
            else None
        )
        publisher_stop = Event()
        publisher = (
            asyncio.create_task(hint_publisher(app.state.db, app.state.settings, publisher_stop))
            if app.state.settings.redis_url
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
            await app.state.ticket_counts.close()
            if owned_recovery_store:
                owned_recovery_store.close()
            if owned_search_client:
                await asyncio.to_thread(owned_search_client.close)
            if app.state.operator_db:
                app.state.operator_db.close()
            if not db and app.state.db:
                app.state.db.close()

    app = create_http_app(lifespan, product=True)

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
    from appchi.configuration.image_routes import router as configuration_images

    app.include_router(configuration_images)
    from appchi.configuration.read_routes import router as configuration_reads

    app.include_router(configuration_reads)
    from appchi.configuration.count_routes import router as configuration_counts

    app.include_router(configuration_counts)
    from appchi.configuration.ticket_count_routes import (
        admin_router as ticket_count_administration,
        router as ticket_counts,
    )

    app.include_router(ticket_counts)
    app.include_router(ticket_count_administration)
    from appchi.maintenance.routes import router as maintenance

    app.include_router(maintenance)
    from appchi.correlation.routes import router as correlation

    app.include_router(correlation)
    from appchi.operators.routes import router as operators

    app.include_router(operators)
    app.include_router(incidents)
    from appchi.reports.incidents import router as reports

    app.include_router(reports)
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
