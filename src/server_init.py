import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.data.factory.decision_params import DecisionParamsFactory
from src.api.decision_route import DecisionRoute
from src.api.params_route import ParamsRoute
from src.api.auth_event_route import AuthEventRoute
from src.api.health_route import HealthRoute
from src.api.monitoring_route import MonitoringRoute

from src.core.logger import setup_logging
from src.core.database import get_db
from src.core.redis import check_redis, get_redis
from src.utils.info_provider import ip_intel

from src.data.model import Base
from src.utils.synchronization import enforce_single_execution

from src.core.exception_handler import register_exception_handlers

import asyncio


@asynccontextmanager
async def lifespan(app: FastAPI):
    await __on_startup()
    try:
        yield
    finally:
        await __on_shutdown()


app = FastAPI(lifespan=lifespan)

# Configure logging before anything below can emit a log record (notably
# register_exception_handlers' own "initialized" message), so it isn't
# silently dropped by the unconfigured root logger.
setup_logging()

# Must run here, before the app serves its first ASGI scope (including the
# `lifespan` scope itself) — Starlette builds its middleware stack, which
# snapshots the exception_handlers dict, on that very first scope. Handlers
# registered later (e.g. from inside the "startup" event, as this used to
# do) are added to the dict too late: the already-built ServerErrorMiddleware
# / ExceptionMiddleware instances never see them, so every error silently
# falls through to Starlette's generic plain-text 500 instead of the
# specific status codes (400/401/408/429) defined below.
register_exception_handlers(app)


@enforce_single_execution(lock_key="recomputing", block=False, timeout=240)
async def __self_init_tasks_schedule(): ...


# recompute ML models (every new 10+ authentications)

# recompute parameter distributions (every new 10+ authentications)


async def __init():
    async def __init_singletons():
        """
        Initialize all the dependencies that are required for the application to
        run.

        This services are singletons and are initialized only at startup level per
        application runner.

        Async methods are not required for all dependencies initialization, but when
        creating sessions the calling method should be async.
        """
        _ = get_db()
        _ = get_redis()
        await check_redis()

        logging.info("Database and redis singletons created!")

    @enforce_single_execution(lock_key="global_lock", block=True, timeout=600)
    async def __init_health_check():

        await DecisionParamsFactory.ensure_default_params_exist()
        r = get_redis()
        await r.set(name="init_redis", value="Redis running!", ex=30)
        init_redis = await r.get(name="init_redis")
        logging.info(f"Redis working: {init_redis}")

    await __init_singletons()
    await __init_health_check()

    # Report which IP intelligence providers are active and what data actually
    # loaded. Logged at startup rather than left to be discovered per lookup,
    # because "the bundle is missing" and "we are calling a third party" are both
    # things an operator needs to see before the first login, not after.
    ip_intel.log_startup_state()

    logging.info("Initialization process completed!")


async def __on_startup():
    global app

    try:
        await __init()

        logging.info("Starting endpoints...")

        decision_controller = DecisionRoute()
        params_route = ParamsRoute()
        auth_event_route = AuthEventRoute()
        health_route = HealthRoute()
        monitoring_route = MonitoringRoute()

        app.include_router(decision_controller.router)
        app.include_router(params_route.router)
        app.include_router(auth_event_route.router)
        app.include_router(health_route.router)
        app.include_router(monitoring_route.router)

        asyncio.create_task(__self_init_tasks_schedule())

    except Exception as e:
        logging.error(f"Error on startup: {e}")
        sys.exit(1)

    logging.info("All endpoints initialized.")


async def __on_shutdown():
    logging.info("Shutting down application.")
