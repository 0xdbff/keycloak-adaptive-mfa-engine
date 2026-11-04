import asyncio
import time

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from src.core.config.environment import HEALTH_CHECK_TIMEOUT
from src.core.database import DB
from src.core.redis import new_health_redis
from src.utils.auth.dependency import require_auth
from src.utils.info_provider.ip_intel import report

# How many abandoned checks can be outstanding per dependency during an outage.
MAX_RUNNING_CHECKS = 3
# Driver timeouts normally end a stuck check within seconds. One that outlives
# this stops counting towards the limit, so a check that never ends cannot keep
# /health at 503 until the engine restarts.
STUCK_CHECK_SECONDS = 30.0
# /health is unauthenticated and each check opens a connection, so a burst of
# calls shares one result instead of becoming a burst of database logins.
MIN_CHECK_INTERVAL = 1.0


class HealthRoute:
    def __init__(self):
        self.router = APIRouter()
        self._running: dict = {}
        self._latest: dict = {}

        self.router.add_api_route(
            "/health",
            self.health_check,
            methods=["GET"],
        )
        # The plain /health above answers liveness for anyone who can reach it
        # (Docker/orchestrator probes, the e2e preflight check, an operator's
        # curl) with no credential required, so it must never carry more than
        # a summary word. The full diagnostic inventory -- absolute filesystem
        # paths, database ages, loaded-category labels, hosting ASN counts --
        # is real reconnaissance value to an attacker and is only available
        # here, behind the same bearer-token check /decision and
        # /params_config already require.
        self.router.add_api_route(
            "/health/detail",
            self.health_detail,
            methods=["GET"],
            dependencies=[Depends(require_auth)],
        )

    @staticmethod
    async def _ping_db() -> None:
        async_session = DB.get_health_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")
        async with async_session() as session:
            await session.execute(text("SELECT 1"))

    @staticmethod
    async def _ping_redis() -> None:
        client = new_health_redis()
        try:
            await client.ping()
        finally:
            await client.aclose()

    async def _status(self, check) -> str:
        """`ok`, or `error` if the check fails or outlasts the deadline.

        A dependency that accepts the connection and then says nothing would
        otherwise hold the probe for a driver timeout, or forever, and the
        caller would see a timeout rather than which dependency is down.

        A check that outlasts the deadline is abandoned, never cancelled.
        Cancelling closes the connection while a thread is still inside the ODBC
        driver, which segfaults the process, so `asyncio.wait_for` would turn a
        database outage into an engine crash. It also waits for the cleanup,
        which blocks on the same hung connection.

        An abandoned check can stay stuck on a dead socket after the dependency
        is back, so a call only shares a check from the last MIN_CHECK_INTERVAL,
        and otherwise starts a new one. MAX_RUNNING_CHECKS limits how many can pile
        up during an outage. Checks use their own connections with short timeouts,
        so stuck ones normally end within seconds and never hold a slot in the
        shared pool.
        """
        now = time.monotonic()
        task, started = self._latest.get(check, (None, now))
        if task is None or now - started >= MIN_CHECK_INTERVAL:
            running = [
                entry for entry in self._running.get(check, []) if not entry[0].done()
            ]
            self._running[check] = running
            counted = sum(now - begun < STUCK_CHECK_SECONDS for _, begun in running)
            if counted >= MAX_RUNNING_CHECKS:
                return "error"
            task = asyncio.create_task(check())
            # Marks the outcome as read when no call is still waiting for it.
            task.add_done_callback(lambda t: t.cancelled() or t.exception())
            started = now
            running.append((task, started))
            self._latest[check] = (task, started)

        done, _ = await asyncio.wait(
            {task}, timeout=max(0, HEALTH_CHECK_TIMEOUT - (now - started))
        )
        if not done or task.cancelled() or task.exception():
            return "error"
        return "ok"

    async def _check_db_and_redis(self) -> tuple[str, str]:
        db_status, redis_status = await asyncio.gather(
            self._status(self._ping_db), self._status(self._ping_redis)
        )
        return db_status, redis_status

    async def health_check(self) -> JSONResponse:
        db_status, redis_status = await self._check_db_and_redis()

        # Readiness depends on the database and Redis only. The IP data block below
        # is reported, never enforced: it describes data files, and a stale or missing
        # one degrades a single risk signal rather than breaking authentication.
        # Failing readiness on it would drain an engine that is authenticating people
        # correctly, and on an air-gapped site that cannot refresh on demand there
        # would be no remedy available.
        all_ok = db_status == "ok" and redis_status == "ok"
        status_code = 200 if all_ok else 503

        return JSONResponse(
            status_code=status_code,
            content={
                "status": "ok" if all_ok else "degraded",
                "db": db_status,
                "redis": redis_status,
                # status_only() swallows its own errors and carries no detail
                # beyond the summary word -- see its docstring and the
                # comment at this router's registration above.
                "ip_data": report.status_only(),
            },
        )

    async def health_detail(self) -> JSONResponse:
        db_status, redis_status = await self._check_db_and_redis()
        all_ok = db_status == "ok" and redis_status == "ok"

        return JSONResponse(
            status_code=200 if all_ok else 503,
            content={
                "status": "ok" if all_ok else "degraded",
                "db": db_status,
                "redis": redis_status,
                # snapshot() swallows its own errors, so this cannot make the
                # endpoint fail. It is the same snapshot the startup log reports.
                "ip_data": report.snapshot(),
            },
        )
