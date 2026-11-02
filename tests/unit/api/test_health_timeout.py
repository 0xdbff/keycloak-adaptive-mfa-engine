"""`/health` must answer while a dependency hangs.

An orchestrator probe has its own short deadline. A dependency that accepts the
connection and then says nothing would otherwise hold the probe until a driver
timeout, or forever, and the probe would report a timeout rather than the 503
that says which dependency is down.
"""

import asyncio
import json
import time

import pytest
from sqlalchemy.pool import NullPool

from src.api import health_route as health_module
from src.api.health_route import HealthRoute
from src.core import database
from src.core import redis as redis_module
from src.core.database import DatabaseConnection

DEADLINE = 0.2


class Session:
    def __init__(self, hang: bool):
        self.hang = hang

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *args, **kwargs):
        if self.hang:
            await asyncio.Event().wait()


class Redis:
    def __init__(self, hang: bool):
        self.hang = hang

    async def ping(self):
        if self.hang:
            await asyncio.Event().wait()

    async def aclose(self):
        pass


def _backends(monkeypatch, db_hangs: bool, redis_hangs: bool) -> None:
    class SessionMaker:
        def __call__(self):
            return Session(db_hangs)

    monkeypatch.setattr(health_module, "async_sessionmaker", SessionMaker)
    monkeypatch.setattr(health_module.DB, "get_health_session", lambda: SessionMaker())
    monkeypatch.setattr(health_module, "new_health_redis", lambda: Redis(redis_hangs))
    monkeypatch.setattr(health_module, "HEALTH_CHECK_TIMEOUT", DEADLINE)
    monkeypatch.setattr(health_module, "MIN_CHECK_INTERVAL", 0)
    monkeypatch.setattr(health_module.report, "status_only", lambda: {"status": "ok"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "db_hangs, redis_hangs, db, redis",
    [
        (True, False, "error", "ok"),
        (False, True, "ok", "error"),
        (True, True, "error", "error"),
    ],
)
async def test_a_hung_dependency_is_reported_within_the_deadline(
    monkeypatch, db_hangs, redis_hangs, db, redis
):
    _backends(monkeypatch, db_hangs, redis_hangs)
    started = time.monotonic()
    response = await asyncio.wait_for(HealthRoute().health_check(), timeout=5)
    elapsed = time.monotonic() - started

    body = json.loads(response.body)
    assert response.status_code == 503
    assert (body["db"], body["redis"]) == (db, redis)
    # Both checks share one deadline, so two hung dependencies do not add up.
    assert elapsed < DEADLINE * 2


@pytest.mark.asyncio
async def test_healthy_dependencies_still_report_ok(monkeypatch):
    _backends(monkeypatch, False, False)
    response = await HealthRoute().health_check()
    body = json.loads(response.body)
    assert response.status_code == 200
    assert (body["db"], body["redis"]) == ("ok", "ok")


@pytest.mark.asyncio
async def test_a_hung_check_is_abandoned_not_cancelled(monkeypatch):
    """Cancelling a call inside the ODBC driver segfaults the engine."""
    _backends(monkeypatch, False, False)
    release = asyncio.Event()
    started, finished, cancelled = [], [], []

    async def hung_db(*args):
        started.append(1)
        try:
            await release.wait()
            finished.append(1)
        except asyncio.CancelledError:
            cancelled.append(1)
            raise

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(hung_db))
    route = HealthRoute()

    assert (await route.health_check()).status_code == 503
    assert not cancelled

    release.set()
    await asyncio.sleep(0)
    assert (await route.health_check()).status_code == 200
    assert finished and not cancelled


@pytest.mark.asyncio
async def test_a_check_stuck_on_a_dead_socket_does_not_hold_back_recovery(monkeypatch):
    """After a silent connection drop the first check hangs for minutes.

    The next call must not wait on it, or /health stays at 503 long after the
    dependency is back.
    """
    _backends(monkeypatch, False, False)
    never = asyncio.Event()
    calls = []

    async def db(*args):
        calls.append(1)
        if len(calls) == 1:
            await never.wait()

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(db))
    route = HealthRoute()

    assert (await route.health_check()).status_code == 503

    started = time.monotonic()
    response = await route.health_check()
    assert response.status_code == 200
    assert time.monotonic() - started < DEADLINE / 2


@pytest.mark.asyncio
async def test_hung_checks_are_capped(monkeypatch):
    _backends(monkeypatch, False, False)
    never = asyncio.Event()
    started, cancelled = [], []

    async def hung_db(*args):
        started.append(1)
        try:
            await never.wait()
        except asyncio.CancelledError:
            cancelled.append(1)
            raise

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(hung_db))
    route = HealthRoute()

    for _ in range(health_module.MAX_RUNNING_CHECKS):
        assert (await route.health_check()).status_code == 503
    assert len(started) == health_module.MAX_RUNNING_CHECKS

    begun = time.monotonic()
    assert (await route.health_check()).status_code == 503
    assert time.monotonic() - begun < DEADLINE * 2
    assert len(started) == health_module.MAX_RUNNING_CHECKS
    assert not cancelled


@pytest.mark.asyncio
async def test_concurrent_calls_share_one_check(monkeypatch):
    _backends(monkeypatch, False, False)
    monkeypatch.setattr(health_module, "MIN_CHECK_INTERVAL", 60)
    release = asyncio.Event()
    started = []

    async def slow_db(*args):
        started.append(1)
        await release.wait()

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(slow_db))
    route = HealthRoute()

    calls = [asyncio.create_task(route.health_check()) for _ in range(5)]
    await asyncio.sleep(0.01)
    release.set()
    responses = await asyncio.gather(*calls)
    assert [r.status_code for r in responses] == [200] * 5
    assert len(started) == 1


@pytest.mark.asyncio
async def test_a_call_joining_a_check_gets_only_what_is_left_of_its_deadline(monkeypatch):
    _backends(monkeypatch, True, False)
    monkeypatch.setattr(health_module, "MIN_CHECK_INTERVAL", 60)
    route = HealthRoute()
    begun = time.monotonic()
    first = asyncio.create_task(route.health_check())
    await asyncio.sleep(DEADLINE * 0.75)
    second = await route.health_check()
    await first
    assert second.status_code == 503
    assert time.monotonic() - begun < DEADLINE * 1.2


@pytest.mark.asyncio
async def test_a_call_after_the_sharing_window_does_not_join_a_doomed_check(monkeypatch):
    """A doomed check must not hold back the first probe after recovery."""
    _backends(monkeypatch, False, False)
    monkeypatch.setattr(health_module, "MIN_CHECK_INTERVAL", DEADLINE / 4)
    calls = []

    async def db(*args):
        calls.append(1)
        if len(calls) == 1:
            await asyncio.Event().wait()

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(db))
    route = HealthRoute()
    first = asyncio.create_task(route.health_check())
    await asyncio.sleep(DEADLINE / 2)
    begun = time.monotonic()
    assert (await route.health_check()).status_code == 200
    assert time.monotonic() - begun < DEADLINE / 4
    await first


@pytest.mark.asyncio
async def test_a_failure_is_reused_only_inside_the_sharing_window(monkeypatch):
    _backends(monkeypatch, False, False)
    monkeypatch.setattr(health_module, "MIN_CHECK_INTERVAL", 0.05)
    outcomes = [RuntimeError("down"), None]

    async def flaky_db(*args):
        outcome = outcomes.pop(0)
        if outcome:
            raise outcome

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(flaky_db))
    route = HealthRoute()
    assert (await route.health_check()).status_code == 503
    assert (await route.health_check()).status_code == 503
    await asyncio.sleep(0.06)
    assert (await route.health_check()).status_code == 200


@pytest.mark.asyncio
async def test_checks_that_never_end_cannot_hold_health_down_for_good(monkeypatch):
    """A driver can leave a check pending forever. The cap must not outlive that."""
    _backends(monkeypatch, False, False)
    monkeypatch.setattr(health_module, "STUCK_CHECK_SECONDS", DEADLINE * 5)
    stuck = health_module.MAX_RUNNING_CHECKS
    calls = []

    async def db(*args):
        calls.append(1)
        if len(calls) <= stuck:
            await asyncio.Event().wait()

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(db))
    route = HealthRoute()
    for _ in range(stuck):
        assert (await route.health_check()).status_code == 503

    # At the cap: no new check starts.
    assert (await route.health_check()).status_code == 503
    assert len(calls) == stuck

    await asyncio.sleep(DEADLINE * 5)
    assert (await route.health_check()).status_code == 200


@pytest.mark.asyncio
async def test_finished_checks_do_not_accumulate(monkeypatch):
    _backends(monkeypatch, False, False)
    route = HealthRoute()
    for _ in range(20):
        assert (await route.health_check()).status_code == 200
    assert all(len(entries) <= 1 for entries in route._running.values())


@pytest.mark.asyncio
async def test_recovery_is_seen_after_a_failed_check(monkeypatch):
    _backends(monkeypatch, False, False)
    outcomes = [RuntimeError("down"), None]

    async def flaky_db(*args):
        outcome = outcomes.pop(0)
        if outcome:
            raise outcome

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(flaky_db))
    route = HealthRoute()
    assert (await route.health_check()).status_code == 503
    assert (await route.health_check()).status_code == 200


@pytest.mark.asyncio
async def test_a_burst_of_calls_shares_one_recent_result(monkeypatch):
    """/health is unauthenticated, and each check is a database login."""
    _backends(monkeypatch, False, False)
    monkeypatch.setattr(health_module, "MIN_CHECK_INTERVAL", 60)
    calls = []

    async def db(*args):
        calls.append(1)

    monkeypatch.setattr(HealthRoute, "_ping_db", staticmethod(db))
    route = HealthRoute()
    for _ in range(10):
        assert (await route.health_check()).status_code == 200
    assert len(calls) == 1


def test_health_checks_do_not_use_the_shared_pool():
    """A shared pool can hand a check a dead socket, and a stuck check holds a slot."""
    connection = DatabaseConnection("postgresql://u:p@db.example.test:5432/amfa")
    assert isinstance(connection.health_engine.pool, NullPool)
    assert connection.health_engine is not connection.engine


def test_health_connections_give_up_at_the_deadline(monkeypatch):
    monkeypatch.setattr(database, "HEALTH_CHECK_TIMEOUT", 2.5)
    assert database._health_connect_args("postgresql+asyncpg://db") == {
        "timeout": 2.5,
        "command_timeout": 2.5,
    }
    # pyodbc takes whole seconds, and 0 would mean no timeout at all.
    assert database._health_connect_args("mssql+aioodbc://db")["timeout"] == 3
    monkeypatch.setattr(database, "HEALTH_CHECK_TIMEOUT", 0.2)
    assert database._health_connect_args("mssql+aioodbc://db")["timeout"] == 1


@pytest.mark.asyncio
async def test_the_redis_client_is_closed_after_each_check(monkeypatch):
    """Keeping one would hand the next check a connection on a dead socket."""
    _backends(monkeypatch, False, False)
    made = []

    class Client(Redis):
        def __init__(self):
            super().__init__(False)
            self.closed = False
            made.append(self)

        async def aclose(self):
            self.closed = True

    monkeypatch.setattr(health_module, "new_health_redis", Client)
    route = HealthRoute()
    await route.health_check()
    await asyncio.sleep(0)
    await route.health_check()
    assert len(made) == 2 and all(c.closed for c in made)


def test_the_health_redis_client_times_out():
    kwargs = redis_module.new_health_redis().connection_pool.connection_kwargs
    assert kwargs["socket_timeout"] == redis_module.environment.HEALTH_CHECK_TIMEOUT
    assert kwargs["socket_connect_timeout"] == redis_module.environment.HEALTH_CHECK_TIMEOUT
