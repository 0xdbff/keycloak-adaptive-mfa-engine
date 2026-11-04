"""The `/health` IP data block, and the guarantee that it is reported not enforced.

The block exists so an operator (or an air-gap reviewer) can see which databases
loaded, how old they are and that nothing calls out. What it must never do is
decide readiness: a stale or missing data file degrades one risk signal, while
failing readiness would drain an engine that is authenticating people correctly.
On an air-gapped site that cannot refresh on demand, that would be an outage with
no remedy available.

The full inventory (paths, ages, per-category labels, hosting ASN counts) is real
reconnaissance value to an unauthenticated caller, so it lives behind
`/health/detail` (auth enforced at the ASGI layer -- see
tests/unit/api/test_auth_wiring.py::test_health_detail_requires_auth_through_stack).
Plain `/health`, reachable by anyone, only ever carries the summary word via
report.status_only() -- never report.snapshot()'s full detail.
"""

import json

import pytest

from src.api.health_route import HealthRoute
from src.api import health_route as health_module


def body_of(response) -> dict:
    return json.loads(response.body)


@pytest.fixture
def healthy_backends(monkeypatch):
    """Database and Redis both answering, so only the IP block varies."""

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def execute(self, *args, **kwargs):
            return None

    class SessionMaker:
        def __call__(self):
            return Session()

    from sqlalchemy.ext.asyncio import async_sessionmaker

    maker = SessionMaker()
    monkeypatch.setattr(
        health_module, "async_sessionmaker", type(maker), raising=True
    )
    monkeypatch.setattr(health_module.DB, "get_health_session", staticmethod(lambda: maker))

    class Redis:
        async def ping(self):
            return True

        async def aclose(self):
            pass

    monkeypatch.setattr(health_module, "new_health_redis", lambda: Redis())


# --- plain /health: summary word only, never the full inventory ------------


@pytest.mark.asyncio
async def test_health_includes_only_the_ip_data_status(healthy_backends, monkeypatch):
    monkeypatch.setattr(health_module.report, "status_only", lambda: {"status": "ok"})

    response = await HealthRoute().health_check()
    payload = body_of(response)

    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["ip_data"] == {"status": "ok"}


@pytest.mark.asyncio
async def test_health_never_calls_the_full_snapshot(healthy_backends, monkeypatch):
    """The unauthenticated route must not even construct the detailed inventory --
    calling snapshot() by mistake here would be the exact regression this finding
    fixes, whether or not its result were then discarded."""

    def boom():
        raise AssertionError("plain /health must not call report.snapshot()")

    monkeypatch.setattr(health_module.report, "snapshot", boom)
    monkeypatch.setattr(health_module.report, "status_only", lambda: {"status": "ok"})

    response = await HealthRoute().health_check()
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_degraded_ip_data_still_returns_200(healthy_backends, monkeypatch):
    """The central guarantee. Missing IP data is not an outage."""
    monkeypatch.setattr(
        health_module.report, "status_only", lambda: {"status": "unavailable"}
    )

    response = await HealthRoute().health_check()
    payload = body_of(response)

    assert response.status_code == 200
    assert payload["status"] == "ok"  # overall readiness unaffected
    assert payload["ip_data"]["status"] == "unavailable"


@pytest.mark.asyncio
async def test_a_raising_status_only_propagates_today(healthy_backends, monkeypatch):
    """Documents actual, current behaviour: status_only() is contractually
    non-raising (see test_report.py), and health_check() does NOT add its own
    try/except around it -- a second layer of suppression here would hide a
    real defect in status_only() itself instead of surfacing it. So if
    status_only() ever did raise, this propagates uncaught (an unhandled-
    exception 500 in production), it does NOT degrade to a graceful 200/503.
    This is a characterization test, not a guarantee -- if that behaviour is
    ever deliberately hardened, update this test to match."""

    def boom():
        raise RuntimeError("reporting is broken")

    monkeypatch.setattr(health_module.report, "status_only", boom)

    with pytest.raises(RuntimeError):
        await HealthRoute().health_check()


@pytest.mark.asyncio
async def test_database_failure_still_fails_readiness(monkeypatch):
    """The reporting block must not have made readiness permissive."""

    def broken_session():
        raise RuntimeError("db down")

    monkeypatch.setattr(health_module.DB, "get_health_session", staticmethod(broken_session))

    class Redis:
        async def ping(self):
            return True

        async def aclose(self):
            pass

    monkeypatch.setattr(health_module, "new_health_redis", lambda: Redis())
    monkeypatch.setattr(health_module.report, "status_only", lambda: {"status": "ok"})

    response = await HealthRoute().health_check()
    payload = body_of(response)

    assert response.status_code == 503
    assert payload["status"] == "degraded"
    assert payload["db"] == "error"


@pytest.mark.asyncio
async def test_redis_failure_still_fails_readiness(healthy_backends, monkeypatch):
    class Redis:
        async def ping(self):
            raise RuntimeError("redis down")

    monkeypatch.setattr(health_module, "new_health_redis", lambda: Redis())
    monkeypatch.setattr(health_module.report, "status_only", lambda: {"status": "ok"})

    response = await HealthRoute().health_check()
    payload = body_of(response)

    assert response.status_code == 503
    assert payload["redis"] == "error"


@pytest.mark.asyncio
async def test_the_block_is_json_serialisable(healthy_backends):
    """The real status_only(), not a stub: JSONResponse must be able to encode it."""
    response = await HealthRoute().health_check()

    payload = body_of(response)
    assert "ip_data" in payload
    assert isinstance(payload["ip_data"]["status"], str)


# --- /health/detail: the full inventory, only reachable past auth ----------
#
# Auth enforcement itself (401 with no token) is covered at the ASGI layer in
# test_auth_wiring.py::test_health_detail_requires_auth_through_stack. These
# tests call the handler directly (bypassing FastAPI's DI, same as this
# module's plain-/health tests above) to check the RESPONSE SHAPE once past
# that gate.


@pytest.mark.asyncio
async def test_health_detail_includes_the_full_ip_data_block(
    healthy_backends, monkeypatch
):
    monkeypatch.setattr(
        health_module.report,
        "snapshot",
        lambda: {"status": "ok", "egress": "none", "geo": {}, "anonymiser": {}, "notes": []},
    )

    response = await HealthRoute().health_detail()
    payload = body_of(response)

    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["ip_data"]["status"] == "ok"
    assert payload["ip_data"]["egress"] == "none"


@pytest.mark.asyncio
async def test_health_detail_degraded_ip_data_still_returns_200(
    healthy_backends, monkeypatch
):
    monkeypatch.setattr(
        health_module.report,
        "snapshot",
        lambda: {
            "status": "unavailable",
            "egress": "none",
            "geo": {},
            "anonymiser": {"loaded": False},
            "notes": ["no anonymiser bundle: VPN and Tor detection inactive"],
        },
    )

    response = await HealthRoute().health_detail()
    payload = body_of(response)

    assert response.status_code == 200
    assert payload["status"] == "ok"  # overall readiness unaffected
    assert payload["ip_data"]["status"] == "unavailable"


@pytest.mark.asyncio
async def test_health_detail_database_failure_still_fails_readiness(monkeypatch):
    def broken_session():
        raise RuntimeError("db down")

    monkeypatch.setattr(health_module.DB, "get_health_session", staticmethod(broken_session))

    class Redis:
        async def ping(self):
            return True

        async def aclose(self):
            pass

    monkeypatch.setattr(health_module, "new_health_redis", lambda: Redis())
    monkeypatch.setattr(
        health_module.report,
        "snapshot",
        lambda: {"status": "ok", "egress": "none", "geo": {}, "anonymiser": {}, "notes": []},
    )

    response = await HealthRoute().health_detail()
    payload = body_of(response)

    assert response.status_code == 503
    assert payload["status"] == "degraded"
    assert payload["db"] == "error"


@pytest.mark.asyncio
async def test_health_detail_is_json_serialisable(healthy_backends):
    """The real snapshot(), not a stub: JSONResponse must be able to encode it,
    and the full inventory (paths/ages/labels) must actually be present here --
    the whole reason this endpoint exists separately from plain /health."""
    response = await HealthRoute().health_detail()

    payload = body_of(response)
    assert "ip_data" in payload
    assert isinstance(payload["ip_data"]["status"], str)
    assert "geo" in payload["ip_data"]
    assert "anonymiser" in payload["ip_data"]
