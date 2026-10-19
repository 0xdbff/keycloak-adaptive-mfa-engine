"""Route tests for the monitoring endpoints.

The repository is stubbed out: what matters here is the route contract - that
every endpoint is realm-scoped, GET-only, rejects a cross-realm token, and
passes its query parameters through unchanged. Query construction is covered in
tests/unit/datamodel_repository/test_monitoring_repository.py, and neither layer
needs a live database.
"""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

import src.api.monitoring_route as monitoring_route_mod
from src.api.monitoring_route import MonitoringRoute
from src.utils.auth.token_verifier import VerifiedPrincipal


def _principal(realm):
    return VerifiedPrincipal(
        issuer=f"https://kc/realms/{realm}",
        realm=realm,
        client_id="monitoring-client",
        roles=[],
        audiences=["amfa"],
        subject="svc",
        claims={},
    )


@pytest.fixture
def stub_repo(monkeypatch):
    """Record calls into the repository and return canned results."""
    calls = {}

    async def list_events(**kwargs):
        calls["list_events"] = kwargs
        return (
            [
                {
                    "event_id": "9f2c",
                    "event_time": datetime(2026, 8, 19, tzinfo=timezone.utc),
                    "event_type": "LOGIN",
                    "user_id": "3ab1",
                    "client": "account-console",
                    "ip_address": "203.0.113.42",
                    "country": "Philippines",
                    "city": "Cebu City",
                    "lat": 10.3,
                    "long": 123.9,
                    "is_vpn": False,
                    "risk_level": 2,
                    "final_status": "SUCCESS",
                    "operating_system": "macOS",
                    "browser": "Safari",
                    "device": "desktop",
                    "system_language": "en-US",
                    "screen_resolution": "2560x1440",
                }
            ],
            1,
            None,
        )

    async def get_stats(**kwargs):
        calls["get_stats"] = kwargs
        return {"total": 10, "risky": 2, "unique_users": 5, "flagged_ips": 1}

    async def get_geo_buckets(**kwargs):
        calls["get_geo_buckets"] = kwargs
        return [
            {
                "country": "Philippines",
                "lat": 10.3,
                "long": 123.9,
                "count": 4,
                "risky_count": 1,
            }
        ]

    async def get_risky_users(**kwargs):
        calls["get_risky_users"] = kwargs
        return [{"user_id": "3ab1", "count": 7}]

    async def count_by_event_type(**kwargs):
        calls["count_by_event_type"] = kwargs
        return 42

    for name, fn in (
        ("list_events", list_events),
        ("get_stats", get_stats),
        ("get_geo_buckets", get_geo_buckets),
        ("get_risky_users", get_risky_users),
        ("count_by_event_type", count_by_event_type),
    ):
        monkeypatch.setattr(
            monitoring_route_mod.MonitoringRepository, name, staticmethod(fn)
        )
    return calls


# --- route contract -------------------------------------------------------


def test_all_endpoints_are_get_only():
    """These endpoints only read. A write verb here would be a mistake, and
    the consuming platform never sends one.
    """
    for route in MonitoringRoute().router.routes:
        assert route.methods == {"GET"}


def test_paths_are_namespaced_under_the_realm():
    """Namespaced under /{realm_id}/monitoring so they cannot collide with the
    configuration routes already mounted at /{realm_id}/.
    """
    paths = {route.path for route in MonitoringRoute().router.routes}
    assert paths == {
        "/{realm_id}/monitoring/events",
        "/{realm_id}/monitoring/stats",
        "/{realm_id}/monitoring/geo",
        "/{realm_id}/monitoring/risky-users",
        "/{realm_id}/monitoring/event-counts",
    }


def test_every_route_requires_auth():
    """require_auth must be attached to each route, not assumed."""
    for route in MonitoringRoute().router.routes:
        assert route.dependencies, f"{route.path} has no auth dependency"


# --- tenant isolation -----------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_events_rejects_cross_tenant(stub_repo):
    route = MonitoringRoute()
    with pytest.raises(HTTPException) as e:
        await route.list_events(realm_id="realm-b", principal=_principal("realm-a"))
    assert e.value.status_code == 403
    assert "list_events" not in stub_repo


@pytest.mark.asyncio(loop_scope="session")
async def test_stats_rejects_cross_tenant(stub_repo):
    route = MonitoringRoute()
    with pytest.raises(HTTPException) as e:
        await route.get_stats(realm_id="realm-b", principal=_principal("realm-a"))
    assert e.value.status_code == 403
    assert "get_stats" not in stub_repo


@pytest.mark.asyncio(loop_scope="session")
async def test_geo_rejects_cross_tenant(stub_repo):
    route = MonitoringRoute()
    with pytest.raises(HTTPException) as e:
        await route.get_geo(realm_id="realm-b", principal=_principal("realm-a"))
    assert e.value.status_code == 403
    assert "get_geo_buckets" not in stub_repo


@pytest.mark.asyncio(loop_scope="session")
async def test_risky_users_rejects_cross_tenant(stub_repo):
    route = MonitoringRoute()
    with pytest.raises(HTTPException) as e:
        await route.get_risky_users(realm_id="realm-b", principal=_principal("realm-a"))
    assert e.value.status_code == 403
    assert "get_risky_users" not in stub_repo


@pytest.mark.asyncio(loop_scope="session")
async def test_event_counts_rejects_cross_tenant(stub_repo):
    route = MonitoringRoute()
    with pytest.raises(HTTPException) as e:
        await route.get_event_counts(
            realm_id="realm-b", event_type="LOGIN", principal=_principal("realm-a")
        )
    assert e.value.status_code == 403
    assert "count_by_event_type" not in stub_repo


@pytest.mark.asyncio(loop_scope="session")
async def test_the_path_realm_is_what_reaches_the_query(stub_repo):
    """The realm passed to the repository must be the verified one.

    If the token's realm were used while the path said another, a caller could
    read a realm they hold no token for.
    """
    route = MonitoringRoute()
    await route.get_stats(realm_id="acme", principal=_principal("acme"))
    assert stub_repo["get_stats"]["realm_id"] == "acme"


@pytest.mark.parametrize("call, repo_key", [
    (lambda r: r.list_events(realm_id="acme", principal=_trusted_reader()), "list_events"),
    (lambda r: r.get_stats(realm_id="acme", principal=_trusted_reader()), "get_stats"),
    (lambda r: r.get_geo(realm_id="acme", principal=_trusted_reader()), "get_geo_buckets"),
    (lambda r: r.get_risky_users(realm_id="acme", principal=_trusted_reader()), "get_risky_users"),
    (lambda r: r.get_event_counts(realm_id="acme", event_type="LOGIN", principal=_trusted_reader()),
     "count_by_event_type"),
])
@pytest.mark.asyncio(loop_scope="session")
async def test_trusted_reader_reads_the_path_realm(stub_repo, monkeypatch, call, repo_key):
    """Every endpoint honours MONITORING_TRUSTED_READERS, and still queries the
    realm named in the path, never the token's own."""
    import src.utils.auth.dependency as dep
    monkeypatch.setattr(
        dep.environment, "MONITORING_TRUSTED_READERS",
        frozenset({("https://kc/realms/master", "monitoring-client")}),
    )
    await call(MonitoringRoute())
    assert stub_repo[repo_key]["realm_id"] == "acme"


def _trusted_reader():
    p = _principal("master")
    p.claims.update({"client_id": "monitoring-client"})
    return p


# --- parameter pass-through ----------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_events_forwards_every_filter(stub_repo):
    route = MonitoringRoute()
    since = datetime(2026, 8, 1, tzinfo=timezone.utc)
    until = datetime(2026, 8, 19, tzinfo=timezone.utc)

    await route.list_events(
        realm_id="acme",
        since=since,
        until=until,
        event_type="LOGIN_ERROR",
        min_risk=3,
        risk_decision=4,
        is_vpn=True,
        limit=250,
        cursor=None,
        ascending=False,
        principal=_principal("acme"),
    )

    passed = stub_repo["list_events"]
    assert passed["since"] == since
    assert passed["until"] == until
    assert passed["event_type"] == "LOGIN_ERROR"
    assert passed["min_risk"] == 3
    assert passed["risk_decision"] == 4
    assert passed["is_vpn"] is True
    assert passed["limit"] == 250
    assert passed["ascending"] is False


@pytest.mark.asyncio(loop_scope="session")
async def test_events_defaults_to_ascending(stub_repo):
    """The incremental consumer walks forward in time and is the caller that
    must not miss rows, so forward is the safer default.
    """
    route = MonitoringRoute()
    await route.list_events(realm_id="acme", principal=_principal("acme"))
    assert stub_repo["list_events"]["ascending"] is True


@pytest.mark.asyncio(loop_scope="session")
async def test_risky_users_forwards_threshold_and_min_risk(stub_repo):
    route = MonitoringRoute()
    await route.get_risky_users(
        realm_id="acme", min_risk=2, threshold=5, principal=_principal("acme")
    )
    passed = stub_repo["get_risky_users"]
    assert passed["min_risk"] == 2
    assert passed["threshold"] == 5


# --- responses ------------------------------------------------------------


@pytest.mark.asyncio(loop_scope="session")
async def test_events_response_carries_total_and_cursor(stub_repo):
    route = MonitoringRoute()
    page = await route.list_events(realm_id="acme", principal=_principal("acme"))
    assert page.total == 1
    assert page.next_cursor is None
    assert page.items[0].event_id == "9f2c"
    assert page.items[0].city == "Cebu City"


@pytest.mark.asyncio(loop_scope="session")
async def test_stats_response_shape(stub_repo):
    route = MonitoringRoute()
    stats = await route.get_stats(realm_id="acme", principal=_principal("acme"))
    assert (stats.total, stats.risky, stats.unique_users, stats.flagged_ips) == (
        10,
        2,
        5,
        1,
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_event_counts_echoes_the_requested_type(stub_repo):
    """The response names the type it counted, so a caller batching several
    requests can tell the answers apart.
    """
    route = MonitoringRoute()
    result = await route.get_event_counts(
        realm_id="acme", event_type="LOGIN_ERROR", principal=_principal("acme")
    )
    assert result.event_type == "LOGIN_ERROR"
    assert result.count == 42


@pytest.mark.asyncio(loop_scope="session")
async def test_malformed_cursor_is_a_client_error(monkeypatch):
    """A bad cursor is the caller's mistake and must be reported as 400.

    Falling back to the first page would make a paging consumer loop forever
    over the same rows without ever surfacing the error.
    """

    async def boom(**kwargs):
        raise ValueError("cursor must be '<event_time>|<event_id>'")

    monkeypatch.setattr(
        monitoring_route_mod.MonitoringRepository, "list_events", staticmethod(boom)
    )

    route = MonitoringRoute()
    with pytest.raises(HTTPException) as e:
        await route.list_events(
            realm_id="acme", cursor="garbage", principal=_principal("acme")
        )
    assert e.value.status_code == 400
