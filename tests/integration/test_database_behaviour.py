"""What the engine's queries return on a real server, on both dialects."""

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from src.api.health_route import HealthRoute
from src.core.config.environment import DB_TYPE, HEALTH_CHECK_TIMEOUT
from src.core.database import DB
from src.core.sql_dialect import JsonText
from src.data.model import (
    AuthContext,
    AuthEvent,
    AuthProcess,
    DecisionParamsConfig,
    Device,
    LocationNetwork,
)
from src.data.repository import monitoring_expr
from src.data.repository.decision_params_config import DecisionParamsConfigRepository
from src.data.repository.monitoring import MonitoringRepository

pytestmark = pytest.mark.asyncio(loop_scope="session")

T0 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
HASH = "a" * 64


async def _add(*rows) -> None:
    async with DB.get_session()() as session:
        session.add_all(rows)
        await session.commit()


def _config(realm: str = "prod", group: str = "default", active: bool = True):
    return DecisionParamsConfig(
        id=uuid.uuid4(),
        realm_id=realm,
        group_id=group,
        is_active=active,
        parameters={"threshold": 3},
        parameters_hash=HASH,
    )


def _auth_context(hash_value: str, **overrides) -> AuthContext:
    fields = dict(
        hash=hash_value,
        client="web",
        ip_address="192.0.2.1",
        system_language="en",
        screen_resolution="1x1",
    )
    return AuthContext(**{**fields, **overrides})


async def _seed_login(
    realm: str = "prod",
    context: dict | None = None,
    event_time: datetime = T0,
    risk: int = 1,
    event_type: str = "LOGIN",
) -> AuthEvent:
    """One login: its config, device, network, process, and event."""
    config = _config(realm=realm)
    device_hash = uuid.uuid4().hex + uuid.uuid4().hex
    network_hash = uuid.uuid4().hex + uuid.uuid4().hex
    process = AuthProcess(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        realm_id=realm,
        auth_context_hash=HASH,
        device_info_hash=device_hash,
        network_location_hash=network_hash,
        auth_context_json=context or {},
        pre_auth_risk_decision=risk,
        parameters_config_id=config.id,
        final_status="success",
    )
    event = AuthEvent(
        id=uuid.uuid4(),
        auth_process=process.id,
        user_id=process.user_id,
        realm_id=realm,
        event_type=event_type,
        event_time=event_time,
    )
    await _add(
        config,
        Device(
            hash=device_hash,
            system_language="en",
            screen_resolution="1x1",
            device="desktop",
        ),
        LocationNetwork(hash=network_hash, ip_address="192.0.2.1"),
    )
    await _add(process)
    await _add(event)
    return event


# --- login scoring: the active-config lookup runs on every login decision ---


async def test_active_config_lookup_returns_only_the_active_row():
    active = _config(active=True)
    await _add(active, _config(group="other", active=False))

    found = await DecisionParamsConfigRepository.get_active_decision_params_config(
        "prod", "default"
    )
    assert found.id == active.id
    assert found.parameters == {"threshold": 3}


async def test_inactive_config_is_not_returned():
    await _add(_config(active=False))
    found = await DecisionParamsConfigRepository.get_active_decision_params_config(
        "prod", "default"
    )
    assert found is None


async def test_listing_active_configs_for_a_realm():
    await _add(_config(group="a"), _config(group="b"), _config(group="c", active=False))
    rows = await DecisionParamsConfigRepository.get_all_active_decision_params_by_realm(
        "prod"
    )
    assert sorted(r.group_id for r in rows) == ["a", "b"]


async def test_deactivating_a_group_config():
    await _add(_config(group="a"))
    await DecisionParamsConfigRepository.deactivate_group_config("prod", "a")
    assert (
        await DecisionParamsConfigRepository.get_active_decision_params_config("prod", "a")
        is None
    )


# --- tenant isolation: Keycloak realm and group names are case-sensitive ---


async def test_realm_lookup_is_case_sensitive():
    upper = _config(realm="Prod")
    await _add(upper)
    assert (
        await DecisionParamsConfigRepository.get_active_decision_params_config(
            "prod", "default"
        )
        is None
    )
    found = await DecisionParamsConfigRepository.get_active_decision_params_config(
        "Prod", "default"
    )
    assert found.id == upper.id


async def test_group_lookup_is_case_sensitive():
    await _add(_config(group="Admins"))
    assert (
        await DecisionParamsConfigRepository.get_active_decision_params_config(
            "prod", "admins"
        )
        is None
    )


async def test_hash_comparison_is_case_sensitive():
    lower = "b" * 64
    await _add(_auth_context(lower))
    async with DB.get_session()() as session:
        upper_match = (
            await session.execute(
                select(AuthContext).where(AuthContext.hash == lower.upper())
            )
        ).scalar_one_or_none()
    assert upper_match is None


async def test_monitoring_does_not_read_another_realm_differing_by_case():
    await _seed_login(realm="Prod")
    rows, total, _ = await MonitoringRepository.list_events("prod")
    assert rows == [] and total == 0


async def test_monitoring_falls_back_to_the_process_snapshot_for_legacy_rows():
    event = await _seed_login(realm="prod", context={"realm_id": "legacy"})
    async with DB.get_session()() as session:
        row = await session.get(AuthEvent, event.id)
        row.realm_id = ""
        process = await session.get(AuthProcess, row.auth_process)
        process.realm_id = None
        await session.commit()
    rows, total, _ = await MonitoringRepository.list_events("legacy")
    assert [r["event_id"] for r in rows] == [event.id] and total == 1


# --- text survives a round trip ---


@pytest.mark.parametrize(
    "country",
    ["Россия", "日本", "Российская Федерация!", "Ελλάδα", "🇵🇹 Portugal"],
)
async def test_non_latin_country_round_trips(country):
    hash_value = uuid.uuid4().hex + uuid.uuid4().hex
    await _add(_auth_context(hash_value, country_name=country))
    async with DB.get_session()() as session:
        row = await session.get(AuthContext, hash_value)
    assert row.country_name == country


async def test_non_latin_event_details_round_trip():
    event = await _seed_login()
    async with DB.get_session()() as session:
        row = await session.get(AuthEvent, event.id)
        row.details = "Устройство 设备 日本"
        await session.commit()
    async with DB.get_session()() as session:
        assert (await session.get(AuthEvent, event.id)).details == "Устройство 设备 日本"


async def test_non_latin_realm_lookup():
    config = _config(realm="Компания")
    await _add(config)
    found = await DecisionParamsConfigRepository.get_active_decision_params_config(
        "Компания", "default"
    )
    assert found.id == config.id


async def test_json_snapshot_keeps_non_latin_text_through_monitoring():
    await _seed_login(context={"country_name": "日本", "city_name": "Москва"})
    rows, _, _ = await MonitoringRepository.list_events("prod")
    assert rows[0]["country"] == "日本"
    assert rows[0]["city"] == "Москва"


# --- dates ---


async def test_event_time_reads_back_as_the_same_utc_instant():
    await _seed_login(event_time=T0)
    rows, _, _ = await MonitoringRepository.list_events("prod")
    value = rows[0]["event_time"]
    assert value.tzinfo is not None
    assert value == T0


async def test_server_default_event_time_is_current_utc():
    before = datetime.now(timezone.utc) - timedelta(minutes=5)
    event = await _seed_login()
    async with DB.get_session()() as session:
        row = await session.get(AuthEvent, event.id)
        process = await session.get(AuthProcess, row.auth_process)
    assert process.started_at.tzinfo is not None
    assert before < process.started_at < before + timedelta(minutes=10)


# --- monitoring: every endpoint's query, executed ---


async def test_event_pages_walk_every_row_once_in_both_directions():
    events = [
        await _seed_login(event_time=T0 + timedelta(seconds=i // 2)) for i in range(7)
    ]
    for ascending in (True, False):
        seen, cursor = [], None
        while True:
            rows, _, cursor = await MonitoringRepository.list_events(
                "prod", limit=3, cursor=cursor, ascending=ascending
            )
            seen += [r["event_id"] for r in rows]
            if cursor is None:
                break
        assert sorted(seen, key=str) == sorted((e.id for e in events), key=str)
        assert len(seen) == len(set(seen))


async def test_first_page_reports_the_total_and_later_pages_skip_it():
    for i in range(3):
        await _seed_login(event_time=T0 + timedelta(seconds=i))
    rows, total, cursor = await MonitoringRepository.list_events("prod", limit=2)
    assert (len(rows), total) == (2, 3)
    rows, total, cursor = await MonitoringRepository.list_events(
        "prod", limit=2, cursor=cursor
    )
    assert (len(rows), total, cursor) == (1, -1, None)


async def test_vpn_filter_reads_the_snapshot():
    await _seed_login(context={"is_vpn": True, "ip_address": "198.51.100.1"})
    await _seed_login(context={"is_vpn": False, "ip_address": "198.51.100.2"})
    await _seed_login(context={})

    on, on_total, _ = await MonitoringRepository.list_events("prod", is_vpn=True)
    off, off_total, _ = await MonitoringRepository.list_events("prod", is_vpn=False)
    assert [r["ip_address"] for r in on] == ["198.51.100.1"] and on_total == 1
    assert off_total == 2 and len(off) == 2
    assert on[0]["is_vpn"] in (True, 1)


async def test_risk_filters():
    await _seed_login(risk=1)
    await _seed_login(risk=4)
    assert (await MonitoringRepository.list_events("prod", min_risk=3))[1] == 1
    assert (await MonitoringRepository.list_events("prod", risk_decision=1))[1] == 1


async def test_window_excludes_since_and_includes_until():
    await _seed_login(event_time=T0)
    await _seed_login(event_time=T0 + timedelta(hours=1))
    assert (await MonitoringRepository.list_events("prod", since=T0))[1] == 1
    assert (await MonitoringRepository.list_events("prod", until=T0))[1] == 1


async def test_stats():
    await _seed_login(risk=1, context={"is_vpn": True, "ip_address": "198.51.100.1"})
    await _seed_login(risk=4, context={"is_vpn": True, "ip_address": "198.51.100.1"})
    await _seed_login(risk=1, context={"is_vpn": False, "ip_address": "198.51.100.2"})
    await _seed_login(realm="other", risk=4)
    assert await MonitoringRepository.get_stats("prod") == {
        "total": 3,
        "risky": 1,
        "unique_users": 3,
        "flagged_ips": 1,
    }


async def test_geo_buckets_group_at_the_configured_precision():
    lisbon = {"country_name": "Portugal", "lat": 38.7223, "long": -9.1393}
    nearby = {"country_name": "Portugal", "lat": 38.7301, "long": -9.1412}
    tokyo = {"country_name": "日本", "lat": 35.6762, "long": 139.6503}
    await _seed_login(context=lisbon, risk=4)
    await _seed_login(context=nearby)
    await _seed_login(context=tokyo)
    await _seed_login(context={"country_name": "Nowhere", "lat": 0, "long": 0})
    await _seed_login(context={"country_name": "Unknown"})

    buckets = await MonitoringRepository.get_geo_buckets("prod")
    assert buckets == [
        {"country": "Portugal", "lat": 38.7, "long": -9.1, "count": 2, "risky_count": 1},
        {"country": "日本", "lat": 35.7, "long": 139.7, "count": 1, "risky_count": 0},
    ]


async def test_geo_buckets_round_the_stored_coordinate_only_once():
    """38.74996 is in the 38.7 cell. Rounding through 4 decimals first gave 38.8."""
    await _seed_login(context={"lat": 38.74996, "long": -9.14996})
    buckets = await MonitoringRepository.get_geo_buckets("prod")
    assert [(b["lat"], b["long"]) for b in buckets] == [(38.7, -9.1)]


@pytest.mark.parametrize(
    "precision, expected",
    [(0, (39.0, -9.0)), (1, (38.7, -9.1)), (4, (38.7223, -9.1393)), (6, (38.722312, -9.139344))],
)
async def test_geo_buckets_honour_the_configured_precision(
    monkeypatch, precision, expected
):
    monkeypatch.setattr(monitoring_expr, "GEO_PRECISION", precision)
    await _seed_login(context={"lat": 38.722312, "long": -9.139344})
    buckets = await MonitoringRepository.get_geo_buckets("prod")
    assert [(b["lat"], b["long"]) for b in buckets] == [expected]


async def test_risky_users():
    event = await _seed_login(risk=4)
    await _seed_login(risk=1)
    assert await MonitoringRepository.get_risky_users("prod") == [
        {"user_id": str(event.user_id), "count": 1}
    ]
    assert await MonitoringRepository.get_risky_users("prod", threshold=2) == []


async def test_count_by_event_type():
    await _seed_login(event_type="LOGIN")
    await _seed_login(event_type="LOGIN_ERROR")
    assert await MonitoringRepository.count_by_event_type("prod", "LOGIN") == 1


# --- SQLAlchemy's compiled cache must not cross JSON keys or bound values ---


async def test_cached_statements_do_not_cross_json_keys():
    await _seed_login(context={"country_name": "Portugal", "city_name": "Lisbon"})
    values = []
    async with DB.get_session()() as session:
        for key in ("country_name", "city_name"):
            stmt = select(JsonText(AuthProcess.auth_context_json, key))
            values.append((await session.execute(stmt)).scalar_one())
    assert values == ["Portugal", "Lisbon"]


async def test_cached_realm_filter_does_not_reuse_the_previous_realm():
    await _seed_login(realm="a")
    await _seed_login(realm="b")
    await _seed_login(realm="b")
    assert (await MonitoringRepository.list_events("a"))[1] == 1
    assert (await MonitoringRepository.list_events("b"))[1] == 2


# --- /health ---------------------------------------------------------------


async def test_the_health_check_runs_on_a_real_server_outside_the_shared_pool(
    monkeypatch,
):
    def shared_pool_used():
        raise AssertionError("/health must not use the shared pool")

    monkeypatch.setattr(DB, "get_session", shared_pool_used)
    await HealthRoute._ping_db()
    assert await HealthRoute()._status(HealthRoute._ping_db) == "ok"


async def test_a_stuck_query_on_a_health_connection_times_out():
    """The driver has to honour the timeout, not just accept the setting."""
    slow = "WAITFOR DELAY '00:00:20'" if DB_TYPE == "mssql" else "SELECT pg_sleep(20)"
    started = time.monotonic()
    with pytest.raises(Exception):
        async with DB.get_health_session()() as session:
            await session.execute(text(slow))
    assert time.monotonic() - started < HEALTH_CHECK_TIMEOUT + 3


async def test_the_real_redis_ping_closes_its_client():
    await HealthRoute._ping_redis()
