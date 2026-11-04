"""Query construction tests for MonitoringRepository.

These assert on the compiled SQL rather than executing it. The behaviour that
matters here is what the statement says - which realm sources it reads, whether
the sort key is total, whether the count agrees with the rows - and that is
decidable from the SQL. It also keeps the suite runnable without Postgres and
Redis, unlike the repository tests that exercise a live session.
"""

from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy.dialects import mssql, postgresql

from src.data.repository import monitoring_expr as expr

from src.data.repository.monitoring import (
    RISKY_THRESHOLD,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MonitoringRepository,
    decode_cursor,
    encode_cursor,
)


def sql(stmt) -> str:
    return str(
        stmt.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


def sql_mssql(stmt) -> str:
    return str(
        stmt.compile(
            dialect=mssql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


def test_events_query_joins_all_three_tables_outer():
    """auth_process and auth_context must both be LEFT JOINed.

    An inner join to auth_process would drop every event whose process never
    linked, and auth_context is never populated at all, so an inner join there
    would return nothing whatsoever.
    """
    s = sql(MonitoringRepository.build_events_query("acme"))
    assert s.count("LEFT OUTER JOIN") == 2
    assert "auth_process" in s and "auth_context" in s


def test_events_query_is_realm_scoped_from_both_sources():
    s = sql(MonitoringRepository.build_events_query("acme"))
    # The indexed column, the JSON snapshot for rows predating it, and the
    # event's own realm for events with no linked process.
    assert "auth_process.realm_id" in s
    assert "->> 'realm_id'" in s
    assert "auth_event.realm_id" in s
    assert "'acme'" in s


def test_events_query_orders_by_compound_key_not_time_alone():
    """The sort must be total.

    Two events can share an event_time. Ordering by event_time alone leaves
    their relative order undefined, so a consumer paging by that key can skip or
    repeat rows at a page boundary.
    """
    s = sql(MonitoringRepository.build_events_query("acme"))
    assert "ORDER BY auth_event.event_time ASC, auth_event.id ASC" in s


def test_events_query_descending_reverses_both_columns():
    s = sql(MonitoringRepository.build_events_query("acme", ascending=False))
    assert "ORDER BY auth_event.event_time DESC, auth_event.id DESC" in s


def test_cursor_uses_row_value_comparison():
    """The keyset predicate must compare the pair, not just the timestamp."""
    cursor = encode_cursor(datetime(2026, 8, 19, 4, 12, tzinfo=timezone.utc), "44444444-4444-4444-8444-444444444401")
    s = sql(MonitoringRepository.build_events_query("acme", cursor=cursor))
    assert "auth_event.event_time >" in s
    assert "OR" in s
    assert "auth_event.id >" in s


def test_cursor_direction_follows_sort_order():
    cursor = encode_cursor(datetime(2026, 8, 19, tzinfo=timezone.utc), "44444444-4444-4444-8444-444444444401")
    asc = sql(MonitoringRepository.build_events_query("acme", cursor=cursor))
    desc = sql(
        MonitoringRepository.build_events_query("acme", cursor=cursor, ascending=False)
    )
    assert "auth_event.event_time >" in asc
    assert "auth_event.event_time <" in desc


def test_mssql_cursor_expands_row_comparison():
    cursor = encode_cursor(datetime(2026, 8, 19, tzinfo=timezone.utc), "44444444-4444-4444-8444-444444444401")
    s = sql_mssql(MonitoringRepository.build_events_query("acme", cursor=cursor))
    assert "auth_event.event_time >" in s
    assert "OR" in s
    assert "(auth_event.event_time, auth_event.id)" not in s
    assert "= 1 = 1" not in s


def test_mssql_json_reads_use_json_value():
    s = sql_mssql(MonitoringRepository.build_events_query("acme", is_vpn=True))
    assert "JSON_VALUE" in s
    assert "$.client" in s
    assert "$.is_vpn" in s
    assert "->>" not in s
    assert "= 1" in s
    assert "= 1 = 1" not in s


def test_cursor_round_trips():
    when = datetime(2026, 8, 19, 4, 12, 7, 441000, tzinfo=timezone.utc)
    event_id = "44444444-4444-4444-8444-444444444401"
    got_time, got_id = decode_cursor(encode_cursor(when, event_id))
    assert got_time == when
    # Returned as a UUID: auth_event.id is a uuid column and PostgreSQL has no
    # `uuid > text` operator, so a string here fails the keyset comparison
    # outright rather than being coerced.
    assert isinstance(got_id, UUID)
    assert str(got_id) == event_id


def test_cursor_rejects_a_non_uuid_event_id():
    """A well-formed cursor carrying a non-UUID id must fail at decode.

    Left to reach the query it becomes `uuid > character varying`, which
    PostgreSQL rejects as a 500 rather than a bad request.
    """
    with pytest.raises(ValueError):
        decode_cursor("2026-08-19T00:00:00+00:00|not-a-uuid")


@pytest.mark.parametrize("bad", ["", "no-separator", "|", "2026-08-19T00:00:00Z|"])
def test_malformed_cursor_raises(bad):
    """A bad cursor must fail loudly.

    Silently restarting from the first page would make a paging consumer loop
    over the same rows forever instead of surfacing the error.
    """
    with pytest.raises(ValueError):
        decode_cursor(bad)


def test_since_is_exclusive_and_until_inclusive():
    """`since` exclusive lets a consumer pass back the last timestamp it saw."""
    s = sql(
        MonitoringRepository.build_events_query(
            "acme",
            since=datetime(2026, 8, 1, tzinfo=timezone.utc),
            until=datetime(2026, 8, 19, tzinfo=timezone.utc),
        )
    )
    assert "auth_event.event_time > " in s
    assert "auth_event.event_time <= " in s


def test_limit_is_capped():
    assert f"LIMIT {MAX_LIMIT}" in sql(
        MonitoringRepository.build_events_query("acme", limit=10_000)
    )


@pytest.mark.parametrize("bad_limit", [0, -1, None])
def test_nonpositive_limit_falls_back_to_default(bad_limit):
    assert f"LIMIT {DEFAULT_LIMIT}" in sql(
        MonitoringRepository.build_events_query("acme", limit=bad_limit)
    )


def test_min_risk_and_exact_risk_are_distinct_filters():
    """`min_risk` is a threshold; `risk_decision` matches one level exactly.

    The alert rules need both: one fires above a level, another only on
    risk-rejected logins.
    """
    at_least = sql(MonitoringRepository.build_events_query("acme", min_risk=3))
    exactly = sql(MonitoringRepository.build_events_query("acme", risk_decision=4))
    assert "pre_auth_risk_decision >= 3" in at_least
    assert "pre_auth_risk_decision = 4" in exactly


def test_is_vpn_filter_reads_through_the_fallback():
    """The VPN flag must come through the COALESCE, not auth_context alone.

    Filtering on `auth_context.is_vpn` by itself matches nothing, because that
    table is never populated.
    """
    s = sql(MonitoringRepository.build_events_query("acme", is_vpn=True))
    assert "coalesce(auth_context.is_vpn" in s
    assert "->> 'is_vpn'" in s


def test_is_vpn_false_is_not_treated_as_absent():
    """is_vpn=False must filter, not fall through as "unset"."""
    s = sql(MonitoringRepository.build_events_query("acme", is_vpn=False))
    assert "= false" in s


def test_projection_covers_every_response_field():
    s = sql(MonitoringRepository.build_events_query("acme"))
    for label in (
        "event_id", "event_time", "event_type", "user_id", "client",
        "ip_address", "country", "city", "lat", "long", "is_vpn",
        "risk_level", "final_status", "operating_system", "browser",
        "device", "system_language", "screen_resolution",
    ):
        assert f"AS {label}" in s, f"{label} missing from projection"


def test_count_query_matches_row_filters_without_paging():
    """The count must use the same predicate as the rows.

    A total computed from different filters reports a number the caller can
    never page to.
    """
    args = dict(
        realm_id="acme",
        since=datetime(2026, 8, 1, tzinfo=timezone.utc),
        event_type="LOGIN",
        min_risk=3,
        is_vpn=True,
    )
    rows = sql(MonitoringRepository.build_events_query(**args))
    count = sql(MonitoringRepository.build_events_count_query(**args))

    assert "count(*)" in count
    assert "LIMIT" not in count
    assert "ORDER BY" not in count
    for fragment in (
        "auth_event.event_time > ",
        "auth_event.event_type = 'LOGIN'",
        "pre_auth_risk_decision >= 3",
    ):
        assert fragment in rows and fragment in count


def test_count_query_ignores_the_cursor():
    """Paging position must not change the total."""
    plain = sql(MonitoringRepository.build_events_count_query("acme"))
    assert "auth_event.id" not in plain.split("FROM")[0]


# --- aggregates -----------------------------------------------------------


def test_stats_counts_distinct_ips_not_events():
    """flagged_ips answers "how many anonymising addresses", not "how many
    VPN logins". One address generating a hundred logins is one address.
    """
    s = sql(MonitoringRepository.build_stats_query("acme"))
    flagged = s.split("AS flagged_ips")[0].split(", count")[-1]
    assert "distinct" in flagged
    assert "CASE WHEN" in flagged
    assert "ip_address" in flagged
    # The VPN condition selects which IPs to count; it must not degrade into
    # counting VPN events.
    assert "is_vpn" in flagged


def test_stats_vpn_and_ip_both_read_through_the_fallback():
    """Reading auth_context.is_vpn / ip_address alone makes this KPI
    permanently zero, because that table is never populated.
    """
    s = sql(MonitoringRepository.build_stats_query("acme"))
    assert "->> 'is_vpn'" in s
    assert "->> 'ip_address'" in s


def test_stats_risky_uses_the_shared_threshold():
    s = sql(MonitoringRepository.build_stats_query("acme"))
    assert f"pre_auth_risk_decision >= {RISKY_THRESHOLD}" in s


def test_stats_all_four_kpis_share_one_window():
    """A KPI scoped to a different window than its siblings reads as zero for
    any window not ending now.
    """
    s = sql(
        MonitoringRepository.build_stats_query(
            "acme",
            since=datetime(2026, 8, 1, tzinfo=timezone.utc),
            until=datetime(2026, 8, 19, tzinfo=timezone.utc),
        )
    )
    # One pair of bounds for the whole statement, not per-aggregate filters.
    assert s.count("auth_event.event_time > ") == 1
    assert s.count("auth_event.event_time <= ") == 1
    for label in ("total", "risky", "unique_users", "flagged_ips"):
        assert f"AS {label}" in s


def test_stats_without_realm_requires_all_tenants_confirmation():
    """realm_id=None is refused unless the caller explicitly opts in.

    No route calls this with realm_id=None today; the flag exists so a
    future caller can't reach the all-realms shape by accident.
    """
    with pytest.raises(ValueError):
        MonitoringRepository.build_stats_query(None)


def test_stats_without_realm_still_requires_a_realm():
    """All-realms must exclude rows with no realm at all.

    An event whose auth_process never linked has no tenant attribution;
    counting it would inflate the KPIs above what any realm-scoped listing
    of the same window can show.
    """
    s = sql(MonitoringRepository.build_stats_query(None, all_tenants=True))
    assert "IS NOT NULL" in s
    assert "'acme'" not in s


def test_stats_with_realm_is_scoped():
    s = sql(MonitoringRepository.build_stats_query("acme"))
    assert "'acme'" in s


def test_geo_groups_by_the_rounded_cell_not_the_raw_coordinate():
    """Grouping by the raw coordinate yields one bucket per distinct location,
    which defeats bucketing entirely. Rounding lives in a subquery so SQL
    Server sees one expression, not two bind copies of it.
    """
    s = sql(MonitoringRepository.build_geo_query("acme"))
    assert "NUMERIC(9, 1)" in s
    group_by = s.split("GROUP BY")[1]
    assert "lat" in group_by
    assert "long" in group_by
    assert "NUMERIC" not in group_by


def test_mssql_geo_groups_by_subquery_columns():
    s = sql_mssql(MonitoringRepository.build_geo_query("acme"))
    assert "NUMERIC(9, 1)" in s
    group_by = s.split("GROUP BY")[1]
    assert "NUMERIC" not in group_by
    assert "= 1 = 1" not in s


def test_geo_scale_follows_the_configured_precision(monkeypatch):
    """The precision used to be capped by a fixed intermediate scale of 4."""
    monkeypatch.setattr(expr, "GEO_PRECISION", 6)
    assert "NUMERIC(14, 6)" in sql(MonitoringRepository.build_geo_query("acme"))
    assert "NUMERIC(14, 6)" in sql_mssql(MonitoringRepository.build_geo_query("acme"))


def test_geo_precision_is_not_a_bind_parameter():
    """Binds in the rounding are what made SQL Server reject the GROUP BY."""
    cell = expr.geo_cell(expr.AuthContext.lat).compile(dialect=mssql.dialect())
    assert not cell.params


def test_geo_excludes_the_zero_zero_sentinel():
    """The geo helper writes 0,0 when a lookup fails, which is normal for a
    private address. Treating it as a location piles every un-geolocatable
    login onto one marker in the Gulf of Guinea.
    """
    s = sql(MonitoringRepository.build_geo_query("acme"))
    assert "!= 0" in s or "NOT (" in s
    assert "IS NOT NULL" in s


def test_geo_orders_busiest_first():
    s = sql(MonitoringRepository.build_geo_query("acme"))
    assert "ORDER BY count(*) DESC" in s


def test_risky_users_applies_threshold_in_having():
    """Filtering after the query would mean returning every user in the realm
    so that most could be discarded.
    """
    s = sql(MonitoringRepository.build_risky_users_query("acme", threshold=5))
    assert "HAVING count(*) >= 5" in s
    assert "GROUP BY auth_event.user_id" in s


def test_risky_users_excludes_null_users():
    s = sql(MonitoringRepository.build_risky_users_query("acme"))
    assert "auth_event.user_id IS NOT NULL" in s


def test_risky_users_min_risk_is_overridable():
    """Rule 2 counts from risk >= 2, below the KPI's own threshold."""
    s = sql(MonitoringRepository.build_risky_users_query("acme", min_risk=2))
    assert "pre_auth_risk_decision >= 2" in s


def test_event_count_filters_type_and_window():
    s = sql(
        MonitoringRepository.build_event_count_query(
            "acme",
            "LOGIN_ERROR",
            since=datetime(2026, 8, 1, tzinfo=timezone.utc),
            until=datetime(2026, 8, 19, tzinfo=timezone.utc),
        )
    )
    assert "count(*)" in s
    assert "auth_event.event_type = 'LOGIN_ERROR'" in s
    assert "auth_event.event_time > " in s
    assert "auth_event.event_time <= " in s


def test_every_aggregate_is_realm_scoped():
    """None of the four may be callable in a way that crosses tenants."""
    for stmt in (
        MonitoringRepository.build_stats_query("acme"),
        MonitoringRepository.build_geo_query("acme"),
        MonitoringRepository.build_risky_users_query("acme"),
        MonitoringRepository.build_event_count_query("acme", "LOGIN"),
    ):
        assert "'acme'" in sql(stmt)


def test_every_aggregate_joins_outer():
    """An inner join to auth_context would return nothing at all, since that
    table is never populated.
    """
    for stmt in (
        MonitoringRepository.build_stats_query("acme"),
        MonitoringRepository.build_geo_query("acme"),
        MonitoringRepository.build_risky_users_query("acme"),
        MonitoringRepository.build_event_count_query("acme", "LOGIN"),
    ):
        assert sql(stmt).count("LEFT OUTER JOIN") == 2


def test_realm_or_clause_is_parenthesized_against_other_filters():
    """The realm predicate is an OR of two sources, so it must bind as a unit.

    Left unparenthesized, `realm_a OR realm_b AND event_time > x` parses as
    `realm_a OR (realm_b AND ...)`, and the first branch would return every
    realm's rows regardless of the window.
    """
    s = sql(
        MonitoringRepository.build_events_query(
            "acme",
            since=datetime(2026, 8, 1, tzinfo=timezone.utc),
            event_type="LOGIN",
        )
    )
    where = s.split("WHERE")[1].split("ORDER BY")[0]
    assert where.strip().startswith("(")
    assert ") AND auth_event.event_time > " in where
