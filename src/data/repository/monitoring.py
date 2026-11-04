"""Read-only queries backing the monitoring endpoints.

Every method is realm-scoped so one tenant's token cannot read another
tenant's history. Both joins are outer: a webhook event can arrive with no
`auth_process`, and nothing populates `auth_context`.
"""

from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from src.core.database import DB
from src.core.sql_dialect import bool_is, row_compare
from src.data.model import AuthContext, AuthEvent, AuthProcess
from src.data.repository import monitoring_expr as expr

# The response is built in memory, so the page size needs a ceiling.
MAX_LIMIT = 500
DEFAULT_LIMIT = 100

# Risk level at which a login counts as risky for the KPI, and the default for
# the risky-user aggregate. Matches the threshold the consuming platform has
# always applied, so the numbers reported here agree with the ones it shows.
RISKY_THRESHOLD = 3


def normalize_limit(limit: Optional[int]) -> int:
    """Clamp a requested page size into range.

    A non-positive limit means unspecified, not one row.
    """
    if not limit or limit <= 0:
        return DEFAULT_LIMIT
    return min(limit, MAX_LIMIT)

_CURSOR_SEP = "|"


def _session() -> async_sessionmaker:
    async_session = DB.get_session()
    if not isinstance(async_session, async_sessionmaker):
        raise ValueError("No async database session available")
    return async_session


def encode_cursor(event_time: datetime, event_id) -> str:
    """Build the cursor identifying the last row of a page."""
    return f"{event_time.isoformat()}{_CURSOR_SEP}{event_id}"


def decode_cursor(cursor: str) -> Tuple[datetime, UUID]:
    """Split a cursor back into its ordering key.

    The id is a UUID: PostgreSQL has no `uuid > text` operator. Raises
    ValueError on a malformed cursor so the route can answer 400.
    """
    raw_time, _, raw_id = cursor.partition(_CURSOR_SEP)
    if not raw_time or not raw_id:
        raise ValueError("cursor must be '<event_time>|<event_id>'")
    try:
        event_id = UUID(raw_id)
    except (AttributeError, TypeError, ValueError):
        raise ValueError(f"cursor event id is not a UUID: {raw_id!r}")
    return datetime.fromisoformat(raw_time), event_id


def _base_columns():
    """The flattened event projection shared by every row-returning query."""
    return [
        AuthEvent.id.label("event_id"),
        AuthEvent.event_time.label("event_time"),
        AuthEvent.event_type.label("event_type"),
        AuthEvent.user_id.label("user_id"),
        expr.client_expr.label("client"),
        expr.ip_expr.label("ip_address"),
        expr.country_expr.label("country"),
        expr.city_expr.label("city"),
        expr.lat_expr.label("lat"),
        expr.long_expr.label("long"),
        expr.is_vpn_expr.label("is_vpn"),
        AuthProcess.pre_auth_risk_decision.label("risk_level"),
        AuthProcess.final_status.label("final_status"),
        expr.os_expr.label("operating_system"),
        expr.browser_expr.label("browser"),
        expr.device_expr.label("device"),
        expr.system_language_expr.label("system_language"),
        expr.screen_resolution_expr.label("screen_resolution"),
    ]


def _joined(stmt):
    """Apply the three-table join every monitoring query needs."""
    return stmt.outerjoin(AuthProcess, AuthProcess.id == AuthEvent.auth_process).outerjoin(
        AuthContext, AuthContext.hash == AuthEvent.auth_context_hash
    )


def _apply_window(stmt, since: Optional[datetime], until: Optional[datetime]):
    """Apply the time-window filter every monitoring query accepts.

    `since` is exclusive, `until` inclusive, so a consumer can pass back the
    last timestamp it saw. Shared by every query builder below so the
    convention can't drift between one endpoint and another.
    """
    if since is not None:
        stmt = stmt.where(AuthEvent.event_time > since)
    if until is not None:
        stmt = stmt.where(AuthEvent.event_time <= until)
    return stmt


def _apply_filters(
    stmt,
    realm_id: str,
    since: Optional[datetime],
    until: Optional[datetime],
    event_type: Optional[str],
    min_risk: Optional[int],
    risk_decision: Optional[int],
    is_vpn: Optional[bool],
):
    """Filters shared by the listing query and its matching count."""
    stmt = _apply_window(stmt.where(expr.realm_filter(realm_id)), since, until)
    if event_type is not None:
        stmt = stmt.where(AuthEvent.event_type == event_type)
    if min_risk is not None:
        stmt = stmt.where(expr.risky_filter(min_risk))
    if risk_decision is not None:
        stmt = stmt.where(AuthProcess.pre_auth_risk_decision == risk_decision)
    if is_vpn is not None:
        stmt = stmt.where(bool_is(expr.is_vpn_expr, is_vpn))
    return stmt


class MonitoringRepository:
    """Read-only, realm-scoped queries for the monitoring endpoints."""

    @staticmethod
    def build_events_query(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        event_type: Optional[str] = None,
        min_risk: Optional[int] = None,
        risk_decision: Optional[int] = None,
        is_vpn: Optional[bool] = None,
        limit: int = DEFAULT_LIMIT,
        cursor: Optional[str] = None,
        ascending: bool = True,
    ):
        """Build the events SELECT.

        Ordering is `(event_time, id)`, never `event_time` alone: two events
        can share a timestamp, and a partial sort lets a paging consumer skip
        or repeat rows.
        """
        limit = normalize_limit(limit)

        stmt = _joined(select(*_base_columns()))
        stmt = _apply_filters(
            stmt, realm_id, since, until, event_type, min_risk, risk_decision, is_vpn
        )

        if cursor:
            cur_time, cur_id = decode_cursor(cursor)
            stmt = stmt.where(
                row_compare(
                    AuthEvent.event_time,
                    AuthEvent.id,
                    cur_time,
                    cur_id,
                    greater=ascending,
                )
            )

        order = (
            (AuthEvent.event_time.asc(), AuthEvent.id.asc())
            if ascending
            else (AuthEvent.event_time.desc(), AuthEvent.id.desc())
        )
        return stmt.order_by(*order).limit(limit)

    @staticmethod
    def build_events_count_query(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        event_type: Optional[str] = None,
        min_risk: Optional[int] = None,
        risk_decision: Optional[int] = None,
        is_vpn: Optional[bool] = None,
    ):
        """Total matching the same filters, without paging."""
        stmt = _joined(select(func.count()).select_from(AuthEvent))
        return _apply_filters(
            stmt, realm_id, since, until, event_type, min_risk, risk_decision, is_vpn
        )

    # Aggregates. Computed in SQL: returning rows for the caller to reduce
    # would transfer a realm's whole history to produce a few integers.

    @staticmethod
    def build_stats_query(
        realm_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        all_tenants: bool = False,
    ):
        """Build the four-KPI aggregate.

        All four share one window so they stay comparable. `flagged_ips`
        counts distinct VPN-flagged addresses, not events.

        `realm_id=None` aggregates across every realm *of one tenant's AMFA
        database* (excluding rows with no realm) — this is what the
        monitoring route serves, and it is safe because each AMFA deployment
        already belongs to exactly one tenant. That is NOT the same as
        aggregating across tenants: no route calls this with `realm_id=None`
        today, so `all_tenants=True` must be passed explicitly to opt into
        that shape, to keep a future caller from reaching it by accident.
        """
        if realm_id is None and not all_tenants:
            raise ValueError(
                "build_stats_query: realm_id=None aggregates across every "
                "realm; pass all_tenants=True to confirm that is intended"
            )

        stmt = _joined(
            select(
                func.count().label("total"),
                func.count(expr.risky_count_case(RISKY_THRESHOLD)).label("risky"),
                func.count(func.distinct(AuthEvent.user_id)).label("unique_users"),
                func.count(
                    func.distinct(
                        case(
                            (
                                bool_is(expr.is_vpn_expr, True),
                                func.nullif(expr.ip_expr, ""),
                            )
                        )
                    )
                ).label("flagged_ips"),
            ).select_from(AuthEvent)
        )

        if realm_id:
            stmt = stmt.where(expr.realm_filter(realm_id))
        else:
            stmt = stmt.where(expr.realm_id_expr.isnot(None))
        return _apply_window(stmt, since, until)

    @staticmethod
    def build_geo_query(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ):
        """Build the map-bucket aggregate.

        Rounding happens in a subquery so SELECT and GROUP BY share one pair
        of bind parameters. Repeating the expression makes SQL Server treat
        each copy as a different parameter (error 8120). Grouping by the raw
        coordinate would give one bucket per location.
        """
        lat_cell = expr.geo_cell(expr.lat_expr)
        long_cell = expr.geo_cell(expr.long_expr)

        inner = _joined(
            select(
                expr.country_expr.label("country"),
                lat_cell.label("lat"),
                long_cell.label("long"),
                expr.risky_count_case(RISKY_THRESHOLD).label("risky_flag"),
            ).select_from(AuthEvent)
        )
        inner = _apply_window(
            inner.where(expr.realm_filter(realm_id)).where(expr.has_usable_geo()),
            since,
            until,
        ).subquery()

        return (
            select(
                inner.c.country,
                inner.c.lat,
                inner.c.long,
                func.count().label("count"),
                func.count(inner.c.risky_flag).label("risky_count"),
            )
            .group_by(inner.c.country, inner.c.lat, inner.c.long)
            .order_by(func.count().desc())
        )

    @staticmethod
    def build_risky_users_query(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        min_risk: int = RISKY_THRESHOLD,
        threshold: int = 1,
    ):
        """Build the repeated-risky-user aggregate.

        The threshold applies in HAVING so the query returns only users that
        cross it.
        """
        stmt = _joined(
            select(
                AuthEvent.user_id.label("user_id"),
                func.count().label("count"),
            ).select_from(AuthEvent)
        )

        stmt = _apply_window(
            stmt.where(expr.realm_filter(realm_id))
            .where(expr.risky_filter(min_risk))
            .where(AuthEvent.user_id.isnot(None)),
            since,
            until,
        )

        return (
            stmt.group_by(AuthEvent.user_id)
            .having(func.count() >= threshold)
            .order_by(func.count().desc())
        )

    @staticmethod
    def build_event_count_query(
        realm_id: str,
        event_type: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ):
        """Build the single-event-type count."""
        stmt = _joined(select(func.count()).select_from(AuthEvent))
        stmt = stmt.where(expr.realm_filter(realm_id)).where(
            AuthEvent.event_type == event_type
        )
        return _apply_window(stmt, since, until)

    @staticmethod
    async def get_stats(
        realm_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> dict:
        """Return the four KPIs for a realm and window."""
        async_session = _session()
        async with async_session() as session:
            row = (
                (
                    await session.execute(
                        MonitoringRepository.build_stats_query(realm_id, since, until)
                    )
                )
                .mappings()
                .one()
            )
        return {
            "total": int(row["total"] or 0),
            "risky": int(row["risky"] or 0),
            "unique_users": int(row["unique_users"] or 0),
            "flagged_ips": int(row["flagged_ips"] or 0),
        }

    @staticmethod
    async def get_geo_buckets(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[dict]:
        """Return map buckets for a realm and window, busiest first."""
        async_session = _session()
        async with async_session() as session:
            rows = (
                (
                    await session.execute(
                        MonitoringRepository.build_geo_query(realm_id, since, until)
                    )
                )
                .mappings()
                .all()
            )
        return [dict(row) for row in rows]

    @staticmethod
    async def get_risky_users(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        min_risk: int = RISKY_THRESHOLD,
        threshold: int = 1,
    ) -> List[dict]:
        """Return users at or above the risky-event threshold."""
        async_session = _session()
        async with async_session() as session:
            rows = (
                (
                    await session.execute(
                        MonitoringRepository.build_risky_users_query(
                            realm_id, since, until, min_risk, threshold
                        )
                    )
                )
                .mappings()
                .all()
            )
        return [
            {"user_id": str(row["user_id"]), "count": int(row["count"])} for row in rows
        ]

    @staticmethod
    async def count_by_event_type(
        realm_id: str,
        event_type: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> int:
        """Return how many events of one type fall in the window."""
        async_session = _session()
        async with async_session() as session:
            total = (
                await session.execute(
                    MonitoringRepository.build_event_count_query(
                        realm_id, event_type, since, until
                    )
                )
            ).scalar()
        return int(total or 0)

    @staticmethod
    async def list_events(
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        event_type: Optional[str] = None,
        min_risk: Optional[int] = None,
        risk_decision: Optional[int] = None,
        is_vpn: Optional[bool] = None,
        limit: int = DEFAULT_LIMIT,
        cursor: Optional[str] = None,
        ascending: bool = True,
        include_total: Optional[bool] = None,
    ) -> Tuple[List[dict], int, Optional[str]]:
        """Return one page of events, the unpaged total, and the next cursor.

        `next_cursor` is None once the page is short of `limit`. The total
        doesn't change between pages of the same filtered query, so by
        default it's only computed on the first page (`cursor` absent) —
        a consumer walking a cursor across many pages would otherwise pay
        for the same unbounded COUNT(*) on every page just to re-report a
        number it already has. `include_total` overrides that default
        either way; when it's skipped, `total` is `-1`.
        """
        if include_total is None:
            include_total = cursor is None

        async_session = _session()

        rows_stmt = MonitoringRepository.build_events_query(
            realm_id, since, until, event_type, min_risk, risk_decision,
            is_vpn, limit, cursor, ascending,
        )

        async with async_session() as session:
            result = await session.execute(rows_stmt)
            rows = [dict(row) for row in result.mappings().all()]
            if include_total:
                count_stmt = MonitoringRepository.build_events_count_query(
                    realm_id, since, until, event_type, min_risk, risk_decision, is_vpn,
                )
                total = (await session.execute(count_stmt)).scalar() or 0
            else:
                total = -1

        effective_limit = normalize_limit(limit)
        next_cursor = (
            encode_cursor(rows[-1]["event_time"], rows[-1]["event_id"])
            if len(rows) == effective_limit
            else None
        )
        return rows, int(total), next_cursor
