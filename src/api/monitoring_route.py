"""Read-only endpoints serving authentication history to external monitoring
and reporting consumers.

Every endpoint is GET and realm-scoped. Paths sit under
`/{realm_id}/monitoring/` to stay clear of the configuration routes at
`/{realm_id}/`.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from src.data.repository.monitoring import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    RISKY_THRESHOLD,
    MonitoringRepository,
)
from src.data.schema import (
    MonitoringEventCount,
    MonitoringEventsPage,
    MonitoringGeoBucket,
    MonitoringRiskyUser,
    MonitoringStats,
)
from src.utils.auth.dependency import enforce_monitoring_read, require_auth
from src.utils.auth.token_verifier import VerifiedPrincipal


class MonitoringRoute:
    def __init__(self):
        self.router = APIRouter(prefix="/{realm_id}/monitoring")

        self.router.add_api_route(
            "/events",
            self.list_events,
            methods=["GET"],
            dependencies=[Depends(require_auth)],
            response_model=MonitoringEventsPage,
        )
        self.router.add_api_route(
            "/stats",
            self.get_stats,
            methods=["GET"],
            dependencies=[Depends(require_auth)],
            response_model=MonitoringStats,
        )
        self.router.add_api_route(
            "/geo",
            self.get_geo,
            methods=["GET"],
            dependencies=[Depends(require_auth)],
            response_model=List[MonitoringGeoBucket],
        )
        self.router.add_api_route(
            "/risky-users",
            self.get_risky_users,
            methods=["GET"],
            dependencies=[Depends(require_auth)],
            response_model=List[MonitoringRiskyUser],
        )
        self.router.add_api_route(
            "/event-counts",
            self.get_event_counts,
            methods=["GET"],
            dependencies=[Depends(require_auth)],
            response_model=MonitoringEventCount,
        )

    async def list_events(
        self,
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        event_type: Optional[str] = None,
        min_risk: Optional[int] = Query(default=None, ge=1, le=4),
        risk_decision: Optional[int] = Query(default=None, ge=1, le=4),
        is_vpn: Optional[bool] = None,
        limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
        cursor: Optional[str] = None,
        ascending: bool = True,
        include_total: Optional[bool] = None,
        principal: VerifiedPrincipal = Depends(require_auth),
    ) -> MonitoringEventsPage:
        """One page of events, ordered by (event_time, id).

        `ascending` defaults to true for incremental consumers. `total` is
        only computed when `cursor` is absent unless `include_total`
        overrides that; a consumer walking multiple pages of one query
        already has the total from its first page, so `total` is `-1` on
        the pages where it wasn't recomputed.
        """
        enforce_monitoring_read(principal, realm_id)

        try:
            rows, total, next_cursor = await MonitoringRepository.list_events(
                realm_id=realm_id,
                since=since,
                until=until,
                event_type=event_type,
                min_risk=min_risk,
                risk_decision=risk_decision,
                is_vpn=is_vpn,
                limit=limit,
                cursor=cursor,
                ascending=ascending,
                include_total=include_total,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        return MonitoringEventsPage(items=rows, total=total, next_cursor=next_cursor)

    async def get_stats(
        self,
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        principal: VerifiedPrincipal = Depends(require_auth),
    ) -> MonitoringStats:
        """The four KPIs for one realm and window."""
        enforce_monitoring_read(principal, realm_id)
        return MonitoringStats(
            **await MonitoringRepository.get_stats(
                realm_id=realm_id, since=since, until=until
            )
        )

    async def get_geo(
        self,
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        principal: VerifiedPrincipal = Depends(require_auth),
    ) -> List[MonitoringGeoBucket]:
        """Events grouped into rounded coordinate cells, busiest first."""
        enforce_monitoring_read(principal, realm_id)
        buckets = await MonitoringRepository.get_geo_buckets(
            realm_id=realm_id, since=since, until=until
        )
        return [MonitoringGeoBucket(**bucket) for bucket in buckets]

    async def get_risky_users(
        self,
        realm_id: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        min_risk: int = Query(default=RISKY_THRESHOLD, ge=1, le=4),
        threshold: int = Query(default=1, ge=1),
        principal: VerifiedPrincipal = Depends(require_auth),
    ) -> List[MonitoringRiskyUser]:
        """Users whose risky-event count reached `threshold` in the window."""
        enforce_monitoring_read(principal, realm_id)
        users = await MonitoringRepository.get_risky_users(
            realm_id=realm_id,
            since=since,
            until=until,
            min_risk=min_risk,
            threshold=threshold,
        )
        return [MonitoringRiskyUser(**user) for user in users]

    async def get_event_counts(
        self,
        realm_id: str,
        event_type: str,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        principal: VerifiedPrincipal = Depends(require_auth),
    ) -> MonitoringEventCount:
        """How many events of one type fall in the window."""
        enforce_monitoring_read(principal, realm_id)
        count = await MonitoringRepository.count_by_event_type(
            realm_id=realm_id, event_type=event_type, since=since, until=until
        )
        return MonitoringEventCount(event_type=event_type, count=count)
