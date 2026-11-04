import logging
import math

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

from src.core.config.environment import (
    ASYNC_DATABASE_URL,
    HEALTH_CHECK_TIMEOUT,
    MSSQL_MAX_OVERFLOW,
    MSSQL_POOL_SIZE,
)


def _health_connect_args(url: str) -> dict:
    """Make a health check's connection give up at the health deadline."""
    if url.startswith("mssql"):
        # pyodbc takes whole seconds, and 0 means no timeout at all.
        seconds = max(1, math.ceil(HEALTH_CHECK_TIMEOUT))

        # `timeout` below only covers the login. This covers the query.
        async def set_query_timeout(connection) -> None:
            connection.timeout = seconds

        return {"timeout": seconds, "after_created": set_query_timeout}
    return {"timeout": HEALTH_CHECK_TIMEOUT, "command_timeout": HEALTH_CHECK_TIMEOUT}


class DatabaseConnection:

    def __init__(self, url: str = ASYNC_DATABASE_URL, async_engine: bool = True):
        if async_engine:
            async_url = url
            if async_url.startswith("postgresql://"):
                async_url = async_url.replace(
                    "postgresql://", "postgresql+asyncpg://", 1
                )
            engine_kwargs = {"future": True}
            # Azure SQL drops idle connections at 30 minutes. The defaults keep
            # 4 workers × (2 + 2 overflow) = 16 under Basic's 30 concurrent
            # workers and logins. Larger tiers should raise them.
            if async_url.startswith("mssql"):
                engine_kwargs["pool_recycle"] = 1800
                engine_kwargs["pool_pre_ping"] = True
                engine_kwargs["pool_size"] = MSSQL_POOL_SIZE
                engine_kwargs["max_overflow"] = MSSQL_MAX_OVERFLOW
            self.engine = create_async_engine(async_url, **engine_kwargs)
            self.Session = async_sessionmaker(
                bind=self.engine, class_=AsyncSession, expire_on_commit=False
            )
            # /health opens its own connection each time. From the shared pool
            # it could pick up a connection on a dead socket, and a stuck check
            # would then hold a slot that real requests need.
            self.health_engine = create_async_engine(
                async_url,
                future=True,
                poolclass=NullPool,
                connect_args=_health_connect_args(async_url),
            )
            self.HealthSession = async_sessionmaker(
                bind=self.health_engine, class_=AsyncSession, expire_on_commit=False
            )
        else:
            raise ValueError("Async ORM required")

    def get_session(
        self,
    ) -> async_sessionmaker[AsyncSession]:
        if not hasattr(self, "Session"):
            raise ValueError("No database session available")
        return self.Session

    def get_health_session(self) -> async_sessionmaker[AsyncSession]:
        return self.HealthSession


PostgreSQLConnection = DatabaseConnection


class DbService:
    client = None

    @classmethod
    def get_singleton(cls):
        if cls.client is None:
            cls.client = DatabaseConnection(async_engine=True)
            logging.info("Database connection rules singleton initialized at startup!")
        return cls.client


def get_db():
    return DbService.get_singleton()


DB = DbService.get_singleton()
