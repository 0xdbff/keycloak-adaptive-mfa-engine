"""Tests here execute against the database named by the POSTGRES_* variables.

Compiling SQL proves nothing about whether the server accepts it, or about what
it returns. These run on PostgreSQL and SQL Server, after `alembic upgrade head`.
"""

import pytest_asyncio
from sqlalchemy import delete, text

from src.core.database import DB
from src.data.model import (
    AuthEvent,
    AuthProcess,
    DecisionParamsConfig,
    Device,
    LocationNetwork,
)


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def clean_tables():
    async with DB.get_session()() as session:
        for model in (
            AuthEvent,
            AuthProcess,
            DecisionParamsConfig,
            Device,
            LocationNetwork,
        ):
            await session.execute(delete(model))
        await session.execute(text("DELETE FROM auth_context"))
        await session.commit()
    yield


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def dispose_engine():
    yield
    await DB.engine.dispose()
