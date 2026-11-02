"""
# AuthProcess Model
"""

from typing import List
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker
import uuid

from src.core.database import DB
from src.data.model import AuthProcess


class AuthProcessRepository:
    """
    # AuthProcess Repository

    Provides an asynchronous interface for interacting with the **auth_process** table
    using SQLAlchemy. Each method uses an `async_sessionmaker` to properly manage session
    scope within an `async with` block.
    """

    @staticmethod
    async def create_auth_process(
        process: AuthProcess,
    ) -> AuthProcess:
        """
        Inserts a new **AuthProcess** record into the database.

        **Parameters**
        - `process`: The **AuthProcess** instance to persist.

        **Returns**
        - The newly created **AuthProcess** with refreshed state.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            session.add(process)
            await session.commit()
            await session.refresh(process)
            return process

    @staticmethod
    async def get_auth_process_by_id(
        process_id: str,
        realm_id: str,
    ) -> AuthProcess | None:
        """
        Retrieves an **AuthProcess** by its primary key (UUID), scoped to a realm.

        **Parameters**
        - `process_id`: The UUID of the **AuthProcess**.
        - `realm_id`: The realm/tenant the caller was authenticated against. A
          process id that exists but belongs to a different realm is treated as
          not found, so a caller can never finalize or read another tenant's
          authentication process even if it learns/guesses the id.

        **Returns**
        - The matching **AuthProcess**, or `None` if not found (or found but
          owned by a different realm).
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(AuthProcess).where(
                AuthProcess.id == process_id,
                AuthProcess.realm_id == realm_id,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    @staticmethod
    async def list_auth_processes(
        final_status: str | None = None,
        limit: int | None = None,
        date_limit: datetime | None = None,
    ) -> List[AuthProcess]:
        """
        Retrieves **AuthProcess** records from the database, optionally filtered by:
        - `final_status` (exact match),
        - `limit` (max record count),
        - `date_limit` (earliest creation date).

        **Parameters**
        - `final_status`: Optional string used to filter by a final status value.
        - `limit`: Optional integer to limit the number of records returned.
        - `date_limit`: Optional datetime indicating the earliest `created_at` timestamp to include.

        **Returns**
        - A list of **AuthProcess** instances matching the criteria.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(AuthProcess)

            if final_status:
                stmt = stmt.where(AuthProcess.final_status == final_status)

            if date_limit:
                stmt = stmt.where(AuthProcess.created_at >= date_limit)

            if limit is not None and limit > 0:
                stmt = stmt.limit(limit)

            result = await session.execute(stmt)
            return result.scalars().all()

    @staticmethod
    async def update_auth_process(
        process: AuthProcess,
    ) -> AuthProcess:
        """
        Updates an existing **AuthProcess** in the database.

        **Parameters**
        - `process`: The **AuthProcess** instance containing updated fields.

        **Returns**
        - The updated **AuthProcess** with refreshed state.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            merged_process = await session.merge(process)
            await session.commit()
            await session.refresh(merged_process)
            return merged_process

    @staticmethod
    async def delete_auth_process(process: AuthProcess) -> None:
        """
        Deletes an **AuthProcess** from the database.

        **Parameters**
        - `process`: The **AuthProcess** instance to be removed.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            process_to_delete = await session.merge(process)
            await session.delete(process_to_delete)
            await session.commit()

    @staticmethod
    async def get_auth_context_json_for_user(
        user_id: uuid.UUID,
        final_status: str,
        limit: int | None = None,
        date_limit: datetime | None = None,
    ) -> List[str]:
        """
        Retrieves only the **auth_context_json** field for a given `user_id`. Optionally filters by:
        - `final_status` (exact match),
        - `limit` (max record count),
        - `date_limit` (earliest creation date).

        **Parameters**
        - `user_id`: The UUID identifying the user.
        - `final_status`: A string used to filter records by final status (exact match).
        - `limit`: Optional integer to limit the number of records returned.
        - `date_limit`: If provided, only records created on or after this date are retrieved.

        **Returns**
        - A list of **auth_context_json** strings matching the query criteria.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(AuthProcess.auth_context_json).where(
                AuthProcess.user_id == user_id,
            )
            if final_status:
                stmt = stmt.where(AuthProcess.final_status == final_status)
            if date_limit:
                stmt = stmt.where(AuthProcess.created_at >= date_limit)
            if limit is not None and limit > 0:
                stmt = stmt.limit(limit)

            result = await session.execute(stmt)
            return [row[0] for row in result.fetchall()]

    @staticmethod
    async def get_complete_records_for_user(
        user_id: uuid.UUID,
        realm_id: str,
        final_status: str | None = None,
        limit: int | None = None,
        date_limit: datetime | None = None,
    ) -> List[AuthProcess]:
        """
        Retrieves complete **AuthProcess** objects for a given `user_id` within a
        single realm/tenant, optionally filtered by:
        - `final_status` (exact match),
        - `limit` (max record count),
        - `date_limit` (earliest creation date).

        **Parameters**
        - `user_id`: The UUID identifying the user.
        - `realm_id`: The realm/tenant the caller was authenticated against. Required
          so one tenant's token can never read another tenant's history for a
          guessed or coincidental `user_id`.
        - `final_status`: A string used to filter records by final status (exact match).
        - `limit`: Optional integer to limit the number of records returned.
        - `date_limit`: If provided, only records created on or after this date are retrieved.

        **Returns**
        - A list of **AuthProcess** instances matching the query criteria.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(AuthProcess).where(
                AuthProcess.user_id == user_id,
                AuthProcess.realm_id == realm_id,
            )
            if final_status:
                stmt = stmt.where(AuthProcess.final_status == final_status)
            if date_limit:
                stmt = stmt.where(AuthProcess.created_at >= date_limit)

            stmt = stmt.order_by(AuthProcess.finished_at.desc())

            if limit is not None and limit > 0:
                stmt = stmt.limit(limit)

            result = await session.execute(stmt)
            return result.scalars().all()
