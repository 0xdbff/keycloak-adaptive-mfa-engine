"""
# LocationNetwork Model
"""

from typing import List

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from src.core.database import DB
from src.data.model import LocationNetwork


class LocationNetworkRepository:
    """
    # LocationNetwork Repository

    Provides an asynchronous interface for interacting with the **location_network** table
    using SQLAlchemy. Each method uses an `async_sessionmaker` to properly manage session
    scope within an `async with` block.
    """

    @staticmethod
    async def create_location_network(loc_net: LocationNetwork) -> LocationNetwork:
        """
        Inserts a new **LocationNetwork** record into the database, unless a
        record with the same hash already exists.

        Two first logins from the same new network can both find no record and
        insert it at the same moment. The one that loses the race gets the
        record the other stored, instead of failing on the primary key.

        **Parameters**
        - `loc_net`: The **LocationNetwork** instance to persist.

        **Returns**
        - The stored **LocationNetwork**: the new one, or the one that already existed.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            session.add(loc_net)
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                existing = await session.get(LocationNetwork, loc_net.hash)
                if existing is None:
                    raise
                return existing
            await session.refresh(loc_net)
            return loc_net

    @staticmethod
    async def get_location_network_by_hash(
        hash_value: str,
    ) -> LocationNetwork | None:
        """
        Retrieves a **LocationNetwork** record by its unique hash value.

        **Parameters**
        - `hash_value`: The unique hash identifying the **LocationNetwork** record.

        **Returns**
        - The matching **LocationNetwork**, or `None` if no record is found.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(LocationNetwork).where(LocationNetwork.hash == hash_value)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    @staticmethod
    async def list_location_networks(limit: int | None = None) -> List[LocationNetwork]:
        """
        Fetches a list of **LocationNetwork** records from the database.

        **Parameters**
        - `limit`: Maximum number of records to retrieve. Defaults to None.

        **Returns**
        - A list of **LocationNetwork** instances.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            if limit is not None and limit > 0:
                stmt = select(LocationNetwork).limit(limit)
            else:
                stmt = select(LocationNetwork)
            result = await session.execute(stmt)
            return result.scalars().all()

    @staticmethod
    async def update_location_network(loc_net: LocationNetwork) -> LocationNetwork:
        """
        Updates an existing **LocationNetwork** record in the database.

        **Parameters**
        - `loc_net`: The **LocationNetwork** instance containing updated fields.

        **Returns**
        - The updated **LocationNetwork** with refreshed state.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            merged_loc_net = await session.merge(loc_net)
            await session.commit()
            await session.refresh(merged_loc_net)
            return merged_loc_net

    @staticmethod
    async def delete_location_network(loc_net: LocationNetwork) -> None:
        """
        Removes a **LocationNetwork** record from the database.

        **Parameters**
        - `loc_net`: The **LocationNetwork** instance to be deleted.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            loc_net_to_delete = await session.merge(loc_net)
            await session.delete(loc_net_to_delete)
            await session.commit()
