"""
# DecisionParamsConfig Model
"""

from typing import List

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from src.core.database import DB
from src.core.sql_dialect import bool_is
from src.data.model import DecisionParamsConfig


class DecisionParamsConfigRepository:
    """
    # DecisionParamsConfig Repository

    Provides an asynchronous interface for interacting with the **decision_params_config** table
    using SQLAlchemy. Each method uses an `async_sessionmaker` to properly manage session scope
    within an `async with` block.
    """

    @staticmethod
    async def create_decision_params_config(
        config: DecisionParamsConfig,
    ) -> DecisionParamsConfig:
        """
        Inserts a new **DecisionParamsConfig** record into the database.

        **Parameters**
        - `config`: The **DecisionParamsConfig** instance to persist.

        **Returns**
        - The newly created **DecisionParamsConfig** with refreshed state.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            session.add(config)
            await session.commit()
            await session.refresh(config)
            return config

    @staticmethod
    async def get_decision_params_config_by_id(
        config_id,
    ) -> DecisionParamsConfig | None:
        """
        Retrieves a **DecisionParamsConfig** record by its unique ID.

        **Parameters**
        - `config_id`: The unique ID (UUID) identifying the **DecisionParamsConfig** record.

        **Returns**
        - The matching **DecisionParamsConfig**, or `None` if no record is found.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(DecisionParamsConfig).where(
                DecisionParamsConfig.id == config_id
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    @staticmethod
    async def list_decision_params_configs(
        limit: int | None = None,
    ) -> List[DecisionParamsConfig]:
        """
        Fetches a list of **DecisionParamsConfig** records from the database.

        **Parameters**
        - `limit`: Maximum number of records to retrieve. Defaults to None.

        **Returns**
        - A list of **DecisionParamsConfig** instances.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            if limit is not None and limit > 0:
                stmt = select(DecisionParamsConfig).limit(limit)
            else:
                stmt = select(DecisionParamsConfig)
            result = await session.execute(stmt)
            return result.scalars().all()

    @staticmethod
    async def update_decision_params_config(
        config: DecisionParamsConfig,
    ) -> DecisionParamsConfig:
        """
        Updates an existing **DecisionParamsConfig** record in the database.

        **Parameters**
        - `config`: The **DecisionParamsConfig** instance containing updated fields.

        **Returns**
        - The updated **DecisionParamsConfig** with refreshed state.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            merged_config = await session.merge(config)
            await session.commit()
            await session.refresh(merged_config)
            return merged_config

    @staticmethod
    async def delete_decision_params_config(
        config: DecisionParamsConfig,
    ) -> None:
        """
        Removes a **DecisionParamsConfig** record from the database.

        **Parameters**
        - `config`: The **DecisionParamsConfig** instance to be deleted.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            config_to_delete = await session.merge(config)
            await session.delete(config_to_delete)
            await session.commit()

    @staticmethod
    async def get_active_decision_params_config(
        realm_id: str, group_id: str
    ) -> DecisionParamsConfig | None:
        """
        Retrieves the single **DecisionParamsConfig** record that is currently active
        for a given `realm_id` and `group_id`.

        **Parameters**
        - `realm_id`: The realm identifier.
        - `group_id`: The group or category identifier within the realm.

        **Returns**
        - The active **DecisionParamsConfig** if one exists, otherwise `None`.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = (
                select(DecisionParamsConfig)
                .where(
                    DecisionParamsConfig.realm_id == realm_id,
                    DecisionParamsConfig.group_id == group_id,
                    bool_is(DecisionParamsConfig.is_active, True),
                )
                .limit(1)
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    @staticmethod
    async def get_all_active_decision_params_by_realm(
        realm_id: str,
    ) -> List[DecisionParamsConfig]:
        """
        **Parameters**
        - `realm_id`: The realm identifier.
        - `group_id`: The group or category identifier within the realm.

        **Returns**
        - The active **DecisionParamsConfig** if one exists, otherwise `None`.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = select(DecisionParamsConfig).where(
                DecisionParamsConfig.realm_id == realm_id,
                bool_is(DecisionParamsConfig.is_active, True),
            )
            result = await session.execute(stmt)
            return result.scalars().all()

    @staticmethod
    async def deactivate_group_config(realm_id: str, group_id: str) -> None:
        """Deactivate all configs for a specific realm/group (used to clear a
        group override that is no longer present)."""
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            await session.execute(
                update(DecisionParamsConfig)
                .where(
                    DecisionParamsConfig.realm_id == realm_id,
                    DecisionParamsConfig.group_id == group_id,
                )
                .values(is_active=False)
            )
            await session.commit()

    @staticmethod
    async def activate_decision_params_config(
        realm_id: str,
        group_id: str,
        parameters_hash: str,
        parameters: list,
    ) -> DecisionParamsConfig:
        """
        Ensures exactly one active **DecisionParamsConfig** record for the specified `realm_id` and `group_id`.
        If a matching record by `parameters_hash` already exists, it is marked as active while all other
        records for that realm-group pair are marked inactive. Otherwise, a new record is created and
        made active while older ones become inactive.

        **Parameters**
        - `realm_id`: The realm identifier.
        - `group_id`: The group or category identifier within the realm.
        - `parameters_hash`: A 64-character hex hash value representing the configuration parameters.
        - `parameters`: The parameter dictionary (JSON) for this configuration.

        **Returns**
        - The active **DecisionParamsConfig** after the operation.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            existing_config_stmt = select(DecisionParamsConfig).where(
                DecisionParamsConfig.realm_id == realm_id,
                DecisionParamsConfig.group_id == group_id,
                DecisionParamsConfig.parameters_hash == parameters_hash,
            )
            result_existing = await session.execute(existing_config_stmt)
            existing_config = result_existing.scalar_one_or_none()

            # Preserve the scoring_config from the currently-active config for
            # this realm/group. Scoring mode/bias/thresholds are managed via a
            # separate endpoint and stored on the active config row, so without
            # this an update to the risk parameters would silently reset the
            # realm's scoring configuration to the deployment default.
            current_active_stmt = select(DecisionParamsConfig).where(
                DecisionParamsConfig.realm_id == realm_id,
                DecisionParamsConfig.group_id == group_id,
                bool_is(DecisionParamsConfig.is_active, True),
            )
            current_active = (
                await session.execute(current_active_stmt)
            ).scalar_one_or_none()
            preserved_scoring_config = (
                current_active.scoring_config if current_active else None
            )

            make_configs_inactive_stmt = (
                update(DecisionParamsConfig)
                .where(
                    DecisionParamsConfig.realm_id == realm_id,
                    or_(
                        DecisionParamsConfig.group_id == group_id,
                        # Also clear phantom configs with an empty/missing group
                        # so they can no longer shadow the real config on read.
                        DecisionParamsConfig.group_id.is_(None),
                        DecisionParamsConfig.group_id == "",
                    ),
                )
                .values(is_active=False)
            )
            await session.execute(make_configs_inactive_stmt)

            if existing_config:
                existing_config.is_active = True
                # Carry the currently-active scoring_config forward verbatim
                # (including None) so a parameter change never changes the
                # realm's scoring settings. Assigned unconditionally to match
                # the new-config branch: a conditional (skip-when-None) here
                # would leave a reactivated row's stale scoring_config in place.
                existing_config.scoring_config = preserved_scoring_config
                session.add(existing_config)
                await session.commit()
                await session.refresh(existing_config)
                return existing_config
            else:
                new_config = DecisionParamsConfig(
                    realm_id=realm_id,
                    group_id=group_id,
                    is_active=True,
                    parameters=parameters,
                    parameters_hash=parameters_hash,
                    scoring_config=preserved_scoring_config,
                )
                session.add(new_config)
                await session.commit()
                await session.refresh(new_config)
                return new_config

    @staticmethod
    async def update_scoring_config(
        realm_id: str, group_id: str, scoring_config: dict | None
    ) -> DecisionParamsConfig | None:
        """
        Sets the ``scoring_config`` on the currently active configuration for the
        given realm/group. Scoring config is independent of the parameter version
        (it is not part of ``parameters_hash``), so it updates the active row in
        place without creating a new version.

        **Returns**
        - The updated active **DecisionParamsConfig**, or ``None`` if no active
          configuration exists for the realm/group.
        """
        async_session = DB.get_session()
        if not isinstance(async_session, async_sessionmaker):
            raise ValueError("No async database session available")

        async with async_session() as session:
            stmt = (
                select(DecisionParamsConfig)
                .where(
                    DecisionParamsConfig.realm_id == realm_id,
                    DecisionParamsConfig.group_id == group_id,
                    bool_is(DecisionParamsConfig.is_active, True),
                )
                .limit(1)
            )
            result = await session.execute(stmt)
            active_config = result.scalar_one_or_none()
            if active_config is None:
                return None

            active_config.scoring_config = scoring_config
            session.add(active_config)
            await session.commit()
            await session.refresh(active_config)
            return active_config
