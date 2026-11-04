from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context
from src.core.config.environment import DATABASE_URL

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata

from src.data.model import Base

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

# ConfigParser treats % as interpolation. Passwords (Azure SQL especially)
# can contain it, so double them for the ini layer only.
config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))

# Indexes autogenerate cannot compare, or that exist on one dialect only: an
# expression key on Postgres, DESC keys and clustered keys on SQL Server. Left
# in, it proposes dropping or rebuilding them on every run. Change these by hand.
HAND_MANAGED_INDEXES = {
    "ix_auth_event_realm_id_event_time_id",
    "ix_auth_user_event_time_desc",
    "ix_auth_process_realm_user_final_finished",
    "cx_auth_event_event_time_id",
    "cx_auth_process_started_at_id",
}


def include_object(obj, name, type_, reflected, compare_to):
    return not (type_ == "index" and name in HAND_MANAGED_INDEXES)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        include_object=include_object,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
