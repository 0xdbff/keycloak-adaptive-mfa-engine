from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mssql import NVARCHAR, VARCHAR


# revision identifiers, used by Alembic.
revision: str = "f7a8b9c0d1e2"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

MSSQL_CS_UTF8 = "Latin1_General_100_CS_AS_SC_UTF8"
MSSQL_BIN2 = "Latin1_General_100_BIN2"


def _defaults():
    """Postgres keeps uuid-ossp / now(); Azure SQL uses NEWID / UTC datetimeoffset."""
    dialect = op.get_bind().dialect.name
    if dialect == "mssql":
        return (
            sa.text("NEWID()"),
            sa.text("TODATETIMEOFFSET(SYSUTCDATETIME(), 0)"),
            sa.text("0"),
        )
    return sa.text("uuid_generate_v4()"), sa.text("now()"), sa.text("false")


def _types(dialect: str):
    """VARCHAR+BIN2 for hashes; NVARCHAR+CS UTF-8 for identifiers and text."""
    if dialect == "mssql":
        def hashed(n=64):
            return VARCHAR(n, collation=MSSQL_BIN2)

        def ident(n=255):
            return NVARCHAR(n, collation=MSSQL_CS_UTF8)

        def human(n):
            return NVARCHAR(n, collation=MSSQL_CS_UTF8)

        def details():
            return NVARCHAR(None, collation=MSSQL_CS_UTF8)

        return hashed, ident, human, details

    def hashed(n=64):
        return sa.String(n)

    def ident(n=255):
        return sa.Unicode(n)

    def human(n):
        return sa.Unicode(n)

    def details():
        return sa.UnicodeText()

    return hashed, ident, human, details


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')

    uuid_default, now_default, false_default = _defaults()
    hashed, ident, human, details = _types(dialect)

    op.create_table(
        "auth_context",
        sa.Column("hash", hashed(64), nullable=False),
        sa.Column("device", human(128), nullable=True),
        sa.Column("client", human(128), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("system_language", human(64), nullable=False),
        sa.Column("screen_resolution", sa.String(length=64), nullable=False),
        sa.Column("operating_system", human(64), nullable=True),
        sa.Column("browser", human(64), nullable=True),
        sa.Column("lat", sa.Float(), nullable=True),
        sa.Column("long", sa.Float(), nullable=True),
        sa.Column("is_vpn", sa.Boolean(), nullable=True),
        sa.Column("country_name", human(32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("hash"),
    )

    op.create_table(
        "decision_params_config",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=uuid_default,
            nullable=False,
        ),
        sa.Column("realm_id", ident(255), nullable=False),
        sa.Column("group_id", ident(255), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=false_default, nullable=True),
        sa.Column("parameters", sa.JSON(), nullable=True),
        sa.Column("parameters_hash", hashed(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.Column("scoring_config", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "device",
        sa.Column("hash", hashed(64), nullable=False),
        sa.Column("system_language", human(64), nullable=False),
        sa.Column("screen_resolution", sa.String(length=64), nullable=False),
        sa.Column("operating_system", human(64), nullable=True),
        sa.Column("browser", human(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.Column("device", human(64), nullable=False),
        sa.Column("client", human(128), nullable=True),
        sa.PrimaryKeyConstraint("hash"),
    )

    op.create_table(
        "location_network",
        sa.Column("hash", hashed(64), nullable=False),
        sa.Column("geolocation_cluster_label", sa.Integer(), nullable=True),
        sa.Column("country", human(32), nullable=True),
        sa.Column("is_vpn_flag", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.PrimaryKeyConstraint("hash"),
    )

    op.create_table(
        "auth_process",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=uuid_default,
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("auth_context_hash", hashed(64), nullable=False),
        sa.Column("device_info_hash", hashed(64), nullable=False),
        sa.Column("network_location_hash", hashed(64), nullable=False),
        sa.Column("auth_context_json", sa.JSON(), nullable=False),
        sa.Column("pre_auth_risk_decision", sa.Integer(), nullable=False),
        sa.Column("parameters_config_id", sa.Uuid(), nullable=False),
        sa.Column("final_status", sa.String(length=32), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.Column(
            "finished_at",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=True,
        ),
        sa.Column("risk_eval_vars", sa.JSON(), nullable=True),
        sa.Column("net_loc_credibility", sa.Float(), nullable=True),
        sa.Column("device_credibility", sa.Float(), nullable=True),
        sa.Column("realm_id", ident(255), nullable=True),
        # auth_context_hash intentionally has no foreign key: the original
        # chain dropped it (b0e1146d79df), auth_context rows are written
        # independently of the processes that reference them.
        sa.ForeignKeyConstraint(["device_info_hash"], ["device.hash"]),
        sa.ForeignKeyConstraint(["network_location_hash"], ["location_network.hash"]),
        sa.ForeignKeyConstraint(["parameters_config_id"], ["decision_params_config.id"]),
        sa.PrimaryKeyConstraint("id", mssql_clustered=False),
    )
    if dialect == "mssql":
        # The id is a random UUID. As the clustered key, every insert lands on
        # a random page. Cluster on time so inserts append.
        op.create_index(
            "cx_auth_process_started_at_id",
            "auth_process",
            ["started_at", "id"],
            mssql_clustered=True,
        )
    op.create_index(
        "ix_auth_process_realm_user_final_finished",
        "auth_process",
        ["realm_id", "user_id", "final_status", sa.text("finished_at DESC")],
    )

    op.create_table(
        "auth_event",
        sa.Column(
            "id",
            sa.Uuid(),
            server_default=uuid_default,
            nullable=False,
        ),
        sa.Column("auth_process", sa.Uuid(), nullable=True),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("details", details(), nullable=True),
        sa.Column(
            "event_time",
            sa.DateTime(timezone=True),
            server_default=now_default,
            nullable=False,
        ),
        sa.Column("auth_context_hash", hashed(64), nullable=True),
        sa.Column("device_info_hash", hashed(64), nullable=True),
        sa.Column("network_location_hash", hashed(64), nullable=True),
        sa.Column("realm_id", ident(255), nullable=True),
        # No foreign key on auth_context_hash, matching auth_process above.
        sa.ForeignKeyConstraint(["auth_process"], ["auth_process.id"]),
        sa.ForeignKeyConstraint(["device_info_hash"], ["device.hash"]),
        sa.ForeignKeyConstraint(["network_location_hash"], ["location_network.hash"]),
        sa.PrimaryKeyConstraint("id", mssql_clustered=False),
    )
    if dialect == "mssql":
        op.create_index(
            "cx_auth_event_event_time_id",
            "auth_event",
            ["event_time", "id"],
            mssql_clustered=True,
        )
    op.create_index(
        "ix_auth_user_event_time_desc",
        "auth_event",
        ["user_id", sa.text("event_time DESC")],
    )
    # Postgres: expression index, because monitoring filters through
    # NULLIF(realm_id, ''), never the bare column (see d5e6f7a8b9c0 in the
    # pre-squash history for the EXPLAIN-verified rationale).
    # SQL Server: same columns without the expression — NULLIF is not a
    # legal index key there, and the queries compare the base column. Its keys
    # ascend: SQL Server scans them backwards for newest-first, and new events
    # append. Descending keys put every insert at the front of the index.
    if dialect == "mssql":
        op.create_index(
            "ix_auth_event_realm_id_event_time_id",
            "auth_event",
            ["realm_id", "event_time", "id"],
        )
    else:
        op.create_index(
            "ix_auth_event_realm_id_event_time_id",
            "auth_event",
            [sa.text("NULLIF(realm_id, '')"), sa.text("event_time DESC"), sa.text("id DESC")],
        )


def downgrade() -> None:
    op.drop_index("ix_auth_event_realm_id_event_time_id", table_name="auth_event")
    op.drop_index("ix_auth_user_event_time_desc", table_name="auth_event")
    op.drop_table("auth_event")
    op.drop_index(
        "ix_auth_process_realm_user_final_finished", table_name="auth_process"
    )
    op.drop_table("auth_process")
    op.drop_table("location_network")
    op.drop_table("device")
    op.drop_table("decision_params_config")
    op.drop_table("auth_context")
    # The uuid-ossp extension is left in place: it is database-scoped, may be
    # shared, and dropping it is an operator decision.
