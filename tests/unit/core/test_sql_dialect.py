"""Postgres stays the default; mssql is a compile/URL option in the same code."""

from datetime import datetime, timezone
from uuid import UUID

import pytest
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    MetaData,
    String,
    Table,
    Uuid,
    func,
    select,
    text,
)
from sqlalchemy.dialects import mssql, postgresql
from sqlalchemy.engine import make_url

from src.core.sql_dialect import (
    JsonBool,
    JsonText,
    bool_is,
    build_database_urls,
    db_type,
    hashed_str,
    ident_str,
    long_text,
    odbc_brace,
    row_compare,
    text_str,
)
from src.data.model import AuthEvent, DecisionParamsConfig


def test_postgres_url_is_unchanged_shape():
    sync, async_url = build_database_urls(
        "postgresql", "amfa", "s3cret", "db.example", 5432, "adaptive_mfa"
    )
    assert sync == "postgresql://amfa:s3cret@db.example:5432/adaptive_mfa"
    assert async_url == "postgresql+asyncpg://amfa:s3cret@db.example:5432/adaptive_mfa"


def test_mssql_url_uses_odbc_and_encrypts():
    sync, async_url = build_database_urls(
        "mssql",
        "amfa",
        "p@ss/word",
        "sql.example.test",
        1433,
        "adaptive_mfa",
    )
    assert sync.startswith(
        "mssql+pyodbc://amfa:p%40ss%2Fword@sql.example.test:1433/adaptive_mfa?"
    )
    assert "driver=ODBC+Driver+18+for+SQL+Server" in sync
    assert "Encrypt=yes" in sync
    assert "TrustServerCertificate=no" in sync
    assert async_url.startswith("mssql+aioodbc://")
    assert "Encrypt=yes" in async_url


def test_sqlalchemy_registers_mssql_aioodbc():
    """The image installs from requirements.txt. aioodbc landed in 2.0.23."""
    from sqlalchemy.dialects.mssql import aioodbc

    assert aioodbc.dialect.driver == "aioodbc"


def test_db_type_defaults_to_postgresql(monkeypatch):
    monkeypatch.delenv("DB_TYPE", raising=False)
    assert db_type() == "postgresql"


def test_db_type_reads_mssql(monkeypatch):
    monkeypatch.setenv("DB_TYPE", "MSSQL")
    assert db_type() == "mssql"


def test_wait_for_db_refuses_postgres(monkeypatch):
    import scripts.wait_for_db as wait_for_db

    monkeypatch.setenv("DB_TYPE", "postgresql")
    assert wait_for_db.main() == 2


def test_odbc_brace_escapes_password_punctuation():
    assert odbc_brace("plain") == "{plain}"
    assert odbc_brace("Ab1;cd{e}F!x9") == "{Ab1;cd{e}}F!x9}"


def test_json_text_compiles_on_postgres_and_mssql():
    table = Table("auth_process", MetaData(), Column("auth_context_json", String))
    expr = func.nullif(JsonText(table.c.auth_context_json, "client"), "")
    stmt = select(expr)
    pg = str(stmt.compile(dialect=postgresql.dialect()))
    ms = str(stmt.compile(dialect=mssql.dialect()))
    assert "->>" in pg
    assert "JSON_VALUE" in ms
    assert "$.client" in ms


def test_json_text_sets_collation_on_mssql_only():
    """JSON columns take the database default; comparing them must not conflict."""
    table = Table("auth_process", MetaData(), Column("auth_context_json", String))
    stmt = select(JsonText(table.c.auth_context_json, "client"))
    assert "COLLATE Latin1_General_100_CS_AS_SC_UTF8" in str(
        stmt.compile(dialect=mssql.dialect())
    )
    assert "COLLATE" not in str(stmt.compile(dialect=postgresql.dialect()))


@pytest.mark.parametrize("helper", [JsonText, JsonBool])
def test_json_helpers_do_not_share_a_compiled_statement_across_keys(helper):
    """The key is in the SQL text. A shared cache entry reads the wrong field."""
    table = Table("auth_process", MetaData(), Column("auth_context_json", String))
    for dialect in (postgresql.dialect(), mssql.dialect()):
        cache = {}
        rendered = [
            str(
                select(helper(table.c.auth_context_json, key))._compile_w_cache(
                    dialect,
                    compiled_cache=cache,
                    column_keys=[],
                    for_executemany=False,
                    schema_translate_map=None,
                )[0]
            )
            for key in ("first_key", "second_key", "first_key")
        ]
        assert "first_key" in rendered[0] and "second_key" in rendered[1]
        assert rendered[2] == rendered[0]
        assert len(cache) == 2


def test_managed_identity_url_has_no_password_and_no_windows_auth():
    sync, async_url = build_database_urls(
        "mssql",
        None,
        None,
        "sql.example.test",
        1433,
        "amfa",
        authentication="ActiveDirectoryMsi",
    )
    assert sync.startswith("mssql+pyodbc://@sql.example.test:1433/amfa?")
    assert async_url.startswith("mssql+aioodbc://@sql.example.test:1433/amfa?")
    args, _ = mssql.pyodbc.dialect().create_connect_args(make_url(sync))
    assert "Authentication=ActiveDirectoryMsi" in args[0]
    assert "Trusted_Connection" not in args[0]
    assert "PWD" not in args[0]


def test_managed_identity_never_sends_a_configured_password():
    for user in (None, "identity-id"):
        sync, async_url = build_database_urls(
            "mssql",
            user,
            "configured-password",
            "sql.example.test",
            1433,
            "amfa",
            authentication="ActiveDirectoryMsi",
        )
        assert "configured-password" not in sync
        assert "configured-password" not in async_url
        args, kwargs = mssql.pyodbc.dialect().create_connect_args(make_url(sync))
        assert "PWD" not in args[0] and "password" not in args[0]


def test_user_assigned_identity_passes_the_client_id_as_user():
    sync, _ = build_database_urls(
        "mssql",
        "client-id",
        None,
        "sql.example.test",
        1433,
        "amfa",
        authentication="ActiveDirectoryMsi",
    )
    args, _ = mssql.pyodbc.dialect().create_connect_args(make_url(sync))
    assert "UID=client-id" in args[0]
    assert "PWD" not in args[0]


def _wait_for_db_connection_string(monkeypatch, **env) -> str:
    pyodbc = pytest.importorskip("pyodbc", exc_type=ImportError)
    import scripts.wait_for_db as wait_for_db

    seen = []

    class Connection:
        def close(self):
            pass

    def connect(conn, timeout):
        seen.append(conn)
        return Connection()

    monkeypatch.setattr(pyodbc, "connect", connect)
    for key in ("POSTGRES_USER", "POSTGRES_PASSWORD", "MSSQL_AUTHENTICATION"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DB_TYPE", "mssql")
    monkeypatch.setenv("POSTGRES_HOST", "sql.example.test")
    monkeypatch.setenv("POSTGRES_DB", "amfa")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert wait_for_db.main() == 0
    return seen[0]


def test_wait_for_db_escapes_the_password(monkeypatch):
    conn = _wait_for_db_connection_string(
        monkeypatch, POSTGRES_USER="amfa", POSTGRES_PASSWORD="Ab1;cd{e}F!x9"
    )
    assert "UID={amfa};PWD={Ab1;cd{e}}F!x9}" in conn


def test_wait_for_db_managed_identity_sends_no_password(monkeypatch):
    conn = _wait_for_db_connection_string(
        monkeypatch,
        MSSQL_AUTHENTICATION="ActiveDirectoryMsi",
        POSTGRES_PASSWORD="ignored",
    )
    assert "Authentication=ActiveDirectoryMsi" in conn
    assert "PWD" not in conn


def test_json_helpers_reject_injected_keys():
    table = Table("auth_process", MetaData(), Column("auth_context_json", String))
    with pytest.raises(ValueError, match="simple identifier"):
        JsonText(table.c.auth_context_json, "x') OR 1=1 --")
    with pytest.raises(ValueError, match="simple identifier"):
        JsonBool(table.c.auth_context_json, "x') OR 1=1 --")


def test_json_bool_compiles_on_postgres_and_mssql():
    table = Table("auth_process", MetaData(), Column("auth_context_json", String))
    stmt = select(JsonBool(table.c.auth_context_json, "is_vpn"))
    pg = str(stmt.compile(dialect=postgresql.dialect()))
    ms = str(stmt.compile(dialect=mssql.dialect()))
    assert "::boolean" in pg
    assert "JSON_VALUE" in ms
    assert "WHEN 'true' THEN 1" in ms


def test_bool_is_compiles_on_postgres_and_mssql():
    table = Table("decision_params_config", MetaData(), Column("is_active", Boolean))
    stmt = select(table.c.is_active).where(bool_is(table.c.is_active, True))
    pg = str(stmt.compile(dialect=postgresql.dialect()))
    ms = str(
        stmt.compile(dialect=mssql.dialect(), compile_kwargs={"literal_binds": True})
    )
    assert "IS true" not in ms
    assert "IS 1" not in ms
    assert "= 1 = 1" not in ms
    assert "is_active" in ms
    assert "= true" in pg or "IS true" in pg or "= true" in pg.lower() or "true" in pg


def test_mssql_descending_index_ddl_is_plain_column_list():
    from sqlalchemy.schema import CreateIndex

    table = Table(
        "auth_process",
        MetaData(),
        Column("realm_id", String),
        Column("user_id", Uuid()),
        Column("final_status", String),
        Column("finished_at", DateTime(timezone=True)),
    )
    idx = Index(
        "ix_auth_process_realm_user_final_finished",
        table.c.realm_id,
        table.c.user_id,
        table.c.final_status,
        text("finished_at DESC"),
    )
    ddl = str(CreateIndex(idx).compile(dialect=mssql.dialect()))
    assert "finished_at DESC" in ddl
    assert "[finished_at DESC]" not in ddl


def test_row_compare_is_portable_or_on_both_dialects():
    table = Table(
        "auth_event",
        MetaData(),
        Column("event_time", DateTime(timezone=True)),
        Column("id", Uuid()),
    )
    when = datetime(2026, 8, 19, tzinfo=timezone.utc)
    event_id = UUID("44444444-4444-4444-8444-444444444401")
    stmt = select(table.c.id).where(
        row_compare(table.c.event_time, table.c.id, when, event_id, greater=True)
    )
    pg = str(stmt.compile(dialect=postgresql.dialect()))
    ms = str(
        stmt.compile(dialect=mssql.dialect(), compile_kwargs={"literal_binds": True})
    )
    assert "auth_event.event_time >" in pg
    assert "OR" in pg
    assert "(auth_event.event_time, auth_event.id)" not in pg
    assert "auth_event.event_time >" in ms
    assert "OR" in ms
    assert "(auth_event.event_time, auth_event.id)" not in ms
    assert "= 1 = 1" not in ms


def test_mssql_identifier_columns_are_nvarchar():
    dialect = mssql.dialect()
    realm = DecisionParamsConfig.__table__.c.realm_id.type.dialect_impl(dialect)
    details = AuthEvent.__table__.c.details.type.dialect_impl(dialect)
    hashed = DecisionParamsConfig.__table__.c.parameters_hash.type.dialect_impl(dialect)
    assert "Unicode" in type(realm).__name__
    assert realm.collation == "Latin1_General_100_CS_AS_SC_UTF8"
    assert "Unicode" in type(details).__name__
    assert "Unicode" not in type(hashed).__name__
    assert hashed.collation == "Latin1_General_100_BIN2"


def test_type_helpers_length_is_characters_on_mssql():
    dialect = mssql.dialect()
    country = text_str(32).dialect_impl(dialect)
    assert "Unicode" in type(country).__name__
    assert country.length == 32
    ident = ident_str(255).dialect_impl(dialect)
    assert ident.length == 255
    hashed = hashed_str(64).dialect_impl(dialect)
    assert hashed.length == 64
    blob = long_text().dialect_impl(dialect)
    assert "Unicode" in type(blob).__name__
