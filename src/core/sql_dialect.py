"""Dialect helpers so the engine talks Postgres (default) and Azure SQL.

Nothing here replaces Postgres. `DB_TYPE=mssql` selects SQL Server compilation
and connection URLs; unset or `postgresql` keeps today's behaviour.
"""

from __future__ import annotations

import os
import re
from urllib.parse import quote_plus, urlencode

from sqlalchemy import Boolean, String, Unicode, UnicodeText, and_, literal, or_, text
from sqlalchemy.dialects.mssql import NVARCHAR, VARCHAR
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.expression import FunctionElement
from sqlalchemy.sql.visitors import InternalTraversal


SUPPORTED_DB_TYPES = ("postgresql", "mssql")

# Azure SQL's default collation is case-insensitive and 8-bit. Keycloak realm
# names are case-sensitive, and country/device strings are not Latin-only.
MSSQL_CS_UTF8 = "Latin1_General_100_CS_AS_SC_UTF8"
MSSQL_BIN2 = "Latin1_General_100_BIN2"
MSSQL_MANAGED_IDENTITY = "ActiveDirectoryMsi"

_JSON_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def db_type() -> str:
    value = (os.getenv("DB_TYPE") or "postgresql").strip().lower()
    return value or "postgresql"


def hashed_str(length: int = 64):
    """ASCII hash. VARCHAR + BIN2 so SQL Server compares it as Postgres does."""
    return String(length).with_variant(VARCHAR(length, collation=MSSQL_BIN2), "mssql")


def ident_str(length: int = 255):
    """Realm, group, and other identifiers. NVARCHAR, case-sensitive UTF-8."""
    return Unicode(length).with_variant(
        NVARCHAR(length, collation=MSSQL_CS_UTF8), "mssql"
    )


def text_str(length: int):
    """Human-readable text. Length is in characters, not bytes."""
    return Unicode(length).with_variant(
        NVARCHAR(length, collation=MSSQL_CS_UTF8), "mssql"
    )


def long_text():
    return UnicodeText().with_variant(
        NVARCHAR(None, collation=MSSQL_CS_UTF8), "mssql"
    )


def uuid_server_default():
    if db_type() == "mssql":
        return text("NEWID()")
    return text("uuid_generate_v4()")


def now_server_default():
    if db_type() == "mssql":
        return text("TODATETIMEOFFSET(SYSUTCDATETIME(), 0)")
    return text("now()")


def boolean_false_server_default():
    if db_type() == "mssql":
        return text("0")
    return text("false")


def build_database_urls(
    db_type_name: str,
    user: str | None,
    password: str | None,
    host: str,
    port: str | int,
    database: str,
    *,
    odbc_driver: str = "ODBC Driver 18 for SQL Server",
    encrypt: bool = True,
    trust_server_certificate: bool = False,
    authentication: str = "",
) -> tuple[str, str]:
    """Return `(sync_url, async_url)` for Alembic and the engine respectively."""
    if authentication == MSSQL_MANAGED_IDENTITY:
        password = None
    user_q = quote_plus(user or "")
    password_q = quote_plus(password or "")
    if db_type_name == "mssql":
        options = {
            "driver": odbc_driver,
            "Encrypt": "yes" if encrypt else "no",
            "TrustServerCertificate": "yes" if trust_server_certificate else "no",
        }
        if authentication:
            options["authentication"] = authentication
        query = urlencode(options)
        credentials = f"{user_q}:{password_q}" if password else user_q
        sync = f"mssql+pyodbc://{credentials}@{host}:{port}/{database}?{query}"
        async_url = f"mssql+aioodbc://{credentials}@{host}:{port}/{database}?{query}"
        return sync, async_url
    sync = f"postgresql://{user_q}:{password_q}@{host}:{port}/{database}"
    return sync, f"postgresql+asyncpg://{user_q}:{password_q}@{host}:{port}/{database}"


def odbc_brace(value: str) -> str:
    """Wrap a UID/PWD so `;`, `{`, and `}` survive an ODBC connection string."""
    return "{" + str(value).replace("}", "}}") + "}"


def bool_is(column, value: bool):
    """Boolean equality that compiles on both dialects.

    `column.is_(True)` is `IS 1` on SQL Server, which is invalid T-SQL.
    `column == True` is `= true` on Postgres and `= 1` on SQL Server.

    Do not wrap this in a Boolean FunctionElement: SQLAlchemy then appends
    another `= 1` and SQL Server rejects `col = 1 = 1`.
    """
    return column == bool(value)


def row_compare(col_a, col_b, val_a, val_b, *, greater: bool):
    """Keyset pagination predicate, portable across Postgres and SQL Server.

    A Boolean FunctionElement wrapping the comparison is compiled with an extra
    `= 1` on SQL Server (`Incorrect syntax near '='`).
    """
    if greater:
        return or_(col_a > val_a, and_(col_a == val_a, col_b > val_b))
    return or_(col_a < val_a, and_(col_a == val_a, col_b < val_b))


def _check_json_key(key: str) -> str:
    if not isinstance(key, str) or not _JSON_KEY.match(key):
        raise ValueError(f"JSON key must be a simple identifier, got {key!r}")
    return key


class _JsonKeyElement(FunctionElement):
    """A JSON column read by key. The key is rendered into the SQL text, so it
    has to be part of the cache key: a bind parameter's value is not, and two
    keys would then share one cached statement.
    """

    inherit_cache = True
    _traverse_internals = FunctionElement._traverse_internals + [
        ("json_key", InternalTraversal.dp_string)
    ]

    def __init__(self, column, key: str):
        self.json_key = _check_json_key(key)
        super().__init__(column)


class JsonText(_JsonKeyElement):
    """JSON object key as text. Compiles to `->>` on Postgres, `JSON_VALUE` on MSSQL."""

    inherit_cache = True
    type = String()


@compiles(JsonText, "postgresql")
def _json_text_pg(element, compiler, **kw):
    column = compiler.process(element.clauses.clauses[0], **kw)
    return f"({column} ->> '{element.json_key}')"


@compiles(JsonText, "mssql")
def _json_text_mssql(element, compiler, **kw):
    # JSON columns take the database's default collation. Without COLLATE,
    # comparing this to an NVARCHAR column fails on any other default (error 4191).
    column = compiler.process(element.clauses.clauses[0], **kw)
    return f"JSON_VALUE({column}, '$.{element.json_key}') COLLATE {MSSQL_CS_UTF8}"


class JsonBool(_JsonKeyElement):
    """JSON object key as boolean. Postgres casts the text; MSSQL maps true/false/1/0."""

    inherit_cache = True
    type = Boolean()


@compiles(JsonBool, "postgresql")
def _json_bool_pg(element, compiler, **kw):
    column = compiler.process(element.clauses.clauses[0], **kw)
    return f"(({column} ->> '{element.json_key}')::boolean)"


@compiles(JsonBool, "mssql")
def _json_bool_mssql(element, compiler, **kw):
    column = compiler.process(element.clauses.clauses[0], **kw)
    return (
        "(CASE LOWER(JSON_VALUE("
        f"{column}, '$.{element.json_key}')) "
        "WHEN 'true' THEN 1 WHEN '1' THEN 1 "
        "WHEN 'false' THEN 0 WHEN '0' THEN 0 ELSE NULL END)"
    )


class NullIfEq(FunctionElement):
    """`NULLIF(col, '') = value` on Postgres (matches the expression index).

    Plain `col = value` on SQL Server so the realm index is sargable.
    Not typed Boolean: a Boolean FunctionElement gets an extra `= 1` on MSSQL.
    """

    inherit_cache = True

    def __init__(self, column, value):
        super().__init__(column, literal(value))


@compiles(NullIfEq, "postgresql")
def _nullif_eq_pg(element, compiler, **kw):
    column, value = (compiler.process(clause, **kw) for clause in element.clauses)
    return f"NULLIF({column}, '') = {value}"


@compiles(NullIfEq, "mssql")
def _nullif_eq_mssql(element, compiler, **kw):
    column, value = (compiler.process(clause, **kw) for clause in element.clauses)
    return f"{column} = {value}"


class EmptyAsNull(FunctionElement):
    """True when the column is missing or blank. Postgres uses NULLIF for the index."""

    inherit_cache = True

    def __init__(self, column):
        super().__init__(column)


@compiles(EmptyAsNull, "postgresql")
def _empty_as_null_pg(element, compiler, **kw):
    column = compiler.process(element.clauses.clauses[0], **kw)
    return f"NULLIF({column}, '') IS NULL"


@compiles(EmptyAsNull, "mssql")
def _empty_as_null_mssql(element, compiler, **kw):
    column = compiler.process(element.clauses.clauses[0], **kw)
    return f"({column} IS NULL OR {column} = N'')"
