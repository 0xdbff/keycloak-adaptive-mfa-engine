#!/usr/bin/env python3
"""Block until the configured database accepts connections.

Postgres uses pg_isready from the entrypoint. Azure SQL has no equivalent in
the image PATH, so this script opens one ODBC connection and exits 0.
"""

from __future__ import annotations

import os
import sys

from src.core.sql_dialect import MSSQL_MANAGED_IDENTITY, db_type, odbc_brace


def main() -> int:
    if db_type() != "mssql":
        print("wait_for_db.py is for DB_TYPE=mssql; use pg_isready for PostgreSQL", file=sys.stderr)
        return 2
    try:
        import pyodbc
    except ImportError:
        print("pyodbc is required when DB_TYPE=mssql", file=sys.stderr)
        return 2

    host = os.environ["POSTGRES_HOST"]
    port = os.environ.get("POSTGRES_PORT") or "1433"
    user = os.environ.get("POSTGRES_USER")
    password = os.environ.get("POSTGRES_PASSWORD")
    authentication = (os.environ.get("MSSQL_AUTHENTICATION") or "").strip()
    database = os.environ["POSTGRES_DB"]
    driver = os.environ.get("MSSQL_ODBC_DRIVER") or "ODBC Driver 18 for SQL Server"
    encrypt = "yes" if os.environ.get("MSSQL_ENCRYPT", "true").lower() in (
        "1", "true", "yes", "on",
    ) else "no"
    trust = "yes" if os.environ.get("MSSQL_TRUST_SERVER_CERTIFICATE", "").lower() in (
        "1", "true", "yes", "on",
    ) else "no"
    conn = (
        f"DRIVER={{{driver}}};SERVER={host},{port};DATABASE={database};"
        f"Encrypt={encrypt};TrustServerCertificate={trust}"
    )
    if authentication:
        conn += f";Authentication={authentication}"
    if user:
        conn += f";UID={odbc_brace(user)}"
    if password and authentication != MSSQL_MANAGED_IDENTITY:
        conn += f";PWD={odbc_brace(password)}"
    try:
        pyodbc.connect(conn, timeout=3).close()
    except Exception as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
