import os
import subprocess
import sys

import pytest

import src.core.config.environment as env
from src.__main__ import main


def test_validate_raises_when_postgres_env_missing(monkeypatch):
    monkeypatch.setattr(env, "POSTGRES_USER", None)
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", "p")
    monkeypatch.setattr(env, "POSTGRES_HOST", "localhost")
    monkeypatch.setattr(env, "POSTGRES_PORT", "5432")
    monkeypatch.setattr(env, "DATABASE", "db")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", ["https://idp.example.com"])

    with pytest.raises(RuntimeError, match="host named 'None'"):
        env.validate()


def test_validate_raises_when_oidc_trusted_base_urls_empty(monkeypatch):
    monkeypatch.setattr(env, "POSTGRES_USER", "u")
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", "p")
    monkeypatch.setattr(env, "POSTGRES_HOST", "localhost")
    monkeypatch.setattr(env, "POSTGRES_PORT", "5432")
    monkeypatch.setattr(env, "DATABASE", "db")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", [])

    with pytest.raises(RuntimeError, match="OIDC_TRUSTED_BASE_URLS is empty"):
        env.validate()


def test_validate_passes_when_required_env_is_set(monkeypatch):
    monkeypatch.setattr(env, "POSTGRES_USER", "u")
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", "p")
    monkeypatch.setattr(env, "POSTGRES_HOST", "localhost")
    monkeypatch.setattr(env, "POSTGRES_PORT", "5432")
    monkeypatch.setattr(env, "DATABASE", "db")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", ["https://idp.example.com"])

    env.validate()


def test_validate_accepts_mssql(monkeypatch):
    monkeypatch.setattr(env, "DB_TYPE", "mssql")
    monkeypatch.setattr(env, "POSTGRES_USER", "u")
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", "p")
    monkeypatch.setattr(env, "POSTGRES_HOST", "localhost")
    monkeypatch.setattr(env, "POSTGRES_PORT", "1433")
    monkeypatch.setattr(env, "DATABASE", "db")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", ["https://idp.example.com"])

    env.validate()


def test_validate_rejects_unknown_db_type(monkeypatch):
    monkeypatch.setattr(env, "DB_TYPE", "mysql")
    monkeypatch.setattr(env, "POSTGRES_USER", "u")
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", "p")
    monkeypatch.setattr(env, "POSTGRES_HOST", "localhost")
    monkeypatch.setattr(env, "POSTGRES_PORT", "3306")
    monkeypatch.setattr(env, "DATABASE", "db")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", ["https://idp.example.com"])

    with pytest.raises(RuntimeError, match="DB_TYPE='mysql'"):
        env.validate()


def test_main_calls_validate_before_uvicorn(monkeypatch):
    def boom():
        raise RuntimeError("validate-called")

    def uvicorn_should_not_run(*args, **kwargs):
        raise AssertionError("uvicorn ran before validate")

    monkeypatch.setattr("src.__main__.validate", boom)
    monkeypatch.setattr("src.__main__.uvicorn.run", uvicorn_should_not_run)

    with pytest.raises(RuntimeError, match="validate-called"):
        main()


def _complete_mssql_env(monkeypatch):
    monkeypatch.setattr(env, "DB_TYPE", "mssql")
    monkeypatch.setattr(env, "POSTGRES_USER", None)
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", None)
    monkeypatch.setattr(env, "POSTGRES_HOST", "sql.example.test")
    monkeypatch.setattr(env, "POSTGRES_PORT", "1433")
    monkeypatch.setattr(env, "DATABASE", "amfa")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", ["https://idp.example.com"])


def test_validate_accepts_managed_identity_without_user_or_password(monkeypatch):
    _complete_mssql_env(monkeypatch)
    monkeypatch.setattr(env, "MSSQL_PASSWORDLESS", True)
    env.validate()


def test_validate_requires_credentials_without_managed_identity(monkeypatch):
    _complete_mssql_env(monkeypatch)
    monkeypatch.setattr(env, "MSSQL_PASSWORDLESS", False)
    with pytest.raises(RuntimeError, match="POSTGRES_USER, POSTGRES_PASSWORD"):
        env.validate()


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"DB_TYPE": "mssql", "MSSQL_AUTHENTICATION": "ActiveDirectoryMsi"},
    ],
)
def test_incomplete_database_settings_do_not_crash_at_import(extra):
    """validate() owns the error message, so importing the module must succeed."""
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("POSTGRES_", "MSSQL_", "DB_TYPE"))}
    result = subprocess.run(
        [sys.executable, "-c", "import src.core.config.environment"],
        env={**clean, "POSTGRES_HOST": "db.example.test", **extra},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("value", [0, -1])
def test_validate_rejects_a_health_timeout_that_could_never_pass(monkeypatch, value):
    monkeypatch.setattr(env, "POSTGRES_USER", "u")
    monkeypatch.setattr(env, "POSTGRES_PASSWORD", "p")
    monkeypatch.setattr(env, "POSTGRES_HOST", "localhost")
    monkeypatch.setattr(env, "POSTGRES_PORT", "5432")
    monkeypatch.setattr(env, "DATABASE", "db")
    monkeypatch.setattr(env, "OIDC_TRUSTED_BASE_URLS", ["https://idp.example.com"])
    monkeypatch.setattr(env, "HEALTH_CHECK_TIMEOUT", value)
    with pytest.raises(RuntimeError, match="HEALTH_CHECK_TIMEOUT"):
        env.validate()
