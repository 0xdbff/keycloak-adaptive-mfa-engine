import importlib

import pytest

import src.core.config.environment as env


@pytest.fixture
def reload_env(monkeypatch):
    """Re-read the environment module under patched env vars, then restore it."""
    def _reload(**values):
        for name in ("REDIS_HOST", "REDIS_PORT", "REDIS_DB", "REDIS_USERNAME",
                     "REDIS_PASSWORD", "REDIS_SSL", "REDIS_SSL_CA_CERTS"):
            monkeypatch.delenv(name, raising=False)
        for name, value in values.items():
            monkeypatch.setenv(name, value)
        # load_dotenv must not refill what the test cleared.
        monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
        return importlib.reload(env)
    yield _reload
    monkeypatch.undo()
    importlib.reload(env)


def test_unset_means_no_credentials_and_no_tls(reload_env):
    e = reload_env()
    assert (e.REDIS_HOST, e.REDIS_PORT, e.REDIS_DB) == ("redis", 6379, 0)
    assert e.REDIS_USERNAME is None and e.REDIS_PASSWORD is None
    assert e.REDIS_SSL is False and e.REDIS_SSL_CA_CERTS is None


def test_empty_values_count_as_unset(reload_env):
    # .env.example ships REDIS_PASSWORD= ; it must not become "" or "None".
    e = reload_env(REDIS_PASSWORD="", REDIS_USERNAME="", REDIS_SSL="", REDIS_SSL_CA_CERTS="")
    assert e.REDIS_PASSWORD is None and e.REDIS_USERNAME is None
    assert e.REDIS_SSL is False and e.REDIS_SSL_CA_CERTS is None


def test_values_are_read(reload_env):
    e = reload_env(REDIS_HOST="cache.internal", REDIS_PORT="6380", REDIS_DB="2",
                   REDIS_USERNAME="amfa", REDIS_PASSWORD="s3cret", REDIS_SSL="true")
    assert (e.REDIS_HOST, e.REDIS_PORT, e.REDIS_DB) == ("cache.internal", 6380, 2)
    assert (e.REDIS_USERNAME, e.REDIS_PASSWORD, e.REDIS_SSL) == ("amfa", "s3cret", True)


@pytest.mark.parametrize("raw, expected", [("true", True), ("TRUE", True), ("1", True), ("yes", True),
                                           ("on", True), ("false", False), ("0", False), ("off", False)])
def test_redis_ssl_accepts_booleans(reload_env, raw, expected):
    assert reload_env(REDIS_SSL=raw).REDIS_SSL is expected


def test_redis_ssl_typo_stops_instead_of_turning_tls_off(reload_env):
    with pytest.raises(ValueError, match="REDIS_SSL"):
        reload_env(REDIS_SSL="ture")


@pytest.fixture
def valid_base(monkeypatch):
    for name, value in {"POSTGRES_USER": "u", "POSTGRES_PASSWORD": "p", "POSTGRES_HOST": "h",
                        "POSTGRES_PORT": "5432", "DATABASE": "db",
                        "OIDC_TRUSTED_BASE_URLS": ["https://idp.example.com"],
                        "REDIS_USERNAME": None, "REDIS_PASSWORD": None,
                        "REDIS_SSL": False, "REDIS_SSL_CA_CERTS": None}.items():
        monkeypatch.setattr(env, name, value)
    return monkeypatch


def test_validate_refuses_a_username_without_password(valid_base):
    valid_base.setattr(env, "REDIS_USERNAME", "amfa")
    with pytest.raises(RuntimeError, match="REDIS_USERNAME is set but REDIS_PASSWORD is not"):
        env.validate()


def test_validate_refuses_a_ca_bundle_without_tls(valid_base, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    valid_base.setattr(env, "REDIS_SSL_CA_CERTS", str(ca))
    with pytest.raises(RuntimeError, match="REDIS_SSL is not true"):
        env.validate()


def test_validate_refuses_an_unreadable_ca_bundle(valid_base, tmp_path):
    valid_base.setattr(env, "REDIS_SSL", True)
    valid_base.setattr(env, "REDIS_SSL_CA_CERTS", str(tmp_path / "missing.pem"))
    with pytest.raises(RuntimeError, match="not a readable file"):
        env.validate()


def test_validate_accepts_password_tls_and_ca(valid_base, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    valid_base.setattr(env, "REDIS_USERNAME", "amfa")
    valid_base.setattr(env, "REDIS_PASSWORD", "s3cret")
    valid_base.setattr(env, "REDIS_SSL", True)
    valid_base.setattr(env, "REDIS_SSL_CA_CERTS", str(ca))
    env.validate()
