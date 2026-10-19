import pytest
from redis import exceptions as redis_exceptions

import src.core.config.environment as env
import src.core.redis as redis_mod


@pytest.fixture
def redis_env(monkeypatch):
    """Today's defaults: no credentials, no TLS."""
    for name, value in {
        "REDIS_HOST": "redis", "REDIS_PORT": 6379, "REDIS_DB": 0,
        "REDIS_USERNAME": None, "REDIS_PASSWORD": None,
        "REDIS_SSL": False, "REDIS_SSL_CA_CERTS": None,
    }.items():
        monkeypatch.setattr(env, name, value)
    return monkeypatch


def test_no_settings_connect_as_before(redis_env):
    assert redis_mod.connection_kwargs() == {
        "host": "redis", "port": 6379, "db": 0, "decode_responses": True,
    }


def test_password_only_authenticates_the_default_user(redis_env):
    redis_env.setattr(env, "REDIS_PASSWORD", "s3cret")
    kwargs = redis_mod.connection_kwargs()
    assert kwargs["password"] == "s3cret"
    assert "username" not in kwargs


def test_acl_user_sends_username_and_password(redis_env):
    redis_env.setattr(env, "REDIS_USERNAME", "amfa")
    redis_env.setattr(env, "REDIS_PASSWORD", "s3cret")
    kwargs = redis_mod.connection_kwargs()
    assert (kwargs["username"], kwargs["password"]) == ("amfa", "s3cret")


def test_tls_verifies_the_certificate_and_its_hostname(redis_env):
    redis_env.setattr(env, "REDIS_SSL", True)
    kwargs = redis_mod.connection_kwargs()
    assert kwargs["ssl"] is True
    assert kwargs["ssl_cert_reqs"] == "required"
    assert kwargs["ssl_check_hostname"] is True
    assert "ssl_ca_certs" not in kwargs


def test_tls_with_a_private_ca(redis_env):
    redis_env.setattr(env, "REDIS_SSL", True)
    redis_env.setattr(env, "REDIS_SSL_CA_CERTS", "/etc/ssl/redis-ca.pem")
    assert redis_mod.connection_kwargs()["ssl_ca_certs"] == "/etc/ssl/redis-ca.pem"


class _FakeRedis:
    def __init__(self, exc=None):
        self.exc = exc

    async def ping(self):
        if self.exc:
            raise self.exc
        return True


@pytest.mark.asyncio(loop_scope="session")
async def test_check_redis_passes_when_redis_answers(redis_env):
    redis_env.setattr(redis_mod, "get_redis", lambda: _FakeRedis())
    await redis_mod.check_redis()


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("exc, expected", [
    (redis_exceptions.AuthenticationError("invalid username-password pair"), "refused authentication"),
    (redis_exceptions.ResponseError("NOAUTH Authentication required."), "requires a password"),
    (redis_exceptions.ConnectionError("Connection refused"), "Cannot connect to Redis"),
])
async def test_check_redis_names_redis_in_the_error(redis_env, exc, expected):
    redis_env.setattr(redis_mod, "get_redis", lambda: _FakeRedis(exc))
    with pytest.raises(RuntimeError, match=expected) as info:
        await redis_mod.check_redis()
    assert "redis:6379" in str(info.value)


@pytest.mark.asyncio(loop_scope="session")
async def test_check_redis_reraises_other_replies(redis_env):
    redis_env.setattr(redis_mod, "get_redis", lambda: _FakeRedis(redis_exceptions.ResponseError("ERR something else")))
    with pytest.raises(redis_exceptions.ResponseError):
        await redis_mod.check_redis()
