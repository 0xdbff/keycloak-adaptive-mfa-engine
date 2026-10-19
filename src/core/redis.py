import redis.asyncio as redis
from redis import exceptions as redis_exceptions

from src.core.config import environment


def connection_kwargs() -> dict:
    """Connection settings for the Redis client, from the REDIS_* environment.

    Credentials and TLS are added only when configured, so a deployment that
    sets none of them connects exactly as before: no AUTH, no TLS.
    """
    kwargs = {
        "host": environment.REDIS_HOST,
        "port": environment.REDIS_PORT,
        "db": environment.REDIS_DB,
        "decode_responses": True,
    }
    if environment.REDIS_PASSWORD:
        kwargs["password"] = environment.REDIS_PASSWORD
        if environment.REDIS_USERNAME:
            kwargs["username"] = environment.REDIS_USERNAME
    if environment.REDIS_SSL:
        # redis-py 5 leaves hostname checking off unless asked: a certificate
        # for any name signed by a trusted CA would otherwise be accepted.
        kwargs["ssl"] = True
        kwargs["ssl_cert_reqs"] = "required"
        kwargs["ssl_check_hostname"] = True
        if environment.REDIS_SSL_CA_CERTS:
            kwargs["ssl_ca_certs"] = environment.REDIS_SSL_CA_CERTS
    return kwargs


class RedisService:
    client = None

    @classmethod
    def get_singleton(cls):
        if cls.client is None:
            cls.client = redis.Redis(**connection_kwargs())
        return cls.client


def get_redis():
    return RedisService.get_singleton()


async def check_redis() -> None:
    """Fail startup with an error that says what is wrong with Redis.

    Without it, a refused password surfaces later from whichever command runs
    first, as a bare "invalid username-password pair" that does not even name
    Redis.
    """
    where = f"{environment.REDIS_HOST}:{environment.REDIS_PORT}"
    if environment.REDIS_SSL:
        where += " over TLS"
    try:
        await get_redis().ping()
    # AuthenticationError subclasses ConnectionError, so it is matched first.
    except redis_exceptions.AuthenticationError as exc:
        raise RuntimeError(
            f"Redis at {where} refused authentication ({exc}). "
            "Check REDIS_PASSWORD, and REDIS_USERNAME for an ACL user; "
            "leave both unset for a Redis without a password."
        ) from exc
    except redis_exceptions.ConnectionError as exc:
        raise RuntimeError(f"Cannot connect to Redis at {where}: {exc}") from exc
    except redis_exceptions.ResponseError as exc:
        # Some servers answer a missing password with a NOAUTH error reply.
        if "NOAUTH" in str(exc).upper():
            raise RuntimeError(
                f"Redis at {where} requires a password and none was sent. "
                "Set REDIS_PASSWORD."
            ) from exc
        raise
