import asyncio
import importlib

import pytest

from src.core.exception import RateLimitException
from src.core.redis import get_redis
import src.core.config.environment as environment_mod
from src.utils.middleware import rate_limit as rate_limit_mod
from src.utils.middleware.rate_limit import control_rate_limit


async def _clear(bucket: str, realm_id: str, user_id: str):
    redis = get_redis()
    await redis.delete(f"rl:{bucket}:{realm_id}:{user_id}")


@pytest.mark.asyncio(loop_scope="session")
async def test_requests_under_the_limit_are_all_allowed(monkeypatch):
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 4)
    await _clear("t", "r", "under-limit")

    for _ in range(4):
        await control_rate_limit(realm_id="r", user_id="under-limit", bucket="t")


@pytest.mark.asyncio(loop_scope="session")
async def test_the_request_over_the_limit_is_rejected(monkeypatch):
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 4)
    await _clear("t", "r", "over-limit")

    for _ in range(4):
        await control_rate_limit(realm_id="r", user_id="over-limit", bucket="t")

    with pytest.raises(RateLimitException):
        await control_rate_limit(realm_id="r", user_id="over-limit", bucket="t")


@pytest.mark.asyncio(loop_scope="session")
async def test_concurrent_requests_in_the_same_instant_are_each_counted(monkeypatch):
    """The old implementation bucketed requests by whole second and checked a
    scan's results against a set of keys that concurrent callers could all
    observe as unchanged -- so any number of requests landing in the same
    second were all allowed. Reproduced live: 20 concurrent requests against
    a limit of 4 all got HTTP 200. This is the direct regression test:
    exactly RATE_LIMIT_MAX_REQ of a burst of concurrent calls must succeed,
    the rest must be rejected, regardless of how tightly they're clustered
    in time."""
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 4)
    await _clear("t", "r", "concurrent-burst")

    results = await asyncio.gather(
        *[
            control_rate_limit(realm_id="r", user_id="concurrent-burst", bucket="t")
            for _ in range(20)
        ],
        return_exceptions=True,
    )

    allowed = [r for r in results if r is None]
    rejected = [r for r in results if isinstance(r, RateLimitException)]
    other_errors = [
        r for r in results if r is not None and not isinstance(r, RateLimitException)
    ]

    assert not other_errors, f"unexpected exceptions: {other_errors}"
    assert len(allowed) == 4, f"expected exactly 4 allowed, got {len(allowed)}"
    assert len(rejected) == 16, f"expected exactly 16 rejected, got {len(rejected)}"


@pytest.mark.asyncio(loop_scope="session")
async def test_window_slides_rather_than_resetting_on_a_fixed_boundary(monkeypatch):
    """A request that falls outside the window is pruned and no longer
    counts, regardless of whether a whole-second (or whole-window) boundary
    was crossed -- this is what makes the window "sliding" rather than a
    fixed bucket that resets abruptly."""
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 2)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_TIME_WINDOW", 1)
    await _clear("t", "r", "sliding")

    await control_rate_limit(realm_id="r", user_id="sliding", bucket="t")
    await control_rate_limit(realm_id="r", user_id="sliding", bucket="t")
    with pytest.raises(RateLimitException):
        await control_rate_limit(realm_id="r", user_id="sliding", bucket="t")

    await asyncio.sleep(1.1)

    # The two earlier requests have aged out of the 1-second window, so
    # fresh requests are allowed again without waiting for any fixed
    # boundary to reset.
    await control_rate_limit(realm_id="r", user_id="sliding", bucket="t")


@pytest.mark.asyncio(loop_scope="session")
async def test_different_buckets_do_not_share_state_for_the_same_realm_and_user(
    monkeypatch,
):
    """/decision's rate-limit key
    is built from an attacker-controlled request field (user_id), never
    checked against the caller's own token subject. Without a distinct
    bucket per endpoint category, any caller could spend /decision requests
    with user_id set to a config-writing identity's client_id and exhaust
    THAT identity's budget. Each bucket must track its own independent
    state."""
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 2)
    monkeypatch.setattr(rate_limit_mod, "CONFIG_RATE_LIMIT_MAX_REQ", 2)
    await _clear("decision", "r", "shared-client-id")
    await _clear("config", "r", "shared-client-id")

    await control_rate_limit(realm_id="r", user_id="shared-client-id", bucket="decision")
    await control_rate_limit(realm_id="r", user_id="shared-client-id", bucket="decision")
    with pytest.raises(RateLimitException):
        await control_rate_limit(realm_id="r", user_id="shared-client-id", bucket="decision")

    # The "decision" bucket is exhausted, but "config" for the same
    # realm+user is untouched.
    await control_rate_limit(realm_id="r", user_id="shared-client-id", bucket="config")
    await control_rate_limit(realm_id="r", user_id="shared-client-id", bucket="config")
    with pytest.raises(RateLimitException):
        await control_rate_limit(realm_id="r", user_id="shared-client-id", bucket="config")


@pytest.mark.asyncio(loop_scope="session")
async def test_config_writes_have_their_own_limit(monkeypatch):
    """Every admin of a realm writes settings and scoring through the same
    Keycloak service account, and each Save costs two writes, so the config
    bucket needs a larger budget than a single user's /decision calls."""
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 2)
    monkeypatch.setattr(rate_limit_mod, "CONFIG_RATE_LIMIT_MAX_REQ", 5)
    await _clear("config", "r", "admin-client")

    for _ in range(5):
        await control_rate_limit(realm_id="r", user_id="admin-client", bucket="config")
    with pytest.raises(RateLimitException):
        await control_rate_limit(realm_id="r", user_id="admin-client", bucket="config")


@pytest.mark.asyncio(loop_scope="session")
async def test_the_config_limit_does_not_raise_the_decision_limit(monkeypatch):
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 2)
    monkeypatch.setattr(rate_limit_mod, "CONFIG_RATE_LIMIT_MAX_REQ", 5)
    await _clear("decision", "r", "a-user")

    for _ in range(2):
        await control_rate_limit(realm_id="r", user_id="a-user", bucket="decision")
    with pytest.raises(RateLimitException):
        await control_rate_limit(realm_id="r", user_id="a-user", bucket="decision")


@pytest.mark.asyncio(loop_scope="session")
async def test_disabled_rate_limit_is_a_no_op(monkeypatch):
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT", False)
    monkeypatch.setattr(rate_limit_mod, "RATE_LIMIT_MAX_REQ", 0)
    await _clear("t", "r", "disabled")

    for _ in range(10):
        await control_rate_limit(realm_id="r", user_id="disabled", bucket="t")


def test_non_positive_window_is_rejected_at_import_rather_than_failing_open(
    monkeypatch,
):
    """Redis's EXPIRE deletes a key immediately
    when given a zero/negative TTL, so a misconfigured
    RATE_LIMIT_TIME_WINDOW <= 0 would silently disable the limiter on every
    call (the just-written ZSET entry vanishes right after ZADD, so the next
    call always sees ZCARD == 0) instead of failing to configure at all.
    Must be caught loudly at import time instead."""
    monkeypatch.setattr(environment_mod, "RATE_LIMIT", True)
    monkeypatch.setattr(environment_mod, "RATE_LIMIT_TIME_WINDOW", 0)

    try:
        with pytest.raises(ValueError):
            importlib.reload(rate_limit_mod)
    finally:
        # Restore real config and reload again so this module is left in a
        # normal, importable state for every other test in the suite.
        monkeypatch.undo()
        importlib.reload(rate_limit_mod)
