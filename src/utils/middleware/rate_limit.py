from src.core.exception import RateLimitException
from src.core.config.environment import (
    RATE_LIMIT_MAX_REQ,
    CONFIG_RATE_LIMIT_MAX_REQ,
    RATE_LIMIT,
    RATE_LIMIT_TIME_WINDOW,
)

import time
import uuid
from src.core.redis import get_redis
from src.utils.auth.dependency import tenant_scoped_id


# Atomically prunes entries older than the window, counts what's left, and
# -- only if still under the limit -- records this request and allows it.
# Everything here runs as a single Lua script: Redis executes a script to
# completion without interleaving any other command, so concurrent callers
# can never race the count-then-write the way separate SCAN/GET+SET calls
# could: a whole-second bucket checked via a separate scan-then-write would
# let any number of requests landing in the same second all observe the
# same pre-existing state and get allowed through.
#
# Using a sorted set keyed by request time, rather than one key per second,
# also makes the window genuinely sliding: the limit is enforced against
# any trailing window-length span, not against whole-second buckets a burst
# could straddle.
_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_req = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= max_req then
    return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, window)
return 1
"""

if RATE_LIMIT and RATE_LIMIT_TIME_WINDOW <= 0:
    # A non-positive window isn't just a no-op -- Redis's EXPIRE deletes a
    # key immediately when given a zero/negative TTL, so the just-written
    # ZSET entry vanishes right after every ZADD and the next call always
    # sees ZCARD == 0. That silently disables the limiter entirely (fail-
    # open) rather than failing to configure it, so this is caught here at
    # import time instead.
    raise ValueError(
        "RATE_LIMIT_TIME_WINDOW must be positive when RATE_LIMIT is enabled, "
        f"got {RATE_LIMIT_TIME_WINDOW!r}."
    )


async def control_rate_limit(realm_id: str, user_id, bucket: str = "decision"):
    """Rate-limit one (bucket, realm_id, user_id) triple.

    `bucket` separates independent endpoint categories that would otherwise
    share a key namespace. `/decision`'s `user_id` comes from the request
    body and is never checked against the caller's own token subject, so it
    is effectively attacker-chosen -- without a distinct bucket, any caller
    in a realm could spend `/decision` requests with `user_id` set to a
    config-writing identity's client_id/subject and exhaust THAT identity's
    budget, causing spurious 429s on the settings/scoring endpoints. Giving
    each endpoint category its own bucket makes that cross-endpoint
    collision impossible regardless of what value a caller supplies.

    The ``config`` bucket allows CONFIG_RATE_LIMIT_MAX_REQ requests per window,
    every other bucket RATE_LIMIT_MAX_REQ.
    """
    if not RATE_LIMIT:
        return

    redis = get_redis()
    scoped = tenant_scoped_id(realm_id, user_id)
    key = f"rl:{bucket}:{scoped}"
    now = time.time()
    # A UUID, not just the timestamp, so two requests landing at the exact
    # same float timestamp under real concurrency still get distinct ZSET
    # members -- a duplicate member would silently collapse into one entry
    # (ZADD updates a member's score rather than adding a second one),
    # undercounting exactly the concurrent-request scenario this fix exists
    # to handle correctly.
    member = f"{now}:{uuid.uuid4()}"
    max_req = CONFIG_RATE_LIMIT_MAX_REQ if bucket == "config" else RATE_LIMIT_MAX_REQ

    # register_script() does no I/O -- it just wraps the (constant) script
    # text and hashes it locally -- so calling it fresh here rather than
    # caching the result costs a cheap SHA1, not a round trip.
    script = redis.register_script(_RATE_LIMIT_SCRIPT)
    allowed = await script(
        keys=[key], args=[now, RATE_LIMIT_TIME_WINDOW, max_req, member]
    )

    if not allowed:
        raise RateLimitException
