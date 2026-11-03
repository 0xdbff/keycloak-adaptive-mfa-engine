import json
import logging
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError

from src.core.config.environment import (
    OIDC_TRUSTED_BASE_URLS,
    OIDC_EXPECTED_AUDIENCE,
    OIDC_VERIFY_AUDIENCE,
    OIDC_CLOCK_SKEW_LEEWAY,
    JWKS_CACHE_TTL,
    OIDC_DISCOVERY_TIMEOUT,
    OIDC_CA_BUNDLE,
    DISCOVERY_FAILURE_CACHE_TTL,
    DISCOVERY_UNREACHABLE_CACHE_TTL,
    DISCOVERY_FAILURE_CACHE_MAX_SIZE,
    DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS,
    DISCOVERY_RATE_LIMIT_WINDOW_SECONDS,
    DISCOVERY_MAX_WAITERS,
)

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Matches any character Python's own str.splitlines() treats as a line
# break: the C0 controls and DEL (\x00-\x1f, \x7f), the C1 controls
# (\x80-\x9f -- notably NEL, \x85), and the Unicode LINE/PARAGRAPH SEPARATOR
# code points. A narrower C0-only blocklist would still let a NEL- or
# U+2028-bearing value fool any Python-based log consumer that calls
# .splitlines() on the file, even though it wouldn't split the raw bytes of
# the log file itself.
#
# `iss` and `kid` are both read from a token BEFORE its signature is checked
# (see _unverified_issuer and _resolve_signing_key below), so they are fully
# attacker-controlled at the point they're first extracted. Python's
# urllib.parse.urlparse silently strips CR/LF while parsing a URL, so a
# crafted issuer can structurally satisfy _validate_issuer's trusted-prefix
# check even though the ORIGINAL, unstripped string -- which is what
# actually gets used to build the discovery URL and gets logged on failure
# -- still carries the embedded line break. Rejecting any of these
# characters the moment either claim is extracted, before anything
# downstream (a parser, an HTTP call, a log line) ever sees it, closes this
# regardless of what any individual downstream consumer does or doesn't
# sanitize.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _sanitize_for_log(value) -> str:
    """Replace control characters (including CR/LF) with a space.

    Defense in depth alongside the extraction-point rejections above: even
    if some future code path fed an unvalidated value to one of the log
    calls below, it could not use that value to start a fake log record.
    """
    if value is None:
        return "None"
    return _CONTROL_CHAR_RE.sub(" ", str(value))


def _ssl_context() -> ssl.SSLContext | None:
    """SSL context for the discovery/JWKS fetch.

    Returns None when no custom CA bundle is configured (urllib/PyJWKClient then use
    the system trust store, so public CAs work). When OIDC_CA_BUNDLE is set, returns a
    default-verifying context that additionally trusts that CA bundle — for Keycloak
    behind a private/internal CA. Certificate verification is never disabled.
    """
    if not OIDC_CA_BUNDLE:
        return None
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=OIDC_CA_BUNDLE)
    return ctx


def _effective_port(parsed) -> int | None:
    return parsed.port or _DEFAULT_PORTS.get(parsed.scheme)


class AuthError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


@dataclass
class VerifiedPrincipal:
    issuer: str
    realm: str
    client_id: str | None
    roles: list[str]
    audiences: list[str]
    subject: str | None
    claims: dict


_jwks_clients: dict[str, PyJWKClient] = {}

# Negative cache for failed discovery lookups -> {issuer: failed_at_epoch}.
# _validate_issuer only checks that an issuer's HOST is trusted (any realm
# under it is accepted, by design, so onboarding a new realm needs no config
# change) -- it never confirms the realm actually exists. _jwks_clients above
# only gets populated on a SUCCESSFUL fetch, so without this, a request
# naming a realm that doesn't exist re-triggers a full outbound HTTP fetch,
# blocking a worker thread for up to OIDC_DISCOVERY_TIMEOUT, on every single
# request. Guarded by its own lock since discovery runs inside worker threads
# (via asyncio.to_thread), which are real OS threads that can genuinely run
# this concurrently, unlike asyncio coroutines on one loop.
_discovery_failures_lock = threading.Lock()
_discovery_failures: dict[str, float] = {}
# The issuers in _discovery_failures whose last failure was Keycloak being
# unreachable rather than the realm not existing; they are remembered only
# for DISCOVERY_UNREACHABLE_CACHE_TTL. Guarded by the same lock.
_discovery_unreachable: set[str] = set()

# Caps total outbound discovery ATTEMPTS (not failures) across all issuers
# combined, independent of the cache above: a client cycling through a
# fresh fake realm name on every request is a cache MISS every time, so the
# per-issuer cache alone can't stop that variant from translating into one
# real outbound fetch per request. A plain lock-protected deque, not the
# Redis-based limiter used for request-level limits elsewhere, since this
# runs inside a background worker thread rather than on the async request
# path, and the worker-thread pool it protects is itself per-process.
_discovery_attempts_lock = threading.Lock()
_discovery_attempt_times: deque = deque()

# Issuers a thread in THIS process is fetching discovery for RIGHT NOW.
# Concurrency testing found the negative cache above provides close to NO
# protection against a genuinely concurrent flood: N threads racing in for
# the same brand-new issuer all pass the cache-miss check before the first
# one's failure is ever recorded, so all N proceed to a real outbound fetch
# -- measured at 36 of 40 truly-simultaneous requests against a single fake
# realm. This single-flight guard closes that: only the first thread to
# claim an issuer makes the real fetch. Threads that find it already claimed
# wait for that fetch and share its result, with NO outbound call and NO
# rate-limit budget spent. Turning them away instead (the original
# behaviour) failed legitimate traffic too: the admin page's two parallel
# loads, or a burst of logins right after an engine restart, got a 503 for
# every request but the first. At most DISCOVERY_MAX_WAITERS threads wait
# at once; past that, a request still gets the immediate 503, so a flood
# cannot park the whole worker-thread pool. Checked/claimed under the same
# lock as the negative cache (not a separate one), since both must be
# evaluated as one atomic step.
class _DiscoveryFlight:
    """One in-progress discovery fetch, shared with the threads waiting on it."""

    __slots__ = ("done", "jwks_uri", "error")

    def __init__(self) -> None:
        self.done = threading.Event()
        self.jwks_uri: str | None = None
        self.error: AuthError | None = None


_discovery_inflight: dict[str, _DiscoveryFlight] = {}
_discovery_waiters = 0


def _keycloak_unreachable(exc: Exception) -> bool:
    """Whether a failed discovery fetch means Keycloak could not be reached
    (connection error, timeout, a 5xx) rather than that the realm does not
    exist (a 404 or other 4xx) or that the document was unusable."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return isinstance(exc, OSError)  # URLError, TimeoutError, ConnectionError


def _failure_ttl(issuer: str) -> int:
    if issuer in _discovery_unreachable:
        return DISCOVERY_UNREACHABLE_CACHE_TTL
    return DISCOVERY_FAILURE_CACHE_TTL


def _prune_discovery_failures(now: float) -> None:
    expired = [iss for iss, ts in _discovery_failures.items() if now - ts > _failure_ttl(iss)]
    for iss in expired:
        del _discovery_failures[iss]
        _discovery_unreachable.discard(iss)
    # Still over capacity after expiring stale entries (many distinct fake
    # issuers arriving within one TTL window) -> drop the oldest until back
    # under the cap. Bounds memory even under sustained attack traffic.
    if len(_discovery_failures) > DISCOVERY_FAILURE_CACHE_MAX_SIZE:
        overflow = len(_discovery_failures) - DISCOVERY_FAILURE_CACHE_MAX_SIZE
        oldest = sorted(_discovery_failures.items(), key=lambda kv: kv[1])[:overflow]
        for iss, _ in oldest:
            del _discovery_failures[iss]
            _discovery_unreachable.discard(iss)


def _check_discovery_rate_limit(now: float) -> None:
    with _discovery_attempts_lock:
        while _discovery_attempt_times and now - _discovery_attempt_times[0] > DISCOVERY_RATE_LIMIT_WINDOW_SECONDS:
            _discovery_attempt_times.popleft()
        if len(_discovery_attempt_times) >= DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS:
            raise AuthError(503, "Unable to fetch OIDC discovery document")
        _discovery_attempt_times.append(now)


def _discover_jwks_uri(issuer: str) -> str:
    """Fetch the issuer's OIDC discovery document and return its jwks_uri.

    The issuer is already on the trusted allow-list before this is called, so the
    fetch target is trusted (no SSRF surface). The discovery document's own issuer
    field must equal the issuer we looked it up under (OIDC integrity check).
    """
    global _discovery_waiters
    now = time.time()

    with _discovery_failures_lock:
        _prune_discovery_failures(now)
        last_failure = _discovery_failures.get(issuer)
        if last_failure is not None and now - last_failure <= _failure_ttl(issuer):
            # Answered locally: a recent attempt for this exact issuer
            # already failed, so don't repeat the outbound fetch (or spend a
            # worker thread waiting on it) for every request that keeps
            # presenting it.
            raise AuthError(503, "Unable to fetch OIDC discovery document")
        flight = _discovery_inflight.get(issuer)
        if flight is None:
            flight = _DiscoveryFlight()
            _discovery_inflight[issuer] = flight
            leader = True
        elif _discovery_waiters >= DISCOVERY_MAX_WAITERS:
            # Enough threads are already parked on in-progress fetches; fail
            # fast rather than tie up another one. A legitimate caller simply
            # retries, same as any other transient 503 from this function.
            raise AuthError(503, "Unable to fetch OIDC discovery document")
        else:
            _discovery_waiters += 1
            leader = False

    if not leader:
        # Another thread in this process is already fetching discovery for
        # this exact issuer: wait for it and share its result instead of
        # making a second, redundant outbound attempt. The fetch itself is
        # bounded by OIDC_DISCOVERY_TIMEOUT; the extra second covers the
        # work around it.
        try:
            finished = flight.done.wait(OIDC_DISCOVERY_TIMEOUT + 1)
        finally:
            with _discovery_failures_lock:
                _discovery_waiters -= 1
        if finished and flight.jwks_uri:
            return flight.jwks_uri
        if finished and flight.error is not None:
            raise AuthError(flight.error.status_code, flight.error.detail)
        raise AuthError(503, "Unable to fetch OIDC discovery document")

    try:
        _check_discovery_rate_limit(now)

        url = f"{issuer}/.well-known/openid-configuration"
        try:
            with urllib.request.urlopen(url, timeout=OIDC_DISCOVERY_TIMEOUT, context=_ssl_context()) as resp:
                doc = json.loads(resp.read())
        except Exception as exc:
            logging.warning(
                "OIDC discovery fetch failed for %s: %s",
                _sanitize_for_log(url), _sanitize_for_log(exc),
            )
            with _discovery_failures_lock:
                _discovery_failures[issuer] = now
                if _keycloak_unreachable(exc):
                    _discovery_unreachable.add(issuer)
                else:
                    _discovery_unreachable.discard(issuer)
            raise AuthError(503, "Unable to fetch OIDC discovery document")
        if doc.get("issuer") != issuer:
            raise AuthError(403, "Discovery document issuer mismatch")
        jwks_uri = doc.get("jwks_uri")
        if not jwks_uri:
            raise AuthError(503, "Discovery document has no jwks_uri")
        flight.jwks_uri = jwks_uri
        return jwks_uri
    except AuthError as exc:
        flight.error = exc
        raise
    finally:
        with _discovery_failures_lock:
            _discovery_inflight.pop(issuer, None)
        flight.done.set()


def _jwks_client(issuer: str) -> PyJWKClient:
    client = _jwks_clients.get(issuer)
    if client is None:
        jwks_uri = _discover_jwks_uri(issuer)
        # Threads that shared one discovery fetch each get here with the same
        # jwks_uri; keep the first client stored so they all use one key cache.
        client = _jwks_clients.setdefault(issuer, PyJWKClient(
            jwks_uri, cache_keys=True, lifespan=JWKS_CACHE_TTL, ssl_context=_ssl_context()
        ))
    return client


# Last-known-good signing keys per issuer -> {kid: (key, fetched_at_epoch)}.
# Lets verification survive a *transient network outage* to Keycloak's JWKS, but
# ONLY within JWKS_CACHE_TTL and ONLY for genuine connectivity failures. A key that
# Keycloak has rotated/revoked out of a successfully-fetched JWKS must FAIL CLOSED —
# otherwise a leaked-then-rotated key would keep verifying, defeating revocation.
_key_cache: dict[str, dict[str, tuple]] = {}


def _reject_unsafe_kid(kid) -> None:
    """Raise if `kid` (the token header's key id) is unsafe to use further.

    kid comes from the token's header, which -- like the issuer claim -- is
    read before any signature check, so it is fully attacker-controlled at
    this point. A real Keycloak kid is never anything but a plain
    identifier; a value carrying control characters (in particular CR/LF)
    can only be a forged header aimed at one of _resolve_signing_key's log
    lines, since it will never match a real key in a fetched JWKS either
    way. Rejecting it here means it can reach neither the JWKS client nor a
    log call.

    Split out as its own function (rather than inlined in
    _resolve_signing_key) so a test can monkeypatch this one gate to prove
    the log calls' own defense-in-depth sanitization independently of it --
    otherwise this gate always fires first and a test exercising those log
    calls with an unsafe kid would be vacuous.
    """
    if kid is not None and (not isinstance(kid, str) or _CONTROL_CHAR_RE.search(kid)):
        raise AuthError(403, "Malformed key id")


def _resolve_signing_key(issuer: str, token: str):
    """Return the signing key for the token.

    Normal path: fetch via JWKS/discovery (handles rotation) and remember the key.
    - Connectivity failure (JWKS unreachable): fall back to the last-known-good key
      for the token's `kid`, but only if it was fetched within JWKS_CACHE_TTL. 503 otherwise.
    - Any other failure (kid absent from a successfully-fetched JWKS = rotated/revoked,
      or a malformed/forged kid): FAIL CLOSED (403). Never serve a stale key here.
    """
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except Exception:
        kid = None

    _reject_unsafe_kid(kid)

    try:
        signing_key = _jwks_client(issuer).get_signing_key_from_jwt(token)
        if kid:
            _key_cache.setdefault(issuer, {})[kid] = (signing_key.key, time.time())
        return signing_key.key
    except AuthError:
        raise
    except PyJWKClientConnectionError as exc:
        # Genuine connectivity failure only -> bounded stale fallback.
        cached = _key_cache.get(issuer, {}).get(kid) if kid else None
        if cached is not None:
            key, fetched_at = cached
            if time.time() - fetched_at <= JWKS_CACHE_TTL:
                logging.warning(
                    "JWKS unreachable for issuer %s; using cached key for kid=%s within TTL: %s",
                    _sanitize_for_log(issuer), _sanitize_for_log(kid), _sanitize_for_log(exc),
                )
                return key
        logging.warning(
            "JWKS unreachable for issuer %s and no fresh cached key for kid=%s: %s",
            _sanitize_for_log(issuer), _sanitize_for_log(kid), _sanitize_for_log(exc),
        )
        raise AuthError(503, "Unable to resolve signing key")
    except Exception as exc:
        # kid not present in a successfully-fetched JWKS (rotated/revoked/forged) or other
        # resolution error -> fail closed. Do NOT fall back to a stale key here.
        logging.warning(
            "Signing key resolution failed for issuer %s kid=%s (failing closed): %s",
            _sanitize_for_log(issuer), _sanitize_for_log(kid), _sanitize_for_log(exc),
        )
        raise AuthError(403, "Unable to resolve signing key")


def _unverified_issuer(token: str) -> str:
    claims = jwt.decode(token, options={"verify_signature": False})
    issuer = claims.get("iss")
    if not issuer:
        raise AuthError(403, "Token has no issuer")
    # Read before any signature check, so fully attacker-controlled. Rejected
    # here, before _validate_issuer's urlparse-based comparison ever sees it:
    # urlparse silently strips CR/LF while parsing, so a crafted issuer's
    # PARSED view can structurally satisfy the trusted-prefix check while the
    # ORIGINAL string -- what's actually used to build the discovery URL and
    # what gets logged if that fetch fails -- still carries the embedded
    # line break, which could otherwise forge a fake log entry.
    if not isinstance(issuer, str) or _CONTROL_CHAR_RE.search(issuer):
        raise AuthError(403, "Malformed issuer")
    return issuer


def _validate_issuer(issuer: str) -> str:
    """Host-pinned issuer validation.

    Accept the issuer only if it is `{trusted-base}/realms/{realm}` for one of the
    configured trusted Keycloak base URLs, matching scheme + host + port EXACTLY
    (structural comparison on parsed URL parts — never a raw string prefix, which
    would be bypassable, e.g. `https://trusted.example.com.evil.com/...`).

    Any realm under a trusted Keycloak instance is accepted, so onboarding a new
    realm requires no config change. Returns the realm segment.
    """
    try:
        u = urlparse(issuer)
    except Exception:
        raise AuthError(403, "Malformed issuer")
    if not u.scheme or not u.hostname:
        raise AuthError(403, "Malformed issuer")

    for base in OIDC_TRUSTED_BASE_URLS:
        b = urlparse(base)
        if u.scheme != b.scheme:
            continue
        if u.hostname != b.hostname:
            continue
        if _effective_port(u) != _effective_port(b):
            continue
        prefix = b.path.rstrip("/") + "/realms/"
        if not u.path.startswith(prefix):
            continue
        realm = u.path[len(prefix):].strip("/")
        if not realm or "/" in realm:
            continue
        return realm

    raise AuthError(403, "Untrusted issuer")


def verify_token(
    token: str,
    *,
    verify_audience: bool | None = None,
    expected_audience: str | None = None,
) -> VerifiedPrincipal:
    """Verify a Keycloak-signed JWT.

    `verify_audience` controls the `aud` check: None (default) uses the global
    `OIDC_VERIFY_AUDIENCE` — used for the bearer/service-account path (`/decision`).
    The webhook path passes `verify_audience=True` with `expected_audience` set to
    the dedicated webhook audience (`WEBHOOK_EXPECTED_AUDIENCE`), so a token minted
    for some other purpose (an ordinary end-user token, or a service-account token
    for an unrelated client) cannot be reshaped into a webhook event even if it is
    otherwise signed by a trusted realm.

    `expected_audience` defaults to `OIDC_EXPECTED_AUDIENCE` (the bearer/service
    -account audience) when not given.
    """
    require_aud = OIDC_VERIFY_AUDIENCE if verify_audience is None else verify_audience
    audience = expected_audience if expected_audience is not None else OIDC_EXPECTED_AUDIENCE
    try:
        issuer = _unverified_issuer(token)
    except AuthError:
        raise
    except Exception:
        raise AuthError(401, "Malformed token")

    realm = _validate_issuer(issuer)

    signing_key = _resolve_signing_key(issuer, token)

    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience if require_aud else None,
            leeway=OIDC_CLOCK_SKEW_LEEWAY,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": require_aud,
            },
        )
    except jwt.PyJWTError as exc:
        raise AuthError(403, f"Token verification failed: {exc.__class__.__name__}")

    aud = claims.get("aud", [])
    audiences = [aud] if isinstance(aud, str) else list(aud or [])
    roles = (claims.get("realm_access") or {}).get("roles", []) or []

    return VerifiedPrincipal(
        issuer=issuer,
        realm=realm,
        client_id=claims.get("azp") or claims.get("client_id"),
        roles=roles,
        audiences=audiences,
        subject=claims.get("sub"),
        claims=claims,
    )
