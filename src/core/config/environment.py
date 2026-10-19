import os
from dotenv import load_dotenv

load_dotenv()

POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_HOST = os.getenv("POSTGRES_HOST")
POSTGRES_PORT = os.getenv("POSTGRES_PORT")
DATABASE = os.getenv("POSTGRES_DB")

REJECTED_AUTH_RISK_LEVEL = str(os.getenv(key="REJECTED_AUTH_RISK_LEVEL", default=4))

SCHEMA = os.getenv("POSTGRES_SCHEMA")

WORKERS = int(os.getenv("WORKERS", 4))

# The listen port. Stays 80 by default: Docker sets
# net.ipv4.ip_unprivileged_port_start=0 inside containers, so the unprivileged
# user the image runs as binds 80 without extra capabilities. Runtimes that do
# not relax that sysctl (some Kubernetes and podman setups) enforce the 1024
# floor instead, and there this has to be set to something above it.
ENGINE_PORT = int(os.getenv("ENGINE_PORT", 80))

database_parameters = {
    "user": POSTGRES_USER,
    "password": POSTGRES_PASSWORD,
    "host": POSTGRES_HOST,
    "port": POSTGRES_PORT,
    "database": DATABASE,
}

# Logging: LOG_LEVEL accepts a name ("INFO", "DEBUG") or a number ("20"); the
# app logs to stdout/stderr by default. Set LOG_DIR to a writable directory to
# also enable a rotating log file there.
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_DIR = os.getenv("LOG_DIR")

DATABASE_URL = "postgresql://{user}:{password}@{host}:{port}/{database}".format(
    **database_parameters
)

def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]

# Trusted Keycloak base URL(s). Any realm under a trusted base is accepted
# (issuer = {base}/realms/{realm}), so new realms need NO config change.
OIDC_TRUSTED_BASE_URLS = _csv(os.getenv("OIDC_TRUSTED_BASE_URLS", ""))
OIDC_EXPECTED_AUDIENCE = os.getenv("OIDC_EXPECTED_AUDIENCE", "amfa")
# Secure by default: enforce the audience on bearer tokens (/decision, /settings).
# Requires the audience mapper (aud=amfa) on the adaptive-auth-api client in EVERY
# realm that calls AMFA. Only set to false if you have added role-based authorization,
# otherwise any valid realm token would be accepted (authorization gap).
OIDC_VERIFY_AUDIENCE = os.getenv("OIDC_VERIFY_AUDIENCE", "true").lower() in ("1", "true", "yes")
# Dedicated audience for the login-event webhook, distinct from OIDC_EXPECTED_AUDIENCE.
# The webhook JWT is hand-built by the Keycloak event listener (not issued through a
# client's configured scopes), so this value must match the listener's own
# AMFA_WEBHOOK_AUDIENCE environment variable exactly. Enforcing a dedicated audience
# means an ordinary end-user or service-account token minted for some other purpose
# cannot be reshaped into a webhook event, even if it is otherwise signed by a
# trusted realm.
WEBHOOK_EXPECTED_AUDIENCE = os.getenv("AMFA_WEBHOOK_AUDIENCE") or "amfa-webhook-event"


def _parse_monitoring_readers(value: str) -> frozenset[tuple[str, str]]:
    """Parse MONITORING_TRUSTED_READERS into (issuer, client_id) pairs.

    Each entry is `{issuer}|{client_id}`, for example
    `https://sso.example.com/realms/master|monitoring-service`. A malformed entry
    raises instead of being skipped: a reader silently dropped from the list
    would only show up later as a monitoring consumer that stopped seeing data.
    """
    readers = set()
    for entry in _csv(value):
        issuer, sep, client_id = entry.rpartition("|")
        issuer, client_id = issuer.strip().rstrip("/"), client_id.strip()
        if not sep or not issuer or not client_id:
            raise ValueError(
                f"MONITORING_TRUSTED_READERS entry {entry!r} must be "
                f"'{{issuer}}|{{client_id}}', e.g. "
                f"'https://sso.example.com/realms/master|monitoring-service'."
            )
        readers.add((issuer, client_id))
    return frozenset(readers)


# Service accounts allowed to read the /monitoring endpoints of ANY realm, not
# just the realm that issued their token. Empty by default, which keeps every
# monitoring read same-realm only. Meant for a monitoring platform that holds
# one confidential client in an admin realm (typically master) and reads every
# realm of that Keycloak with it. A listed client gains read access to the
# monitoring data of every realm and to nothing else: /decision, /settings and
# the webhook still require a token from the realm itself.
MONITORING_TRUSTED_READERS = _parse_monitoring_readers(os.getenv("MONITORING_TRUSTED_READERS", ""))
OIDC_CLOCK_SKEW_LEEWAY = int(os.getenv("OIDC_CLOCK_SKEW_LEEWAY", 30))
# Bounds BOTH how long a signing key is cached (so a rotated/revoked key stops being
# accepted within this window) AND the stale-key fallback window during a JWKS outage.
# 300s balances timely revocation against JWKS fetch load and outage resilience.
JWKS_CACHE_TTL = int(os.getenv("JWKS_CACHE_TTL", 300))
OIDC_DISCOVERY_TIMEOUT = int(os.getenv("OIDC_DISCOVERY_TIMEOUT", 5))

# _validate_issuer only checks that an issuer's HOST is trusted (by design --
# onboarding a new realm needs no config change), never that the realm
# actually exists, and a failed discovery lookup was never cached before, so
# a request naming a nonexistent realm re-triggered a full outbound HTTP
# fetch (blocking a worker thread for up to OIDC_DISCOVERY_TIMEOUT) on every
# single request.
#
# How long a failed discovery lookup for one issuer is remembered before a
# fresh attempt is allowed. Short enough that a genuine new realm's very
# first legitimate login isn't held back for long by an earlier failure,
# but long enough that a client repeatedly presenting the same nonexistent
# issuer can't force a fresh outbound fetch on every request.
DISCOVERY_FAILURE_CACHE_TTL = int(os.getenv("DISCOVERY_FAILURE_CACHE_TTL", 30))
# Caps how many distinct failed issuers are remembered at once. The realm
# segment of an issuer is attacker-chosen and otherwise unbounded, so
# nothing else limits how many distinct cache entries a client could create;
# this keeps the cache itself from becoming its own memory-exhaustion
# vector under sustained attack traffic with many distinct fake realms.
DISCOVERY_FAILURE_CACHE_MAX_SIZE = int(os.getenv("DISCOVERY_FAILURE_CACHE_MAX_SIZE", 1000))
# Caps total outbound discovery *attempts* (not just failures) across ALL
# issuers combined in this window, independent of the negative cache above:
# a client cycling through a fresh fake realm name on every request is a
# cache MISS every time, so the negative cache alone can't stop that
# variant from translating into one real outbound fetch per request.
# Both this cache and the rate limiter above are plain in-process state (a
# dict / a deque), not shared storage -- each engine worker PROCESS enforces
# its own independent copy of these limits. With W worker processes, the
# true system-wide ceiling is up to W times the configured value here, not
# the configured value alone (e.g. 4 workers x MAX_ATTEMPTS=10 -> up to 40
# outbound attempts per WINDOW_SECONDS across the whole engine). Confirmed
# live against a 4-worker deployment. Chosen deliberately over a shared
# (e.g. Redis-backed) limiter because _discover_jwks_uri runs synchronously
# inside a background worker THREAD (via asyncio.to_thread), and the
# resource actually being protected -- the worker-thread pool -- is itself
# per-process, so a per-process bound is what matters here; just don't
# mistake these constants for a global cap when sizing them.
DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("DISCOVERY_RATE_LIMIT_MAX_ATTEMPTS", 10))
DISCOVERY_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("DISCOVERY_RATE_LIMIT_WINDOW_SECONDS", 10))

WEBHOOK_REPLAY_TTL = int(os.getenv("WEBHOOK_REPLAY_TTL", 300))
# Optional path to a CA bundle (PEM) to trust for the Keycloak discovery/JWKS fetch
# over HTTPS. Leave unset to use the system trust store (public CAs). Set this when
# Keycloak's certificate is issued by a private/internal CA. Verification is never disabled.
OIDC_CA_BUNDLE = os.getenv("OIDC_CA_BUNDLE") or None

EVENT_TIME_WINDOW = int(os.getenv(key="EVENT_TIME_WINDOW", default=4))

DEFAULT_INACTIVE_DAYS = int(os.getenv(key="DEFAULT_INACTIVE_DAYS", default=40))

DEFAULT_RISK_LEVEL = str(os.getenv(key="DEFAULT_RISK_LEVEL", default=2))

DEBUG = os.getenv("DEBUG", default=False)

RESPONSE_TIMEOUT = int(os.getenv("RESPONSE_TIMEOUT", default=False))
CACHE_DURATION_DAYS = int(os.getenv("CACHE_DURATION_DAYS", default=180))


GEOLOC_RADIUS = int(os.getenv(key="GEOLOC_RADIUS", default=100))

# Impossible-travel detection (A1). A leg faster than the absolute cap is always
# impossible (faster than a commercial aircraft); otherwise a speed above the
# user's own median flags only within a short "burst" window, so a slow move
# spread over a long gap between logins is treated as feasible.
IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH = float(
    os.getenv("IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH", 900)
)
IMPOSSIBLE_TRAVEL_BURST_GAP_MINUTES = int(
    os.getenv("IMPOSSIBLE_TRAVEL_BURST_GAP_MINUTES", 60)
)

# Drop-down time decay: on a clean login, an escalation older than
# DROP_DOWN_DECAY_DAYS is relaxed by DROP_DOWN_DECAY_STEPS risk-level steps instead of
# the baseline 1. Result is always clamped to risk >= 1. STEPS=1 disables the
# acceleration; STEPS>=3 effectively resets to baseline from any elevation.
DROP_DOWN_DECAY_DAYS = int(os.getenv(key="DROP_DOWN_DECAY_DAYS", default=30))
DROP_DOWN_DECAY_STEPS = int(os.getenv(key="DROP_DOWN_DECAY_STEPS", default=2))

TIME_ZONE = os.getenv(key="TIME_ZONE", default="Europe/Lisbon")


N_ROWS_TO_KEEP = int(os.getenv(key="N_ROWS_TO_KEEP", default=10))

AMFA_TIMEOUT = float(os.getenv(key="AMFA_TIMEOUT", default=0.8))

RATE_LIMIT = bool(os.getenv(key="RATE_LIMIT", default=True))
RATE_LIMIT_MAX_REQ = int(os.getenv(key="RATE_LIMIT_MAX_REQ", default=4))
RATE_LIMIT_TIME_WINDOW = int(os.getenv(key="RATE_LIMIT_TIME_WINDOW", default=60))

# Caps the number of distinct group_ids a single settings PUT may submit. Each
# group is one activate_decision_params_config() write performed inside the
# realm's config-write lock, so an unbounded count lets one request's body
# size dictate how long that lock is held.
MAX_CONFIG_GROUPS_PER_REQUEST = int(os.getenv(key="MAX_CONFIG_GROUPS_PER_REQUEST", default=50))

# How long a realm's config-write lock is held before it self-expires in
# Redis. Must comfortably exceed the worst-case duration of the critical
# section it protects, or the lock can silently expire mid-write and let a
# second writer in concurrently. That worst case is up to
# MAX_CONFIG_GROUPS_PER_REQUEST activation writes for the submitted groups
# PLUS up to that many more deactivation writes for previously-active groups
# the submission dropped (ParamsConfigService.__update_realm_params does
# both) -- roughly 2x MAX_CONFIG_GROUPS_PER_REQUEST database round trips, not
# just one x.
CONFIG_LOCK_TIMEOUT_SECONDS = float(os.getenv(key="CONFIG_LOCK_TIMEOUT_SECONDS", default=30.0))

FALLBACK_RISK_LEVEL = str(os.getenv(key="FALLBACK_RISK_LEVEL", default=3))


def _reject_unsafe_fallback_risk_level(fallback: str, default: str) -> None:
    """Fail loudly at import time if FALLBACK_RISK_LEVEL is more permissive
    (a lower risk level -- 1=none, 2=OTP, 3=OTP+authenticator, 4=reject) than
    DEFAULT_RISK_LEVEL, the level given to a user the engine has never seen
    before.

    FALLBACK_RISK_LEVEL is not read by any active evaluation path --
    evaluation failures return a non-2xx response with no riskLevel at all,
    so a malformed request can never turn a real Risk 4 (deny) verdict into
    an HTTP 200 Risk 1 (no challenge) via this setting (see
    tests/e2e/test_engine_api.py's V05 docstring). A permissive value here
    is still misleading to an operator reading the example as documentation,
    and a landmine for any future change that wires this value back into a
    live path. Rejecting the unsafe combination here, rather than letting it
    load silently, is cheap insurance against both.
    """
    if int(fallback) < int(default):
        raise ValueError(
            f"FALLBACK_RISK_LEVEL ({fallback}) must not be more permissive than "
            f"DEFAULT_RISK_LEVEL ({default}) -- an evaluation failure must never "
            f"be treated as safer than a user the engine has never seen before."
        )


_reject_unsafe_fallback_risk_level(FALLBACK_RISK_LEVEL, DEFAULT_RISK_LEVEL)

# Scoring mode: "bayesian" (default, Log-Odds probability model) or "weight"
# (legacy per-parameter cumulative-weight bands). Both are interchangeable and
# selectable per realm via scoring_config; bayesian is the recommended default
# because it aggregates evidence continuously, while weight mode buckets a
# cumulative weight sum (see WEIGHT_RISK_BANDS).
SCORING_MODE = os.getenv(key="SCORING_MODE", default="bayesian").strip().lower()

# Weight-mode risk bands, as two ascending cumulative-weight thresholds "t2,t3".
# The summed weight of the changed signals maps to a risk level:
#   weight < t2      -> Risk 1
#   t2 <= weight < t3 -> Risk 2
#   weight >= t3     -> Risk 3
# Defaults "3,6": one weight-3 signal is Risk 2, two are Risk 3. Only used when
# SCORING_MODE="weight".
WEIGHT_RISK_BANDS = tuple(
    int(t)
    for t in os.getenv(key="WEIGHT_RISK_BANDS", default="3,6").split(",")
)

# Hazard activation (weight mode). When at least HAZARD_CHANGED_PARAMS_THRESHOLD
# signals change in a single login the context is treated as very unfamiliar and
# risk is forced to 3 (to 4 when there are also at least
# HAZARD_FAILED_ATTEMPTS_THRESHOLD failed logins in the last 24h). The
# failed-attempts threshold also gates the consecutive-high-risk escalation.
HAZARD_CHANGED_PARAMS_THRESHOLD = int(
    os.getenv(key="HAZARD_CHANGED_PARAMS_THRESHOLD", default=6)
)
HAZARD_FAILED_ATTEMPTS_THRESHOLD = int(
    os.getenv(key="HAZARD_FAILED_ATTEMPTS_THRESHOLD", default=2)
)

# Calibration bias for the Log-Odds model (only used when SCORING_MODE="bayesian").
# More negative => more trusting (lower base fraud rate). See log_odds.py for the
# per-industry guidance table. Default -3.9 ~ e-commerce / lower-financial.
BAYESIAN_BIAS = float(os.getenv(key="BAYESIAN_BIAS", default=-3.9))

# Three ascending probabilities partitioning [0,1] into risk-level bands 1..4.
BAYESIAN_RISK_THRESHOLDS = tuple(
    float(t)
    for t in os.getenv(key="BAYESIAN_RISK_THRESHOLDS", default="0.3,0.6,0.85").split(",")
)


def _env_bool(key: str, default: bool) -> bool:
    return os.getenv(key, str(default)).strip().lower() in ("1", "true", "yes", "on")


# Login-failure pattern analysis. Detects high failure rate, distributed
# brute-force (many source IPs), bot-like timing regularity, and activity bursts
# over the user's recent LOGIN_ERROR history.
LOGIN_FAILURE_DETECTION_ENABLED = _env_bool("LOGIN_FAILURE_DETECTION_ENABLED", True)
LOGIN_FAILURE_WINDOW_MINUTES = int(os.getenv("LOGIN_FAILURE_WINDOW_MINUTES", 60))
LOGIN_FAILURE_RATE_THRESHOLD = int(os.getenv("LOGIN_FAILURE_RATE_THRESHOLD", 5))
LOGIN_FAILURE_DISTINCT_IP_THRESHOLD = int(
    os.getenv("LOGIN_FAILURE_DISTINCT_IP_THRESHOLD", 3)
)
# Hard ceiling: at/above this many failures in the window, flag regardless of
# pattern (basic DoS / credential-stuffing mitigation).
LOGIN_FAILURE_DOS_CAP = int(os.getenv("LOGIN_FAILURE_DOS_CAP", 50))

# Concurrent-session detection. Approximates active sessions from recent
# successful logins: many distinct source IPs in the active window suggests
# credential sharing; many logins from a single IP suggests bot activity.
CONCURRENT_SESSION_DETECTION_ENABLED = _env_bool(
    "CONCURRENT_SESSION_DETECTION_ENABLED", True
)
CONCURRENT_SESSION_ACTIVE_WINDOW_MINUTES = int(
    os.getenv("CONCURRENT_SESSION_ACTIVE_WINDOW_MINUTES", 30)
)
CONCURRENT_SESSION_DISTINCT_IP_THRESHOLD = int(
    os.getenv("CONCURRENT_SESSION_DISTINCT_IP_THRESHOLD", 3)
)
CONCURRENT_SESSION_PER_IP_THRESHOLD = int(
    os.getenv("CONCURRENT_SESSION_PER_IP_THRESHOLD", 10)
)

# Recent-account-change detection (E4 user-actions monitoring). Flags a login
# that follows a sensitive account action (password change/reset, MFA credential
# add/remove, email change) within the window below — the classic
# account-takeover-then-login pattern. The Keycloak webhook forwards these
# events; the engine caches them under d:<EVENT_TYPE>:<user>:* and this check
# scans that recent history.
ACCOUNT_ACTION_DETECTION_ENABLED = _env_bool("ACCOUNT_ACTION_DETECTION_ENABLED", True)
ACCOUNT_ACTION_WINDOW_MINUTES = int(os.getenv("ACCOUNT_ACTION_WINDOW_MINUTES", 1440))
# Keycloak event types treated as sensitive account changes.
ACCOUNT_ACTION_EVENT_TYPES = [
    t.strip()
    for t in os.getenv(
        "ACCOUNT_ACTION_EVENT_TYPES",
        "UPDATE_PASSWORD,RESET_PASSWORD,UPDATE_CREDENTIAL,REMOVE_CREDENTIAL,"
        "UPDATE_EMAIL,FEDERATED_IDENTITY_LINK,IDENTITY_PROVIDER_LINK_ACCOUNT,"
        "REMOVE_FEDERATED_IDENTITY",
    ).split(",")
    if t.strip()
]

# When False (default), the browser signal is the browser family only ("Chrome")
# rather than family + major version ("Chrome|150"). Browsers auto-update their
# major version frequently, so including the version makes an ordinary update
# look like a changed device/browser signal and needlessly triggers step-up.
# Set True to restore version sensitivity (e.g. for a high-assurance deployment).
DEVICE_SIGNAL_INCLUDE_BROWSER_VERSION = _env_bool(
    "DEVICE_SIGNAL_INCLUDE_BROWSER_VERSION", False
)

def _strict_env_bool(key: str, default: bool) -> bool:
    """Like _env_bool, but an unrecognised value raises instead of reading as False.

    For switches where a typo must not quietly turn a protection off.
    """
    raw = os.getenv(key)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{key}={raw!r} is not a boolean; use true or false.")


# Redis connection. An empty value counts as unset, so REDIS_PASSWORD= in an
# .env file means "no password", never an empty or literal "None" password.
REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
REDIS_PORT = int(os.getenv("REDIS_PORT") or 6379)
REDIS_DB = int(os.getenv("REDIS_DB") or 0)
# Optional Redis 6+ ACL user. Needs REDIS_PASSWORD; without a username the
# password authenticates the default user (requirepass).
REDIS_USERNAME = os.getenv("REDIS_USERNAME") or None
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None
# TLS to Redis, verifying the server certificate and its hostname. The CA
# bundle is only needed for a private CA; otherwise the system trust store is
# used.
REDIS_SSL = _strict_env_bool("REDIS_SSL", False)
REDIS_SSL_CA_CERTS = os.getenv("REDIS_SSL_CA_CERTS") or None

MIN_AUTH_EVENTS = int(os.getenv(key="MIN_AUTH_EVENTS", default="4"))
MAX_AUTH_EVENTS = int(os.getenv(key="MAX_AUTH_EVENTS", default="500"))

LOCATION_NETWORK_KEY_TEMPLATE = "auth:location_network:v1:{}"
DEVICE_KEY_TEMPLATE = "auth:device:v1:{}"


# --- IP intelligence ---------------------------------------------------------
#
# Geolocation and anonymiser (VPN / proxy / Tor) detection are resolved entirely
# from local data files read from disk. There is no third-party API and no
# outbound connection on the authentication path, which is what makes on-premise
# and air-gapped deployment possible; the previous design called an external
# service for every uncached lookup, so an isolated site could not use these
# signals at all.

# Root of the bundled data. Per-edition overrides let an operator point at their
# own MMDB, for example a MaxMind licence they already hold, in which case the
# licence obligation stays with them rather than being redistributed by us. MMDB
# is a shared format across DB-IP, MaxMind, IPinfo and IP2Location, so the reader
# does not care whose file it is.
IP_DATA_DIR = os.getenv(key="IP_DATA_DIR", default="/opt/amfa/ipdata")
GEOIP_COUNTRY_PATH = os.getenv("GEOIP_COUNTRY_PATH") or os.path.join(
    IP_DATA_DIR, "dbip-country-lite.mmdb"
)
GEOIP_ASN_PATH = os.getenv("GEOIP_ASN_PATH") or os.path.join(
    IP_DATA_DIR, "dbip-asn-lite.mmdb"
)
# City is the only source of true coordinates, and is enabled by default.
#
# It costs ~125 MB of image size for the weakest-accuracy tier of the free data,
# but without it every address in a country resolves to the same centroid: two of
# the nineteen signals (impossible_travel, geolocation_cluster_label) then see
# zero distance for any intra-country movement, and impossible-travel can only
# observe cross-border hops.
#
# Set GEOIP_CITY_PATH to an empty value to run country-only, which keeps the
# country tier (the most accurate of the free databases, and what the allow/deny
# lists consume) and falls back to COUNTRY_CENTROID_PATH for coordinates.
GEOIP_CITY_PATH = (
    os.getenv("GEOIP_CITY_PATH")
    if "GEOIP_CITY_PATH" in os.environ
    else os.path.join(IP_DATA_DIR, "dbip-city-lite.mmdb")
) or None
COUNTRY_CENTROID_PATH = os.getenv("COUNTRY_CENTROID_PATH") or os.path.join(
    IP_DATA_DIR, "country_centroids.csv"
)
ANON_BUNDLE_DIR = os.getenv("ANON_BUNDLE_DIR") or os.path.join(IP_DATA_DIR, "anon")

# Whether a datacenter/hosting match ALONE sets is_vpn.
#
# OPEN DECISION, defaulted off as the conservative choice. The measurements
# behind that default:
#
# `anonymous_detection` carries the default weight of 3, the heaviest tier, and
# with the default WEIGHT_RISK_BANDS="3,6" a single weight-3 signal lands exactly
# on the Risk 2 band. A false positive is therefore not a nudge to the score, it
# is a step-up prompt on every login indefinitely, because the address does not
# change. Legitimate shared egress lives in hosting ranges (a measured 15.3% of
# sampled Apple iCloud Private Relay ranges are flagged by the naive lists), and
# for a workforce IdP corporate SASE routes an entire organisation out through
# hosting. tor_exit and commercial_vpn set is_vpn regardless of this flag.
ANON_DATACENTER_IS_VPN = _env_bool("ANON_DATACENTER_IS_VPN", False)

# Age past which a positive anonymiser verdict is reported less confidently, in
# whole days. It never blocks authentication or fails readiness: an air-gapped site
# cannot refresh on demand, and old data is still better evidence than none. This is
# a deliberate divergence from Elastic and OpenSearch, which hard-stop enrichment at
# expiry, correct for a log pipeline and an outage for an auth path.
#
# 45 rather than the 30 those products use, because they track twice-weekly
# databases whereas DB-IP Lite publishes monthly. A freshly built bundle is
# routinely ~30 days old, so 30 would warn on day one and train operators to ignore
# the warning.
#
# A graded model (aging / stale / degraded / expired, assessed per database because
# country churn is ~0.4%/month against city at ~16%) is designed but not built. Its
# thresholds are deliberately NOT declared here until something reads them: an
# unused config variable, declared here and in the operator documentation, promises
# behaviour that does not exist.
IP_DATA_STALE_WARN_DAYS = int(os.getenv(key="IP_DATA_STALE_WARN_DAYS", default=45))

# How often to re-stat local data files for hot reload, keeping the syscall off
# the per-lookup hot path.
IP_DATA_RELOAD_CHECK_SECONDS = float(
    os.getenv(key="IP_DATA_RELOAD_CHECK_SECONDS", default=30.0)
)


DEFAULT_DECISION_PARAMS = [
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "client",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "ip_address",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "device",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "operating_system",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "browser",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "date_time",
        "weight": 2,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "time_interval",
        "weight": 2,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "event_cluster_label",
        "weight": 2,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "geolocation_cluster_label",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "system_language",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "screen_resolution",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "anonymous_detection",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "inactive_account",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
        "inactive_days": DEFAULT_INACTIVE_DAYS,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "impossible_travel",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "country_name",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "geo_loc",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "concurrent_session",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "login_failure",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
    {
        "group_id": "default",
        "realm_id": "default",
        "parameter_name": "recent_account_change",
        "weight": 3,
        "disabled": True,
        "blacklist": None,
        "whitelist": None,
    },
]

ALLOWED_CLUSTERING_PARAMS = {
    "client",
    "ip_address",
    "device",
    "operating_system",
    "browser",
    "system_language",
    "screen_resolution",
    "country_name",
}

#!TODO make this have a function reference for each parameter data validation
ALLOWED_BLACK_WHITE_LIST_PARAMS = (
    "operating_system",  # options
    "country_name",  # static list
    "ip_address",  # regex
)


def validate() -> None:
    missing = [
        name
        for name, value in (
            ("POSTGRES_USER", POSTGRES_USER),
            ("POSTGRES_PASSWORD", POSTGRES_PASSWORD),
            ("POSTGRES_HOST", POSTGRES_HOST),
            ("POSTGRES_PORT", POSTGRES_PORT),
            ("POSTGRES_DB", DATABASE),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"AMFA cannot start: required Postgres env vars are unset: {', '.join(missing)}. "
            "Unset values format into the connection string literally, so the failure looks "
            "like a connection error to a host named 'None'."
        )
    if not OIDC_TRUSTED_BASE_URLS:
        raise RuntimeError(
            "AMFA cannot start: OIDC_TRUSTED_BASE_URLS is empty. "
            "Set it to a comma-separated list of Keycloak base URLs "
            "(e.g. https://idp.example.com)."
        )
    if REDIS_USERNAME and not REDIS_PASSWORD:
        raise RuntimeError(
            "AMFA cannot start: REDIS_USERNAME is set but REDIS_PASSWORD is not. "
            "A Redis ACL user always needs its password."
        )
    if REDIS_SSL_CA_CERTS and not REDIS_SSL:
        raise RuntimeError(
            "AMFA cannot start: REDIS_SSL_CA_CERTS is set but REDIS_SSL is not true, "
            "so the connection to Redis would not use TLS at all."
        )
    if REDIS_SSL_CA_CERTS and not os.access(REDIS_SSL_CA_CERTS, os.R_OK):
        raise RuntimeError(
            f"AMFA cannot start: REDIS_SSL_CA_CERTS={REDIS_SSL_CA_CERTS!r} is not a readable file."
        )
