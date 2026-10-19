# Environment Variables

All variables are read by `src/core/config/environment.py`. Variables without a default are required.

## PostgreSQL

| Variable            | Default | Description       |
| ------------------- | ------- | ----------------- |
| `POSTGRES_USER`     | —       | Database username |
| `POSTGRES_PASSWORD` | —       | Database password |
| `POSTGRES_HOST`     | —       | Database host     |
| `POSTGRES_PORT`     | —       | Database port     |
| `POSTGRES_DB`       | —       | Database name     |
| `POSTGRES_SCHEMA`   | —       | Database schema   |

The engine's tables call `uuid_generate_v4()`, so the database needs the `uuid-ossp` extension. The compose stack creates it from `config/keycloak/init-db.sql`, which Postgres runs only when it initialises an empty data directory, so it does not help a database that already exists. The base Alembic migration also runs `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`.

That `CREATE EXTENSION` is enough on Docker Postgres and on CloudNativePG when the Database object lists `uuid-ossp`. `uuid-ossp` is a trusted extension, so the role running the migration needs `CREATE` on the database rather than superuser, which is why this works where the application user is not a superuser. Some managed Postgres products (Azure Database for PostgreSQL Flexible Server via `azure.extensions`) reject `CREATE EXTENSION` until the extension is allow-listed at the server. If you are not using the compose stack, confirm that allow-list before the first migration.

## Redis

Redis holds security state (webhook replay protection, login failure counters,
rate limits, locks), so a Redis reachable by anything other than the engine
should require a password, and TLS where the network is not trusted. With none
of the optional settings below, the engine connects without a password and
without TLS, as before.

| Variable             | Default   | Description |
| -------------------- | --------- | ----------- |
| `REDIS_HOST`         | `redis`   | Redis host. |
| `REDIS_PORT`         | `6379`    | Redis port. |
| `REDIS_DB`           | `0`       | Redis database number. |
| `REDIS_PASSWORD`     | (unset)   | Password for a Redis with `requirepass`, or for the ACL user in `REDIS_USERNAME`. Empty counts as unset. |
| `REDIS_USERNAME`     | (unset)   | Redis 6+ ACL user. Needs `REDIS_PASSWORD`; without it the password authenticates the default user. |
| `REDIS_SSL`          | `false`   | Connect over TLS. The server certificate and its hostname are verified, so `REDIS_HOST` must match a name on the certificate. Anything other than true or false stops startup. |
| `REDIS_SSL_CA_CERTS` | (unset)   | PEM CA bundle for a Redis certificate from a private CA. Unset uses the system trust store. Needs `REDIS_SSL=true`. |

The engine checks Redis at startup and stops with an error naming Redis when it
cannot connect or the credentials are refused.

## OIDC / JWT

The trusted base URL must be reachable *from the engine container* (the JWKS
is fetched from the issuer), and every AMFA realm needs an
`adaptive-auth-api` client with an `aud=amfa` mapper — see
[Keycloak Setup](keycloak-setup.md) for the full checklist.

| Variable                 | Default | Description                                                                                     |
| ------------------------ | ------- | ----------------------------------------------------------------------------------------------- |
| `OIDC_TRUSTED_BASE_URLS` | (empty) | Comma-separated trusted Keycloak base URL(s). Any realm under a trusted base is accepted (issuer = `{base}/realms/{realm}`). Empty rejects all issuers. |
| `OIDC_EXPECTED_AUDIENCE` | `amfa`  | Expected `aud` claim on bearer tokens (requires an audience mapper on the adaptive-auth-api client). |
| `OIDC_VERIFY_AUDIENCE`   | `true`  | Enforce the audience on bearer tokens. Disable only if you add role-based authorization instead. |
| `OIDC_CLOCK_SKEW_LEEWAY` | `30`    | Allowed clock skew (seconds) for token exp/iat.                                                 |
| `JWKS_CACHE_TTL`         | `300`   | Signing-key cache lifetime and stale-key fallback window during a JWKS outage (seconds).         |
| `OIDC_DISCOVERY_TIMEOUT` | `5`     | Timeout (seconds) for the OIDC discovery / JWKS fetch.                                          |
| `WEBHOOK_REPLAY_TTL`     | `300`   | Replay-protection window (seconds) for signed webhook `jti`s.                                    |
| `OIDC_CA_BUNDLE`         | (unset) | Optional PEM CA bundle to trust for the discovery/JWKS fetch (private/internal CA). Unset uses the system trust store. |
| `MONITORING_TRUSTED_READERS` | (empty) | Comma-separated `{issuer}\|{client_id}` pairs, e.g. `https://sso.example.com/realms/master\|monitoring-service`. Each listed client's **service-account** token may read the read-only `/{realm}/monitoring/*` endpoints of any realm, not only its own. A person signing in through the same client is not trusted, and `/decision`, `/settings` and the webhook still require a token from the realm itself. Empty keeps every monitoring read same-realm. A malformed entry stops startup. Each cross-realm read is logged at INFO. |

## Risk-Level Decisions

| Variable            | Default | Description                                                         |
| ------------------- | ------- | ------------------------------------------------------------------- |
| `DEFAULT_RISK_LEVEL`      | `2`     | Risk level returned when no prior risk data exists for the user     |
| `FALLBACK_RISK_LEVEL`     | `3`     | Not currently read by any evaluation path -- a failed evaluation returns a server error instead of a risk level (see below). Kept only as a guarded setting: the engine refuses to start if this is set more permissive than `DEFAULT_RISK_LEVEL`. |
| `REJECTED_AUTH_RISK_LEVEL`| `4`     | Risk level assigned to explicitly rejected authentications          |

`FALLBACK_RISK_LEVEL` is vestigial. Evaluation failures (timeouts, storage
errors, unhandled exceptions) return a non-2xx response with no `riskLevel` in
the body at all, rather than trusting a configured level -- so a malformed
request can never turn a real Risk 4 (deny) verdict into an HTTP 200 Risk 1
(no challenge) via this setting. Keycloak's
own SPI already treats any non-2xx `/decision` response as a failure and applies
its own separately-configured fallback, so this hands the failure to the layer
that was always meant to own it. The variable is kept, guarded, rather than
removed outright, in case a future evaluation path needs a configurable fallback
again -- but shipping it more permissive than `DEFAULT_RISK_LEVEL` is rejected at
startup so an unsafe combination can never be adopted silently.

A deny-list match on any signal is a **hard override that forces Risk 4**, the
rejection level, regardless of the score or of any allow-list match. It is not
configurable, because a deny list that only asked for a second factor would weaken
the one control meant to be absolute. An allow-list match instead caps the level at
2 when the score would otherwise be higher.

## Scoring

Two interchangeable scoring modes turn the changed risk signals into a risk
level. `bayesian` is the default. Both can be overridden per realm via the
`scoring_config` on the realm's decision parameters.

| Variable                   | Default        | Description                                                                                          |
| -------------------------- | -------------- | ---------------------------------------------------------------------------------------------------- |
| `SCORING_MODE`             | `bayesian`     | `bayesian` (Log-Odds probability model) or `weight` (legacy cumulative-weight bands)                 |
| `BAYESIAN_BIAS`            | `-3.9`         | Log-Odds calibration bias; more negative is more trusting. Only used when `SCORING_MODE=bayesian`    |
| `BAYESIAN_RISK_THRESHOLDS` | `0.3,0.6,0.85` | Three ascending fraud probabilities partitioning `[0,1]` into risk bands 1..4 (bayesian mode)         |
| `WEIGHT_RISK_BANDS`        | `3,6`          | Two ascending cumulative-weight thresholds `t2,t3`: sum<t2 is Risk 1, <t3 is Risk 2, else Risk 3 (weight mode) |

## Hazard Activation

Weight-mode escalation gate: when many signals change at once the login is
treated as a very unfamiliar context and risk is forced up.

| Variable                           | Default | Description                                                                                             |
| ---------------------------------- | ------- | ------------------------------------------------------------------------------------------------------- |
| `HAZARD_CHANGED_PARAMS_THRESHOLD`  | `6`     | Number of signals that must change in one login to force Risk 3                                          |
| `HAZARD_FAILED_ATTEMPTS_THRESHOLD` | `2`     | Failed logins in the last 24h that push the forced Risk 3 to Risk 4, and gate the consecutive escalation |

## Risk Evaluation

| Variable                | Default         | Description                                                         |
| ----------------------- | --------------- | ------------------------------------------------------------------- |
| `DEFAULT_INACTIVE_DAYS` | `40`            | Days of inactivity before flagging an account as inactive           |
| `MIN_AUTH_EVENTS`       | `4`             | Minimum number of past events required before clustering is applied |
| `DEVICE_SIGNAL_INCLUDE_BROWSER_VERSION` | `false` | Include the browser major version in the browser/device signal. Default `false` (family only) so routine browser auto-updates are not treated as a changed device |
| `MAX_AUTH_EVENTS`       | `500`           | Maximum number of events retrieved per user for evaluation          |
| `TIME_ZONE`             | `Europe/Lisbon` | Timezone applied to datetime-based risk checks                      |
| `IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH`     | `900` | Absolute speed cap for impossible-travel; a leg above it is always impossible |
| `IMPOSSIBLE_TRAVEL_BURST_GAP_MINUTES` | `60`  | The above-median relative check only flags when logins are closer in time than this |

## IP Intelligence

Geolocation and anonymiser (VPN / proxy / Tor) detection are resolved entirely
from data files shipped inside the image and read from disk. **There is no
third-party API and no outbound connection on the authentication path**, which is
what makes on-premise and air-gapped deployment possible.

Having no network in this path removes whole classes of problem rather than
relocating them: no lookup can time out, so no login waits on someone else's
outage; no failure needs caching, so a transient error cannot be remembered as a
fact; there is no API key to hold, rotate or leak, and no daily call ceiling a
busy hour can exhaust; and nothing about a user's address is disclosed to a third
party in order to evaluate it.

What it costs is freshness and precision, since the data is a snapshot. That is
handled explicitly: coverage and age travel with every verdict, and the age of a
file never blocks an authentication.

### Data files

| Variable                 | Default                               | Description                                                            |
| ------------------------ | ------------------------------------- | ---------------------------------------------------------------------- |
| `IP_DATA_DIR`            | `/opt/amfa/ipdata`                    | Root directory for the bundled databases and lists                     |
| `GEOIP_COUNTRY_PATH`     | `$IP_DATA_DIR/dbip-country-lite.mmdb` | Country database (DB-IP Lite, CC BY 4.0)                               |
| `GEOIP_CITY_PATH`        | `$IP_DATA_DIR/dbip-city-lite.mmdb`    | City database, the only source of true coordinates                     |
| `GEOIP_ASN_PATH`         | `$IP_DATA_DIR/dbip-asn-lite.mmdb`     | ASN database, used for the `asn` signal and hosting detection          |
| `COUNTRY_CENTROID_PATH`  | `$IP_DATA_DIR/country_centroids.csv`  | Per-country approximate coordinates, used where the city database cannot place an address |
| `ANON_BUNDLE_DIR`        | `$IP_DATA_DIR/anon`                   | Directory of anonymiser CIDR lists plus their `manifest.json`          |
| `ANON_DATACENTER_IS_VPN` | `false`                               | Whether a hosting-range match alone sets `is_vpn` (see below)          |

Any path may be pointed at an operator-supplied file, including a MaxMind
GeoLite2 or commercial MMDB, since the record schema is the same. The licence
obligation for such a file stays with the operator who holds it.

Coordinates come from the city database, falling back to the country centroid
table. To run country-only (a ~125 MB smaller image, at the cost of intra-country
precision) set `GEOIP_CITY_PATH` to an empty value and build with
`--build-arg IP_BUNDLE_ARGS=--with-city`. With neither a city database nor a
centroid table, no coordinate is available and impossible-travel and
geo-clustering cannot contribute to scoring; this is logged at startup.

**`ANON_DATACENTER_IS_VPN` defaults to `false` deliberately.** Legitimate shared
egress lives in hosting ranges: Apple iCloud Private Relay, CDNs, and corporate
SASE gateways. Enabling this makes every user behind such a gateway look like a
VPN, and because the address does not change, that means a step-up prompt on
every login indefinitely rather than a one-off nudge. The `datacenter` label is
recorded as evidence either way, so the signal stays visible in logs without
driving a challenge. Enabling it with no suppression list loaded produces a
startup warning.

### Data freshness

The engine never blocks or fails authentication on the age of a data file, because
an air-gapped site cannot refresh on demand and old data is still far better
evidence than none.

| Variable                       | Default | Description                                                     |
| ------------------------------ | ------- | --------------------------------------------------------------- |
| `IP_DATA_STALE_WARN_DAYS`      | `45`    | Age past which a positive anonymiser verdict is reported less confidently |
| `IP_DATA_RELOAD_CHECK_SECONDS` | `30.0`  | How often to check whether a data file has been replaced on disk |

Age has exactly one effect today: past `IP_DATA_STALE_WARN_DAYS`, a positive
anonymiser verdict carries a lower confidence value. A graded model (aging, stale,
degraded, expired, assessed per database since country data churns at roughly 0.4%
a month against city at roughly 16%) is designed but not implemented, so its
thresholds are not offered as settings: an unused config variable, declared here
and in `environment.py`, promises behaviour that does not exist.

Files are reloaded in place when they change, so a bundle can be refreshed under a
running engine with no restart. Replacement is detected by `(mtime, size, inode)`
rather than by hashing contents, so refresh by renaming a new file over the old
one, which is what the bundle builder does.

### Inspecting what loaded

`GET /health` is unauthenticated -- reachable by Docker/orchestrator probes, the
e2e preflight check, and anyone else who can reach the service -- so it only ever
carries a one-word `ip_data.status` (`ok`, `degraded`, `unavailable` or `unknown`),
never the detail behind it:

```json
{"status": "ok", "db": "ok", "redis": "ok", "ip_data": {"status": "ok"}}
```

The full inventory -- absolute filesystem paths, database ages, which detection
categories are loaded, hosting ASN counts, IPv6 coverage -- is real reconnaissance
value to an unauthenticated caller (it tells an attacker exactly which evasion
routes carry no penalty before a single attempt is made), so it lives behind
**`GET /health/detail`** instead, gated by the same bearer-token check `/decision`
and `/params_config` already require:

```json
{
  "status": "ok", "db": "ok", "redis": "ok",
  "ip_data": {
    "status": "ok",
    "egress": "none",
    "geo": {
      "editions": {
        "country": {"loaded": true, "path": "...dbip-country-lite.mmdb", "age_days": 30},
        "city":    {"loaded": true, "path": "...dbip-city-lite.mmdb",    "age_days": 30},
        "asn":     {"loaded": true, "path": "...dbip-asn-lite.mmdb",     "age_days": 30}
      },
      "coordinates": "city-db"
    },
    "anonymiser": {
      "loaded": true, "age_days": 0,
      "labels": ["commercial_vpn", "datacenter", "tor_exit"],
      "ipv6_labels": [], "hosting_asns": 892,
      "suppression_data": false, "datacenter_is_vpn": false
    },
    "notes": []
  }
}
```

`ip_data.status` is one of `ok`, `degraded`, `unavailable` or `unknown` on both
endpoints; `/health/detail`'s `notes` explain any value other than `ok`, for
example `"no coordinate source: impossible-travel and geo-clustering inactive"`.
The same snapshot is written to the startup log, so an operator who can read that
log (or authenticate to `/health/detail`) sees the same picture either way.

Two `/health/detail` fields answer questions that otherwise require digging:
`egress` is always `none`, which is the first thing an air-gap review asks; and
`ipv6_labels` shows which detection lists have IPv6 data, so it is visible that
the shipped lists are IPv4-only and an IPv6 client is evaluated by the ASN-backed
check alone.

**This block never affects readiness.** Both endpoints return 200 with
`ip_data.status: "unavailable"` when no data is present at all. Readiness depends
on PostgreSQL and Redis only, because missing or stale IP data degrades one risk
signal rather than breaking authentication, and on an air-gapped site that cannot
refresh on demand, failing readiness for it would be an outage with no available
remedy. A database or Redis failure does still return 503, on both endpoints.

### Refreshing the data, and building without internet access

`scripts/build_ip_bundle.py` fetches the databases and lists and writes a bundle
directory with a `NOTICE` recording each source, its licence and its SHA-256. The
image builds its own bundle in a separate stage, so a normal build needs network
access at build time only; the *running* container never does.

```bash
python scripts/build_ip_bundle.py --out bundle --with-city --keep-city
```

For a host with no internet access, the script resolves each artefact through
three layers, in this order:

1. **A staged directory** (`--source-dir`), populated from a connected host.
   Highest priority, because staging is a deliberate act.
2. **The network**, unless `--offline` is passed.
3. **The seed files committed under `ipdata/seed/`**, as a last resort.

The seed is consulted *after* the network on purpose: a connected build is never
quietly pinned to data committed months ago, but the fallback is still there when
there is no network. Which layer answered is printed at the end of the build and
recorded per artefact under `provenance` in the bundle's `manifest.json`, so
"was this built from fresh data or a fallback" stays answerable long after the
build logs are gone.

**What the committed seed covers.** The anonymiser lists (Tor exits, commercial
VPN and datacenter ranges, hosting ASNs) and the country centroid table, about
900 KB in total. The geolocation databases are deliberately *not* committed: DB-IP
Lite country and ASN are 4.0 MB and 5.2 MB compressed and city is 62 MB, which
does not belong in git history where every refresh adds another permanent copy.
So an offline build with no staged files still gives working VPN, Tor and hosting
detection, but no country, coordinates or ASN, and the engine says so at startup.

**To get geolocation on an isolated host,** stage the databases from a connected
one:

```bash
# On a connected host: fetch everything and keep the raw downloads
python scripts/build_ip_bundle.py --out /tmp/throwaway --with-city --save-sources staged/

# Transfer staged/ (about 69 MB) to the isolated host, then build with no network
python scripts/build_ip_bundle.py --out bundle --with-city --keep-city \
    --offline --source-dir staged/
```

For an image build, drop the same files into `ipdata/staged/` in the build context
and override the build argument:

```bash
docker build --build-arg \
  IP_BUNDLE_ARGS="--with-city --keep-city --source-dir ipdata/staged --offline" .
```

The alternative to building at the isolated site is to build the bundle on a
connected host and mount the resulting directory, pointing `IP_DATA_DIR` at it.
The engine reloads data files in place, so this also works as the ongoing refresh
mechanism with no image rebuild and no restart.

Two further flags: `--no-seed` makes a build fail rather than fall back to the
committed data, for pipelines that must produce fresh output or stop; and
`--include-privacy-relay` adds Apple iCloud Private Relay ranges as a suppression
list, which is off by default because its redistribution grant is not established.

## Rate Limiting

| Variable                 | Default | Description                                        |
| ------------------------ | ------- | -------------------------------------------------- |
| `RATE_LIMIT`             | `True`  | Enable or disable rate limiting                    |
| `RATE_LIMIT_MAX_REQ`     | `4`     | Maximum number of requests allowed per time window |
| `RATE_LIMIT_TIME_WINDOW` | `60`    | Rate limit time window in seconds                  |

## Server

| Variable    | Default | Description                                        |
| ----------- | ------- | -------------------------------------------------- |
| `WORKERS`   | `4`     | Number of Uvicorn worker processes                 |
| `LOG_LEVEL` | `10`    | Python logging level (10 = DEBUG, 20 = INFO, etc.) |
| `DEBUG`     | `False` | Enable debug mode                                  |
