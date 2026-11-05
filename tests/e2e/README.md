# AMFA end-to-end suite

Black-box scenarios that run against a **live stack** (Keycloak + engine + redis
+ postgres + Mailpit) and validate the wiring between components:

```
Keycloak SPI  ->  engine /auth_context + /decision  ->  redis/postgres
     ^                                                        |
     +----------  risk-based MFA step-up  <-------------------+
```

Per-signal scoring *logic* (impossible-travel, login-failure, concurrent-session,
account-change, drop-down decay, hazard thresholds, weight/bayesian scoring) is
covered by the **engine unit suite** (`tests/unit`, 499 tests). This suite covers
what unit tests cannot: the real HTTP/authenticator wiring across the three
repos. See [scenario-coverage.md](scenario-coverage.md) for the full map.

Two things live here:

| | What it is |
| --- | --- |
| `run_e2e.py` | scenario smoke gate, 14 checks, non-zero exit on failure |
| `test_signal_matrix.py` | the risk-signal matrix under `weight` scoring, compared against a committed baseline |
| `test_bayesian_matrix.py` | the same rows under `bayesian` scoring, which is the engine's default, with its own baseline |
| `test_resilience.py` | what a login does when the engine cannot answer |
| `test_engine_api.py` | what `/decision` accepts, refuses, and returns when it breaks |
| `test_browser_journeys.py` | real-browser journeys via Playwright, opt-in (see [browser-plan.md](browser-plan.md)) |

## Run

```bash
python3 tests/e2e/run_e2e.py
```

Exit code is non-zero if any check fails, so it works as a post-deploy smoke
gate. Requires `requests` (`pip install requests`).

### Which suite runs where

Two of these modules import the engine, and two do not. That decides where they can
run, and it is worth knowing before a confusing failure.

| Module | Imports `src` | Run from |
| --- | --- | --- |
| `run_e2e.py` | no | host |
| `test_signal_matrix.py` | no | host |
| `test_signal_gating_e2e.py` | yes | inside the engine container |
| `test_inactive_days_e2e.py` | yes | inside the engine container |

The two that import `src` need the engine's dependency set, and `pandas` is installed
by the Dockerfile rather than declared in `requirements.in`, so a host that installed
only the declared requirements cannot import the engine at all. Run them where those
dependencies live:

```bash
docker cp tests amfa-adaptive_auth-1:/app/tests
docker exec amfa-adaptive_auth-1 sh -lc \
    'cd /app && python -m pytest tests/e2e/test_signal_gating_e2e.py tests/e2e/test_inactive_days_e2e.py -q'
```

The two that do not import `src` run from the host with nothing installed but
`requests`:

```bash
PYTHONPATH=. python3 -m pytest tests/e2e/test_signal_matrix.py -q
```

`conftest.py` supplies host-reachable Postgres and Redis defaults, including the
published port 5433 rather than the container's 5432, so a partially configured shell
does not fail during collection with a SQLAlchemy error about parsing `'None'` as a
port. Existing environment variables always win, so it changes nothing inside the
container.

## Prerequisites

- The compose stack up: Keycloak `:8443` (reachable at `https://keycloak:8443`
  via the `keycloak` hosts-file entry from the main README's Prerequisites),
  engine `:8095`, redis, postgres, Mailpit `:8025` (see
  `config/keycloak/docker-compose.yml`).
- Realm `test-amfa` with the AMFA browser flow bound and the `amfa-webhook`
  event listener enabled, a public client `test-login` (redirect
  `https://keycloak:8443/*`), and user `alice` / `Passw0rd!` with an email
  address.

## SQL Server

The suite runs against SQL Server when the engine does. Set `DB_TYPE=mssql` and the
`POSTGRES_*` variables on the engine, then run the suite with `E2E_DB_TYPE=mssql`. Its
database queries then go through the engine container, so they need no SQL client.
`test_signal_gating_e2e.py` and `test_inactive_days_e2e.py` import the engine, so run
them inside the engine container as shown above, where the engine's own settings apply.
The SSO suite in `tests/e2e/sso` starts its own stack on Postgres, so it does not run
against SQL Server.
Keycloak keeps its own Postgres database either way.

## Configuration

Every endpoint and credential is overridable via environment variables (defaults
in `e2e_common.py`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `E2E_KC_BASE` | `https://keycloak:8443` | Keycloak base URL |
| `E2E_ENGINE_BASE` | `http://localhost:8095` | Engine base URL |
| `E2E_MAILPIT_BASE` | `http://localhost:8025` | Mailpit API (email OTP) |
| `E2E_REALM` | `test-amfa` | Realm under test |
| `E2E_USER` / `E2E_PASS` | `alice` / `Passw0rd!` | Login user |
| `E2E_TOTP_SECRET` | (unset) | alice's raw TOTP secret; set it so the TOTP step-up tier can also be completed automatically |
| `E2E_COMPOSE_PROJECT` | `amfa` | Compose project name, which the container names below derive from |
| `E2E_DOCKER_ENGINE` / `E2E_DOCKER_PG` / `E2E_DOCKER_REDIS` / `E2E_DOCKER_KEYCLOAK` / `E2E_DOCKER_MAILPIT` | `amfa-<service>-1` | Containers for the log/DB/redis assertions (skipped if `docker` is unavailable) |

The container names derive from one variable rather than being spelled out, because they
were previously hardcoded with a `keycloak-` prefix that only matched a stack started
from inside `config/keycloak`. Started any other way, every docker-backed helper failed
*silently*: `redis_set` could not seed a key and `engine_log_since` read nothing, so a
scenario whose fixture never landed reported a failed product assertion instead. The
compose file now declares `name: amfa`, so the names follow from it wherever the stack
is started.

## The risk-signal matrix

`test_signal_matrix.py` runs one real login per row against a chosen context, and
asserts against the engine's own account of its decision rather than a level someone
typed into a table. 23 rows, about 40 seconds.

```bash
# the full set, compared against the committed baseline
PYTHONPATH=. python3 -m pytest tests/e2e/test_signal_matrix.py

# accept intentional changes, then commit the diff
PYTHONPATH=. python3 -m pytest tests/e2e/test_signal_matrix.py --update-baseline
```

It needs `KC_PROXY_HEADERS: xforwarded`, because six signals derive from the client IP
and driving them means choosing the address Keycloak reports. The base compose leaves
that unset deliberately, since trusting a forwarded address with no proxy in front lets
any client pick the IP its own risk is judged on, so the suite opts in via an overlay:

```bash
docker compose -f config/keycloak/docker-compose.yml \
    -f config/keycloak/docker-compose.e2e.yml up -d
```

Each run works in a throwaway realm it creates and deletes, so it does not touch
`test-amfa` and can be run repeatedly with no cleanup. Design, guarantees and the full
list of determinism guards are in [signal-matrix-plan.md](signal-matrix-plan.md).

### How a row is affordable

The engine gates on history: below `MIN_AUTH_EVENTS` completed logins it short-circuits
to a cautious level and every row reads the same whatever it sends. Training each row's
user through the browser would be about 30 minutes for the set. Instead one golden user
is trained once, and each row clones that profile onto a fresh user by copying its
`auth_process` rows in SQL and rewriting when they happened. About 2 seconds a row.

Three signals cannot be expressed as one login, so they perform a real sequence
instead: `concurrent_session` logs in from other addresses first, `recent_account_change`
has the user change their own password, `login_failure` fails logins first.

### The two scoring modes

`SCORING_MODE` defaults to `bayesian`, and that is what most deployments run. The matrix
pins `weight` because that is the mode whose arithmetic can be checked, so both are
covered separately and each has its own baseline. The levels are not comparable: 13 of
21 shared rows land on a different level. `artifacts/mode-comparison.md`, written by the
bayesian suite, is the row-by-row table.

Three mechanisms do not run under bayesian scoring, because `__evaluate_risk` returns
from that branch first: hazard activation, the drop-down decay, and the credibility
adjustment. Credibility is still used, as a model feature rather than a post-hoc
adjustment. Do not assume a rule documented for weight mode applies to the default one.

### What it does not cover

Stated here because a green run should not be read as more than it is:

- **`login_failure` cannot fire from real behaviour.** `F01` is `xfail(strict=True)`
  carrying the measurement. A wrong password emits Keycloak's LOGIN_ERROR but no auth
  process is open yet, so the engine discards it; a wrong emailed code happens inside an
  open process but Keycloak emits no event for it. Either fix is a product decision.
- **Risk 4 is not a rejection in this realm.** The deny-list rows do force Risk 4, but
  the flow has only `risk-2-EQUAL` and `risk-3-GREATER_OR_EQUAL`, so Risk 4 lands in the
  `>= 3` branch and gets the same email code as Risk 3.
- **The hazard floor is not reachable through the front door**, so it is covered only by
  `tests/unit/services/test_hazard_floor.py`.
- **Single-signal isolation is not reachable either.** `event_cluster_label` clusters the
  whole context vector, so it fires on essentially any change and a "browser only" delta
  is really browser plus cluster. Rows are honest delta sets and the reported signal list
  shows what actually fired.

## Browser journeys

Opt-in, and not a second signal matrix: the HTTP driver reaches the same decisions, so
these exist for what only a browser does, which is run the page. The client-side
JavaScript, the rendered templates, cookies and sessions.

```bash
pip install playwright && playwright install chromium
PYTHONPATH=. python3 -m pytest tests/e2e/test_browser_journeys.py

# watch it happen
PYTHONPATH=. python3 -m pytest tests/e2e/test_browser_journeys.py --headed

# everything except the browser
PYTHONPATH=. python3 -m pytest tests/e2e -m 'not browser'
```

Without Playwright installed they skip with a message saying how to enable them, so a
machine with only `requests` still runs everything else.

Seven journeys today: the first sign-in end to end, the browser's own screen resolution
reaching the decision, a returning user going unchallenged, a wrong code being visibly
rejected, authenticator enrolment including whether the QR renders, the TOTP challenge,
and a denied login showing a proper error page. They take 15 to 40 seconds, the spread
being the TOTP journey waiting for a fresh code window.

## Is the HTTP driver faithful to a browser?

Yes, and it is checked automatically rather than asserted. The matrix drives logins with
`requests`, which is what makes it fast, and that puts a question under the whole suite:
a driver that does not present a login the way a browser does would be measuring itself
rather than the product.

`test_browser_journeys.py::test_both_drivers_reach_the_same_decision` answers it on every
browser run. It signs one user in through Chromium, reads back the headers and screen
resolution the browser actually put on the wire, replays exactly those through the HTTP
driver against a twin user with the same seeded history, and requires the same risk level
reached by the same signals.

Feeding the driver what the browser *presented*, rather than what the test asked for,
is the part that makes it meaningful: a browser derives its own `Accept-Language` and
reports its own screen, so comparing against the test's intent would hide the divergence
this is looking for.

This replaces `chrome_spotcheck.py`, a manual three-command version of the same check
that has been removed. It was the only step in the suite that needed a person.

One limit is unchanged: a browser cannot send `X-Forwarded-For`, so the journeys inject
it. Everything else about them is genuine, but no journey here is a completely unmodified
browser.

## Notes

- The risk tier a login receives depends on the user's evolving history, so the
  flagship scenario uses a unique novel context each run and completes whichever
  step-up factor the engine chooses: **email** always (caught via Mailpit),
  **TOTP** only when `E2E_TOTP_SECRET` is set (otherwise the step-up itself is
  still asserted and completion is reported as skipped).
- The suite performs logins and read-only lookups only; it does not mutate realm
  or user configuration. The one exception is the E4 scenario, which seeds a
  single transient account-change event in redis and deletes it afterwards
  (it stands in for the Keycloak webhook, whose ingestion is separately proven
  by the login-success webhook in the flagship scenario).
- The blacklist scenario reads whatever `ip_address` blacklist the realm already
  has on its default group; if none is configured it is skipped.
- The E4 scenario needs `docker` access (redis seed + engine log inspection); it
  is skipped when docker is unavailable.
