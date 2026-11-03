# SSO end-to-end suite

Logins through an identity provider, end to end: Keycloak with the AMFA plugin,
the engine, and a second Keycloak realm, `corp`, acting as the identity
provider. It runs AMFA as the provider's post login flow and checks every risk
tier and what the engine records for these logins.

Unlike the main suite in `tests/e2e`, this one starts its own stack and tears it
down again, so it needs nothing running beforehand and can run next to the main
stack.

## Run

```bash
python3 tests/e2e/sso/run_sso_e2e.py
```

Requires Docker with Compose v2, Python 3.9+ and `requests`. A run takes about
four minutes, most of it the image build and Keycloak's first start. Exit code
is non-zero if any check fails.

The suite takes the plugin and vavr jars from `config/keycloak`, where the main
stack's `providers` service downloads them and verifies their digests. On a
fresh checkout, fetch them once:

```bash
cd config/keycloak && cp -n .env.example .env && docker compose run --rm providers
```

To test a plugin build other than the released one, point the suite at its jar,
and at the vavr version that jar was built against:

```bash
E2E_SSO_PLUGIN_JAR=/path/to/keycloak-adaptive-mfa-1.0.1.jar \
E2E_SSO_VAVR_JAR=/path/to/vavr-1.0.1.jar \
python3 tests/e2e/sso/run_sso_e2e.py
```

## What it checks

- A first-ever and a repeat SSO login at risk 1 complete, and reach the engine
  with the device data AMFA collected (browser, screen resolution, language).
- No AMFA data appears in the access or ID token.
- Risk 2 sets up TOTP on the first login and asks for the code on the next one.
- Risk 3 asks for the email code (read from Mailpit).
- Risk 4 refuses the login, the engine stores the refusal once against the
  user, and the login's decision is closed.
- A silent re-login on an existing session completes without any page and
  carries no device data, by design: a stolen session cookie must not report
  the victim's device as its own.
- A local login reaches the engine with device data, and a refused local login
  is stored against the user.
- The Keycloak log has no AMFA plugin errors.

The risk tier of each login is set by `risk_override_proxy.py`, which sits
between Keycloak and the engine and replaces the level in the engine's
`/decision` answer. Everything else, including the login-event webhook, passes
through unchanged.

### Checks that need the plugin's brokered-login support

Device data on SSO logins and refused logins recorded against their user need
a plugin release with the brokered-login support. The suite reads the jar to
find out, and prints it at the start. Without that support those checks are
reported as `XFAIL` (expected failure) rather than `FAIL`, and an unexpected
pass as `XPASS`. The released plugin pinned in `config/keycloak` (1.0.1)
predates that support, so a run with the defaults shows them as `XFAIL`.

## How it works

- `docker-compose.sso.yml`: Postgres, Redis, Mailpit, the engine (built from
  this repository), the risk proxy and Keycloak. Keycloak serves plain HTTP on
  `E2E_SSO_KC_PORT`, the same port inside and outside its container, under the
  name `E2E_SSO_KC_HOST`. The login driver resolves that name to 127.0.0.1, so
  one URL works for the driver, for Keycloak calling the `corp` realm, and for
  the engine checking token issuers, with no LAN address or hosts-file entry.
- `run_sso_e2e.py`: prepares the realms in a run folder under `artifacts/`,
  starts the stack, runs the scenarios, prints the summary and stops the stack.
  It imports the shipped `config/keycloak/test-amfa-realm.json` and changes only
  environment settings: the Keycloak and engine addresses, the test client's
  redirect, a local test user, the `corp` provider bound to `amfa-post-broker`,
  and a high brute-force threshold so the suite's deliberate refusals do not
  lock its users.
- `post-broker-flow.json`: the `amfa-post-broker` flow and its tier subflows.
  The suite adds them to the realm when the realm does not already have them.
- `sso_login.py`: the browser-style login driver.
- `lb.py`: round-robin load balancer for cluster mode.

## Cluster mode (optional)

```bash
E2E_SSO_CLUSTER=1 python3 tests/e2e/sso/run_sso_e2e.py
```

Starts two Keycloak nodes sharing the database and an Infinispan cluster
(`--cache=ispn`, `jdbc-ping`), behind `lb.py`, which alternates every request
between them. A login's AMFA steps and the request that fires its LOGIN event
then land on different nodes. The same checks run.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `E2E_SSO_PLUGIN_JAR` | `config/keycloak/keycloak-adaptive-mfa.jar` | Plugin jar under test |
| `E2E_SSO_VAVR_JAR` | `config/keycloak/vavr-1.0.1.jar` | vavr jar for the plugin; the suite warns if the plugin was built against another version |
| `E2E_SSO_REALM_FILE` | `config/keycloak/test-amfa-realm.json` | Realm to import |
| `E2E_SSO_KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak:26.6.3` | Keycloak image |
| `E2E_SSO_PYTHON_IMAGE` | `python:3.12-alpine` | Image that runs the risk proxy and the load balancer |
| `E2E_SSO_KC_HOST` | `sso-keycloak` | Keycloak's hostname in the stack |
| `E2E_SSO_KC_PORT` | `18180` | Keycloak's port; cluster mode also uses the next two ports for the nodes |
| `E2E_SSO_KC_NODE2_PORT` | `E2E_SSO_KC_PORT` + 2 | Second node's port in cluster mode |
| `E2E_SSO_MAILPIT_PORT` | `18125` | Mailpit API port on the host |
| `E2E_SSO_PROJECT` | `amfa-sso-e2e` | Compose project name |
| `E2E_SSO_ADMIN_USER` / `E2E_SSO_ADMIN_PASS` | `admin` / `admin` | Keycloak bootstrap admin of the throwaway stack |
| `E2E_SSO_CLUSTER` | `0` | `1` for cluster mode |
| `E2E_SSO_KEEP` | `0` | `1` leaves the stack running after the run, for debugging; stop it with `docker compose -p amfa-sso-e2e down -v` |

## What these logins cannot show

Two failures never reach AMFA, for SSO users: a wrong password at the identity
provider (it never reaches Keycloak), and a wrong TOTP or email code (Keycloak
emits no event for it, for local users either).
