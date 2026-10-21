# Adaptive MFA — Adaptive Multi-Factor Authentication for Keycloak

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Adaptive MFA is a production-grade adaptive authentication engine for [Keycloak](https://www.keycloak.org/). It evaluates login risk in real time using local ML inference and returns a risk-level decision (1-4) that drives step-up MFA in Keycloak flows.

| Risk level | Meaning | What the shipped flow asks for |
|-----|---------|---------|
| 1 | Low risk | Nothing beyond the password |
| 2 | Medium risk | An authenticator code (TOTP) |
| 3 | High risk | A code sent by email |
| 4 | Rejected | The login is denied |

The mapping is realm configuration rather than engine behaviour: the engine returns the
level and the Keycloak flow decides what to do with it, so a deployment can route the
tiers differently. The table describes the flow shipped in
`config/keycloak/test-amfa-realm.json`.

## Why AMFA

Adaptive authentication is a statistical problem, not a language problem. It means scoring
one login against a user's behavioural history, at volume, in milliseconds, and getting the
same answer every time. Large language models are not built for that.

- **It scales.** No inference call per login, no rate limit, no per-token cost. The cost of
  the ten-thousandth login is the cost of the first.
- **It is explainable.** Scoring is deterministic, so a decision can be traced and defended
  to an auditor. Every evaluation records which signals differed from the user's norm, what
  each contributed, and which rule decided the outcome.
- **It runs air-gapped.** Keycloak is deployed heavily in government and isolated networks.
  Adaptive authentication that depends on a hosted model cannot run there at all. This can:
  IP intelligence ships as local databases and no request leaves your network.
- **No external model, no GPU.** The engine is an ordinary Python service you run next to
  Keycloak, on the same commodity hardware, using around a gigabyte of RAM. If Keycloak
  runs there, AMFA runs there.
- **Keycloak is mature. Its adaptive authentication should be too.**
- **Pluggable IP intelligence.** Local databases by default, so it works offline out of the
  box. Any third-party provider can be wired in behind the same interface; open an issue if
  you would like help doing that.

## Features

- **19 configurable risk signals**, including impossible travel, VPN/proxy detection, geo clustering, device fingerprint, behavioral clustering and time anomaly
- **Local ML inference** — K-Modes, DBSCAN, and histogram-based time profiling run on-premise
- **Self-hosted scoring** — authentication risk is evaluated on your own infrastructure
- **Per-realm configuration** — weights, whitelists, and blacklists configurable per Keycloak realm
- **REST API** — `POST /decision` and `POST /auth_context` endpoints

## Repository Layout

This is one of three repositories that make up the full AMFA system:

| Repository | Language | Role |
|---|---|---|
| [**keycloak-adaptive-mfa-engine**](https://github.com/DefensePoint/keycloak-adaptive-mfa-engine) (this repo) | Python | Risk evaluation engine + Docker Compose stack |
| [keycloak-adaptive-mfa](https://github.com/DefensePoint/keycloak-adaptive-mfa) | Java | Keycloak SPI plugin — authenticator that calls the engine |
| [keycloak-adaptive-mfa-admin-ui](https://github.com/DefensePoint/keycloak-adaptive-mfa-admin-ui) | TypeScript | Keycloak Admin UI extension — AMFA configuration pages |

This repo is the entry point. Its `config/keycloak/docker-compose.yml` starts the entire
stack and ships pre-built JARs from the other two repos so you can run everything with
Docker alone. You only need to build the other repos if you are making changes to the SPI
or the Admin UI.

## Architecture

```
Keycloak SPI (Java)          Adaptive MFA Engine (Python)
   Adaptive Auth        ───►  POST /decision  ───►  Risk evaluation
   Authenticator               ◄─── Risk 1-4           (ML + rules)
```

The engine is a FastAPI microservice. It connects to PostgreSQL (event history) and Redis (distributed mutex, caching, rate limiting).

## Prerequisites

- **Docker and Docker Compose** — the quick-start stack runs entirely in containers
- **PostgreSQL `uuid-ossp`** — required. Compose and the base migration both create it. Some managed Postgres products need it allow-listed at the server first (see [Environment Variables](docs/environment-variables.md)).
- **`keycloak` hostname** — Keycloak tokens use `https://keycloak:8443` as the issuer, so
  both the engine container and your browser need to resolve the hostname. Add this once:

  ```bash
  echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
  ```

  This is required because the engine and your browser must reach Keycloak under the
  **same URL**. The engine fetches JWKS from the token issuer to verify signatures; if the
  hostname does not resolve in your browser, the admin console will not open.

- **mkcert** — the stack uses HTTPS. mkcert generates a locally-trusted TLS certificate
  so your browser and the engine both trust it without warnings.

  Install mkcert and set up the local CA:

  **macOS:**
  ```bash
  brew install mkcert nss
  mkcert -install
  ```

  **Windows:**
  ```powershell
  choco install mkcert
  mkcert -install
  ```
  Or with Scoop: `scoop bucket add extras && scoop install mkcert`.

  **Linux (Ubuntu/Debian):**
  ```bash
  sudo apt install libnss3-tools
  curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
  chmod +x mkcert-v*-linux-amd64
  sudo mv mkcert-v*-linux-amd64 /usr/local/bin/mkcert
  mkcert -install
  ```

  Generate the certificate for the `keycloak` hostname:
  ```bash
  mkdir -p config/keycloak/certs
  cd config/keycloak/certs
  mkcert keycloak
  cp "$(mkcert -CAROOT)/rootCA.pem" .
  ```

  The certs directory is excluded from git. You need to generate these once per machine.

## Quick Start

### 1. Start the stack

```bash
cd config/keycloak
cp .env.example .env
docker compose up --build -d
```

> **Local development only.** The compose stack ships default credentials
> that are meant for local use only. The Keycloak admin account
> (`admin/admin`) and database password (`password`) are set in
> `docker-compose.yml`; the engine's `POSTGRES_PASSWORD` is in `.env`.
> Redis runs with no authentication and its port is published on 6379.
> Never use these defaults in a production or internet-facing deployment
> -- replace every password in both files before exposing the stack
> outside your machine.

The stack is named `amfa`, so containers are `amfa-keycloak-1`, `amfa-adaptive_auth-1`,
and so on regardless of your working directory.

This starts five services:

| Service | Port | Purpose |
|---|---|---|
| Keycloak | `https://keycloak:8443` | Identity provider |
| AMFA engine | `http://localhost:8095` | Risk evaluation API |
| PostgreSQL | `localhost:5433` | Event history for the engine |
| Redis | `localhost:6379` | Caching and rate limiting |
| Mailpit | `http://localhost:8025` | Local SMTP sink for email OTP codes |

### 2. Verify the engine is healthy

```bash
curl http://localhost:8095/health 
# {"status":"ok","db":"ok","redis":"ok"}
```

### 3. Verify the realm was imported

The **test-amfa** realm is automatically imported on first start. Open
<https://keycloak:8443>, log in with **admin / admin**, and confirm **test-amfa** appears
in the realm dropdown (top-left).

The realm comes pre-configured with the `adaptive-auth-api` service-account client,
audience mapper, `frontendUrl`, and the Adaptive MFA authenticator wired into the browser
flow.

### 4. Create a test user

1. Switch to the **test-amfa** realm, go to **Users**, and click **Add user**
2. Set **Username** to `alice`, **Email** to `alice@test.local`, toggle **Email verified** on
3. Click **Create**, open the **Credentials** tab
4. Click **Set password**, enter `Passw0rd!`, toggle **Temporary** off, and save

### 5. Test a login

Open <https://keycloak:8443/realms/test-amfa/account> and log in as **alice / Passw0rd!**.
The AMFA engine evaluates risk on every login. A new user has no history, so the engine
returns Risk 2 or 3 by default and will prompt for a TOTP code or an email OTP.

Email OTP codes land in Mailpit at <http://localhost:8025> — no real mail is sent.

## High-Availability Setup

A multi-node HA configuration is available for testing session replication and
failover. It runs two Keycloak nodes clustered via Infinispan (JDBC_PING) and
two AMFA engine replicas behind an nginx load balancer, using the same ports and
prerequisites as the single-node stack.

See [docs/ha-setup.md](docs/ha-setup.md) for full instructions.

## Building from Source

The stack ships pre-built JARs for the Keycloak SPI and Admin UI. Follow these steps only
if you have made changes to those repos and need to deploy your own builds.

### Keycloak SPI (keycloak-adaptive-mfa)

Requires JDK 17 and Maven 3.8+.

```bash
cd keycloak-adaptive-mfa
mvn clean package -DskipTests
# Output: target/keycloak-adaptive-mfa-<version>.jar
```

Copy the JAR into the stack and restart Keycloak:

```bash
cp target/keycloak-adaptive-mfa-*.jar ../keycloak-adaptive-mfa-engine/config/keycloak/keycloak-adaptive-mfa.jar
docker compose -f ../keycloak-adaptive-mfa-engine/config/keycloak/docker-compose.yml restart keycloak
```

The provider JARs are fetched from their pinned releases (versions in
`config/keycloak/docker-compose.yml`), not committed, so a JAR
you copy in is a local override. The `providers` service leaves an existing file
alone and only reports that it differs from the released asset, so a local build
survives a `docker compose up`. Delete the file to go back to the released version.

### Admin UI (keycloak-adaptive-mfa-admin-ui)

Requires Node.js 18+, pnpm 9+, and JDK 17+ (for the `jar` command).

```bash
cd keycloak-adaptive-mfa-admin-ui
./build.sh
# Output: dist/keycloak-admin-ui-amfa.jar
```

To build and hot-deploy in one step:

```bash
./build.sh --deploy ../keycloak-adaptive-mfa-engine/config/keycloak/
```

This copies the JAR and restarts Keycloak automatically.

## Running Tests

Unit tests run without Docker:

```bash
pip install -r requirements.txt
pytest -v ./tests/unit/
```

## Configuration

Copy `config/keycloak/.env.example` to `config/keycloak/.env` and set the variables. Key settings:

| Variable | Description |
|---|---|
| `OIDC_TRUSTED_BASE_URLS` | Comma-separated trusted Keycloak base URL(s); any realm under a trusted base is accepted. Required. |
| `OIDC_EXPECTED_AUDIENCE` / `OIDC_VERIFY_AUDIENCE` | Expected `aud` and whether to enforce it on bearer tokens |
| `POSTGRES_*` | Database connection |
| `REDIS_*` | Redis connection |
| `DEFAULT_RISK_LEVEL` | Risk level returned when there is no prior risk data (default: `2`) |
| `FALLBACK_RISK_LEVEL` | Not currently read on any evaluation path -- an evaluation error returns a server error instead, never a risk level. Kept only as a guarded setting: the engine refuses to start if this is set more permissive than `DEFAULT_RISK_LEVEL` (default: `3`) |
| `DROP_DOWN_DECAY_DAYS` | Age (days) beyond which a clean login relaxes a stale escalation faster (default: `30`) |
| `DROP_DOWN_DECAY_STEPS` | Risk-level steps to drop for a stale escalation; clamped to risk ≥ 1 (default: `2`) |
| `IP_DATA_DIR` | Location of the bundled IP geolocation and VPN-detection data (default: `/opt/amfa/ipdata`) |

Geolocation and VPN/proxy/Tor detection are resolved from data files shipped inside the
image, so no API key is needed and the authentication path makes no outbound request. See
[Environment Variables](docs/environment-variables.md#ip-intelligence) for the full
reference.

## Troubleshooting

### "We are sorry... HTTPS required" in the Keycloak browser UI

This means you are accessing Keycloak over HTTP but the realm requires HTTPS. The correct
fix is to set up HTTPS using mkcert — follow the **Prerequisites** section above. The
stack is configured to use HTTPS by default; HTTP access will trigger this error.

### Port already in use

The stack uses ports `8443`, `5433`, `6379`, `8095`, `8025`, and `1025`. If any of these
conflict with services already running on your machine, edit
`config/keycloak/docker-compose.yml` and change the **host-side** port (the left side of
`host:container`). The containers communicate over the internal `amfa_net` network and are
not affected by host port changes.

If you remap Keycloak's HTTPS port, you must also update four other places consistently:

1. `KC_HTTPS_PORT` env var in the `keycloak` service (so Keycloak listens on the new port internally)
2. `frontendUrl` in `config/keycloak/test-amfa-realm.json`
3. `OIDC_TRUSTED_BASE_URLS` in `config/keycloak/.env`
4. The mkcert certificate — regenerate it if you change the hostname

### `keycloak` hostname does not resolve

Verify the entry is in `/etc/hosts`:

```bash
grep keycloak /etc/hosts
# expected: 127.0.0.1 keycloak
```

If it is missing, add it:

```bash
echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
```

## How risk scoring works

On each login the Keycloak SPI sends the engine a few signals about the attempt (device fingerprint, browser, OS, IP/geolocation, VPN/proxy, time of day, behavioral patterns). The engine turns them into a risk level (1-4) in three steps:

1. **Learn the user's normal** from their past logins in PostgreSQL, using on-device ML (K-Modes for categorical fingerprints, DBSCAN for location/behavior clusters, histogram-based time profiling). With too little history it uses the realm's configured fallback level.
2. **Flag anomalies:** each signal that deviates from that norm (new device, unusual country, impossible travel, VPN, odd hour, burst of failed logins).
3. **Score the anomalies** in one of two modes:
   - *Weight-based (default):* each signal carries a weight. When anomalies are present a hazard step combines them into a level; when the login is clean the level instead relaxes toward baseline (see self-healing below).
   - *Log-Odds Bayesian:* each signal adds evidence on a log-odds scale; the total plus a bias term becomes a fraud probability mapped to levels by configurable thresholds.

**Device/network familiarity.** Alongside the score, the engine measures how closely this device and network match the user's history as a credibility value in [0,1] (weighted 55% device, 45% network). It adjusts the level in both directions:

| Familiarity | Effect on the level |
|---|---|
| below 0.30 | raised to at least 3, unless an allow-listed attribute is present, so a brand-new device and network can never resolve as low risk |
| 0.30 to 0.60 | unchanged |
| 0.60 to 0.85 | lowered by one step |
| 0.85 and above | lowered to 1 |

The downward half is what stops a known device being challenged for every small change, and it decides the final level on a large share of logins, so it is worth knowing about when a decision looks lower than the changed signals suggest.

**One exception, and it matters.** A hazard escalation is a floor that familiarity cannot lower. When six or more signals change in a single login the level is forced to 3 (or 4 with recent failed attempts) and it stays there however familiar the device is. That case, where the device is the one thing that still looks normal while the network, country, language and hour have all moved, is the shape hazard activation exists to catch, so letting familiarity discount it would soften the rule exactly where it is needed. Deny-list matches sit after this for the same reason.

**Self-healing.** On a clean login the level drops one step below the previous decision; if the last escalation is older than a configurable window (default 30 days) it drops by more (default 2 steps). A user who stops triggering anomalies therefore decays back to low risk over repeated good logins, always clamped to at least 1.

Per-realm **allow/deny lists** (country, IP, OS) hard-override the score in either mode. The final level drives step-up MFA: 1 = none, 2 = OTP, 3 = OTP + authenticator, 4 = reject.

## Related Projects

- [keycloak-adaptive-mfa](https://github.com/DefensePoint/keycloak-adaptive-mfa) — Keycloak SPI (Java)
- [keycloak-adaptive-mfa-admin-ui](https://github.com/DefensePoint/keycloak-adaptive-mfa-admin-ui) — Keycloak Admin UI extension (TypeScript/React)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).

## IP Data Attribution

IP Geolocation by [DB-IP](https://db-ip.com). The engine uses the DB-IP Lite
country, ASN and city databases, licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); `country_centroids.csv`
is a derived work computed from DB-IP City Lite. The engine also redistributes
Tor exit addresses (CC0) and the X4BNet VPN, datacenter and hosting-ASN lists (MIT).
Full attribution, including the modification notice and per-artefact licences, is
generated as a `NOTICE` file in each built IP data bundle (`IP_DATA_DIR`).
