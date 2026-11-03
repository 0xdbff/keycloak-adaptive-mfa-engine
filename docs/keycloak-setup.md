# Keycloak Realm Setup

Every Keycloak realm that uses Adaptive MFA needs a small amount of one-time
setup so the Keycloak SPI can call the engine and the engine can verify the
tokens it receives. Without these steps the admin console's Adaptive MFA page
returns **500** and the engine logs `403 Untrusted issuer` or
`403 Invalid audience`.

## 1. Create the `adaptive-auth-api` client

The SPI uses this client's service account to talk to the engine.

1. **Clients → Create client**
    - Client ID: `adaptive-auth-api`
    - Client authentication: **On** (confidential)
    - Service accounts roles: **On**
    - Standard flow / direct access grants: off
2. Save.

Equivalent admin REST call:

```bash
curl -X POST "$KEYCLOAK/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"clientId":"adaptive-auth-api","enabled":true,"protocol":"openid-connect",
       "publicClient":false,"serviceAccountsEnabled":true,
       "standardFlowEnabled":false,"directAccessGrantsEnabled":false}'
```

## 2. Add the `amfa` audience mapper

The engine enforces `aud=amfa` on every bearer token
(`OIDC_VERIFY_AUDIENCE=true`, the secure default). Add an audience mapper to
the client created above:

1. **Clients → adaptive-auth-api → Client scopes → adaptive-auth-api-dedicated
   → Add mapper → By configuration → Audience**
    - Name: `amfa-audience`
    - Included Custom Audience: `amfa`
    - Add to access token: **On**
2. Save.

```bash
curl -X POST "$KEYCLOAK/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"amfa-audience","protocol":"openid-connect",
       "protocolMapper":"oidc-audience-mapper",
       "config":{"included.custom.audience":"amfa",
                 "access.token.claim":"true","id.token.claim":"false"}}'
```

## 3. Make the token issuer trusted and reachable

The engine validates the token issuer against `OIDC_TRUSTED_BASE_URLS`
(host-pinned, scheme + host + port must match exactly) and fetches the
issuer's JWKS **from the issuer URL itself**. Two rules follow:

- The issuer base must be listed in the engine's `OIDC_TRUSTED_BASE_URLS`.
- The issuer URL must be reachable from the engine container.

**Production (single public hostname):** if Keycloak is served at one public
URL (e.g. `https://sso.example.com`) that the engine can also reach, just set
`OIDC_TRUSTED_BASE_URLS=https://sso.example.com` and you are done.

**The bundled compose file avoids split-horizon rather than working around
it.** The Prerequisites section has you add `127.0.0.1 keycloak` to
`/etc/hosts` specifically so your browser and the engine reach Keycloak at
the exact same URL, `https://keycloak:8443` — there is no separate
browser-facing hostname to reconcile. The realm's `frontendUrl` is set
uniformly to that same URL (already shipped in
`config/keycloak/test-amfa-realm.json`), and `OIDC_TRUSTED_BASE_URLS` in
`config/keycloak/.env.example` matches it, so tokens, JWKS fetches, and admin
console redirects all agree.

**True split-horizon (browser and engine genuinely cannot share a
hostname)** — for example, a reverse proxy or ingress terminates TLS for
browsers at a public hostname the engine container cannot resolve, or does
not need to reach. Tokens carry the browser-facing issuer by default, which
the engine can then neither trust nor resolve. Pin the issuer per realm to
whatever URL the engine *can* reach by setting the realm attribute
`frontendUrl`:

```bash
# Merge frontendUrl into the realm attributes (do not replace the whole map)
curl -X PUT "$KEYCLOAK/admin/realms/$REALM" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$KEYCLOAK/admin/realms/$REALM" \
        | jq '.attributes.frontendUrl = "<engine-reachable-issuer-url>"')"
```

!!! warning
    `frontendUrl` changes every URL Keycloak generates for that realm,
    including browser redirects for interactive logins. If the engine's URL
    is not also reachable from the browser, end-user login flows against that
    realm will redirect somewhere the browser cannot resolve — add a
    hosts-file entry, use an internal DNS record, or fall back to a single
    public hostname as in production.

## 4. Point the realm at the engine

In the admin console: **Realm settings → Security defenses → Adaptive MFA**,
set **AMFA Engine Endpoint** (e.g. `http://adaptive_auth` in the bundled
compose network) and enable the feature. Saving writes the
`adaptiveAuthEndpoint` realm attribute the SPI reads at request time.

### Co-hosting realms on one engine

Multiple realms may point at the same engine — each realm's config, decision
history, and rate limits are namespaced by realm. That isolation is a
per-tenant boundary, not a per-trust-domain one: realms that belong to
genuinely different trust domains (different organizations, different
security postures, or where one tenant should never be able to affect
another's *availability*) should not share an engine process. Give each trust
domain its own engine deployment instead.

### When the engine cannot be reached

Every call to the engine (connection failure, timeout, non-2xx response, or a
TLS/certificate error alike) is handled the same way, controlled by two realm
attributes:

- **`fallbackRisk`** (`1`-`4`): the risk level applied in **advisory** mode
  (see below). Unset, blank, non-numeric, or out of range all resolve to `3`
  (OTP + authenticator) rather than propagating an error — erring high is
  deliberate, since an unconfigured realm should ask for a step-up rather than
  either refusing every login or waving everyone through.
- **`adaptiveAuthFailureMode`** (`advisory` or `mandatory`, default
  `advisory`): whether an unreachable engine is advisory (proceed at
  `fallbackRisk`) or mandatory (deny the login outright). A realm that needs
  the engine to be a real security control, not just a risk signal, should set
  this to `mandatory`.

Set both via **Realm settings → Security defenses → Adaptive MFA**, or the
admin REST API alongside `adaptiveAuthEndpoint`.

Whichever mode is active, the resulting Keycloak login event carries a
`decision_source` detail (`engine` or `fallback`) so a degraded deployment —
every login silently proceeding at the fallback level because the engine has
been unreachable since installation, or because of the certificate issue
below — is visible in the event log rather than indistinguishable from normal
operation. Failures are also logged with the stable marker
`ADAPTIVE_AUTH_ENGINE_UNREACHABLE`, greppable independent of the surrounding
message text, for log-based alerting.

!!! warning "TLS trust for an HTTPS engine endpoint"
    The SPI has no certificate/truststore configuration of its own — every
    call to the engine goes through Keycloak's own globally-configured HTTP
    client, which trusts whatever `KC_TRUSTSTORE_PATHS` names. If
    `adaptiveAuthEndpoint` points at an `https://` engine, the CA that signed
    the engine's certificate **must** be included in `KC_TRUSTSTORE_PATHS` (or
    the system trust store), separately from any CA needed for Keycloak's own
    certificate. If it isn't, every single engine call fails with a TLS
    handshake error — indistinguishable from the engine simply being down,
    and permanent rather than transient until the truststore is corrected.

## 5. Enable the login-history event listener

The risk engine learns from login history. The `amfa-webhook` event listener
emits each login to the engine's `/login_event/webhook` (as a realm-signed
token) so that history is recorded — without it the engine evaluates every
login as first-time and risk never adapts.

**Realm settings → Events → Event listeners**, add **`amfa-webhook`** to the
list and save. (The listener is inert on realms where Adaptive MFA is not
enabled, so it is safe to leave configured.)

```bash
curl -X PUT "$KEYCLOAK/admin/realms/$REALM/events/config" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"eventsListeners":["jboss-logging","amfa-webhook"]}'
```

The listener also needs the AMFA authenticators bound into the realm's browser
flow, so that each login captures the authentication context the webhook
reports. In the "forms" subflow, set these as REQUIRED **in this order**, the
order the test realm in `config/keycloak` ships:

1. **Screen Resolution**: renders a brief page whose JS
   captures `screen.width x screen.height` into the `screenResolution`
   session note (a risk signal). Requires the realm **Login theme** set to
   `keycloak-amfa` (Realm settings → Themes) so its template/JS load.
2. **Username Password Form**: the realm's own login form.
3. **Auth User Context Authenticator**: captures device/geo/UA
   context and gets the auth-context hash from the engine.
4. **Adaptive Authentication**: calls the engine for the ACR
   decision and drives step-up.

Screen Resolution must come before the two AMFA steps, so that they see the
value it captured. A login without a screen resolution, through a flow without
this step or a direct grant, is still scored, with the screen resolution
treated as unknown; the step gives the engine one more signal to compare.

## 6. Configure risk-based step-up

The `Adaptive Authentication` authenticator does not challenge the user itself.
It writes the engine's risk level (1-4) into an auth note, and **conditional
subflows** downstream read that note to decide which second factor, if any, to
run. This is what turns a risk score into an actual TOTP or email challenge.

The routing is expressed with the `Conditional - User Risk Level`
authenticator (`conditional-adaptive-auth`), which has two config properties:

- **Risk Level** — the level to compare against.
- **Comparison** — `GREATER_OR_EQUAL` (`>=`, the default), `EQUAL` (`==`), or
  `LESS_OR_EQUAL` (`<=`).

A condition only gates the flow when it sits inside a **Conditional** subflow
(it is a no-op inside an Alternative subflow). So each tier is its own
Conditional subflow. The reference policy below is

- risk `>= 4` → the login is **refused**
- risk `>= 3` → **Email OTP**
- risk `== 2` → **TOTP**
- risk `== 1` → no step-up

Build it inside the "forms" subflow, after `Adaptive Authentication`, as the
test realm does. Do not put the tiers next to the "forms" subflow in the
top-level browser flow: there, "forms" and Cookie are Alternative, and Keycloak
ignores the Alternative steps of a level that also has Conditional ones, so no
login form is shown at all.

**AMFA Deny** (subflow, requirement **Conditional**)
1. `Conditional - User Risk Level`: REQUIRED
   - Risk Level: `4`, Comparison: `GREATER_OR_EQUAL`
2. `Deny access` (`deny-access-authenticator`): REQUIRED

**AMFA High Risk** (subflow, requirement **Conditional**)
1. `Conditional - User Risk Level` — REQUIRED
   - Risk Level: `3`, Comparison: `GREATER_OR_EQUAL`
2. `Adaptive MFA - Email OTP` (`amfa-email`) — REQUIRED

**AMFA Medium Risk** (subflow, requirement **Conditional**)
1. `Conditional - User Risk Level` — REQUIRED
   - Risk Level: `2`, Comparison: `EQUAL`
2. `Adaptive MFA - TOTP` (`amfa-totp`) — REQUIRED

Keep the three subflows independent (do not nest them), with AMFA Deny first.
A level-4 login is refused by AMFA Deny before the email tier is reached, and
because the medium tier matches `== 2` exactly, the other tiers never overlap: a
level-3 login runs Email only, a level-2 login runs TOTP only, and a level-1
login runs neither. Also disable
Keycloak's stock "Browser - Conditional OTP/2FA" subflow so it does not add a
second, unconditional challenge.

!!! note
    `amfa-totp` sets the `CONFIGURE_TOTP` required action when a user hits the
    TOTP tier without an authenticator app enrolled, so first-time users are
    walked through enrollment before the challenge. Email OTP needs no
    per-user enrollment but does require the realm **Email theme** set to
    `keycloak-amfa` and a working SMTP server (Realm settings → Email).

To adjust the policy, change the **Risk Level** / **Comparison** on each
`Conditional - User Risk Level` execution, or add/remove tier subflows. For
example, to also step up level-2 logins to Email, set the High Risk tier's
Comparison to `GREATER_OR_EQUAL` with Risk Level `2` and drop the Medium tier.

### Contract: the engine owns the risk level, the flow only routes on it

Risk is a **discrete integer level (1-4)** everywhere on the Keycloak side. The
engine's `/decision` returns `riskLevel` as an `int`; `Adaptive Authentication`
stores it verbatim in the `adaptive-auth-risk-level` auth note; and
`Conditional - User Risk Level` reads it back with an integer parse and an
integer comparison. The flow never sees how that number was produced.

Keep it that way when you change the scoring model. Whatever the engine uses
internally (rules, clustering, a **Bayesian** posterior, or anything else) must
be collapsed to one of the discrete levels **inside the engine** before it
returns. A Bayesian model, for instance, produces a continuous posterior such
as `P(risky) = 0.87`; threshold it into a level engine-side (e.g. `<0.3` → 1,
`0.3-0.6` → 2, `0.6-0.85` → 3, `>0.85` → 4). Done this way, a model swap is a
pure engine change: the note stays an integer, the conditional subflows above
keep working unchanged, and no theme or flow edits are needed.

Do **not** return a continuous score in the `riskLevel` field. A value like
`0.87` fails to deserialize into the `int` response field, and even past that
the conditional matcher does `Integer.parseInt` with no fallback, so a
non-integer note raises a `NumberFormatException` mid-flow and breaks the login
(this matcher is not fail-open, unlike `Auth User Context Authenticator`).

Routing on the probability itself (e.g. "step up when `P(risky) > 0.75`", or
stepping up on model **uncertainty**) is possible but is a contract change, not
a config change: the engine response and the risk note must carry a separate
floating-point score, and the conditional authenticator needs a threshold
comparison mode that parses it as a `double`. Only take that on when a policy
genuinely needs the continuous value; the integer-level contract covers the
common tiered cases.

### Scoring mode: weight-based or Log-Odds Bayesian

The engine ships two interchangeable ways to turn signals into the `riskLevel`
it returns, selectable without any Keycloak-side change (the contract above
holds either way):

- **`weight`** (default) — per-parameter weighted ACR averaging.
- **`bayesian`** — a Log-Odds model. Each signal contributes evidence in
  log-odds space, summed with a calibration **bias** and passed through a
  logistic to a continuous `P(fraud)` in `[0, 1]`, which is then bucketed to
  ACR 1-4 by three ascending **thresholds**. Lower (more negative) bias is more
  trusting; higher bias is more suspicious.

**Deployment-wide** (engine env, applies to every realm unless overridden):

```bash
SCORING_MODE=bayesian
BAYESIAN_BIAS=-3.9              # e-commerce / lower-financial default
BAYESIAN_ACR_THRESHOLDS=0.3,0.6,0.85
```

**Per-realm** (overrides the env default for that realm) via the admin console:
**Realm settings → Security defenses → Adaptive MFA → Scoring**, set *Scoring
Mode*, *Bias*, and *ACR Thresholds*. Equivalent REST call (proxied by Keycloak
to the engine, so it uses the same admin token):

```bash
curl -X POST "$KEYCLOAK/realms/$REALM/amfa-api/updateScoringConfig" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"mode":"bayesian","bias":-3.5,"thresholds":[0.3,0.6,0.85]}'
# GET .../amfa-api/fetchScoringConfig returns the current config.
```

Any field left unset falls back to the engine env default. Because the model
still returns a discrete ACR, the risk-tier subflows in the previous section
route Bayesian output exactly as they route weight-based output. To see the
posterior and its bucketing in the engine log, set `LOG_LEVEL=DEBUG` (the
`Log-Odds scoring: ... p(fraud)=... -> ACR=N` line); the summary
`Bayesian scoring: p(fraud)=... => base ACR=N` line is logged at INFO.

## 7. Logins through an identity provider (SSO)

Sections 5 and 6 put AMFA in the browser flow's "forms" subflow. A user who
signs in through an identity provider (another Keycloak, Entra ID, Google and
so on) leaves the browser flow at the provider's button, and Keycloak finishes
the login in its broker flows. Without the setup below, such a login is not
risk-scored: there is no decision and no step-up, and the engine only receives
the login event.

Run AMFA after the provider's login instead. Create a top-level flow, for
example `amfa-post-broker`, with the same executions as the "forms" subflow
except Username Password Form:

1. **Screen Resolution**: REQUIRED
2. **Auth User Context Authenticator**: REQUIRED
3. **Adaptive Authentication**: REQUIRED
4. The tier subflows from section 6, each **Conditional**. Create them again
   inside this flow, with the same conditions: a subflow belongs to one flow.

Then set it as the **Post login flow** of each identity provider whose users
AMFA should score (Identity providers → *provider* → Post login flow), or:

```bash
kcadm.sh update identity-provider/instances/$IDP_ALIAS -r $REALM \
  -s postBrokerLoginFlowAlias=amfa-post-broker
```

Keycloak runs the post login flow after every login through that provider,
including a user's first, when the account is created. Every tier works there:
no step-up at risk 1, TOTP at 2 (with enrollment for users without an
authenticator app), Email OTP at 3, and a deny tier refuses the login after the
provider has accepted it. The test realm in `config/keycloak` ships the flow
as `amfa-post-broker`; bind it to your provider to try it.

!!! warning
    The post login flow is set per identity provider, and a new provider has
    none. Logins through a provider without the AMFA flow skip AMFA entirely:
    no risk score, no step-up and no deny, and nothing reports it. The engine
    still receives the LOGIN event, but no decision is made for it. Bind every
    provider, including any added later, and check the realm after changing
    its providers:

    ```bash
    kcadm.sh get identity-provider/instances -r $REALM \
      --fields alias,enabled,postBrokerLoginFlowAlias
    ```

    A provider listed without `postBrokerLoginFlowAlias` has no post login
    flow.

A provider has only one post login flow. If one of yours already has its own
(for example to set attributes after the login), do not replace it with
`amfa-post-broker`: add the executions listed above at the end of that flow
instead, so both run.

What AMFA does not see for these users:

- A wrong password at the identity provider. The attempt never reaches
  Keycloak; the provider handles it, including its own lockout.
- A wrong TOTP or email code. Keycloak emits no event for it, for local users
  either, so the engine does not learn of it. Keycloak's brute-force
  protection still counts it.

!!! note
    The engine records device data (browser, OS, screen, language) for these
    logins, and records a refused login against its user, only with a Keycloak
    plugin that carries them onto brokered login events. No plugin release
    does that yet (the latest is 1.0.1). Until one does, the login is still
    scored and stepped up, but the engine stores it without device data, and a
    refused one without its user.

## 8. Verify

```bash
# Should return 200 with the realm's parameters
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$KEYCLOAK/realms/$REALM/amfa-api/fetchAdaptiveMFAParameters"
```

| Symptom | Cause |
|---|---|
| `403 Untrusted issuer` in engine logs | Issuer base not in `OIDC_TRUSTED_BASE_URLS`, or realm `frontendUrl` not set in a split-horizon setup |
| `503 Unable to fetch OIDC discovery document` | Issuer URL not reachable from the engine container |
| `403 Invalid audience` | Audience mapper missing on `adaptive-auth-api` |
| `Client not found: adaptive-auth-api` in Keycloak logs | Step 1 skipped for this realm |
