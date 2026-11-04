"""Driving real logins for the risk-signal matrix, and reading back the verdict.

The matrix needs one thing the rest of the e2e suite does not: the ability to log a
user in with a *chosen* context, repeatedly, and to recover the engine's own
explanation of the decision it made. That is what this module provides.

Two design notes worth stating, because both are load-bearing.

**The explanation is harvested, never authored.** Each row's "why" comes from the
engine's ``[RISK WHY]`` log line, matched on the user id. Writing those strings by
hand would mean the matrix documents a belief about the code rather than the code,
and would drift the first time a message changed. This only works because the line
is emitted as a single log record; a multi-line block cannot be scraped reliably.

**A row is only meaningful once the user is trained.** Below ``MIN_AUTH_EVENTS``
completed logins the engine short-circuits to a cautious level and every row reads
identically, whatever signals were sent. ``train()`` exists to get past that, and
``assert_trained()`` to fail loudly rather than silently produce a uniform matrix.
"""

import os
import re
import subprocess
import time
import uuid

import requests

# Container names come from e2e_common so the whole e2e directory has exactly one
# definition of them. They used to be spelled out here with an "rhsso-" prefix, which
# only matched a stack started with `-p rhsso`; the compose file now declares
# `name: amfa`, and anything hardcoded would break on the next rename regardless.
from tests.e2e.e2e_common import (
    DOCKER_ENGINE,
    DOCKER_PG,
    IS_MSSQL,
    PG_DB,
    PG_USER,
    mssql_query,
)

KC_BASE = os.getenv("E2E_KC_BASE", "https://keycloak:8443")
# Defaults suit running this from the host, where the suite lives: Keycloak is
# reachable by the hostname the realm issues tokens for, Mailpit by its published
# port. The harness needs the host anyway, to read the engine's log via docker.
MAILPIT = os.getenv("E2E_MAILPIT_BASE", "http://localhost:8025")
REALM = os.getenv("E2E_REALM", "test-amfa")
ADMIN_USER = os.getenv("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("E2E_ADMIN_PASS", "admin")
ENGINE_CONTAINER = DOCKER_ENGINE
PASSWORD = "Passw0rd!"

# The context a login presents. Every field here is something a real client controls
# and at least one risk signal is derived from, so a row in the matrix is expressed
# as this dict plus the deltas applied to it.
BASELINE_CONTEXT = {
    "client": os.getenv("E2E_TEST_CLIENT", "test-login"),
    "user_agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    ),
    "screen_res": "1728x1117",
    "accept_language": "en-US,en;q=0.9",
    # A routable, clean, non-hosting address, so the baseline has a real country and
    # city and the anonymiser check has something to clear. TEST-NET ranges are
    # tempting for documentation reasons but resolve as non_public, which leaves the
    # baseline with no country at all and makes every geo row a two-signal change.
    # Verified against the bundled databases: CH / Zurich, no anonymiser labels.
    "xff": "212.51.144.1",
}


# --- Keycloak admin ---------------------------------------------------------


def admin_token() -> str:
    r = requests.post(
        f"{KC_BASE}/realms/master/protocol/openid-connect/token",
        data={
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
            "grant_type": "password",
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _admin(method: str, path: str, token: str, **kwargs):
    return requests.request(
        method,
        f"{KC_BASE}/admin/realms/{REALM}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=20,
        **kwargs,
    )


def create_user(token: str, prefix: str) -> tuple[str, str]:
    """A fresh user with an email address, so an email step-up can complete.

    Returns (username, user_id). The name carries a uuid fragment because these
    accumulate in a shared dev realm and a fixed name would collide with the row
    that ran yesterday.
    """
    username = f"{prefix}-{uuid.uuid4().hex[:8]}"
    r = _admin(
        "POST",
        "/users",
        token,
        json={
            "username": username,
            "email": f"{username}@example.com",
            "emailVerified": True,
            "firstName": "Matrix",
            "lastName": "Row",
            "enabled": True,
            "credentials": [
                {"type": "password", "value": PASSWORD, "temporary": False}
            ],
        },
    )
    r.raise_for_status()
    return username, user_id_of(token, username)


def create_public_client(token: str, client_id: str) -> str:
    """A second public client in the run realm, for the `client` signal.

    The shipped realm has exactly one usable public client, so no matrix row can vary
    the application being signed in to. Idempotent: returns the id whether or not it
    already existed, since the realm is per-run but a module may ask twice.
    """
    _admin("POST", "/clients", token, json={
        "clientId": client_id,
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "redirectUris": [f"{KC_BASE}/*", "https://keycloak:8443/*"],
        "webOrigins": ["*"],
    })
    return client_id


def user_id_of(token: str, username: str) -> str:
    r = _admin("GET", f"/users?username={username}&exact=true", token)
    r.raise_for_status()
    return r.json()[0]["id"]


def delete_user(token: str, user_id: str) -> None:
    _admin("DELETE", f"/users/{user_id}", token)


def realm_attributes(token: str) -> dict:
    r = _admin("GET", "", token)
    r.raise_for_status()
    return r.json().get("attributes", {})


def set_realm_attributes(token: str, attributes: dict) -> None:
    """Replace the realm's attribute map.

    Replace, not merge, because that is what the admin API does. Callers must pass
    the full set they want: sending a partial map silently drops the rest, and
    dropping `fallbackRisk` alone is enough to break every login in the realm.
    """
    r = _admin("PUT", "", token, json={"realm": REALM, "attributes": attributes})
    r.raise_for_status()


# --- Mailpit ---------------------------------------------------------------


def clear_mail() -> None:
    requests.delete(f"{MAILPIT}/api/v1/messages", timeout=10)


def latest_code(timeout_s: float = 20.0) -> str | None:
    """The newest numeric code in the mailbox, or None if none arrives."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = requests.get(f"{MAILPIT}/api/v1/messages", params={"limit": 10}, timeout=10)
        for message in r.json().get("messages", []):
            body = requests.get(
                f"{MAILPIT}/api/v1/message/{message['ID']}", timeout=10
            ).json()
            text = f"{body.get('Text') or ''} {body.get('HTML') or ''}"
            hit = re.search(r"\b(\d{6,8})\b", text)
            if hit:
                return hit.group(1)
        time.sleep(1.0)
    return None


# --- the login itself ------------------------------------------------------

_FORM_ID = re.compile(r'<form[^>]*\bid="([^"]+)"[^>]*\baction="([^"]+)"', re.I)
_FORM_ID_REV = re.compile(r'<form[^>]*\baction="([^"]+)"[^>]*\bid="([^"]+)"', re.I)


def _forms(html: str) -> dict:
    found = {fid: action for fid, action in _FORM_ID.findall(html)}
    found.update({fid: action for action, fid in _FORM_ID_REV.findall(html)})
    return {fid: action.replace("&amp;", "&") for fid, action in found.items()}


def _code_in(response) -> str | None:
    for source in (response.url, response.headers.get("Location", "")):
        hit = re.search(r"[?&]code=([^&]+)", source or "")
        if hit:
            return hit.group(1)
    return None


_TOTP_SECRET = re.compile(r'name="totpSecret"[^>]*value="([^"]+)"')


def totp_now(secret_raw: str, digits: int = 6, period: int = 30) -> str:
    """The current TOTP code for a raw (not base32) secret.

    Keycloak's enrolment form carries the raw secret in a hidden field while showing
    the base32 form to the user, so this takes the raw one.
    """
    import hashlib
    import hmac
    import struct

    counter = int(time.time()) // period
    mac = hmac.new(secret_raw.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def wait_for_next_totp_window(period: int = 30) -> float:
    """Block until the current TOTP window ends, and report how long that took.

    A code is single use: an authenticator that has just accepted one for enrolment
    rejects the same one for the challenge that follows seconds later. Without this
    wait, enrolling and then answering a challenge looks like a broken authenticator,
    and the login loops on a form that keeps being re-served.
    """
    now = time.time()
    remaining = period - (now % period)
    time.sleep(remaining + 0.5)
    return remaining + 0.5


class LoginResult:
    def __init__(self):
        self.ok = False
        self.steps: list[str] = []
        self.detail = ""
        # Filled when a login completes TOTP enrolment, so the caller can answer
        # future challenges for this user.
        self.totp_secret: str | None = None
        # Set by the browser driver only. Declared here rather than attached ad hoc so
        # a caller can read them unconditionally, and so the two drivers return the
        # same shape even when one of them cannot fill these in.
        self.final_url: str | None = None
        self.page_text: str | None = None
        # What the page's JavaScript actually reported, as opposed to what the HTTP
        # driver would have made up. Only a browser can fill this in.
        self.reported_screen: str | None = None
        # Whether the enrolment page actually showed its QR code. A secret a user
        # cannot scan is a broken page that still passes every functional assertion.
        self.qr_visible: bool | None = None
        # The headers the browser actually sent, as opposed to those the test asked
        # for. Only the browser driver fills this in.
        self.presented: dict | None = None

    def __repr__(self):
        return f"LoginResult(ok={self.ok}, steps={self.steps}, detail={self.detail!r})"


def login(context: dict, username: str, password: str = PASSWORD,
          email: str | None = None, new_password: str | None = None,
          bad_code: bool = False, timeout: float = 20.0,
          totp_secret: str | None = None,
          allow_totp_enrolment: bool = False) -> LoginResult:
    """One full login with the given context, completing any step-up.

    Returns once Keycloak issues an authorization code, or once the flow reaches
    something this cannot answer. Every branch is recorded in ``steps`` so a row
    that behaved unexpectedly can be read after the fact.

    ``timeout`` is per request. The default suits a healthy stack, where the slowest
    step is a few hundred milliseconds. The resilience tests raise it, because a
    Keycloak waiting on an unreachable engine holds the password POST for over two
    minutes, and a client that gives up first would look like the product hanging.
    """
    result = LoginResult()
    credentials_offered = False
    session = requests.Session()
    session.headers.update({
        "User-Agent": context["user_agent"],
        "Accept": "*/*",
        "Accept-Language": context["accept_language"],
    })
    # A context with no address sends no header at all, so Keycloak falls back to the
    # socket address. That is what lets the Chrome spot-check compare like with like:
    # a browser cannot send X-Forwarded-For, so the only way the driver can present the
    # same address is to not send one either. Sending the header with a None value
    # would raise in requests rather than omit it.
    if context.get("xff"):
        session.headers["X-Forwarded-For"] = context["xff"]

    redirect_uri = f"{KC_BASE}/e2e-callback"
    url = (
        f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/auth"
        f"?client_id={context['client']}"
        f"&redirect_uri={requests.utils.quote(redirect_uri, safe='')}"
        f"&response_type=code&scope=openid&state=m&nonce=m"
    )
    clear_mail()
    response = session.get(url, timeout=timeout, allow_redirects=True)

    for _ in range(10):
        if _code_in(response):
            result.ok = True
            result.detail = "authorization code issued"
            return result

        forms = _forms(response.text)

        if "screenResForm" in forms:
            result.steps.append("screenRes")
            response = session.post(
                forms["screenResForm"],
                data={"screenRes": context["screen_res"]},
                timeout=timeout,
            )
            continue

        if "kc-form-login" in forms:
            # A second sight of this form means the first submission was rejected.
            # Stopping here rather than resubmitting: the loop used to re-post the
            # same wrong password until the step budget ran out, so one call with a
            # bad password generated nine rejections instead of one. Measured: five
            # calls produced 45 LOGIN_ERROR events.
            if credentials_offered:
                result.steps.append("password-rejected")
                result.detail = "credentials rejected"
                return result
            credentials_offered = True
            result.steps.append("password")
            response = session.post(
                forms["kc-form-login"],
                data={"username": username, "password": password, "credentialId": ""},
                timeout=timeout,
            )
            continue

        if "kc-email-code-login-form" in forms:
            if bad_code:
                # A deliberate step-up failure, which is how a row can produce a
                # LOGIN_ERROR that the engine attaches to its open auth process.
                result.steps.append("email-otp-wrong")
                session.post(
                    forms["kc-email-code-login-form"], data={"code": "000000"},
                    timeout=timeout,
                )
                result.detail = "step-up failed deliberately"
                return result

            code = latest_code()
            result.steps.append("email-otp" if code else "email-otp-missing")
            if not code:
                result.detail = "no email code arrived"
                return result
            response = session.post(
                forms["kc-email-code-login-form"], data={"code": code},
                timeout=timeout,
            )
            continue

        if "kc-passwd-update-form" in forms:
            # Only reached when a row's choreography sets the UPDATE_PASSWORD required
            # action. Keycloak emits the UPDATE_PASSWORD event on submission, which is
            # what the engine's recent_account_change signal ultimately reads.
            result.steps.append("update-password")
            response = session.post(
                forms["kc-passwd-update-form"],
                data={
                    "password-new": new_password or PASSWORD,
                    "password-confirm": new_password or PASSWORD,
                },
                timeout=timeout,
            )
            continue

        if "kc-update-profile-form" in forms:
            result.steps.append("update-profile")
            response = session.post(
                forms["kc-update-profile-form"],
                data={
                    "email": email or f"{username}@example.com",
                    "firstName": "Matrix",
                    "lastName": "Row",
                },
                timeout=timeout,
            )
            continue

        # Enrolment, either because the CONFIGURE_TOTP required action is set or
        # because the realm's Risk 2 branch offers it to a user with no authenticator.
        # Checked before the challenge branch below, because "kc-totp-settings-form"
        # also contains the substring "otp" and would be mistaken for a challenge.
        #
        # Off by default, and that is deliberate. Answering it changes the user's
        # credentials mid-run, so a matrix row would stop being independent of the
        # rows before it, and every Risk 2 row would complete by enrolling rather than
        # recording what a user without an authenticator experiences. Only the tests
        # that are specifically about enrolment switch it on.
        if "kc-totp-settings-form" in forms and allow_totp_enrolment:
            found = _TOTP_SECRET.search(response.text)
            if not found:
                result.steps.append("totp-enrol-unreadable")
                result.detail = "the enrolment form carried no totpSecret field"
                return result
            secret = found.group(1)
            result.totp_secret = secret
            result.steps.append("totp-enrol")
            response = session.post(
                forms["kc-totp-settings-form"],
                data={
                    "totp": totp_now(secret),
                    "totpSecret": secret,
                    "userLabel": "e2e",
                },
                timeout=timeout,
            )
            continue

        # A TOTP challenge, answerable only by a user who has enrolled.
        if any("otp" in fid.lower() for fid in forms):
            if totp_secret:
                result.steps.append("totp")
                form_id = next(fid for fid in forms if "otp" in fid.lower())
                response = session.post(
                    forms[form_id],
                    data={"otp": totp_now(totp_secret)},
                    timeout=timeout,
                )
                continue
            result.steps.append("totp-required")
            result.detail = "TOTP step-up requested; user has no enrolled authenticator"
            return result

        result.detail = (
            f"stopped at {sorted(forms) or 'no form'} (HTTP {response.status_code})"
        )
        return result

    result.detail = "flow did not settle within the step budget"
    return result


# --- reading the verdict back ---------------------------------------------

_WHY = re.compile(
    r"\[RISK WHY\] user=(?P<user>[0-9a-f-]+) realm=(?P<realm>\S+) "
    r"scoring=(?P<mode>\S+) => final Risk (?P<risk>\d+) because: (?P<why>.*)$"
)


def engine_log_lines() -> list[str]:
    out = subprocess.run(
        ["docker", "logs", ENGINE_CONTAINER],
        capture_output=True, text=True, timeout=60,
    )
    return (out.stdout + out.stderr).splitlines()


_CREDIBILITY = re.compile(
    r"Computed credibility\. Device: ([0-9.]+) - Network Location: ([0-9.]+)"
)


def credibility_since(mark: int) -> tuple[float, float] | None:
    """The device and network credibility the engine computed, from its own log.

    Read from the log rather than from the explanation because the explanation only
    mentions familiarity when the adjustment actually moves the level. In the middle
    band it says nothing at all, so a test that parsed the message could not observe
    the value it most needs.
    """
    for line in reversed(engine_log_lines()[mark:]):
        found = _CREDIBILITY.search(line)
        if found:
            return float(found.group(1)), float(found.group(2))
    return None


def log_mark() -> int:
    """How many engine log lines exist now, so a later read can start after them."""
    return len(engine_log_lines())


def last_verdict(user_id: str, since: int) -> dict | None:
    """The engine's own explanation of its most recent decision for this user.

    Matched on the user id rather than position, because the engine runs several
    workers and interleaves their output.
    """
    for line in reversed(engine_log_lines()[since:]):
        hit = _WHY.search(line)
        if hit and hit.group("user") == user_id:
            return {
                "risk": int(hit.group("risk")),
                "mode": hit.group("mode"),
                "why": hit.group("why").strip(),
            }
    return None


# --- training --------------------------------------------------------------


def completed_logins(user_id: str) -> int:
    """LOGIN rows for the user, which is what the history gate counts."""
    raw = psql(
        f"select count(*) from auth_process where user_id='{user_id}' "
        f"and final_status='LOGIN';"
    )
    try:
        return int(raw.splitlines()[0])
    except (ValueError, IndexError):
        return -1


def train(context: dict, username: str, user_id: str, target: int = 5) -> list[dict]:
    """Log in repeatedly with an unchanged context until the profile is established.

    Returns the verdict of each login, so a caller can see the level walking down as
    history accumulates. Identical context every time is the point: it is what makes
    the later single-signal deltas attributable to the signal that changed.
    """
    history = []
    for attempt in range(target):
        since = log_mark()
        outcome = login(context, username)
        verdict = last_verdict(user_id, since) or {}
        history.append({
            "attempt": attempt + 1,
            "ok": outcome.ok,
            "steps": outcome.steps,
            "risk": verdict.get("risk"),
            "mode": verdict.get("mode"),
            "why": verdict.get("why", ""),
            "logins_on_record": completed_logins(user_id),
        })
        if not outcome.ok:
            history[-1]["detail"] = outcome.detail
            break
    return history


# --- profile cloning -------------------------------------------------------

def psql(sql: str) -> str:
    if IS_MSSQL:
        return mssql_query(sql)
    out = subprocess.run(
        ["docker", "exec", "-e", "PGPASSWORD=password", DOCKER_PG,
         "psql", "-U", PG_USER, "-d", PG_DB, "-t", "-A", "-c", sql],
        capture_output=True, text=True, timeout=60,
    )
    return (out.stdout.strip() or out.stderr.strip())


def stored_device_hash(user_id: str) -> str:
    """The device hash the engine computed for a user's most recent login."""
    return _latest_login_column("device_info_hash", user_id).strip()


def _latest_login_column(column: str, user_id: str) -> str:
    where = f"from auth_process where user_id='{user_id}' order by started_at desc"
    if IS_MSSQL:
        return psql(f"select top 1 {column} {where};")
    return psql(f"select {column} {where} limit 1;")


def stored_auth_context(user_id: str) -> dict:
    """The context the engine recorded for a user's most recent login.

    Used to compare the two drivers on what was actually presented rather than on what
    a test intended: a browser derives its own Accept-Language and sends headers the
    HTTP driver does not, so "the same context" has to mean the one the engine saw.
    """
    import json

    column = "auth_context_json" if IS_MSSQL else "auth_context_json::text"
    raw = _latest_login_column(column, user_id)
    try:
        return json.loads(raw.strip())
    except (ValueError, AttributeError):
        return {}


def clone_profile(golden_id: str, user_id: str, days_ago_of_oldest: int = 8,
                  hour_shift: int = 0, prior_decision: int = 1,
                  rows_to_copy: int | None = None) -> str:
    """Give ``user_id`` a trained profile copied from ``golden_id``.

    Copies the completed logins and rewrites when they happened, one per day ending
    yesterday. Two details make this work where a naive copy does not.

    The rows are the ones real logins produced, so every context hash is whatever the
    factories actually compute. Nothing is synthesised and nothing can drift.

    The timestamp is rewritten *inside* ``auth_context_json``, not only in
    ``started_at``. ``df_user`` is assembled from that JSON, so its embedded
    ``event_time`` is the only clock the time-based signals ever see. Copying a row
    verbatim reproduces the original burst of logins in a single minute, which reads
    as an unusual hour and an irregular gap on every row.

    ``hour_shift`` moves the whole history by N hours, which is how the ``date_time``
    row makes the current hour look unusual without touching anything else.

    ``rows_to_copy`` copies only the oldest N logins, which is how the history-gate
    boundary is reached: the gate counts completed logins, so landing exactly on and
    one below ``MIN_AUTH_EVENTS`` needs control of how many exist.

    ``prior_decision`` rewrites what the copied logins were scored, and defaults to 1
    for a reason that is not obvious. The engine relaxes a clean login one step below
    the previous decision, so history recorded at Risk 3 makes a clean login come out
    at Risk 2. In the shipped realm Risk 2 demands TOTP while Risk 3 accepts an email
    code, so a user with an email address and no authenticator can complete a Risk 3
    login but not a Risk 2 one. Copying the training logins verbatim therefore produces
    a baseline that cannot log in at all. Recording the history as low risk is both the
    fix and an accurate description of the profile being modelled: a user whose recent
    logins were unremarkable.
    """
    if IS_MSSQL:
        return _clone_profile_mssql(
            golden_id, user_id, days_ago_of_oldest, hour_shift, prior_decision, rows_to_copy
        )
    return psql(f"""
    with src as (
        select *, row_number() over (order by started_at) as n
        from auth_process
        where user_id = '{golden_id}' and final_status = 'LOGIN'
        order by started_at
        {"limit " + str(rows_to_copy) if rows_to_copy is not None else ""}
    )
    insert into auth_process (
        id, user_id, auth_context_hash, device_info_hash, network_location_hash,
        auth_context_json, pre_auth_risk_decision, parameters_config_id, final_status,
        started_at, finished_at, risk_eval_vars, net_loc_credibility,
        device_credibility, realm_id)
    select uuid_generate_v4(), '{user_id}', auth_context_hash, device_info_hash,
        network_location_hash,
        jsonb_set(
            auth_context_json::jsonb, '{{event_time}}',
            to_jsonb(extract(epoch from (
                now() - (({days_ago_of_oldest} - n) || ' days')::interval
                      - ('{hour_shift} hours')::interval
            )) * 1000)
        )::json,
        {prior_decision}, parameters_config_id, final_status,
        now() - (({days_ago_of_oldest} - n) || ' days')::interval,
        now() - (({days_ago_of_oldest} - n) || ' days')::interval + interval '4 seconds',
        risk_eval_vars, net_loc_credibility, device_credibility, realm_id
    from src;
    """)


def _clone_profile_mssql(golden_id: str, user_id: str, days_ago_of_oldest: int,
                         hour_shift: int, prior_decision: int,
                         rows_to_copy: int | None) -> str:
    """`clone_profile` in T-SQL, which has no `jsonb_set` or interval arithmetic."""
    top = f"top ({rows_to_copy})" if rows_to_copy is not None else ""
    order = "order by started_at" if rows_to_copy is not None else ""
    happened = f"dateadd(day, n - {days_ago_of_oldest}, sysutcdatetime())"
    return psql(f"""
    with src as (
        select {top} *, row_number() over (order by started_at) as n
        from auth_process
        where user_id = '{golden_id}' and final_status = 'LOGIN'
        {order}
    )
    insert into auth_process (
        id, user_id, auth_context_hash, device_info_hash, network_location_hash,
        auth_context_json, pre_auth_risk_decision, parameters_config_id, final_status,
        started_at, finished_at, risk_eval_vars, net_loc_credibility,
        device_credibility, realm_id)
    select newid(), '{user_id}', auth_context_hash, device_info_hash,
        network_location_hash,
        json_modify(
            auth_context_json, '$.event_time',
            datediff_big(millisecond, '1970-01-01', dateadd(hour, -{hour_shift}, {happened}))
        ),
        {prior_decision}, parameters_config_id, final_status,
        {happened},
        dateadd(second, 4, {happened}),
        risk_eval_vars, net_loc_credibility, device_credibility, realm_id
    from src;
    """)


def login_with_fixed_code(context: dict, username: str, code: str) -> LoginResult:
    """A login that answers the emailed-code form with a code chosen by the caller.

    Exists for the replay test: `login` fetches whichever code arrives, which is the
    right behaviour everywhere else and precisely wrong for asking whether an already
    spent code is accepted a second time.
    """
    result = LoginResult()
    session = requests.Session()
    session.headers.update({
        "User-Agent": context["user_agent"],
        "Accept": "*/*",
        "Accept-Language": context["accept_language"],
    })
    if context.get("xff"):
        session.headers["X-Forwarded-For"] = context["xff"]

    url = (
        f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/auth"
        f"?client_id={context['client']}"
        f"&redirect_uri={requests.utils.quote(f'{KC_BASE}/e2e-callback', safe='')}"
        f"&response_type=code&scope=openid&state=m&nonce=m"
    )
    response = session.get(url, timeout=20, allow_redirects=True)

    for _ in range(10):
        if _code_in(response):
            result.ok = True
            result.detail = "authorization code issued"
            return result
        forms = _forms(response.text)
        if "screenResForm" in forms:
            result.steps.append("screenRes")
            response = session.post(forms["screenResForm"],
                                    data={"screenRes": context["screen_res"]}, timeout=20)
            continue
        if "kc-form-login" in forms:
            result.steps.append("password")
            response = session.post(
                forms["kc-form-login"],
                data={"username": username, "password": PASSWORD, "credentialId": ""},
                timeout=20)
            continue
        if "kc-email-code-login-form" in forms:
            result.steps.append("email-otp-replayed")
            response = session.post(forms["kc-email-code-login-form"],
                                    data={"code": code}, timeout=20)
            # One attempt only: the question is whether the spent code works, and
            # looping would answer a different one.
            if _code_in(response):
                result.ok = True
                result.detail = "the replayed code was accepted"
            else:
                result.detail = "the replayed code was rejected"
            return result
        result.detail = f"stopped at {sorted(forms) or 'no form'}"
        return result

    result.detail = "flow did not settle"
    return result


def enrol_totp(token: str, username: str, user_id: str) -> str:
    """Enrol an authenticator for a user and return its secret.

    The TOTP tier is the one factor the suite could never complete, so every row that
    reached Risk 2 stopped there. Driven the way a real user does it: the
    CONFIGURE_TOTP required action is set, the next login is presented with the
    enrolment form, and the secret it carries is used to answer immediately.
    """
    _admin("PUT", f"/users/{user_id}", token,
           json={"requiredActions": ["CONFIGURE_TOTP"]}).raise_for_status()

    outcome = login(BASELINE_CONTEXT, username, allow_totp_enrolment=True)
    if not outcome.totp_secret:
        raise AssertionError(
            f"could not enrol an authenticator: steps={outcome.steps}, "
            f"detail={outcome.detail}"
        )
    return outcome.totp_secret


def run_row(token: str, golden_id: str, row_id: str, delta: dict,
            hour_shift: int = 0, days_ago_of_oldest: int = 8,
            before=None, clone: bool = True, prior_decision: int = 1,
            rows_to_copy: int | None = None) -> dict:
    """One matrix row: a fresh trained user, one login, one harvested verdict.

    ``delta`` overrides fields of BASELINE_CONTEXT, so a row states only what it
    changes. ``before`` is an optional callable(token, username, user_id) for rows
    that need something to happen first, such as failed logins or a password change.

    A `before` may return a dict to change how the row's own login is driven, which
    the password-change choreography needs: it leaves the account on a new password,
    so the row login has to use it. It may also return `facts`, recorded in the
    artifact so the choreography's own outcome is visible rather than assumed.
    """
    username, user_id = create_user(token, f"mx-{row_id.lower()}")
    if clone:
        clone_profile(golden_id, user_id, days_ago_of_oldest, hour_shift,
                      prior_decision=prior_decision, rows_to_copy=rows_to_copy)

    prepared = (before(token, username, user_id) or {}) if before else {}

    context = {**BASELINE_CONTEXT, **delta}
    since = log_mark()
    outcome = login(context, username, password=prepared.get("password", PASSWORD))
    verdict = last_verdict(user_id, since) or {}

    return {
        "row": row_id,
        "choreography": prepared.get("facts"),
        "delta": ", ".join(f"{k}={v}" for k, v in delta.items()) or "(baseline)",
        "risk": verdict.get("risk"),
        "mode": verdict.get("mode"),
        "why": verdict.get("why", ""),
        "login_ok": outcome.ok,
        "steps": ",".join(outcome.steps),
        "user_id": user_id,
        "username": username,
        "context": context,
    }
