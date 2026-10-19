"""Shared helpers for the AMFA end-to-end suite.

These talk to a RUNNING stack (Keycloak + engine + redis + postgres + Mailpit),
so they are integration helpers, not unit-test fixtures. Everything is
configurable via environment variables (see the DEFAULTS below) so the suite can
point at a different deployment without code changes.

Nothing here mutates persistent realm/user configuration; scenarios only perform
logins and read-only lookups.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
import subprocess
import time
from html import unescape

import requests

# --- configuration (env-overridable) ----------------------------------------

KC_BASE = os.getenv("E2E_KC_BASE", "https://keycloak:8443")
ENGINE_BASE = os.getenv("E2E_ENGINE_BASE", "http://localhost:8095")
MAILPIT_BASE = os.getenv("E2E_MAILPIT_BASE", "http://localhost:8025")
REALM = os.getenv("E2E_REALM", "test-amfa")
ADMIN_USER = os.getenv("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("E2E_ADMIN_PASS", "admin")
TEST_CLIENT = os.getenv("E2E_TEST_CLIENT", "test-login")
REDIRECT_URI = os.getenv("E2E_REDIRECT_URI", f"{KC_BASE}/e2e-callback")
ENGINE_CLIENT = os.getenv("E2E_ENGINE_CLIENT", "adaptive-auth-api")
TEST_USER = os.getenv("E2E_USER", "alice")
TEST_PASS = os.getenv("E2E_PASS", "Passw0rd!")
# Optional: alice's raw TOTP secret, so the TOTP step-up tier can also be
# completed automatically. Unset -> the email tier is used for completion.
TOTP_SECRET = os.getenv("E2E_TOTP_SECRET") or None

# Docker container names for the best-effort log/DB/redis assertions (optional).
# Compose names its containers "<project>-<service>-<n>". The project is declared as
# `name: amfa` in config/keycloak/docker-compose.yml, so these follow from it.
#
# They were previously hardcoded with a "keycloak-" prefix, which matched the project
# only when the stack happened to be started from inside config/keycloak, since Compose
# derived the name from the directory. Started any other way the names were wrong, and
# every docker-backed helper then failed silently: redis_set could not seed a key and
# engine_log_since read nothing. Nothing reported an error, so a scenario whose fixture
# never landed reported a failed *product* assertion instead. Declaring the project
# removes the ambiguity; deriving these from one variable keeps a rename to one edit.
COMPOSE_PROJECT = os.getenv("E2E_COMPOSE_PROJECT", "amfa")
DOCKER_ENGINE = os.getenv("E2E_DOCKER_ENGINE", f"{COMPOSE_PROJECT}-adaptive_auth-1")
DOCKER_PG = os.getenv("E2E_DOCKER_PG", f"{COMPOSE_PROJECT}-postgres-1")
DOCKER_REDIS = os.getenv("E2E_DOCKER_REDIS", f"{COMPOSE_PROJECT}-redis-1")
DOCKER_KEYCLOAK = os.getenv("E2E_DOCKER_KEYCLOAK", f"{COMPOSE_PROJECT}-keycloak-1")
DOCKER_MAILPIT = os.getenv("E2E_DOCKER_MAILPIT", f"{COMPOSE_PROJECT}-mailpit-1")
PG_DB = os.getenv("E2E_PG_DB", "adaptive_mfa")
PG_USER = os.getenv("E2E_PG_USER", "keycloak")

# The form action URLs Keycloak renders use its configured hostname, which in the
# bundled compose stack is the internal "keycloak:8443" (TLS terminated at
# Keycloak itself; see docs/keycloak-setup.md). The 8080/plain-HTTP variants are
# kept for older or differently-configured stacks. Rewrite to the externally
# reachable base so curl/requests from the host can post back.
_INTERNAL_HOSTS = (
    "http://keycloak:8080",
    "https://keycloak:8080",
    "http://keycloak:8443",
    "https://keycloak:8443",
)


def _external(url: str) -> str:
    for h in _INTERNAL_HOSTS:
        url = url.replace(h, KC_BASE)
    return url


def _send(session: requests.Session, method: str, url: str, **kwargs):
    """Issue a request, sending the session jar's cookies as an explicit header.

    Python's http.cookiejar mishandles cookies for the dotless host "localhost"
    (it stores them but declines to attach them at send time), so Keycloak would
    see no session and reject the login POST with HTTP 400. Building the Cookie
    header from the jar ourselves sidesteps that; responses still update the jar
    normally, so multi-step flows keep working.
    """
    cookie_header = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
    headers = dict(kwargs.pop("headers", {}) or {})
    if cookie_header:
        headers["Cookie"] = cookie_header
    kwargs.setdefault("timeout", 15)
    return session.request(method, url, headers=headers, **kwargs)


# --- Keycloak admin / tokens -------------------------------------------------


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


def client_secret(client_id: str, admin_tok: str | None = None) -> str:
    admin_tok = admin_tok or admin_token()
    r = requests.get(
        f"{KC_BASE}/admin/realms/{REALM}/clients",
        params={"clientId": client_id},
        headers={"Authorization": f"Bearer {admin_tok}"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()[0]["secret"]


def user_id(username: str, admin_tok: str | None = None) -> str | None:
    admin_tok = admin_tok or admin_token()
    r = requests.get(
        f"{KC_BASE}/admin/realms/{REALM}/users",
        params={"username": username, "exact": "true"},
        headers={"Authorization": f"Bearer {admin_tok}"},
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    return data[0]["id"] if data else None


def engine_sa_token(secret: str | None = None) -> str:
    """Client-credentials token for the adaptive-auth-api client (aud=amfa)."""
    secret = secret or client_secret(ENGINE_CLIENT)
    r = requests.post(
        f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "client_id": ENGINE_CLIENT,
            "client_secret": secret,
            "grant_type": "client_credentials",
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


# --- engine API (direct /auth_context + /decision) ---------------------------


def engine_auth_context(token: str, ctx: dict) -> requests.Response:
    return requests.post(
        f"{ENGINE_BASE}/auth_context",
        json=ctx,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )


def engine_decision(token: str, req: dict) -> requests.Response:
    return requests.post(
        f"{ENGINE_BASE}/decision",
        json=req,
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )


# --- Mailpit (email OTP) -----------------------------------------------------


def _created_epoch(created: str) -> float:
    # Mailpit "Created" is ISO-8601, e.g. "2026-07-27T07:37:30Z".
    try:
        from datetime import datetime

        return datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def mailpit_latest_code(to_contains: str = "", since_epoch: float = 0.0) -> str | None:
    """Return the newest 6-8 digit code from Mailpit, filtered by recipient and
    ignoring messages older than ``since_epoch`` (rejects stale codes from a
    previous run so the OTP we submit is the one this login triggered)."""
    r = requests.get(f"{MAILPIT_BASE}/api/v1/messages", params={"limit": 10}, timeout=15)
    r.raise_for_status()
    for m in r.json().get("messages", []):
        if to_contains and not any(
            to_contains in (a.get("Address") or "") for a in m.get("To", [])
        ):
            continue
        if since_epoch and _created_epoch(m.get("Created", "")) + 2 < since_epoch:
            continue
        body = requests.get(
            f"{MAILPIT_BASE}/api/v1/message/{m['ID']}", timeout=15
        ).json()
        text = (body.get("Text") or "") + " " + re.sub(
            r"<[^>]+>", " ", body.get("HTML") or ""
        )
        codes = re.findall(r"\b(\d{6,8})\b", text)
        if codes:
            return codes[0]
    return None


# --- TOTP (authenticator-app OTP) --------------------------------------------


def totp_now(secret_raw: str, digits: int = 6, period: int = 30) -> str:
    """RFC-6238 TOTP. AMFA stores the secret as a RAW string, so the HMAC key is
    the raw UTF-8 bytes (NOT base32-decoded)."""
    counter = int(time.time()) // period
    mac = hmac.new(secret_raw.encode(), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


# --- Keycloak browser-flow login driver --------------------------------------

_FORM_RE = re.compile(r'<form[^>]*id="([^"]+)"[^>]*action="([^"]+)"', re.I)


def _forms(html: str):
    return [(fid, unescape(action)) for fid, action in _FORM_RE.findall(html)]


def _has_code(resp: requests.Response) -> str | None:
    for r in list(resp.history) + [resp]:
        loc = r.headers.get("location", "")
        m = re.search(r"[?&]code=([^&]+)", loc)
        if m:
            return m.group(1)
    m = re.search(r"[?&]code=([^&]+)", resp.url or "")
    return m.group(1) if m else None


def kc_login(
    username: str,
    password: str,
    user_agent: str = "curl/8.7.1",
    screen_res: str = "1920x1080",
    accept_language: str = "",
    totp_secret: str | None = None,
    email_recipient: str = "",
):
    """Drive a full browser-flow login through the AMFA authentication flow.

    Walks the rendered pages step by step: screen-resolution capture, then
    username/password, then whatever risk-based step-up the engine's decision
    triggers (email OTP or TOTP). Returns a dict describing the outcome:

        {"ok": bool, "step_up": "none"|"email"|"totp", "code": str|None,
         "steps": [...form ids...], "detail": str}

    ``ok`` is True once Keycloak issues an authorization code (login complete).
    """
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
    if accept_language:
        s.headers["Accept-Language"] = accept_language
    start = time.time()

    authorize = (
        f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/auth"
        f"?client_id={TEST_CLIENT}&redirect_uri={requests.utils.quote(REDIRECT_URI, safe='')}"
        f"&response_type=code&scope=openid&state=e2e&nonce=e2e"
    )
    resp = _send(s, "GET", authorize)
    step_up = "none"
    steps: list[str] = []
    pw_submitted = False

    for _ in range(8):
        code = _has_code(resp)
        if code:
            return {"ok": True, "step_up": step_up, "code": code, "steps": steps,
                    "detail": "authorization code issued"}

        html = resp.text
        forms = _forms(html)
        fids = [f[0] for f in forms]

        if "screenResForm" in fids:
            action = _external(dict(forms)["screenResForm"])
            steps.append("screenRes")
            resp = _send(s, "POST", action, data={"screenRes": screen_res})
            continue

        if "kc-form-login" in fids:
            # If the login form re-renders after we already submitted, the
            # credentials were rejected (Keycloak re-shows the form with an error).
            if pw_submitted:
                err = re.search(
                    r'class="[^"]*(?:kc-feedback|alert-error|pf-m-error)[^"]*"[^>]*>(.*?)</',
                    html, re.S,
                )
                msg = re.sub(r"<[^>]+>", "", err.group(1)).strip() if err else "invalid credentials"
                return {"ok": False, "step_up": step_up, "code": None, "steps": steps,
                        "detail": f"login rejected: {msg[:120]}"}
            action = _external(dict(forms)["kc-form-login"])
            steps.append("password")
            pw_submitted = True
            resp = _send(
                s, "POST", action,
                data={"username": username, "password": password, "credentialId": ""},
            )
            continue

        if "kc-email-code-login-form" in fids:
            step_up = "email"
            action = _external(dict(forms)["kc-email-code-login-form"])
            steps.append("email-otp")
            code = None
            for _try in range(10):
                code = mailpit_latest_code(email_recipient, since_epoch=start)
                if code:
                    break
                time.sleep(1)
            if not code:
                return {"ok": False, "step_up": step_up, "code": None, "steps": steps,
                        "detail": "email OTP not received via Mailpit"}
            resp = _send(s, "POST", action, data={"code": code})
            continue

        # TOTP form: Keycloak's default id is kc-otp-login-form (input name "otp").
        totp_form = next((f for f in forms if "otp" in f[0].lower()), None)
        if totp_form or 'name="otp"' in html:
            step_up = "totp"
            action = _external(totp_form[1] if totp_form else forms[0][1])
            steps.append("totp")
            if not totp_secret:
                return {"ok": False, "step_up": step_up, "code": None, "steps": steps,
                        "detail": "TOTP step-up required but no totp_secret provided"}
            resp = _send(s, "POST", action, data={"otp": totp_now(totp_secret)})
            continue

        # No known form and no code: surface any visible error message.
        err = re.search(
            r'class="[^"]*(?:kc-feedback|alert-error|pf-m-error)[^"]*"[^>]*>(.*?)</',
            html, re.S,
        )
        msg = re.sub(r"<[^>]+>", "", err.group(1)).strip() if err else "unknown page"
        return {"ok": False, "step_up": step_up, "code": None, "steps": steps,
                "detail": f"stopped: {msg[:160]}"}

    return {"ok": False, "step_up": step_up, "code": None, "steps": steps,
            "detail": "exceeded step budget"}


def ensure_login_history(username: str, password: str, uid: str, min_events: int = 4) -> int:
    """Top up ``uid``'s successful-login count to at least ``min_events`` real,
    completed browser logins.

    The engine's history-gate returns a canned Risk 3 (and skips every other
    signal check, including recent_account_change) for any user below
    MIN_AUTH_EVENTS (default 4) — see decision.py's early-return branch. A
    scenario that seeds a signal and expects to observe it firing must first
    get the target user past that gate, or the check under test never runs at
    all and a "did not fire" result is meaningless.

    Building this via repeated real logins (rather than crafting auth_process
    rows directly) keeps the fixture honest: every row is a genuine completed
    login, scored and finalized by the real product path, the same way
    sc_login_stepup_and_complete's single login already is.

    Returns the number of logins actually performed (0 if already enough).
    Raises if a login needed to build history does not complete.
    """
    have = db_scalar(
        f"select count(*) from auth_process where user_id='{uid}' and final_status='LOGIN'"
    )
    have = int(have) if have is not None else 0
    needed = max(0, min_events - have)
    for _ in range(needed):
        wait_for_decision_slot(uid)  # each login spends one of the user's /decision calls
        res = kc_login(username, password, email_recipient=username)
        if not res["ok"]:
            raise RuntimeError(f"could not build login history: {res['detail']}")
    return needed


# --- best-effort stack introspection (docker) --------------------------------


def docker_available() -> bool:
    return _docker("version", "--format", "{{.Server.Version}}") is not None


def _docker(*args: str) -> str | None:
    try:
        out = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=20
        )
        # Merge stdout+stderr: `docker logs` sends the container's stderr stream
        # (where Python's logging writes by default) to the CLI's stderr, so
        # capturing stdout alone would miss every app log line.
        return (out.stdout + out.stderr) if out.returncode == 0 else None
    except (FileNotFoundError, subprocess.SubprocessError):
        return None


def _engine_logs_chronological() -> str | None:
    """docker logs with stderr merged INTO stdout at the OS level, so lines stay
    in real chronological order. (uvicorn access logs go to stdout, app logs to
    stderr; capturing them separately and concatenating would interleave them
    wrongly and break line-offset slicing.)"""
    try:
        out = subprocess.run(
            ["docker", "logs", DOCKER_ENGINE],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20,
        )
        return out.stdout if out.returncode == 0 else None
    except Exception:
        return None


def engine_log_line_count() -> int | None:
    out = _engine_logs_chronological()
    return len(out.splitlines()) if out is not None else None


def engine_log_since(base_lines: int) -> str:
    out = _engine_logs_chronological()
    if out is None:
        return ""
    return "\n".join(out.splitlines()[base_lines:])


def db_scalar(sql: str) -> str | None:
    out = _docker("exec", DOCKER_PG, "psql", "-U", PG_USER, "-d", PG_DB, "-tAc", sql)
    return out.strip() if out is not None else None


def redis_set(key: str, value: str = "1", ttl: int = 3600) -> bool:
    """Seed a key in the engine's redis (used to inject a cached event).

    True only when redis answers OK: redis-cli exits 0 even when redis refuses
    the command (NOAUTH from a password-protected redis without REDISCLI_AUTH,
    say), so a successful docker exec alone does not mean the key landed.
    """
    out = _docker("exec", DOCKER_REDIS, "redis-cli", "set", key, value, "EX", str(ttl))
    return out is not None and out.strip() == "OK"


def redis_del_pattern(pattern: str) -> None:
    _docker(
        "exec", DOCKER_REDIS, "sh", "-c",
        f"redis-cli --scan --pattern '{pattern}' | xargs -r redis-cli del",
    )


# --- pacing against the engine's rate limits ----------------------------------


def _engine_rate_limit() -> tuple[int, float]:
    """The engine's per-user /decision limit as (max requests, window seconds),
    read from the engine container, or the engine's defaults if it can't be."""
    out = _docker("exec", DOCKER_ENGINE, "printenv") or ""
    env = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    try:
        return int(env.get("RATE_LIMIT_MAX_REQ", 4)), float(env.get("RATE_LIMIT_TIME_WINDOW", 60))
    except ValueError:
        return 4, 60.0


_pacing_warned = False


def _warn_no_pacing(answer) -> None:
    """Say once that the suite cannot pace to the rate limit, so later 429s are
    not a mystery."""
    global _pacing_warned
    if _pacing_warned:
        return
    _pacing_warned = True
    if answer:
        why = " ".join(answer)[:80].rstrip(".") + ". A password-protected redis needs REDISCLI_AUTH set on that container"
    else:
        why = "docker exec failed"
    print(f"  ! cannot read the engine's rate limit from {DOCKER_REDIS} ({why}); "
          "not pacing, so calls may get HTTP 429.")


# The longest wait_for_rate_limit_slot sleeps for one slot, in seconds.
_MAX_RATE_LIMIT_WAIT = 120


def wait_for_rate_limit_slot(bucket: str, identity: str, realm: str = REALM) -> float:
    """Wait until the engine would accept one more call in ``bucket`` from
    ``identity``.

    The engine allows RATE_LIMIT_MAX_REQ calls per RATE_LIMIT_TIME_WINDOW
    seconds for each (bucket, realm, identity): ``decision`` per user, for
    /decision, and ``config`` per caller, for the settings and scoring writes.
    The scenarios here log in as one user and change settings as one service
    account, so by the later ones a window can be full and their own call would
    get a 429 that says nothing about what they check. This paces the suite to
    the limit instead of weakening it: it only reads the limiter's sorted set
    (the ``rl:<bucket>:<realm>:<identity>`` key and scores the engine writes)
    and sleeps until the oldest call in the window ages out. It never changes
    the limiter's state. Returns the seconds waited; gives up after one window
    (at most _MAX_RATE_LIMIT_WAIT) plus a margin and lets the call go ahead, so
    a stuck or very long limit shows up as the 429 it is rather than a hang.
    """
    max_req, window = _engine_rate_limit()
    key = f"rl:{bucket}:{realm}:{identity}"
    # A window longer than this is not one a test run can wait out; the call
    # then goes ahead and its 429 says so.
    max_wait = min(window, _MAX_RATE_LIMIT_WAIT) + 10
    waited = 0.0
    while waited <= max_wait:
        # The engine scores entries with its own clock, so compare against the
        # clock of the same Docker host via redis TIME, not this runner's.
        # Anything unreadable (no docker, a redis that refuses redis-cli)
        # means no pacing, not a crash: the call goes ahead as before.
        t = (_docker("exec", DOCKER_REDIS, "redis-cli", "TIME") or "").split()
        try:
            now = int(t[0]) + int(t[1]) / 1e6
        except (IndexError, ValueError):
            _warn_no_pacing(t)
            return waited
        out = _docker("exec", DOCKER_REDIS, "redis-cli", "ZRANGEBYSCORE", key,
                      f"({now - window}", "+inf", "WITHSCORES")
        try:
            scores = [float(v) for v in (out or "").split()[1::2]]
        except ValueError:
            _warn_no_pacing(out.split())
            return waited
        if out is None:
            _warn_no_pacing(None)
            return waited
        if len(scores) < max_req:
            return waited
        pause = min(max(min(scores) + window - now, 0) + 0.5, max_wait - waited + 0.5)
        time.sleep(pause)
        waited += pause
    return waited


def wait_for_decision_slot(uid: str, realm: str = REALM) -> float:
    """wait_for_rate_limit_slot for ``uid``'s /decision calls; every real login
    spends one."""
    return wait_for_rate_limit_slot("decision", uid, realm)


# --- engine settings (per-realm decision params) -----------------------------


def get_settings(token: str) -> list:
    """GET the realm's decision parameters (list of param dicts)."""
    r = requests.get(
        f"{ENGINE_BASE}/{REALM}/settings",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    return data if isinstance(data, list) else data.get("parameters", [])


def put_settings(token: str, params: list) -> requests.Response:
    """Replace the realm's decision parameters (a full list, all groups).

    A no-op round-trip (PUT of an unmodified GET) is faithful, so callers can
    flip one field, PUT, then PUT the original back to restore.

    Paced to the engine's per-caller limit on settings writes, so a restore
    that follows a change is not refused and leaves the realm changed.
    """
    wait_for_rate_limit_slot("config", ENGINE_CLIENT)
    return requests.put(
        f"{ENGINE_BASE}/{REALM}/settings",
        json=params,
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    )
