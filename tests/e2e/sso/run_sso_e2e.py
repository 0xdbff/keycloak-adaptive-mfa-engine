#!/usr/bin/env python3
"""End-to-end suite for logins through an identity provider (SSO).

Starts its own stack (docker-compose.sso.yml), imports the shipped test-amfa
realm plus a "corp" realm that acts as the identity provider, binds corp to
AMFA's post login flow, runs the scenarios, prints a summary and tears the
stack down. Exit code is non-zero if any check fails.

Checks that need the plugin's brokered-login support (device data on SSO
logins, refused logins recorded against their user) are marked "needs fix".
With a plugin jar that lacks it they are reported as XFAIL, not FAIL.

usage: python3 tests/e2e/sso/run_sso_e2e.py      (settings: README.md)
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
import sso_login  # noqa: E402

# --- settings ------------------------------------------------------------------

def env(name: str, default: str) -> str:
    return os.environ.get(name) or default


PROJECT = env("E2E_SSO_PROJECT", "amfa-sso-e2e")
KC_HOST = env("E2E_SSO_KC_HOST", "sso-keycloak")
KC_PORT = int(env("E2E_SSO_KC_PORT", "18180"))
MAILPIT_PORT = int(env("E2E_SSO_MAILPIT_PORT", "18125"))
CLUSTER = env("E2E_SSO_CLUSTER", "0") == "1"
NODE2_PORT = int(env("E2E_SSO_KC_NODE2_PORT", str(KC_PORT + 2)))
PLUGIN_JAR = Path(env("E2E_SSO_PLUGIN_JAR", str(REPO / "config/keycloak/keycloak-adaptive-mfa.jar"))).resolve()
VAVR_JAR = Path(env("E2E_SSO_VAVR_JAR", str(REPO / "config/keycloak/vavr-1.0.1.jar"))).resolve()
REALM_FILE = Path(env("E2E_SSO_REALM_FILE", str(REPO / "config/keycloak/test-amfa-realm.json"))).resolve()
KEEP = env("E2E_SSO_KEEP", "0") == "1"
ADMIN_USER = env("E2E_SSO_ADMIN_USER", "admin")
ADMIN_PASS = env("E2E_SSO_ADMIN_PASS", "admin")
# Test-only credentials, created by this suite in its own throwaway realms.
SSO_PASS = "Sso-Pass-2026-x"
LOCAL_PASS = "Local-Pass-2026-x"
BROKER_SECRET = "sso-e2e-broker-secret"

KC_URL = f"http://{KC_HOST}:{KC_PORT}"
MAILPIT_URL = f"http://localhost:{MAILPIT_PORT}"
COMPOSE_FILE = HERE / "docker-compose.sso.yml"
RUN_DIR = HERE / "artifacts" / datetime.now().strftime("run-%Y%m%d-%H%M%S")

# --- output --------------------------------------------------------------------

RESULTS: list[tuple[str, str, str]] = []
HAS_FIX = False


def check(name: str, ok: bool, detail: str = "", needs_fix: bool = False) -> bool:
    if needs_fix and not HAS_FIX:
        status = "XPASS" if ok else "XFAIL"
    else:
        status = "PASS" if ok else "FAIL"
    RESULTS.append((status, name, detail))
    print(f"  [{status}] {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


def log(msg: str) -> None:
    print(msg, flush=True)


# --- stack ---------------------------------------------------------------------

def compose_env() -> dict:
    e = dict(os.environ)
    e.update({
        "E2E_SSO_PROJECT": PROJECT,
        "E2E_SSO_RUN_DIR": str(RUN_DIR),
        "E2E_SSO_KC_URL": KC_URL,
        "E2E_SSO_KC_HOST": KC_HOST,
        "E2E_SSO_KC_PORT": str(KC_PORT),
        "E2E_SSO_MAILPIT_PORT": str(MAILPIT_PORT),
        "E2E_SSO_ADMIN_USER": ADMIN_USER,
        "E2E_SSO_ADMIN_PASS": ADMIN_PASS,
        # Single node: node 1 is Keycloak itself. Cluster: node 1 and node 2 sit
        # behind the load balancer, which takes over the public name and port.
        "E2E_SSO_KC_NODE1_PORT": str(KC_PORT + 1 if CLUSTER else KC_PORT),
        "E2E_SSO_KC_NODE1_ALIAS": "keycloak-node1" if CLUSTER else KC_HOST,
        "E2E_SSO_KC_NODE2_PORT": str(NODE2_PORT),
        "E2E_SSO_KC_CACHE": "ispn" if CLUSTER else "local",
    })
    return e


def compose(*args: str, check_rc: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)]
    if CLUSTER:
        cmd += ["--profile", "cluster"]
    return subprocess.run(cmd + list(args), env=compose_env(), check=check_rc, text=True,
                          stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)


def sql(query: str) -> list[list[str]]:
    out = compose("exec", "-T", "postgres", "psql", "-U", "keycloak", "-d", "adaptive_mfa",
                  "-tA", "-F", "\t", "-c", query, capture=True).stdout
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def port_free(port: int) -> bool:
    with socket.socket() as s:
        # A port left in TIME_WAIT by the previous run is free to listen on.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def plugin_has_fix(jar: Path) -> bool:
    """True if the jar carries the brokered-login support (its amfa_user_id detail)."""
    with zipfile.ZipFile(jar) as z:
        name = "org/keycloak/amfa/util/EventBuilderHelper.class"
        return name in z.namelist() and b"amfa_user_id" in z.read(name)


def plugin_vavr_version(jar: Path) -> str | None:
    with zipfile.ZipFile(jar) as z:
        for name in z.namelist():
            if name.startswith("META-INF/maven/") and name.endswith("/pom.xml"):
                m = re.search(rb"<vavr.version>([^<]+)</vavr.version>", z.read(name))
                return m.group(1).decode() if m else None
    return None


def prepare_run_dir() -> None:
    (RUN_DIR / "providers").mkdir(parents=True)
    (RUN_DIR / "import").mkdir()
    (RUN_DIR / "forced-risk").write_text("")
    (RUN_DIR / "providers" / PLUGIN_JAR.name).write_bytes(PLUGIN_JAR.read_bytes())
    (RUN_DIR / "providers" / VAVR_JAR.name).write_bytes(VAVR_JAR.read_bytes())

    realm = json.loads(REALM_FILE.read_text())
    # AMFA's post login flow for identity providers, unless the realm already has it.
    fragment = json.loads((HERE / "post-broker-flow.json").read_text())
    flows = {f["alias"] for f in realm["authenticationFlows"]}
    configs = {c["alias"] for c in realm.get("authenticatorConfig", [])}
    realm["authenticationFlows"] += [f for f in fragment["authenticationFlows"] if f["alias"] not in flows]
    realm.setdefault("authenticatorConfig", []).extend(
        c for c in fragment["authenticatorConfig"] if c["alias"] not in configs)
    # Environment settings only: where Keycloak and the engine are, the test
    # client's redirect, a local user, and no brute-force lockout from the
    # suite's own deliberate denials.
    realm["attributes"]["frontendUrl"] = KC_URL
    realm["attributes"]["adaptiveAuthEndpoint"] = "http://risk_proxy:8099"
    realm["failureFactor"] = 1000
    for c in realm["clients"]:
        if c["clientId"] == sso_login.CLIENT:
            c["redirectUris"] = [f"{KC_URL}/*", sso_login.REDIRECT]
            c["webOrigins"] = ["+"]
    realm.setdefault("users", []).append({
        "username": "local-user", "enabled": True, "email": "local-user@example.com", "emailVerified": True,
        "firstName": "Local", "lastName": "User",
        "credentials": [{"type": "password", "value": LOCAL_PASS, "temporary": False}]})
    realm.setdefault("identityProviders", []).append({
        "alias": sso_login.IDP, "providerId": "oidc", "enabled": True, "trustEmail": True,
        "firstBrokerLoginFlowAlias": "first broker login", "postBrokerLoginFlowAlias": "amfa-post-broker",
        "config": {
            "authorizationUrl": f"{KC_URL}/realms/corp/protocol/openid-connect/auth",
            "tokenUrl": f"{KC_URL}/realms/corp/protocol/openid-connect/token",
            "userInfoUrl": f"{KC_URL}/realms/corp/protocol/openid-connect/userinfo",
            "jwksUrl": f"{KC_URL}/realms/corp/protocol/openid-connect/certs",
            "issuer": f"{KC_URL}/realms/corp", "validateSignature": "true", "useJwksUrl": "true",
            "clientId": "amfa-broker", "clientSecret": BROKER_SECRET, "clientAuthMethod": "client_secret_post",
            "defaultScope": "openid email profile", "syncMode": "IMPORT"}})
    corp = {"realm": "corp", "enabled": True,
            "clients": [{"clientId": "amfa-broker", "enabled": True, "publicClient": False, "secret": BROKER_SECRET,
                         "standardFlowEnabled": True,
                         "redirectUris": [f"{KC_URL}/realms/{sso_login.REALM}/broker/{sso_login.IDP}/endpoint"]}],
            "users": [{"username": u, "enabled": True, "email": f"{u}@example.com", "emailVerified": True,
                       "firstName": u, "lastName": "User",
                       "credentials": [{"type": "password", "value": SSO_PASS, "temporary": False}]}
                      for u in ("sso-tier1", "sso-tier2", "sso-silent")]}
    (RUN_DIR / "import" / "test-amfa-realm.json").write_text(json.dumps(realm, indent=1))
    (RUN_DIR / "import" / "corp-realm.json").write_text(json.dumps(corp, indent=1))


def wait_for(url: str, timeout: int = 300) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=3).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def start_stack() -> None:
    log(f"starting {PROJECT} ({'two Keycloak nodes behind a load balancer' if CLUSTER else 'one Keycloak node'})")
    compose("down", "-v", "--remove-orphans", capture=True, check_rc=False)
    compose("up", "-d", "--build", "--quiet-pull")
    for realm in (sso_login.REALM, "corp"):
        if not wait_for(f"{KC_URL}/realms/{realm}"):
            raise SystemExit(f"Keycloak did not serve realm {realm} at {KC_URL} in time")
    if CLUSTER and not wait_for(f"http://localhost:{NODE2_PORT}/realms/corp"):
        raise SystemExit("the second Keycloak node did not start in time")


# --- engine and Keycloak lookups -------------------------------------------------

def admin_token() -> str:
    return requests.post(f"{KC_URL}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli", "username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=10).json()["access_token"]


def user_id(username: str) -> str | None:
    users = requests.get(f"{KC_URL}/admin/realms/{sso_login.REALM}/users",
                         params={"username": username, "exact": "true"},
                         headers={"Authorization": f"Bearer {admin_token()}"}, timeout=10).json()
    return users[0]["id"] if users else None


def events(uid: str | None, event_type: str) -> list[dict]:
    """The user's stored events of one type, oldest first, with their device.

    No events for a user Keycloak does not know (uid None), so the checks that
    rely on them fail instead of the run stopping.
    """
    if uid is None:
        return []
    rows = sql(
        "select e.event_type, coalesce(e.auth_process::text,''), coalesce(d.browser,''), "
        "coalesce(d.screen_resolution,''), coalesce(d.system_language,'') "
        "from auth_event e left join device d on d.hash = e.device_info_hash "
        f"where e.user_id::text = '{uid}' and e.event_type = '{event_type}' order by e.event_time")
    return [dict(zip(("type", "decision", "browser", "screen", "language"), r + [""] * (5 - len(r)))) for r in rows]


def decision_status(decision: str) -> str:
    rows = sql(f"select coalesce(final_status,'') from auth_process where id::text = '{decision}'")
    return rows[0][0] if rows and rows[0] else ""


def wait_events(uid: str | None, event_type: str, count: int, timeout: float = 15.0) -> list[dict]:
    deadline = time.time() + timeout
    while True:
        found = events(uid, event_type)
        if len(found) >= count or time.time() > deadline:
            return found
        time.sleep(1)


def has_device(e: dict | None) -> bool:
    return bool(e) and e["screen"] == sso_login.SCREEN and "Safari" in e["browser"] and bool(e["language"])


def describe(e: dict | None) -> str:
    if not e:
        return "no event"
    return (f"browser={e['browser'] or '(empty)'} screen={e['screen'] or '(empty)'} "
            f"language={e['language'] or '(empty)'} decision={'linked' if e['decision'] else 'none'}")


def force_risk(level: int | None) -> None:
    (RUN_DIR / "forced-risk").write_text("" if level is None else str(level))


# --- scenarios -------------------------------------------------------------------

def scenarios() -> None:
    secrets_: dict[str, str] = {}

    def browser() -> sso_login.Browser:
        return sso_login.Browser(KC_URL, MAILPIT_URL, secrets_)

    def login(b, mode, user, risk, **kw):
        force_risk(risk)
        r = b.login(mode, user, SSO_PASS if mode == "sso" else LOCAL_PASS, f"{user}@example.com", **kw)
        time.sleep(1)
        return r

    log("SSO login, risk 1, first ever for the user")
    r = login(browser(), "sso", "sso-tier1", 1, tokens=True)
    check("first SSO login completes without step-up", r["outcome"] == "logged in", "; ".join(r["steps"][-2:]))
    check("no AMFA data in the access or ID token", r.get("amfa_in_tokens") is False)
    uid = user_id("sso-tier1")
    e = (wait_events(uid, "LOGIN", 1) or [None])[-1] if uid else None
    check("first SSO login reaches the engine with device data", has_device(e), describe(e), needs_fix=True)

    log("SSO login, risk 1, repeat")
    r = login(browser(), "sso", "sso-tier1", 1)
    e = (wait_events(uid, "LOGIN", 2) or [None])[-1]
    check("repeat SSO login completes", r["outcome"] == "logged in", "; ".join(r["steps"][-2:]))
    check("repeat SSO login reaches the engine with device data", has_device(e), describe(e), needs_fix=True)

    log("SSO login, risk 2: TOTP setup, then a TOTP code")
    r = login(browser(), "sso", "sso-tier2", 2)
    check("risk 2 sets up TOTP and completes",
          r["outcome"] == "logged in" and any("TOTP setup" in s for s in r["steps"]), "; ".join(r["steps"][-3:]))
    # Keycloak refuses a code from the 30-second window the setup used.
    time.sleep(31 - time.time() % 30 + 1)
    r = login(browser(), "sso", "sso-tier2", 2)
    check("risk 2 asks for the TOTP code and completes",
          r["outcome"] == "logged in" and any("TOTP code page" in s for s in r["steps"]), "; ".join(r["steps"][-3:]))

    log("SSO login, risk 3: email code")
    r = login(browser(), "sso", "sso-tier1", 3)
    check("risk 3 asks for the email code and completes",
          r["outcome"] == "logged in" and any("email code" in s for s in r["steps"]), "; ".join(r["steps"][-3:]))

    log("SSO login, risk 4: refused")
    before = len(events(uid, "LOGIN_ERROR"))
    r = login(browser(), "sso", "sso-tier1", 4)
    check("risk 4 refuses the SSO login", r["outcome"] != "logged in", "; ".join(r["steps"][-2:]))
    errors = wait_events(uid, "LOGIN_ERROR", before + 1)
    time.sleep(3)
    errors = events(uid, "LOGIN_ERROR")
    check("the refusal is stored once, against the user", len(errors) - before == 1,
          f"{len(errors) - before} new LOGIN_ERROR rows", needs_fix=True)
    last = errors[-1] if len(errors) > before else None
    status = decision_status(last["decision"]) if last and last["decision"] else None
    check("the refused login's decision is closed", status == "LOGIN_ERROR",
          f"decision status {status or 'n/a'}", needs_fix=True)

    log("SSO login, then a silent re-login on the same session")
    b = browser()
    login(b, "sso", "sso-silent", 1)
    sid = user_id("sso-silent")
    wait_events(sid, "LOGIN", 1)
    r = login(b, "sso", "sso-silent", None, silent_only=True)
    check("the second login completes silently", r["outcome"] == "logged in", "; ".join(r["steps"][-2:]))
    logins = wait_events(sid, "LOGIN", 2)
    e = logins[-1] if len(logins) >= 2 else None
    check("the silent re-login carries no device data",
          bool(e) and not e["screen"] and not e["decision"], describe(e))

    log("Local login and local denial")
    r = login(browser(), "local", "local-user", 1)
    lid = user_id("local-user")
    e = (wait_events(lid, "LOGIN", 1) or [None])[-1]
    check("local login completes", r["outcome"] == "logged in", "; ".join(r["steps"][-2:]))
    check("local login reaches the engine with device data", has_device(e), describe(e))
    before = len(events(lid, "LOGIN_ERROR"))
    r = login(browser(), "local", "local-user", 4)
    check("risk 4 refuses the local login", r["outcome"] != "logged in", "; ".join(r["steps"][-2:]))
    wait_events(lid, "LOGIN_ERROR", before + 1)
    time.sleep(2)
    check("the local refusal is stored against the user", len(events(lid, "LOGIN_ERROR")) - before == 1,
          f"{len(events(lid, 'LOGIN_ERROR')) - before} new LOGIN_ERROR rows", needs_fix=True)
    force_risk(None)


def keycloak_errors() -> int:
    services = ["keycloak", "keycloak2"] if CLUSTER else ["keycloak"]
    out = compose("logs", "--no-color", *services, capture=True, check_rc=False).stdout or ""
    return sum(1 for line in out.splitlines() if "org.keycloak.amfa" in line and re.search(r"ERROR|Exception", line))


# --- main ------------------------------------------------------------------------

def main() -> int:
    global HAS_FIX
    for path, what in ((PLUGIN_JAR, "plugin jar (E2E_SSO_PLUGIN_JAR)"), (VAVR_JAR, "vavr jar (E2E_SSO_VAVR_JAR)"),
                       (REALM_FILE, "test realm (E2E_SSO_REALM_FILE)")):
        if not path.is_file():
            hint = ""
            if path.parent == REPO / "config/keycloak" and path.suffix == ".jar":
                hint = ("; fetch the released jars with `docker compose run --rm providers` "
                        "in config/keycloak (see tests/e2e/sso/README.md)")
            raise SystemExit(f"missing {what}: {path}{hint}")
    busy = [p for p in (KC_PORT, MAILPIT_PORT, *((KC_PORT + 1, NODE2_PORT) if CLUSTER else ())) if not port_free(p)]
    if busy:
        raise SystemExit(f"ports already in use: {busy}; set E2E_SSO_KC_PORT / E2E_SSO_MAILPIT_PORT")
    if sso_login.host_resolves(KC_HOST):
        log(f"note: {KC_HOST} resolves on this machine; the driver still sends it to 127.0.0.1")
    sso_login.map_host(KC_HOST)

    HAS_FIX = plugin_has_fix(PLUGIN_JAR)
    log(f"plugin jar: {PLUGIN_JAR}")
    log("  brokered-login support: " + ("yes" if HAS_FIX else
        "NO, checks marked 'needs fix' are expected to fail (XFAIL)"))
    wanted = plugin_vavr_version(PLUGIN_JAR)
    if wanted and wanted not in VAVR_JAR.name:
        log(f"  warning: the plugin was built against vavr {wanted}, but E2E_SSO_VAVR_JAR is {VAVR_JAR.name}")
    log(f"Keycloak: {KC_URL}  Mailpit: {MAILPIT_URL}  run files: {RUN_DIR}")

    prepare_run_dir()
    try:
        start_stack()
        scenarios()
        check("no AMFA plugin errors in the Keycloak log", keycloak_errors() == 0, f"{keycloak_errors()} lines")
        if CLUSTER:
            lb = compose("logs", "--no-color", "kc_lb", capture=True, check_rc=False).stdout or ""
            served = {n: sum(1 for line in lb.splitlines() if f"| {n} " in line and "-> 502" not in line)
                      for n in ("n1", "n2")}
            check("both Keycloak nodes served the logins", all(served.values()),
                  f"node 1: {served['n1']} requests, node 2: {served['n2']}")
    finally:
        force_risk(None)
        if KEEP:
            log(f"E2E_SSO_KEEP=1: stack {PROJECT} left running")
        else:
            compose("down", "-v", "--remove-orphans", capture=True, check_rc=False)

    counts = {s: sum(1 for r in RESULTS if r[0] == s) for s in ("PASS", "FAIL", "XFAIL", "XPASS")}
    log("")
    log("summary: " + ", ".join(f"{n} {s}" for s, n in counts.items() if n))
    for status, name, detail in RESULTS:
        if status in ("FAIL", "XPASS"):
            log(f"  {status}: {name}" + (f" ({detail})" if detail else ""))
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
