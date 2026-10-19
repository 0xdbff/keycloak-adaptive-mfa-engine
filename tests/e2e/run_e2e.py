#!/usr/bin/env python3
"""AMFA end-to-end scenario runner.

Runs a set of black-box scenarios against a RUNNING stack and prints a PASS/FAIL
report. Exits non-zero if any scenario fails, so it is usable in CI as a smoke
gate after a deploy.

    python3 tests/e2e/run_e2e.py

The scenarios validate the WIRING between components (Keycloak SPI -> engine ->
redis/DB -> MFA step-up). The per-signal scoring LOGIC is covered separately by
the engine unit suite (tests/unit). See scenario-coverage.md for the full map of
what is exercised where.

Prerequisites: the compose stack up (Keycloak :8080, engine :8095, redis,
postgres, Mailpit :8025), realm `test-amfa` with the AMFA browser flow bound,
and user alice. Override any endpoint/credential via the E2E_* env vars in
e2e_common.py.
"""

from __future__ import annotations

import sys
import time
import uuid

import e2e_common as e2e

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "", xfail: str | None = None) -> None:
    """Record a check. With ``xfail`` set, the check documents a known bug: a
    failure is expected (XFAIL) and does not fail the suite, while an unexpected
    pass (XPASS) signals the bug is fixed. Both count as non-failing so the guard
    can live in the suite before the fix lands."""
    if xfail is not None:
        label = "XPASS" if ok else "XFAIL"
        RESULTS.append((name, True, detail))  # never fails the suite
        print(f"  [{label}] {name}" + (f" — {detail}" if detail else "") + f"  (xfail: {xfail})")
        return
    RESULTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def scenario(fn):
    """Run one scenario function; catch exceptions as failures."""
    name = fn.__doc__.strip().splitlines()[0]
    print(f"\n▶ {name}")
    try:
        fn(name)
    except Exception as exc:  # noqa: BLE001 - a scenario crash is a failure, not a stop
        record(name, False, f"exception: {exc!r}")


# --- engine API scenarios (direct, deterministic) ---------------------------


def sc_engine_rejects_no_token(_name):
    """Engine rejects an unauthenticated /decision (auth is enforced)"""
    import requests

    r = requests.post(f"{e2e.ENGINE_BASE}/decision", json={}, timeout=15)
    record("no-token -> 401/403", r.status_code in (401, 403), f"HTTP {r.status_code}")


def sc_engine_decision_new_user(_name):
    """Engine scores a fresh user end-to-end via /auth_context + /decision"""
    token = e2e.engine_sa_token()
    ctx = {
        "client": "test-login",
        "ip_address": "203.0.113.10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "system_language": "en-US",
        "screen_resolution": "1920x1080",
    }
    ac = e2e.engine_auth_context(token, ctx)
    ok_ac = ac.status_code == 200 and "hash" in ac.text.lower()
    record("/auth_context -> 200 + hash", ok_ac, f"HTTP {ac.status_code}")
    if not ok_ac:
        return
    ctx_hash = ac.json().get("hash") or ac.json().get("auth_context_hash")

    req = {
        "event_id": str(uuid.uuid4()),
        "group_id": "default",
        "realm_id": e2e.REALM,
        "user_id": str(uuid.uuid4()),  # brand-new synthetic user, no history
        **ctx,
        "auth_context_hash": ctx_hash,
        "cookie": None,
    }
    dec = e2e.engine_decision(token, req)
    risk = dec.json().get("riskLevel") if dec.status_code == 200 else None
    ok = dec.status_code == 200 and isinstance(risk, int) and 1 <= risk <= 4
    record("/decision -> 200 + riskLevel in 1..4", ok, f"HTTP {dec.status_code} riskLevel={risk}")


# --- full browser-flow login scenarios (SPI + engine + MFA) ------------------


def _novel_context() -> tuple[str, str]:
    """A context alice has never used, so the engine sees several changed signals
    and scores elevated risk (driving a step-up). Made unique per run via the
    clock so repeated runs stay 'novel' rather than becoming familiar."""
    tick = int(time.time())
    ua = f"Mozilla/5.0 (X11; Linux x86_64; rv:{100 + tick % 25}.0) Gecko/20100101 Firefox/{100 + tick % 25}.0"
    screen_res = f"{1280 + tick % 640}x{720 + tick % 360}"
    return ua, screen_res


def sc_login_stepup_and_complete(_name):
    """Novel-context login drives the full chain -> risk step-up -> completion"""
    base = e2e.engine_log_line_count()
    admin = e2e.admin_token()
    uid = e2e.user_id(e2e.TEST_USER, admin)
    before = e2e.db_scalar(
        f"select count(*) from auth_event where user_id='{uid}'"
    ) if uid else None

    ua, screen_res = _novel_context()
    if uid:
        e2e.wait_for_decision_slot(uid)
    res = e2e.kc_login(
        e2e.TEST_USER, e2e.TEST_PASS,
        user_agent=ua, screen_res=screen_res, accept_language="",
        totp_secret=e2e.TOTP_SECRET, email_recipient="alice",
    )

    # Hard assertion: the engine's decision drove a risk-based step-up factor.
    # (A novel context is never a no-step-up Risk 1, so a factor must appear.)
    reached_stepup = res["step_up"] in ("email", "totp")
    record("risk-based step-up enforced (SPI<->engine wiring)", reached_stepup,
           f"step_up={res['step_up']} steps={res['steps']}")

    # Completion (auth code + success webhook + event) needs a satisfiable factor:
    # email is always satisfiable via Mailpit; TOTP only with E2E_TOTP_SECRET.
    completable = res["step_up"] == "email" or (res["step_up"] == "totp" and e2e.TOTP_SECRET)
    if not completable:
        record("login completion", True,
               "SKIPPED: TOTP tier hit but no E2E_TOTP_SECRET set (step-up itself verified above)")
        return

    record("login completes (auth code issued)", res["ok"], res["detail"])
    if not res["ok"]:
        return

    # Engine-side chain assertions (best-effort; skipped when docker unavailable).
    # Let stdout flush so the INFO decision line and the webhook line are visible.
    if base is not None:
        time.sleep(3.0)
        newlog = e2e.engine_log_since(base)
        logged_calls = "POST /auth_context" in newlog and "POST /decision" in newlog
        record("engine logged /auth_context + /decision", logged_calls,
               "seen in logs" if logged_calls else "not found in captured log window")
        risk_line = [
            l for l in newlog.splitlines()
            if "risk_level=" in l or "risk-level=" in l or "final Risk" in l
        ]
        record("engine emitted a final risk level", bool(risk_line),
               risk_line[-1].split("::")[-1].strip() if risk_line else "not found")
        webhook_fired = "/login_event/webhook" in newlog
        record("login-success webhook fired", webhook_fired,
               "seen in logs" if webhook_fired else "not found in captured log window")
    if uid and before is not None:
        after = e2e.db_scalar(f"select count(*) from auth_event where user_id='{uid}'")
        ok = after is not None and int(after) > int(before)
        record("auth_event recorded (count increased)", ok, f"{before} -> {after}")


def sc_login_wrong_password(_name):
    """Wrong password is rejected (no authorization code issued)"""
    uid = e2e.user_id(e2e.TEST_USER, e2e.admin_token())
    if uid:
        e2e.wait_for_decision_slot(uid)
    ua, screen_res = _novel_context()
    res = e2e.kc_login(
        e2e.TEST_USER, "definitely-wrong-password",
        user_agent=ua, screen_res=screen_res, accept_language="",
    )
    # Success would mean an auth code was issued; we expect a clean rejection.
    ok = (not res["ok"]) and "rejected" in res["detail"].lower()
    record("bad password -> login rejected", ok, res["detail"])


def _decide(token, ip, uid, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    """Run /auth_context + /decision for a synthetic user and return riskLevel."""
    ctx = {"client": "test-login", "ip_address": ip, "user_agent": ua,
           "system_language": "en-US", "screen_resolution": "1920x1080"}
    ac = e2e.engine_auth_context(token, ctx)
    ctx_hash = ac.json().get("hash")
    req = {"event_id": str(uuid.uuid4()), "group_id": "default", "realm_id": e2e.REALM,
           "user_id": uid, **ctx, "auth_context_hash": ctx_hash, "cookie": None}
    dec = e2e.engine_decision(token, req)
    return dec.status_code, dec.json().get("riskLevel")


def sc_blacklist_override(_name):
    """A blacklisted IP forces an elevated risk regardless of scoring"""
    token = e2e.engine_sa_token()

    # Find an IP that is blacklisted in the default group (non-mutating: uses
    # whatever the realm already has configured).
    blacklisted_ip = None
    all_bw = set()
    for p in e2e.get_settings(token):
        if p.get("group_id") == "default" and p.get("parameter_name") == "ip_address":
            bl = p.get("blacklist") or []
            all_bw.update(bl)
            all_bw.update(p.get("whitelist") or [])
            if bl and not blacklisted_ip:
                blacklisted_ip = bl[0]
    if not blacklisted_ip:
        record("blacklist override", True,
               "SKIPPED: no ip_address blacklist configured on the default group")
        return

    # A clean IP that is neither black- nor white-listed anywhere.
    clean_ip = next(ip for ip in ("198.51.100.5", "198.51.100.6", "203.0.113.200")
                    if ip not in all_bw)

    st_bl, risk_bl = _decide(token, blacklisted_ip, str(uuid.uuid4()))
    st_cl, risk_cl = _decide(token, clean_ip, str(uuid.uuid4()))
    record("blacklisted IP forces high risk (>= clean IP, >= 3)",
           st_bl == 200 and st_cl == 200 and isinstance(risk_bl, int)
           and risk_bl >= 3 and risk_bl >= (risk_cl or 0),
           f"blacklisted({blacklisted_ip})={risk_bl} vs clean({clean_ip})={risk_cl}")


def sc_e4_account_change(_name):
    """A recent account change surfaces the E4 recent_account_change signal"""
    if not e2e.docker_available():
        record("E4 account-change", True, "SKIPPED: docker not available (needs redis + engine logs)")
        return
    admin = e2e.admin_token()
    uid = e2e.user_id(e2e.TEST_USER, admin)
    if not uid:
        record("E4 account-change", True, f"SKIPPED: user {e2e.TEST_USER} not found")
        return

    token = e2e.engine_sa_token()
    # The redis key must be tenant-scoped ("<bucket>:<event_type>:<realm>:<user>:<epoch>",
    # matching tenant_scoped_id() in decision.py's __count_recent_account_actions) or the
    # engine's scan never matches it. A realm-less key silently seeds nothing.
    key = f"d:UPDATE_PASSWORD:{e2e.REALM}:{uid}:{time.time()}"
    e2e.redis_del_pattern(f"d:UPDATE_PASSWORD:{e2e.REALM}:{uid}:*")  # clean slate

    # The history-gate (< MIN_AUTH_EVENTS successful logins) short-circuits before
    # recent_account_change is ever evaluated, so a fresh test user can never
    # observe this signal regardless of whether it fires. Build real history first.
    e2e.ensure_login_history(e2e.TEST_USER, e2e.TEST_PASS, uid)

    # recent_account_change ships disabled (opt-in). Enable it on the default
    # group for the check, then restore. (Before the __param_is_enabled fix the
    # signal fired even while disabled, so this scenario passed by accident; it
    # must now enable the signal explicitly, like a real deployment.)
    original = e2e.get_settings(token)
    modified = [dict(p) for p in original]
    target = [p for p in modified
              if p.get("group_id") == "default" and p.get("parameter_name") == "recent_account_change"]
    if not target:
        record("E4 account-change", True,
               "SKIPPED: recent_account_change not on the default group")
        return
    target[0]["disabled"] = False

    try:
        put = e2e.put_settings(token, modified)
        if put.status_code != 200:
            record("E4 account-change", True, f"SKIPPED: could not enable (HTTP {put.status_code})")
            return
        # A failed seed must not be reported as a product failure. Before the
        # container names were corrected this silently did nothing, and the
        # assertion below then read "recent_account_change did not fire", which
        # looked like broken E4 wiring rather than a fixture that never landed.
        if not e2e.redis_set(key):
            record("E4 account-change", True,
                   f"SKIPPED: could not seed redis via {e2e.DOCKER_REDIS}")
            return
        base = e2e.engine_log_line_count()
        if base is None:
            record("E4 account-change", True,
                   f"SKIPPED: could not read engine logs via {e2e.DOCKER_ENGINE}")
            return
        e2e.wait_for_decision_slot(uid)
        st, risk = _decide(token, "198.51.100.5", uid)
        record("engine scored the login with the account-change present",
               st == 200 and isinstance(risk, int), f"HTTP {st} riskLevel={risk}")
        time.sleep(3.0)
        newlog = e2e.engine_log_since(base) if base is not None else ""
        surfaced = ("Account-action analysis" in newlog and "SUSPICIOUS" in newlog) or \
                   ("'recent_account_change': 'SUSPICIOUS'" in newlog)
        record("recent_account_change flagged SUSPICIOUS (E4 wiring)", surfaced,
               "seen in engine logs" if surfaced else "not seen in engine logs")
    finally:
        e2e.put_settings(token, original)  # restore realm config
        e2e.redis_del_pattern(f"d:UPDATE_PASSWORD:{e2e.REALM}:{uid}:*")


def sc_disabled_signal_does_not_fire(_name):
    """A DISABLED signal must not fire (guard for the __param_is_enabled bug)"""
    if not e2e.docker_available():
        record("disabled-signal guard", True, "SKIPPED: docker not available")
        return
    admin = e2e.admin_token()
    uid = e2e.user_id(e2e.TEST_USER, admin)
    if not uid:
        record("disabled-signal guard", True, f"SKIPPED: user {e2e.TEST_USER} not found")
        return

    token = e2e.engine_sa_token()
    original = e2e.get_settings(token)
    # Flip recent_account_change to disabled on the default group.
    modified = [dict(p) for p in original]
    target = [p for p in modified
              if p.get("group_id") == "default" and p.get("parameter_name") == "recent_account_change"]
    if not target:
        record("disabled-signal guard", True,
               "SKIPPED: recent_account_change not on the default group")
        return
    target[0]["disabled"] = True

    # Same history precondition as the positive E4 test: below MIN_AUTH_EVENTS the
    # history-gate returns before recent_account_change is evaluated either way, so
    # "did not fire" would be vacuously true regardless of the disabled flag.
    e2e.ensure_login_history(e2e.TEST_USER, e2e.TEST_PASS, uid)

    e2e.redis_del_pattern(f"d:UPDATE_PASSWORD:{e2e.REALM}:{uid}:*")
    try:
        put = e2e.put_settings(token, modified)
        if put.status_code != 200:
            record("disabled-signal guard", True, f"SKIPPED: could not disable (HTTP {put.status_code})")
            return

        # Same setup as the positive E4 test: seed the (tenant-scoped) account-change event.
        e2e.redis_set(f"d:UPDATE_PASSWORD:{e2e.REALM}:{uid}:{time.time()}")
        base = e2e.engine_log_line_count()
        e2e.wait_for_decision_slot(uid)
        st, risk = _decide(token, "198.51.100.5", uid)
        # "Did not fire" only means something if the engine scored the login:
        # a rejected call (a 429 from the rate limit, say) never reaches the
        # signal at all, and used to let this check pass with nothing checked.
        if st != 200 or not isinstance(risk, int):
            record("disabled recent_account_change does NOT fire", False,
                   f"not checked: the decision was not scored (HTTP {st} riskLevel={risk})")
            return
        time.sleep(3.0)
        newlog = e2e.engine_log_since(base) if base is not None else ""
        fired = ("Account-action analysis" in newlog and "SUSPICIOUS" in newlog) or \
                ("'recent_account_change': 'SUSPICIOUS'" in newlog)
        # Correct behaviour: a disabled signal must NOT fire. Fixed in
        # fix/signal-gating: __param_is_enabled now checks membership in
        # decision_params, so a dropped (disabled) param reads as off.
        record("disabled recent_account_change does NOT fire", not fired,
               "did not fire (correct)" if not fired else "FIRED while disabled")
    finally:
        e2e.put_settings(token, original)  # restore realm config
        e2e.redis_del_pattern(f"d:UPDATE_PASSWORD:{e2e.REALM}:{uid}:*")


def main() -> int:
    print("=" * 70)
    print("AMFA end-to-end scenarios")
    print(f"  Keycloak: {e2e.KC_BASE}  engine: {e2e.ENGINE_BASE}  realm: {e2e.REALM}")
    print("=" * 70)

    for fn in (
        sc_engine_rejects_no_token,
        sc_engine_decision_new_user,
        sc_login_stepup_and_complete,
        sc_login_wrong_password,
        sc_blacklist_override,
        sc_e4_account_change,
        sc_disabled_signal_does_not_fire,
    ):
        scenario(fn)

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print("\n" + "=" * 70)
    print(f"RESULT: {passed}/{total} checks passed")
    print("=" * 70)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
