"""A login that never collects a screen resolution, driven through Keycloak.

A direct grant has no page to run the screen resolution step on, so the SPI sends
`screen_resolution` as null. Every other login in this suite goes through the browser
flow, which always collects one, so nothing here exercised that path end to end: the
engine refused both calls with 422 and the login fell back to the realm's fallback
risk, without any test noticing.

**How the login is made.** The shipped realm's direct grant flow does not run AMFA at
all, so each realm gets one that does (username, password, auth context, adaptive
auth) and the test client is bound to it. Browser logins are unaffected.

**What is asserted.** The login is scored, the screen is not reported as changed
(there is nothing to compare), and the decision fingerprints the same device the
event webhook stores for it. The browser login that follows is not reported as a
screen change either, because the login it is compared with had no screen. Two
controls run first in the same realm, so a test that cannot see the signal at all
cannot pass: an unchanged browser login is not flagged, and a changed screen is.
Every test runs under both scoring modes, which detect a changed signal separately.
"""

import json

import pytest
import requests

from tests.e2e import matrix_env as env
from tests.e2e import matrix_lib as lib
from tests.e2e.matrix_rows import signals_from_why

DIRECT_GRANT_FLOW = "amfa-direct-grant"


def _admin(method: str, path: str, token: str, **kwargs) -> requests.Response:
    r = lib._admin(method, path, token, **kwargs)
    assert r.status_code < 300, f"{method} {path}: HTTP {r.status_code} {r.text[:300]}"
    return r


def bind_amfa_direct_grant(token: str) -> None:
    """Give the run realm a direct grant flow that runs the AMFA steps."""
    _admin("POST", "/authentication/flows", token, json={
        "alias": DIRECT_GRANT_FLOW, "providerId": "basic-flow",
        "topLevel": True, "builtIn": False,
    })
    for provider in ("direct-grant-validate-username", "direct-grant-validate-password",
                     "auth-context-authenticator", "adaptive-auth"):
        _admin("POST", f"/authentication/flows/{DIRECT_GRANT_FLOW}/executions/execution",
               token, json={"provider": provider})
    executions = f"/authentication/flows/{DIRECT_GRANT_FLOW}/executions"
    for execution in _admin("GET", executions, token).json():
        _admin("PUT", executions, token, json={**execution, "requirement": "REQUIRED"})

    flow_id = next(flow["id"] for flow in _admin("GET", "/authentication/flows", token).json()
                   if flow["alias"] == DIRECT_GRANT_FLOW)
    client_id = lib.BASELINE_CONTEXT["client"]
    client = _admin("GET", f"/clients?clientId={client_id}", token).json()[0]
    client["directAccessGrantsEnabled"] = True
    client["authenticationFlowBindingOverrides"] = {
        **(client.get("authenticationFlowBindingOverrides") or {}),
        "direct_grant": flow_id,
    }
    _admin("PUT", f"/clients/{client['id']}", token, json=client)


def direct_grant(username: str) -> requests.Response:
    """A direct grant presenting the baseline context, so only the screen differs."""
    context = lib.BASELINE_CONTEXT
    return requests.post(
        f"{lib.KC_BASE}/realms/{lib.REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": context["client"],
              "username": username, "password": lib.PASSWORD, "scope": "openid"},
        headers={"User-Agent": context["user_agent"],
                 "Accept-Language": context["accept_language"],
                 "X-Forwarded-For": context["xff"]},
        timeout=30,
    )


def raised(why: str) -> list[str]:
    """The signals a verdict says pushed the risk up, in either scoring mode.

    Weighted scoring lists them as differing from the user's norm, which is what
    `signals_from_why` reads; bayesian scoring names them separately.
    """
    if "Signals pushing risk up:" in why:
        listed = why.split("Signals pushing risk up:", 1)[1].split("|")[0]
        return signals_from_why(f"differ from this user's norm: {listed}")
    return signals_from_why(why)


def latest_decision(user_id: str) -> dict:
    if lib.IS_MSSQL:
        return json.loads(lib.psql(
            "select top 1 id, device_info_hash as device, "
            "json_value(auth_context_json, '$.screen_resolution') as screen "
            f"from auth_process where user_id = '{user_id}' order by started_at desc "
            "for json path, without_array_wrapper, include_null_values;"
        ))
    return json.loads(lib.psql(
        "select json_build_object('id', id, 'device', device_info_hash, "
        "'screen', auth_context_json::json->>'screen_resolution') "
        f"from auth_process where user_id = '{user_id}' order by started_at desc limit 1;"
    ))


def event_device(decision_id: str) -> str | None:
    """The device hash the event webhook stored for this decision's login."""
    return lib.psql(
        f"select device_info_hash from auth_event where auth_process = '{decision_id}';"
    ) or None


@pytest.fixture(scope="module", params=env.SCORING_MODES)
def realm(request):
    with env.MatrixRun(mode=request.param) as run:
        original = lib.REALM
        lib.REALM = run.realm
        try:
            token = lib.admin_token()
            username, golden_id = lib.create_user(token, "golden")
            run.track(golden_id)
            needed = int(env._engine_scoring_env()["MIN_AUTH_EVENTS"])
            lib.train(lib.BASELINE_CONTEXT, username, golden_id, target=needed)
            if lib.completed_logins(golden_id) < needed:
                pytest.fail("could not train the golden profile past the history gate")
            bind_amfa_direct_grant(token)
            yield {"run": run, "token": token, "golden_id": golden_id}
        finally:
            lib.REALM = original


def trained_user(realm, prefix: str) -> tuple[str, str]:
    username, user_id = lib.create_user(realm["token"], prefix)
    realm["run"].track(user_id)
    lib.clone_profile(realm["golden_id"], user_id)
    return username, user_id


def browser_login(username: str, user_id: str, **delta) -> tuple[lib.LoginResult, dict]:
    since = lib.log_mark()
    outcome = lib.login({**lib.BASELINE_CONTEXT, **delta}, username)
    return outcome, lib.last_verdict(user_id, since) or {}


def test_control_an_unchanged_browser_login_is_not_a_screen_change(realm):
    username, user_id = trained_user(realm, "nosr-same")

    outcome, verdict = browser_login(username, user_id)

    assert outcome.ok, outcome
    assert "screen_resolution" not in raised(verdict["why"]), verdict


def test_control_a_changed_screen_is_reported(realm):
    username, user_id = trained_user(realm, "nosr-changed")

    _, verdict = browser_login(username, user_id, screen_res="1024x768")

    assert "screen_resolution" in raised(verdict["why"]), (
        f"a changed screen was not reported, so the tests below could not tell a "
        f"missing screen from an ignored one: {verdict}"
    )


def test_a_direct_grant_is_scored_and_the_next_browser_login_is_not_a_screen_change(realm):
    username, user_id = trained_user(realm, "nosr-direct")

    since = lib.log_mark()
    response = direct_grant(username)
    verdict = lib.last_verdict(user_id, since) or {}
    decision = latest_decision(user_id)

    assert response.status_code == 200 and "access_token" in response.json(), (
        f"the direct grant failed: HTTP {response.status_code} {response.text[:300]}"
    )
    assert verdict, (
        "the engine made no decision for a login without a screen resolution, so "
        "Keycloak used the realm's fallback risk"
    )
    assert decision["screen"] is None, decision
    assert "screen_resolution" not in raised(verdict["why"]), (
        f"a login with no screen resolution was reported as a screen change: {verdict}"
    )
    assert event_device(decision["id"]) == decision["device"], (
        "the decision and the event webhook fingerprinted different devices for the "
        "same login"
    )

    outcome, verdict = browser_login(username, user_id)

    assert outcome.ok, outcome
    assert "screen_resolution" not in raised(verdict["why"]), (
        f"a browser login after one without a screen resolution was reported as a "
        f"screen change: {verdict}"
    )
