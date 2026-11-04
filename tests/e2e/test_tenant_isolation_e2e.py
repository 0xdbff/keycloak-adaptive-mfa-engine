"""Cross-tenant isolation on the risk decision API.

`user_id` in the request body is not, by itself, a safe key for a user's
authentication history: the API must also check that the caller is entitled
to that user, and that the user belongs to the caller's own tenant, not just
that the token's realm matches a second body field, `realm_id`, which a
caller satisfies simply by declaring its own realm. Without that check, a
token accepted for realm A could probe realm B's computed risk for a guessed
user_id (an oracle) and write a fabricated device/network fingerprint into
that user's profile (poisoning). This test demonstrates both attacks against
a real second realm.

This provisions a genuine second, throwaway realm (via `MatrixRun`, the same
mechanism the rest of this suite uses for an isolated tenant) alongside the
shared `test-amfa` realm, and confirms a token from one can never read or
influence the other's history for the same guessed user_id -- checked both
through the API's own response and directly against the stored rows.

Runs from the host against a live stack; needs `requests` and Docker
(MatrixRun creates/destroys the throwaway realm via the Keycloak Admin API).
"""

import json
import uuid

import pytest
import requests

from tests.e2e import e2e_common as c
from tests.e2e import matrix_env as env
from tests.e2e.test_engine_api import base_context, decision_body, post_decision, token

TIMEOUT = 20


def _create_isolated_realm() -> str:
    """Like `matrix_env.create_run_realm`, but pins `frontendUrl` to the
    engine's trusted issuer base instead of leaving it unset, and skips
    matrix parameter/scoring setup (not needed for these tests).

    `create_run_realm` deliberately strips `frontendUrl` so a realm's tokens
    claim whatever hostname actually issued them -- fine when the suite runs
    somewhere that hostname is already what the engine trusts. This suite
    runs from the host against `localhost:8443`, which is NOT what the
    engine trusts (`https://keycloak:8443`); the shipped `test-amfa` realm
    pins the same attribute for the same reason (see docs/keycloak-setup.md).
    """
    realm_name = f"amfa-e2e-tenant-{uuid.uuid4().hex[:8]}"
    admin_tok = env.admin_token()
    rep = env._realm_representation(realm_name)
    rep.setdefault("attributes", {})["frontendUrl"] = "https://keycloak:8443"
    r = requests.post(
        f"{env.KC_BASE}/admin/realms",
        headers={"Authorization": f"Bearer {admin_tok}", "Content-Type": "application/json"},
        data=json.dumps(rep),
        timeout=90,
    )
    if r.status_code not in (201, 204):
        raise RuntimeError(f"could not create realm {realm_name!r} ({r.status_code}): {r.text[:400]}")
    return realm_name


@pytest.fixture(scope="module")
def other_realm():
    """A second, throwaway realm -- an unrelated tenant on the same engine."""
    realm_name = _create_isolated_realm()
    tracked_user_ids = []
    try:
        yield realm_name, tracked_user_ids
    finally:
        env.delete_run_realm(realm_name, tracked_user_ids)


@pytest.fixture(scope="module")
def other_token(other_realm) -> str:
    realm_name, _ = other_realm
    return env.engine_token(realm_name)


def test_a_realm_cannot_read_or_poison_another_realms_history_for_a_guessed_user(
    token, base_context, other_realm, other_token
):
    """The full reported chain: build real history for a victim under
    test-amfa, then confirm an unrelated realm guessing the same user_id
    neither sees it (the oracle) nor can make its own write land in
    test-amfa's partition (the poisoning write)."""
    realm_name, tracked_user_ids = other_realm
    victim_user = str(uuid.uuid4())
    tracked_user_ids.append(victim_user)  # also removes test-amfa's rows for this id

    familiar_ctx = {
        **base_context,
        "user_id": victim_user,
        "ip_address": "10.0.0.6",
        "user_agent": "e2e-familiar-agent/1.0",
        "screen_resolution": "1920x1080",
    }

    # Build real, finalized LOGIN history for the victim under test-amfa: enough
    # consistent logins to clear MIN_AUTH_EVENTS. Only ONE call actually goes to
    # /decision -- it is what produces a row with a genuine, correctly-computed
    # auth_context_hash/device_info_hash/network_location_hash for familiar_ctx.
    # The rest of the required history is a self-clone of that one row,
    # backdated a day apart each, via direct SQL -- the same day-by-day
    # backdating clone_profile() uses elsewhere in this suite, rather than a
    # tight loop of live /decision calls: this test's own isolation check has
    # nothing to do with request pacing, and a tight loop of real calls would
    # correctly trip the per-user rate limit, forcing this test to out-race
    # that limiter for no reason connected to what it's actually checking.
    body = decision_body(token, {**familiar_ctx, "realm_id": c.REALM})
    resp = post_decision(token, body)
    assert resp.status_code == 200, resp.text[:300]
    env.psql(
        f"update auth_process set final_status = 'LOGIN' "
        f"where user_id = '{victim_user}' and realm_id = '{c.REALM}';"
    )
    needed = int(env._engine_scoring_env()["MIN_AUTH_EVENTS"])
    if needed > 1 and env.IS_MSSQL:
        env.psql(f"""
        with src as (
            select top 1 * from auth_process
            where user_id = '{victim_user}' and realm_id = '{c.REALM}'
                and final_status = 'LOGIN'
            order by started_at desc
        ), days as (
            select top ({needed - 1}) row_number() over (order by object_id) as n
            from sys.objects
        )
        insert into auth_process (
            id, user_id, auth_context_hash, device_info_hash, network_location_hash,
            auth_context_json, pre_auth_risk_decision, parameters_config_id,
            final_status, started_at, finished_at, risk_eval_vars,
            net_loc_credibility, device_credibility, realm_id)
        select newid(), user_id, auth_context_hash, device_info_hash,
            network_location_hash,
            json_modify(
                auth_context_json, '$.event_time',
                datediff_big(millisecond, '1970-01-01', dateadd(day, -n, sysutcdatetime()))
            ),
            pre_auth_risk_decision, parameters_config_id, final_status,
            dateadd(day, -n, sysutcdatetime()),
            dateadd(second, 4, dateadd(day, -n, sysutcdatetime())),
            risk_eval_vars, net_loc_credibility, device_credibility, realm_id
        from src, days;
        """)
    elif needed > 1:
        env.psql(f"""
        with src as (
            select * from auth_process
            where user_id = '{victim_user}' and realm_id = '{c.REALM}'
                and final_status = 'LOGIN'
            order by started_at desc limit 1
        )
        insert into auth_process (
            id, user_id, auth_context_hash, device_info_hash, network_location_hash,
            auth_context_json, pre_auth_risk_decision, parameters_config_id,
            final_status, started_at, finished_at, risk_eval_vars,
            net_loc_credibility, device_credibility, realm_id)
        select uuid_generate_v4(), user_id, auth_context_hash, device_info_hash,
            network_location_hash,
            jsonb_set(
                auth_context_json::jsonb, '{{event_time}}',
                to_jsonb(extract(epoch from (now() - (n || ' days')::interval)) * 1000)
            )::json,
            pre_auth_risk_decision, parameters_config_id, final_status,
            now() - (n || ' days')::interval,
            now() - (n || ' days')::interval + interval '4 seconds',
            risk_eval_vars, net_loc_credibility, device_credibility, realm_id
        from src, generate_series(1, {needed - 1}) as n;
        """)

    # Positive control: a further login from the SAME familiar context is now
    # low risk, proving the history actually took and this account is a
    # meaningful target -- not one an isolation bug would be masked by an
    # already-cautious verdict either way.
    healthy_body = decision_body(token, {**familiar_ctx, "realm_id": c.REALM})
    healthy = post_decision(token, healthy_body)
    assert healthy.status_code == 200, healthy.text[:300]
    healthy_risk = healthy.json()["riskLevel"]
    assert healthy_risk == 1, (
        f"expected the familiar-context re-login to be low risk (1) once real "
        f"history exists, got Risk {healthy_risk}"
    )

    # The attacker: a token from an unrelated, ordinary realm, guessing the
    # victim's user_id, declaring its OWN (accepted) realm_id -- exactly the
    # attack described above.
    attacker_ctx = {
        **base_context,
        "user_id": victim_user,
        "ip_address": "203.0.113.5",
        "user_agent": "attacker-agent/1.0",
        "screen_resolution": "640x480",
    }
    attacker_body = decision_body(
        other_token, {**attacker_ctx, "realm_id": realm_name}
    )
    attacker_resp = post_decision(other_token, attacker_body)
    assert attacker_resp.status_code == 200, attacker_resp.text[:300]
    attacker_risk = attacker_resp.json()["riskLevel"]

    # Under the attacker's own realm partition this guessed user_id has zero
    # real records, so the engine must fall back to the insufficient-history
    # gate (a fixed Risk 3) -- never the victim's real, familiar-device Risk 1.
    # Seeing anything other than 3 here means it saw test-amfa's real history.
    assert attacker_risk == 3, (
        f"expected the insufficient-history verdict (3) since {realm_name!r} has "
        f"no real history for this guessed user_id, got Risk {attacker_risk} -- "
        f"a value other than 3 means the attacker's realm saw test-amfa's data"
    )

    # Direct check: the two realms' rows for this shared user_id must never mix,
    # each staying tagged with only the realm that actually produced it.
    rows = env.psql(
        f"select distinct realm_id from auth_process where user_id = '{victim_user}' "
        f"order by realm_id;"
    )
    realms_seen = {r for r in rows.splitlines() if r}
    assert realms_seen == {c.REALM, realm_name}, (
        f"expected exactly the two realms' own rows for this user_id, got "
        f"{realms_seen!r}"
    )
