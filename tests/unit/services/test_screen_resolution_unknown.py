"""A login that reports no screen resolution is scored with it as unknown.

Direct grant logins, and browser flows without the screen resolution step, have
no screen resolution. The engine refused their /auth_context and /decision
calls (422), so the login got no score at all. The value is now optional: a
missing one is left out of the comparison with earlier logins, earns no trust,
and is stored empty in the device fingerprint, which is what the event webhook
already stores for such a login.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from src.data.factory.device import DeviceFactory
from src.data.schema import AuthContextSchema, DecisionRequest
from src.service.decision import DecisionService
from src.service.risk_evaluation.scoring.log_odds import LogOddsScorer


def _decision_kwargs(**overrides) -> dict:
    base = {
        "event_id": "e",
        "group_id": "g",
        "realm_id": "r",
        "user_id": "u",
        "client": "c",
        "ip_address": "1.1.1.1",
        "user_agent": "ua",
        "system_language": "en",
    }
    base.update(overrides)
    return base


def test_decision_request_without_screen_resolution_or_context_hash_is_accepted():
    req = DecisionRequest(**_decision_kwargs())
    assert req.screen_resolution is None
    assert req.auth_context_hash is None


@pytest.mark.parametrize("value", ["", "not-a-resolution"])
def test_decision_request_still_refuses_a_malformed_screen_resolution(value):
    # Only a missing value means "no screen resolution"; a present one must
    # still have the "<width>x<height>" form.
    with pytest.raises(ValidationError) as exc_info:
        DecisionRequest(**_decision_kwargs(screen_resolution=value))
    assert "screen_resolution" in str(exc_info.value)


def test_auth_context_without_screen_resolution_is_accepted():
    ctx = AuthContextSchema(
        client="c", ip_address="1.1.1.1", user_agent="ua", system_language="en"
    )
    assert ctx.screen_resolution is None


@pytest.mark.asyncio
async def test_missing_and_empty_screen_resolution_give_the_same_device(mocker):
    mocker.patch(
        "src.data.factory.device.get_cached_device_by_hash",
        new_callable=AsyncMock,
        return_value=None,
    )
    create = mocker.patch(
        "src.data.factory.device.DeviceRepository.create_device",
        new_callable=AsyncMock,
    )

    def request(screen):
        r = MagicMock(AuthContextSchema)
        r.client, r.user_agent, r.system_language = "c", "Mozilla/5.0", "en"
        r.screen_resolution = screen
        return r

    missing = await DeviceFactory.identify_from_auth_request(request(None))
    empty = await DeviceFactory.identify_from_auth_request(request(""))

    assert missing == empty
    assert create.await_args_list[0].args[0].screen_resolution == ""


def test_bucketing_a_missing_screen_resolution_returns_it_unchanged():
    assert DecisionService._bucket_screen_resolution(None, "user-1") is None


def _changed_vars(previous_screen, current_screen):
    svc = DecisionService.__new__(DecisionService)
    svc.decision_params = {"screen_resolution": {"enabled": True, "weight": 3}}
    return svc._DecisionService__detect_param_change_short_term(
        {
            "previous_event": {"screen_resolution": previous_screen},
            "current_event": {"screen_resolution": current_screen},
        }
    )


def test_a_login_without_screen_resolution_is_not_a_screen_change():
    assert _changed_vars("1920x1080", None) == []


def test_a_previous_login_without_screen_resolution_is_not_a_screen_change():
    assert _changed_vars(None, "1920x1080") == []
    assert _changed_vars("", "1920x1080") == []


def test_two_different_screen_resolutions_are_still_a_change():
    assert _changed_vars("1920x1080", "1280x720") == ["screen_resolution"]


def test_unavailable_screen_resolution_earns_no_trust():
    params = {"screen_resolution": {"enabled": True, "weight": 3}}
    known = LogOddsScorer(params, bias=0.0).score([], 0.5, 0.5)
    unknown = LogOddsScorer(params, bias=0.0).score(
        [], 0.5, 0.5, unavailable_vars=["screen_resolution"]
    )

    assert "screen_resolution" not in unknown.contributions
    assert known.contributions["screen_resolution"] < 0
    assert unknown.evidence > known.evidence


def test_signals_unavailable_for_this_login_lists_a_missing_screen():
    assert DecisionService._unavailable_signals(
        {"previous_event": {"screen_resolution": "1920x1080"}, "current_event": {}}
    ) == {"screen_resolution"}
    assert DecisionService._unavailable_signals(
        {
            "previous_event": {"screen_resolution": "1920x1080"},
            "current_event": {"screen_resolution": "1280x720"},
        }
    ) == set()


def test_first_login_with_a_screen_resolution_keeps_the_signal():
    # No earlier login to compare with is not the same as an earlier login
    # without a screen: a first login's scoring must not change.
    assert DecisionService._unavailable_signals(
        {"previous_event": {}, "current_event": {"screen_resolution": "1920x1080"}}
    ) == set()
