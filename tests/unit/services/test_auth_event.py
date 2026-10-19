import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4
from datetime import datetime

from src.data.model import AuthEvent, AuthProcess
from src.data.schema import WebhookPayload
from src.service.auth_event import AuthEventService


@pytest.mark.asyncio
async def test_process_auth_event(mocker):
    mock_user_id = str(uuid4())
    mock_process_id = str(uuid4())

    mock_auth_event = AuthEvent(
        auth_process=mock_process_id,
        user_id=mock_user_id,
        event_type="LOGIN",
        auth_context_hash="hash",
        device_info_hash=str(uuid4()),
        network_location_hash="location_network.hash",
        event_time=datetime.now(),
    )

    mock_auth_process = AuthProcess(
        user_id=mock_user_id,
        auth_context_hash="hash",
        device_info_hash="device_hash",
        network_location_hash="location_network.hash",
        auth_context_json={},
        pre_auth_risk_decision=1,
        parameters_config_id="decision_id",
        final_status="LOGIN",
        started_at=datetime.now(),
        device_credibility=0.3,
        net_loc_credibility=0.2,
    )

    payload = WebhookPayload(
        **{
            "type": "LOGIN",
            "id": "uuid",
            "timestamp": 1,
            "data": {
                "user_id": mock_user_id,
                "event_timestamp": 1,
                "auth_context_hash": "hash",
            },
            "authContextModel": {
                "client": "client",
                "ip_address": "8.8.8.8",
                "user_agent": "user_agent",
                "system_language": "en",
                "screen_resolution": "1980x1020",
            },
        }
    )

    service = AuthEventService(payload=payload, realm="test-amfa")

    mocker.patch.object(service, "redis", autospec=True)
    mock_partial_from_request = mocker.patch(
        "src.data.factory.AuthEventFactory.partial_from_request",
        return_value=mock_auth_event,
    )

    mock_get_open_auth_process = mocker.patch.object(
        service,
        "_AuthEventService__get_open_auth_process",
        return_value=mock_process_id,
    )

    mock_update_redis_cache = mocker.patch.object(
        service, "_AuthEventService__update_redis_cache", new_callable=AsyncMock
    )
    mocker.patch.object(
        service, "_AuthEventService__delete_redis_cache", new_callable=AsyncMock
    )

    mock_create_auth_event = mocker.patch(
        "src.data.repository.AuthEventRepository.create_auth_event",
        new_callable=AsyncMock,
    )

    mock_get_auth_process_by_id = mocker.patch(
        "src.data.repository.AuthProcessRepository.get_auth_process_by_id",
        return_value=mock_auth_process,
    )

    mock_update_auth_process = mocker.patch(
        "src.data.repository.AuthProcessRepository.update_auth_process",
        new_callable=AsyncMock,
    )

    await service._AuthEventService__process_auth_event()

    mock_partial_from_request.assert_called_once_with(payload, realm="test-amfa")
    mock_get_open_auth_process.assert_called_once_with(mock_user_id)
    mock_update_redis_cache.assert_called_once_with(
        event_type="LOGIN", user_id=mock_user_id
    )
    mock_create_auth_event.assert_called_once_with(mock_auth_event)

    mock_get_auth_process_by_id.assert_called_once_with(
        mock_process_id, realm_id="test-amfa"
    )
    mock_update_auth_process.assert_called_once()


@pytest.mark.asyncio
async def test_process_auth_event_raise_error_if_auth_process_does_not_exist(mocker):
    mock_user_id = str(uuid4())
    mock_process_id = str(uuid4())

    mock_auth_event = AuthEvent(
        auth_process=mock_process_id,
        user_id=mock_user_id,
        event_type="LOGIN",
        auth_context_hash="hash",
        device_info_hash=str(uuid4()),
        network_location_hash="location_network.hash",
        event_time=datetime.now(),
    )
    payload = WebhookPayload(
        **{
            "type": "LOGIN",
            "id": "uuid",
            "timestamp": 1,
            "data": {
                "user_id": mock_user_id,
                "event_timestamp": 1,
                "auth_context_hash": "hash",
            },
            "authContextModel": {
                "client": "client",
                "ip_address": "8.8.8.8",
                "user_agent": "user_agent",
                "system_language": "en",
                "screen_resolution": "1980x1020",
            },
        }
    )

    service = AuthEventService(payload=payload, realm="test-amfa")

    mocker.patch.object(service, "redis", autospec=True)
    mock_partial_from_request = mocker.patch(
        "src.data.factory.AuthEventFactory.partial_from_request",
        return_value=mock_auth_event,
    )

    mock_get_open_auth_process = mocker.patch.object(
        service,
        "_AuthEventService__get_open_auth_process",
        return_value=mock_process_id,
    )

    mock_update_redis_cache = mocker.patch.object(
        service, "_AuthEventService__update_redis_cache", new_callable=AsyncMock
    )

    mock_create_auth_event = mocker.patch(
        "src.data.repository.AuthEventRepository.create_auth_event",
        new_callable=AsyncMock,
    )

    mock_get_auth_process_by_id = mocker.patch(
        "src.data.repository.AuthProcessRepository.get_auth_process_by_id",
        return_value=None,
    )

    mock_update_auth_process = mocker.patch(
        "src.data.repository.AuthProcessRepository.update_auth_process",
        new_callable=AsyncMock,
    )

    with pytest.raises(ValueError) as exc_info:
        await service._AuthEventService__process_auth_event()

    assert (
        str(exc_info.value)
        == "Authentication process does not exist, cannot update final authentication status"
    )

    mock_partial_from_request.assert_called_once_with(payload, realm="test-amfa")
    mock_get_open_auth_process.assert_called_once_with(mock_user_id)
    mock_update_redis_cache.assert_called_once_with(
        event_type="LOGIN", user_id=mock_user_id
    )
    mock_create_auth_event.assert_called_once_with(mock_auth_event)

    mock_get_auth_process_by_id.assert_called_once_with(
        mock_process_id, realm_id="test-amfa"
    )
    mock_update_auth_process.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["LOGIN", "LOGIN_ERROR"])
async def test_final_event_without_open_process_is_stored_unlinked(
    mocker, event_type
):
    """A final event that arrives after the user's auth process expired, or
    without one, is still stored, linked to no process, so monitoring sees
    it. There is no process to finalize."""
    mock_user_id = str(uuid4())
    mock_auth_event = AuthEvent(
        user_id=mock_user_id,
        event_type=event_type,
        auth_context_hash="hash",
        device_info_hash=str(uuid4()),
        network_location_hash="location_network.hash",
        event_time=datetime.now(),
    )
    payload = _minimal_payload(mock_user_id)
    payload.event_type = event_type

    service = AuthEventService(payload=payload, realm="test-amfa")

    mocker.patch.object(service, "redis", autospec=True)
    mocker.patch(
        "src.data.factory.AuthEventFactory.partial_from_request",
        return_value=mock_auth_event,
    )
    mocker.patch.object(
        service,
        "_AuthEventService__get_open_auth_process",
        return_value=None,
    )
    mock_update_redis_cache = mocker.patch.object(
        service, "_AuthEventService__update_redis_cache", new_callable=AsyncMock
    )
    mock_create_auth_event = mocker.patch(
        "src.data.repository.AuthEventRepository.create_auth_event",
        new_callable=AsyncMock,
    )
    mock_get_auth_process_by_id = mocker.patch(
        "src.data.repository.AuthProcessRepository.get_auth_process_by_id",
        new_callable=AsyncMock,
    )

    await service._AuthEventService__process_auth_event()

    mock_create_auth_event.assert_called_once_with(mock_auth_event)
    assert mock_auth_event.auth_process is None
    mock_update_redis_cache.assert_called_once_with(
        event_type=event_type, user_id=mock_user_id
    )
    mock_get_auth_process_by_id.assert_not_called()


def _minimal_payload(user_id: str) -> WebhookPayload:
    return WebhookPayload(
        **{
            "type": "LOGIN",
            "id": "uuid",
            "timestamp": 1,
            "data": {
                "user_id": user_id,
                "event_timestamp": 1,
                "auth_context_hash": "hash",
            },
            "authContextModel": {
                "client": "client",
                "ip_address": "8.8.8.8",
                "user_agent": "user_agent",
                "system_language": "en",
                "screen_resolution": "1980x1020",
            },
        }
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_open_auth_process_pointer_is_isolated_by_realm():
    """Regression for the tenant-isolation fix: the
    Redis pointer connecting a webhook event to its pending AuthProcess row
    must be scoped by the realm that SIGNED the event, not by user_id alone.
    Otherwise a caller in realm A can plant/overwrite a pointer for a
    guessed/colliding user_id and hijack finalization of realm B's real login
    (or vice versa read/clear realm B's pointer). Exercises a real Redis
    connection (env-configured), same as this repo's other "unit" tests that
    are really integration tests against live backing services.
    """
    user_id = str(uuid4())
    victim = AuthEventService(payload=_minimal_payload(user_id), realm="victim-realm")
    attacker = AuthEventService(payload=_minimal_payload(user_id), realm="attacker-realm")

    # Matches the production key format (auth_process:{realm}:{user_id})
    # intentionally, to set up state for the private read/delete methods
    # under test without going through the full write path in decision.py.
    victim_key = "auth_process:victim-realm:" + user_id
    attacker_key = "auth_process:attacker-realm:" + user_id
    await victim.redis.set(victim_key, "victim-process-id", ex=60)

    try:
        assert (
            await attacker._AuthEventService__get_open_auth_process(user_id) is None
        )
        assert (
            await victim._AuthEventService__get_open_auth_process(user_id)
            == "victim-process-id"
        )

        # The attacker's delete must not be able to clear the victim's pointer.
        await attacker._AuthEventService__delete_redis_cache(user_id)
        assert await victim.redis.get(victim_key) == "victim-process-id"
    finally:
        await victim.redis.delete(victim_key)
        await victim.redis.delete(attacker_key)
