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


def _service_without_open_process(mocker, event_type: str, event_id: str, user_id: str):
    """A service for a final event that finds no open process, with the
    repository calls stubbed. Returns (service, auth_event, mocks)."""
    auth_event = AuthEvent(
        user_id=user_id,
        event_type=event_type,
        auth_context_hash="hash",
        device_info_hash=str(uuid4()),
        network_location_hash="location_network.hash",
        event_time=datetime.now(),
    )
    payload = _minimal_payload(user_id)
    payload.event_type = event_type
    payload.id = event_id
    service = AuthEventService(payload=payload, realm="test-amfa")
    mocker.patch.object(service, "redis", autospec=True)
    mocker.patch(
        "src.data.factory.AuthEventFactory.partial_from_request",
        return_value=auth_event,
    )
    mocker.patch.object(
        service, "_AuthEventService__get_open_auth_process", return_value=None
    )
    mocker.patch.object(
        service, "_AuthEventService__update_redis_cache", new_callable=AsyncMock
    )
    mocks = {
        "create": mocker.patch(
            "src.data.repository.AuthEventRepository.create_auth_event",
            new_callable=AsyncMock,
        ),
        "get": mocker.patch(
            "src.data.repository.AuthProcessRepository.get_auth_process_by_id",
            new_callable=AsyncMock,
        ),
        "update": mocker.patch(
            "src.data.repository.AuthProcessRepository.update_auth_process",
            new_callable=AsyncMock,
        ),
        "delete_cache": mocker.patch.object(
            service, "_AuthEventService__delete_redis_cache", new_callable=AsyncMock
        ),
    }
    return service, auth_event, mocks


def _process(user_id: str, final_status):
    return AuthProcess(
        user_id=user_id,
        auth_context_hash="hash",
        device_info_hash="device_hash",
        network_location_hash="location_network.hash",
        auth_context_json={},
        pre_auth_risk_decision=2,
        parameters_config_id="decision_id",
        final_status=final_status,
        started_at=datetime.now(),
        device_credibility=0.3,
        net_loc_credibility=0.2,
    )


@pytest.mark.asyncio
async def test_login_after_a_wrong_code_closes_its_own_decision(mocker):
    """A wrong code closes the decision as LOGIN_ERROR and removes the open
    pointer, so the LOGIN of the right code finds nothing open. That LOGIN
    carries the decision's id, so it is linked to it and the decision ends as
    LOGIN."""
    user_id, process_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", process_id, user_id)
    process = _process(user_id, "LOGIN_ERROR")
    m["get"].return_value = process

    await service._AuthEventService__process_auth_event()

    m["get"].assert_awaited_once_with(process_id, realm_id="test-amfa")
    assert str(auth_event.auth_process) == process_id
    assert process.final_status == "LOGIN"
    m["update"].assert_awaited_once_with(process)
    m["create"].assert_awaited_once_with(auth_event)
    # There is no open pointer to clear, and a newer one must not be cleared.
    m["delete_cache"].assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["LOGIN", "LOGIN_ERROR"])
async def test_final_event_closes_its_own_expired_decision(mocker, event_type):
    """A decision whose 5 minute pointer expired before the outcome arrived
    still has the status it was created with; the outcome under its id
    closes it."""
    user_id, process_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, event_type, process_id, user_id)
    process = _process(user_id, "pre-auth")
    m["get"].return_value = process

    await service._AuthEventService__process_auth_event()

    assert str(auth_event.auth_process) == process_id
    assert process.final_status == event_type
    m["update"].assert_awaited_once_with(process)


@pytest.mark.asyncio
async def test_login_error_does_not_undo_a_successful_decision(mocker):
    user_id, process_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN_ERROR", process_id, user_id)
    process = _process(user_id, "LOGIN")
    m["get"].return_value = process

    await service._AuthEventService__process_auth_event()

    assert str(auth_event.auth_process) == process_id
    assert process.final_status == "LOGIN"
    m["update"].assert_not_called()


@pytest.mark.asyncio
async def test_decision_of_another_user_is_left_alone(mocker):
    user_id, process_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", process_id, user_id)
    process = _process(str(uuid4()), "LOGIN_ERROR")
    m["get"].return_value = process

    await service._AuthEventService__process_auth_event()

    assert auth_event.auth_process is None
    assert process.final_status == "LOGIN_ERROR"
    m["update"].assert_not_called()
    m["create"].assert_awaited_once_with(auth_event)


@pytest.mark.asyncio
async def test_event_id_that_is_not_a_uuid_is_not_looked_up(mocker):
    user_id = str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", "not-a-uuid", user_id)

    await service._AuthEventService__process_auth_event()

    m["get"].assert_not_called()
    assert auth_event.auth_process is None
    m["create"].assert_awaited_once_with(auth_event)


@pytest.mark.asyncio
async def test_non_final_event_without_open_process_is_not_looked_up(mocker):
    user_id, process_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "UPDATE_TOTP", process_id, user_id)

    await service._AuthEventService__process_auth_event()

    m["get"].assert_not_called()
    assert auth_event.auth_process is None


@pytest.mark.asyncio
async def test_event_id_naming_no_decision_falls_back_to_the_open_one(mocker):
    """An outcome whose id names no decision (a login without AMFA's step, or
    one sent under Keycloak's own event id) is linked through the open pointer
    exactly as before."""
    user_id, open_id, event_id = str(uuid4()), str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", event_id, user_id)
    mocker.patch.object(
        service, "_AuthEventService__get_open_auth_process", return_value=open_id
    )
    process = _process(user_id, "pre-auth")
    m["get"].side_effect = lambda pid, realm_id: process if pid == open_id else None

    await service._AuthEventService__process_auth_event()

    assert auth_event.auth_process == open_id
    assert process.final_status == "LOGIN"
    m["update"].assert_awaited_once_with(process)
    m["delete_cache"].assert_awaited_once()


@pytest.mark.asyncio
async def test_event_id_naming_the_open_decision_closes_it_as_usual(mocker):
    user_id, open_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", open_id, user_id)
    mocker.patch.object(
        service, "_AuthEventService__get_open_auth_process", return_value=open_id
    )
    process = _process(user_id, "pre-auth")
    m["get"].return_value = process

    await service._AuthEventService__process_auth_event()

    assert str(auth_event.auth_process) == open_id
    assert process.final_status == "LOGIN"
    m["update"].assert_awaited_once_with(process)
    m["delete_cache"].assert_awaited_once()


@pytest.mark.asyncio
async def test_open_decision_is_recognised_whatever_the_id_spelling(mocker):
    """The pointer holds the decision id as the client sent it; an outcome
    naming the same decision in another spelling still clears it."""
    user_id, open_id = str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", open_id, user_id)
    mocker.patch.object(
        service, "_AuthEventService__get_open_auth_process", return_value=open_id.upper()
    )
    process = _process(user_id, "pre-auth")
    m["get"].return_value = process

    await service._AuthEventService__process_auth_event()

    assert process.final_status == "LOGIN"
    m["delete_cache"].assert_awaited_once()


@pytest.mark.asyncio
async def test_event_id_wins_over_a_newer_open_decision(mocker):
    """The same user logs in twice at once: the pointer names the newer
    decision, while the first login's outcome carries the older one's id. It is
    linked to its own decision, and the newer one stays open for its login."""
    user_id, older_id, newer_id = str(uuid4()), str(uuid4()), str(uuid4())
    service, auth_event, m = _service_without_open_process(mocker, "LOGIN", older_id, user_id)
    mocker.patch.object(
        service, "_AuthEventService__get_open_auth_process", return_value=newer_id
    )
    older, newer = _process(user_id, "pre-auth"), _process(user_id, "pre-auth")
    m["get"].side_effect = lambda pid, realm_id: {older_id: older, newer_id: newer}.get(pid)

    await service._AuthEventService__process_auth_event()

    assert str(auth_event.auth_process) == older_id
    assert older.final_status == "LOGIN"
    assert newer.final_status == "pre-auth"
    m["update"].assert_awaited_once_with(older)
    m["delete_cache"].assert_not_called()
