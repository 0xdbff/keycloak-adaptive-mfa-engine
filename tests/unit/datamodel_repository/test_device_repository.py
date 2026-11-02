import asyncio
import pytest
from datetime import datetime

from sqlalchemy.exc import IntegrityError

from src.data.model.device import Device
from src.data.repository.device import DeviceRepository
from tests.fixture.util import unique_hash


def make_device(label: str) -> Device:
    """A device whose identity is unique to this run.

    A fixed hash collides with the row the previous run left behind, since these
    tests share one database and it is never reset.
    """
    return Device(
        hash=unique_hash(label),
        client="Client",
        device="Device",
        system_language="en",
        screen_resolution="1980x1080",
        operating_system="macOS",
        browser="Chrome",
        created_at=datetime.now(),
    )


@pytest.mark.asyncio(loop_scope="session")
async def test_create_device(tracked):
    device = make_device("test-create-device")

    created = await DeviceRepository.create_device(device)
    tracked.add(DeviceRepository.delete_device, created)

    assert created.hash == device.hash
    assert created.client == device.client
    assert created.device == device.device
    assert created.system_language == device.system_language
    assert created.screen_resolution == device.screen_resolution
    assert created.operating_system == device.operating_system
    assert created.browser == device.browser
    assert created.created_at == device.created_at


@pytest.mark.asyncio(loop_scope="session")
async def test_get_device_by_hash(tracked):
    device = make_device("test-get-device-by-hash")

    await DeviceRepository.create_device(device)
    tracked.add(DeviceRepository.delete_device, device)

    found = await DeviceRepository.get_device_by_hash(device.hash)

    assert found is not None
    assert found.hash == device.hash
    assert found.client == device.client
    assert found.device == device.device
    assert found.system_language == device.system_language
    assert found.screen_resolution == device.screen_resolution
    assert found.operating_system == device.operating_system
    assert found.browser == device.browser
    assert found.created_at == device.created_at


@pytest.mark.asyncio(loop_scope="session")
async def test_list_devices(tracked):
    for i in range(3):
        device = make_device(f"test-list-devices-{i}")
        await DeviceRepository.create_device(device)
        tracked.add(DeviceRepository.delete_device, device)

    all_devices = await DeviceRepository.list_devices()

    limited_devices = await DeviceRepository.list_devices(limit=2)

    assert len(all_devices) >= 3
    assert len(limited_devices) == 2


@pytest.mark.asyncio(loop_scope="session")
async def test_update_device(tracked):
    device = make_device("test-update-by-hash")

    saved = await DeviceRepository.create_device(device)
    tracked.add(DeviceRepository.delete_device, saved)

    saved.operating_system = "Windows"
    saved.browser = "Safari"
    updated = await DeviceRepository.update_device(saved)

    assert saved.operating_system == "Windows"
    assert updated.browser == "Safari"


@pytest.mark.asyncio(loop_scope="session")
async def test_delete_device():
    # No tracker here: deleting the row is what this test asserts.
    device_to_delete = make_device("test-delete-device")
    await DeviceRepository.create_device(device_to_delete)

    await DeviceRepository.delete_device(device_to_delete)

    deleted = await DeviceRepository.get_device_by_hash(device_to_delete.hash)
    assert deleted is None


@pytest.mark.asyncio(loop_scope="session")
async def test_create_device_twice_at_once_keeps_one_row(tracked):
    # Two first logins from the same new device run create_device for the same
    # hash at the same moment; the second insert must not fail.
    first = make_device("test-create-device-concurrent")
    second = make_device("unused")
    second.hash = first.hash

    created = await asyncio.gather(
        DeviceRepository.create_device(first),
        DeviceRepository.create_device(second),
    )
    tracked.add(DeviceRepository.delete_device, first)

    assert [c.hash for c in created] == [first.hash, first.hash]
    found = await DeviceRepository.get_device_by_hash(first.hash)
    assert found is not None
    assert found.browser == first.browser


@pytest.mark.asyncio(loop_scope="session")
async def test_create_device_that_exists_returns_the_stored_row(tracked):
    stored = make_device("test-create-device-existing")
    await DeviceRepository.create_device(stored)
    tracked.add(DeviceRepository.delete_device, stored)

    again = make_device("unused")
    again.hash = stored.hash
    again.browser = "Other"
    created = await DeviceRepository.create_device(again)

    assert created.hash == stored.hash
    assert created.browser == stored.browser


@pytest.mark.asyncio(loop_scope="session")
async def test_create_device_still_fails_on_other_errors():
    # Only an existing hash is tolerated; a row the database refuses for another
    # reason must still raise.
    device = make_device("test-create-device-invalid")
    device.system_language = None

    with pytest.raises(IntegrityError):
        await DeviceRepository.create_device(device)
