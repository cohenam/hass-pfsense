from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from homeassistant.exceptions import HomeAssistantError
import pytest

from custom_components.pfsense import update


def _entity(client):
    entity = object.__new__(update.PfSenseFirmwareUpdatesAvailableUpdate)
    entity.hass = SimpleNamespace(
        async_add_executor_job=AsyncMock(side_effect=lambda func, *args: func(*args))
    )
    entity.coordinator = Mock()
    entity._install_in_progress = False
    entity.async_write_ha_state = Mock()
    entity._get_pfsense_client = Mock(return_value=client)
    return entity


def test_update_is_unavailable_while_firmware_info_is_missing():
    entity = _entity(Mock())
    entity.coordinator.data = {"firmware_update_info": None}

    assert entity.available is False
    assert entity.extra_state_attributes == {}


@pytest.mark.asyncio
async def test_async_install_monitors_without_blocking_event_loop():
    client = Mock()
    client.upgrade_firmware.return_value = 123
    client.pid_is_running.side_effect = [True, False]
    entity = _entity(client)

    with patch.object(update.asyncio, "sleep", AsyncMock()) as sleep:
        await entity.async_install()

    assert sleep.await_count == 2
    assert client.pid_is_running.call_count == 2
    assert entity.in_progress is False
    assert entity.async_write_ha_state.call_count == 2


@pytest.mark.asyncio
async def test_async_install_rejects_parallel_install():
    client = Mock()
    entity = _entity(client)
    entity._install_in_progress = True

    with pytest.raises(HomeAssistantError, match="already in progress"):
        await entity.async_install()

    client.upgrade_firmware.assert_not_called()


@pytest.mark.asyncio
async def test_async_install_rejects_missing_pid():
    client = Mock()
    client.upgrade_firmware.return_value = None
    entity = _entity(client)

    with pytest.raises(HomeAssistantError, match="did not start"):
        await entity.async_install()

    assert entity.in_progress is False


@pytest.mark.asyncio
async def test_async_install_has_bounded_monitoring():
    client = Mock()
    client.upgrade_firmware.return_value = 123
    entity = _entity(client)

    with (
        patch.object(update, "FIRMWARE_INSTALL_TIMEOUT", 0),
        pytest.raises(HomeAssistantError, match="Timed out"),
    ):
        await entity.async_install()

    client.pid_is_running.assert_not_called()
    assert entity.in_progress is False
