from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from homeassistant.exceptions import ServiceValidationError
import pytest

from custom_components.pfsense import services
from custom_components.pfsense.const import (
    CONF_ALLOW_UNSAFE_SERVICES,
    COORDINATOR,
    DOMAIN,
    PFSENSE_CLIENT,
    PFSENSE_DATA,
    SERVICE_EXEC_COMMAND,
    SERVICE_SYSTEM_REBOOT,
)


def _hass(entries):
    clients = {entry_id: Mock() for entry_id in entries}
    pfsense_data = {
        entry_id: Mock(invalidate_slow_state=Mock()) for entry_id in entries
    }
    coordinators = {
        entry_id: Mock(async_request_refresh=AsyncMock()) for entry_id in entries
    }
    runtime = {
        entry_id: {
            PFSENSE_CLIENT: clients[entry_id],
            PFSENSE_DATA: pfsense_data[entry_id],
            COORDINATOR: coordinators[entry_id],
        }
        for entry_id in entries
    }
    hass = SimpleNamespace(
        data={DOMAIN: runtime},
        config_entries=SimpleNamespace(async_get_entry=Mock(side_effect=entries.get)),
        async_add_executor_job=AsyncMock(side_effect=lambda func, *args: func(*args)),
    )
    return hass, clients, pfsense_data, coordinators


@pytest.mark.asyncio
async def test_service_dispatches_once_per_config_entry_and_refreshes_once():
    entries = {
        "entry-1": SimpleNamespace(data={}, options={}),
        "entry-2": SimpleNamespace(data={}, options={}),
    }
    hass, clients, pfsense_data, coordinators = _hass(entries)
    call = SimpleNamespace(
        service=SERVICE_SYSTEM_REBOOT,
        data={"entity_id": [f"sensor.pfsense_{index}" for index in range(100)]},
    )

    with patch.object(
        services,
        "async_extract_config_entry_ids",
        AsyncMock(return_value={"entry-1", "entry-2"}),
    ):
        await services.ServiceRegistrar(hass)._async_send_service(call)

    clients["entry-1"].system_reboot.assert_called_once_with()
    clients["entry-2"].system_reboot.assert_called_once_with()
    pfsense_data["entry-1"].invalidate_slow_state.assert_called_once_with()
    pfsense_data["entry-2"].invalidate_slow_state.assert_called_once_with()
    coordinators["entry-1"].async_request_refresh.assert_awaited_once_with()
    coordinators["entry-2"].async_request_refresh.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_raw_service_is_rejected_for_all_targets_before_dispatch():
    entries = {
        "enabled": SimpleNamespace(data={}, options={CONF_ALLOW_UNSAFE_SERVICES: True}),
        "disabled": SimpleNamespace(data={}, options={}),
    }
    hass, clients, _pfsense_data, _coordinators = _hass(entries)
    call = SimpleNamespace(
        service=SERVICE_EXEC_COMMAND,
        data={"entity_id": ["sensor.one"], "command": "id"},
    )

    with (
        patch.object(
            services,
            "async_extract_config_entry_ids",
            AsyncMock(return_value={"enabled", "disabled"}),
        ),
        pytest.raises(ServiceValidationError, match="disabled"),
    ):
        await services.ServiceRegistrar(hass)._async_send_service(call)

    hass.async_add_executor_job.assert_not_awaited()
    clients["enabled"]._exec_command.assert_not_called()
    clients["disabled"]._exec_command.assert_not_called()


@pytest.mark.asyncio
async def test_raw_service_runs_when_config_entry_opted_in():
    entries = {
        "entry-1": SimpleNamespace(data={}, options={CONF_ALLOW_UNSAFE_SERVICES: True})
    }
    hass, clients, pfsense_data, coordinators = _hass(entries)
    call = SimpleNamespace(
        service=SERVICE_EXEC_COMMAND,
        data={
            "entity_id": ["sensor.one"],
            "command": "id",
            "background": True,
        },
    )

    with patch.object(
        services,
        "async_extract_config_entry_ids",
        AsyncMock(return_value={"entry-1"}),
    ):
        await services.ServiceRegistrar(hass)._async_send_service(call)

    clients["entry-1"]._exec_command.assert_called_once_with("id", True)
    pfsense_data["entry-1"].invalidate_slow_state.assert_called_once_with()
    coordinators["entry-1"].async_request_refresh.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_service_rejects_target_without_loaded_pfsense_entry():
    hass, _clients, _pfsense_data, _coordinators = _hass({})
    call = SimpleNamespace(
        service=SERVICE_SYSTEM_REBOOT,
        data={"entity_id": ["sensor.unrelated"]},
    )

    with (
        patch.object(
            services,
            "async_extract_config_entry_ids",
            AsyncMock(return_value={"unrelated"}),
        ),
        pytest.raises(ServiceValidationError, match="loaded pfSense"),
    ):
        await services.ServiceRegistrar(hass)._async_send_service(call)


def test_all_services_register_as_admin_services():
    hass = SimpleNamespace(
        services=SimpleNamespace(has_service=Mock(return_value=False))
    )

    with patch.object(services, "async_register_admin_service") as register:
        services.ServiceRegistrar(hass).async_register()

    registered = {call.args[2] for call in register.call_args_list}
    assert registered == {
        services.SERVICE_CLOSE_NOTICE,
        services.SERVICE_FILE_NOTICE,
        services.SERVICE_START_SERVICE,
        services.SERVICE_STOP_SERVICE,
        services.SERVICE_RESTART_SERVICE,
        services.SERVICE_RESET_STATE_TABLE,
        services.SERVICE_KILL_STATES,
        services.SERVICE_SYSTEM_HALT,
        services.SERVICE_SYSTEM_REBOOT,
        services.SERVICE_SEND_WOL,
        services.SERVICE_SET_DEFAULT_GATEWAY,
        services.SERVICE_EXEC_COMMAND,
        services.SERVICE_EXEC_PHP,
    }
