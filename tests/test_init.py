import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from custom_components.pfsense import (
    PfSenseData,
    async_migrate_entry,
    async_unload_entry,
    dict_get,
)
from custom_components.pfsense.const import (
    CONF_TLS_INSECURE,
    DOMAIN,
    LOADED_PLATFORMS,
)


class FakeHass:
    async def async_add_executor_job(self, target, *args):
        return target(*args)

    def async_create_task(self, coro, name=None):
        return asyncio.create_task(coro, name=name)


def _interface(counter):
    return {
        key: counter
        for key in (
            "inbytes",
            "outbytes",
            "inbytespass",
            "outbytespass",
            "inbytesblock",
            "outbytesblock",
            "inpkts",
            "outpkts",
            "inpktspass",
            "outpktspass",
            "inpktsblock",
            "outpktsblock",
        )
    }


def _client(telemetry):
    client = Mock()
    client.get_system_info.return_value = {
        "hostname": "router",
        "domain": "example",
        "netgate_device_id": "device-id",
    }
    client.get_host_firmware_version.return_value = {
        "platform": "pfSense",
        "firmware": {"version": "2.8.1"},
    }
    client.get_telemetry.return_value = telemetry
    client.get_config.return_value = {}
    client.get_services.return_value = []
    client.get_carp_interfaces.return_value = []
    client.get_carp_status.return_value = {}
    client.get_dhcp_leases.return_value = []
    client.are_notices_pending.return_value = False
    client.get_notices.return_value = []
    return client


def test_dict_get_returns_default_for_missing_or_wrong_shape():
    assert dict_get({"items": [{"value": 1}]}, "items.0.value") == 1
    assert dict_get({"items": []}, "items.0.value", "missing") == "missing"
    assert dict_get(None, "items", "missing") == "missing"


@pytest.mark.asyncio
async def test_migration_updates_data_and_version_through_home_assistant():
    config_entry = SimpleNamespace(
        version=1,
        data={CONF_TLS_INSECURE: True, "url": "https://router"},
    )
    hass = SimpleNamespace(config_entries=SimpleNamespace(async_update_entry=Mock()))

    assert await async_migrate_entry(hass, config_entry) is True

    hass.config_entries.async_update_entry.assert_called_once_with(
        config_entry,
        data={"url": "https://router", "verify_ssl": False},
        version=2,
    )
    assert config_entry.version == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("unload_ok", [False, True])
async def test_unload_only_removes_runtime_data_after_platforms_unload(unload_ok):
    entry = SimpleNamespace(entry_id="entry")
    runtime_data = {LOADED_PLATFORMS: ["sensor", "switch"]}
    hass = SimpleNamespace(
        data={DOMAIN: {"entry": runtime_data}},
        config_entries=SimpleNamespace(
            async_unload_platforms=AsyncMock(return_value=unload_ok)
        ),
    )

    assert await async_unload_entry(hass, entry) is unload_ok
    assert ("entry" not in hass.data[DOMAIN]) is unload_ok


def test_failed_refresh_retains_last_good_state():
    client = _client({})
    client.get_telemetry.side_effect = TimeoutError
    data = PfSenseData(
        client,
        SimpleNamespace(entry_id="entry", options={}),
        FakeHass(),
    )
    data._state = {"last_good": True}

    with pytest.raises(TimeoutError):
        data.update()

    assert data.state == {"last_good": True}


def test_slow_metadata_is_cached_until_invalidated():
    client = _client({"interfaces": {}, "openvpn": {"servers": {}}})
    data = PfSenseData(
        client,
        SimpleNamespace(entry_id="entry", options={}),
        FakeHass(),
    )

    data.update()
    data.update()

    assert client.get_system_info.call_count == 1
    assert client.get_config.call_count == 1
    assert client.get_telemetry.call_count == 2
    client.are_notices_pending.assert_not_called()

    data.invalidate_slow_state()
    data.update()

    assert client.get_system_info.call_count == 2
    assert client.get_config.call_count == 2


def test_counter_reset_is_ignored_and_new_interface_does_not_stop_rates():
    telemetry = {
        "interfaces": {
            "new": _interface(10),
            "wan": _interface(200),
        },
        "openvpn": {"servers": {}},
    }
    data = PfSenseData(
        _client(telemetry),
        SimpleNamespace(entry_id="entry", options={}),
        FakeHass(),
    )
    data._state = {
        "update_time": 1.0,
        "telemetry": {
            "interfaces": {
                "wan": _interface(100),
            },
            "openvpn": {"servers": {}},
        },
    }

    data.update()

    assert (
        "inbytes_kilobytes_per_second"
        not in data.state["telemetry"]["interfaces"]["new"]
    )
    assert (
        data.state["telemetry"]["interfaces"]["wan"]["inbytes_kilobytes_per_second"]
        >= 0
    )


def test_decreasing_counter_does_not_create_positive_rate():
    telemetry = {
        "interfaces": {"wan": _interface(10)},
        "openvpn": {"servers": {}},
    }
    data = PfSenseData(
        _client(telemetry),
        SimpleNamespace(entry_id="entry", options={}),
        FakeHass(),
    )
    data._state = {
        "update_time": 1.0,
        "telemetry": {
            "interfaces": {"wan": _interface(100)},
            "openvpn": {"servers": {}},
        },
    }

    data.update()

    assert not any(
        key.endswith(("_per_second",))
        for key in data.state["telemetry"]["interfaces"]["wan"]
    )


@pytest.mark.asyncio
async def test_firmware_refresh_is_coalesced_and_cached():
    client = Mock()
    client.get_firmware_update_info.return_value = {"base": {"version": "2.8.1"}}
    data = PfSenseData(
        client,
        SimpleNamespace(entry_id="entry", options={}),
        FakeHass(),
    )

    data.async_schedule_firmware_refresh()
    first_task = data._firmware_task
    data.async_schedule_firmware_refresh()

    await first_task
    data.async_schedule_firmware_refresh()

    assert client.get_firmware_update_info.call_count == 1
    assert data._firmware_task is first_task


@pytest.mark.asyncio
async def test_failed_firmware_refresh_is_throttled():
    client = Mock()
    client.get_firmware_update_info.side_effect = TimeoutError
    data = PfSenseData(
        client,
        SimpleNamespace(entry_id="entry", options={}),
        FakeHass(),
    )

    data.async_schedule_firmware_refresh()
    await data._firmware_task
    data.async_schedule_firmware_refresh()

    assert client.get_firmware_update_info.call_count == 1
