import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

import pytest

from custom_components.pfsense import device_tracker
from custom_components.pfsense.const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICES,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    PFSENSE_CLIENT,
)


def _entity(state, *, consider_home=0):
    entity = object.__new__(device_tracker.PfSenseScannerEntity)
    entity.coordinator = SimpleNamespace(data=state)
    entity.config_entry = SimpleNamespace(
        options={CONF_DEVICE_TRACKER_CONSIDER_HOME: consider_home}
    )
    entity._mac_address = "aa:bb:cc:dd:ee:ff"
    entity._last_known_ip = None
    entity._last_known_hostname = None
    entity._last_known_connected_time = None
    entity._extra_state = {}
    return entity


@pytest.mark.asyncio
async def test_mac_vendor_data_loads_cache_first():
    lookup = Mock()
    lookup.load_vendors = AsyncMock()
    lookup.update_vendors = AsyncMock()

    with patch.object(device_tracker, "AsyncMacLookup", return_value=lookup):
        assert await device_tracker._async_load_mac_vendor_lookup() is lookup

    lookup.load_vendors.assert_awaited_once_with()
    lookup.update_vendors.assert_not_awaited()


@pytest.mark.asyncio
async def test_mac_vendor_data_updates_only_when_cache_load_fails():
    lookup = Mock()
    lookup.load_vendors = AsyncMock(side_effect=FileNotFoundError)
    lookup.update_vendors = AsyncMock()

    with patch.object(device_tracker, "AsyncMacLookup", return_value=lookup):
        assert await device_tracker._async_load_mac_vendor_lookup() is lookup

    lookup.update_vendors.assert_awaited_once_with()


def test_tracked_arp_ips_are_filtered_and_deduplicated():
    state = {
        "arp_table": [
            {
                "mac-address": "AA:BB:CC:DD:EE:FF",
                "ip-address": "192.0.2.10",
            },
            {
                "mac-address": "11:22:33:44:55:66",
                "ip-address": "192.0.2.20",
            },
            {
                "mac-address": "aa:bb:cc:dd:ee:ff",
                "ip-address": "192.0.2.10",
            },
        ]
    }

    assert device_tracker._tracked_arp_ips(
        state,
        ["aa:bb:cc:dd:ee:ff"],
    ) == ["192.0.2.10"]


@pytest.mark.asyncio
async def test_setup_batches_arp_cleanup_once_per_refresh():
    state = {
        "arp_table_by_mac": {
            "aa:bb:cc:dd:ee:ff": {"ip-address": "192.0.2.10"},
            "11:22:33:44:55:66": {"ip-address": "192.0.2.20"},
        }
    }
    coordinator = Mock(data=state)
    coordinator.async_add_listener.return_value = Mock()
    client = Mock()
    config_entry = Mock(
        entry_id="entry",
        options={
            CONF_DEVICES: [
                "11:22:33:44:55:66",
                "aa:bb:cc:dd:ee:ff",
            ]
        },
    )
    hass = SimpleNamespace(
        data={
            DOMAIN: {
                "entry": {
                    DEVICE_TRACKER_COORDINATOR: coordinator,
                    PFSENSE_CLIENT: client,
                }
            }
        },
        async_add_executor_job=AsyncMock(side_effect=lambda func, *args: func(*args)),
        async_create_task=asyncio.create_task,
    )

    with (
        patch.object(
            device_tracker,
            "_async_load_mac_vendor_lookup",
            AsyncMock(return_value=Mock()),
        ),
        patch.object(device_tracker, "async_get_dev_reg", return_value=Mock()),
        patch.object(device_tracker, "CoordinatorEntityManager") as manager,
    ):
        await device_tracker.async_setup_entry(hass, config_entry, Mock())
        await asyncio.sleep(0)

        listener = coordinator.async_add_listener.call_args.args[0]
        listener()
        await asyncio.sleep(0)

    assert client.delete_arp_entries.call_args_list == [
        call(["192.0.2.10", "192.0.2.20"]),
        call(["192.0.2.10", "192.0.2.20"]),
    ]
    manager.return_value.process_entities.assert_called_once_with()


def test_device_registry_cleanup_only_removes_owned_association():
    registry = Mock()
    foreign_device = SimpleNamespace(id="foreign", config_entries={"other"})
    shared_device = SimpleNamespace(
        id="shared",
        config_entries={"pfsense", "other"},
    )
    owned_device = SimpleNamespace(id="owned", config_entries={"pfsense"})

    device_tracker._remove_device_association(registry, foreign_device, "pfsense")
    device_tracker._remove_device_association(registry, shared_device, "pfsense")
    device_tracker._remove_device_association(registry, owned_device, "pfsense")

    assert registry.async_update_device.call_args_list == [
        call("shared", remove_config_entry_id="pfsense"),
        call("owned", remove_config_entry_id="pfsense"),
    ]
    registry.async_remove_device.assert_not_called()


def test_entity_properties_are_pure():
    state = {
        "update_time": 1234,
        "arp_table": [
            {
                "mac-address": "AA:BB:CC:DD:EE:FF",
                "ip-address": "192.0.2.10",
                "hostname": "example",
                "interface": "lan",
            }
        ],
    }
    entity = _entity(state)
    initial_cache = dict(entity.__dict__)

    assert entity.is_connected is True
    assert entity.icon == "mdi:lan-connect"
    assert entity.ip_address == "192.0.2.10"
    assert entity.hostname == "example"
    assert entity.extra_state_attributes["interface"] == "lan"
    assert entity.__dict__ == initial_cache

    entity._update_cached_state()
    assert entity._last_known_ip == "192.0.2.10"
    assert entity._last_known_hostname == "example"
    assert entity._last_known_connected_time is not None
