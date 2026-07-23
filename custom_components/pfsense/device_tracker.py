"""Support for tracking for pfSense devices."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Mapping

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import (
    CONNECTION_NETWORK_MAC,
    async_get as async_get_dev_reg,
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify
from mac_vendor_lookup import AsyncMacLookup

from . import CoordinatorEntityManager, PfSenseEntity, dict_get
from .const import (
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    PFSENSE_CLIENT,
    SHOULD_RELOAD,
    TRACKED_MACS,
)

_LOGGER = logging.getLogger(__name__)


async def _async_load_mac_vendor_lookup() -> AsyncMacLookup:
    mac_vendor_lookup = AsyncMacLookup()
    try:
        await mac_vendor_lookup.load_vendors()
    except Exception:
        try:
            await mac_vendor_lookup.update_vendors()
        except Exception as err:
            _LOGGER.debug("Unable to update MAC vendor data: %s", err)
    return mac_vendor_lookup


def lookup_mac(mac_vendor_lookup: AsyncMacLookup, mac: str) -> str | None:
    if not mac_vendor_lookup.prefixes:
        return None
    mac = mac_vendor_lookup.sanitise(mac)
    if isinstance(mac, str):
        mac = mac.encode("utf8")
    vendor = mac_vendor_lookup.prefixes.get(mac[:6])
    if isinstance(vendor, bytes):
        return vendor.decode("utf8")
    return vendor if isinstance(vendor, str) else None


def get_device_tracker_unique_id(mac: str, netgate_id: str):
    """Generate device_tracker unique ID."""
    return slugify(f"{netgate_id}_mac_{mac}")


def _tracked_arp_ips(state: dict, mac_addresses: list[str]) -> list[str]:
    tracked_macs = {
        mac.lower() for mac in mac_addresses if isinstance(mac, str) and mac
    }
    if not tracked_macs:
        return []

    arp_table_by_mac = state.get("arp_table_by_mac")
    if isinstance(arp_table_by_mac, dict):
        arp_table_by_mac = {
            mac.lower(): entry
            for mac, entry in arp_table_by_mac.items()
            if isinstance(mac, str)
        }
    else:
        arp_table = state.get("arp_table")
        if not isinstance(arp_table, list):
            return []
        arp_table_by_mac = {
            mac.lower(): entry
            for entry in arp_table
            if isinstance(entry, dict)
            and isinstance((mac := entry.get("mac-address")), str)
        }

    return sorted(
        {
            ip_address
            for mac_address in tracked_macs
            if isinstance((entry := arp_table_by_mac.get(mac_address)), dict)
            and isinstance((ip_address := entry.get("ip-address")), str)
            and ip_address
        }
    )


def _remove_device_association(dev_reg, device, config_entry_id: str) -> None:
    config_entries = set(device.config_entries)
    if config_entry_id not in config_entries:
        return
    dev_reg.async_update_device(
        device.id,
        remove_config_entry_id=config_entry_id,
    )


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker for pfSense component."""
    mac_vendor_lookup = await _async_load_mac_vendor_lookup()

    dev_reg = async_get_dev_reg(hass)
    data = hass.data[DOMAIN][config_entry.entry_id]
    coordinator = data[DEVICE_TRACKER_COORDINATOR]
    client = data[PFSENSE_CLIENT]
    pending_cleanup_ips: set[str] = set()
    cleanup_task: asyncio.Task[None] | None = None

    @callback
    def schedule_arp_cleanup() -> None:
        nonlocal cleanup_task

        state = coordinator.data
        if not isinstance(state, dict):
            return

        ip_addresses = _tracked_arp_ips(
            state,
            config_entry.options.get(CONF_DEVICES, []),
        )
        if not ip_addresses:
            return
        pending_cleanup_ips.update(ip_addresses)
        if cleanup_task is not None and not cleanup_task.done():
            return

        async def async_cleanup() -> None:
            while pending_cleanup_ips:
                cleanup_batch = sorted(pending_cleanup_ips)
                pending_cleanup_ips.difference_update(cleanup_batch)
                try:
                    await hass.async_add_executor_job(
                        client.delete_arp_entries,
                        cleanup_batch,
                    )
                except Exception:
                    _LOGGER.warning(
                        "Unable to clean up pfSense ARP entries",
                        exc_info=True,
                    )

        cleanup_task = hass.async_create_task(async_cleanup())

    config_entry.async_on_unload(coordinator.async_add_listener(schedule_arp_cleanup))

    @callback
    def cancel_arp_cleanup() -> None:
        if cleanup_task is not None and not cleanup_task.done():
            cleanup_task.cancel()

    config_entry.async_on_unload(cancel_arp_cleanup)
    schedule_arp_cleanup()

    @callback
    def process_entities_callback(
        hass: HomeAssistant, config_entry: ConfigEntry
    ) -> list[PfSenseScannerEntity]:
        # options = config_entry.options
        data = hass.data[DOMAIN][config_entry.entry_id]
        previous_mac_addresses = {
            mac.lower()
            for mac in config_entry.data.get(TRACKED_MACS, [])
            if isinstance(mac, str)
        }
        coordinator = data[DEVICE_TRACKER_COORDINATOR]
        state = coordinator.data
        # seems unlikely *all* devices are intended to be monitored
        # disable by default and let users enable specific entries they care about
        enabled_default = False
        device_per_arp_entry = False

        entities = []
        mac_addresses = []

        # use configured mac addresses if setup, otherwise create an entity per arp
        # entry
        configured_mac_addresses = [
            mac.lower()
            for mac in config_entry.options.get(CONF_DEVICES, [])
            if isinstance(mac, str) and mac
        ]
        if configured_mac_addresses:
            mac_addresses = list(dict.fromkeys(configured_mac_addresses))
            enabled_default = True
        else:
            if device_per_arp_entry:
                arp_entries = dict_get(state, "arp_table")
                if not arp_entries:
                    return []

                mac_addresses = [
                    mac_address.lower()
                    for arp_entry in arp_entries
                    if (mac_address := arp_entry.get("mac-address"))
                ]

        for mac_address in mac_addresses:
            mac_vendor = None
            try:
                mac_vendor = lookup_mac(mac_vendor_lookup, mac_address)
            except Exception:
                pass

            entity = PfSenseScannerEntity(
                hass,
                config_entry,
                coordinator,
                enabled_default,
                mac_address,
                mac_vendor,
            )

            entities.append(entity)

        # Get the MACs that need to be removed and remove their devices
        for mac_address in previous_mac_addresses - set(mac_addresses):
            device = dev_reg.async_get_device(
                {}, {(CONNECTION_NETWORK_MAC, mac_address)}
            )
            if device:
                _remove_device_association(dev_reg, device, config_entry.entry_id)

        if set(mac_addresses) != previous_mac_addresses:
            data[SHOULD_RELOAD] = False
            new_data = config_entry.data.copy()
            new_data[TRACKED_MACS] = mac_addresses.copy()
            hass.config_entries.async_update_entry(config_entry, data=new_data)

        return entities

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][DEVICE_TRACKER_COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class PfSenseScannerEntity(PfSenseEntity, ScannerEntity):
    """Represent a scanned device."""

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        coordinator: DataUpdateCoordinator,
        enabled_default: bool,
        mac: str,
        mac_vendor: str | None,
    ) -> None:
        """Set up the pfSense scanner entity."""
        self.hass = hass
        self.config_entry = config_entry
        self.coordinator = coordinator
        self._mac_address = mac.lower()
        self._mac_vendor = mac_vendor
        self._last_known_ip = None
        self._last_known_hostname = None
        self._last_known_connected_time = None
        self._extra_state = {}

        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_unique_id = get_device_tracker_unique_id(
            mac, self.pfsense_device_unique_id
        )

    def _get_pfsense_arp_entry(self) -> dict[str, Any] | None:
        state = self.coordinator.data
        # Use MAC index for O(1) lookup if available
        arp_table_by_mac = dict_get(state, "arp_table_by_mac")
        if isinstance(arp_table_by_mac, dict):
            entry = arp_table_by_mac.get(self._mac_address)
            return entry if isinstance(entry, dict) else None
        # Fallback to linear search if index not available
        arp_table = dict_get(state, "arp_table")
        if not isinstance(arp_table, list):
            return None
        for entry in arp_table:
            if (
                isinstance(entry, dict)
                and isinstance((mac_address := entry.get("mac-address")), str)
                and mac_address.lower() == self._mac_address
            ):
                return entry
        return None

    @property
    def available(self) -> bool:
        state = self.coordinator.data
        arp_table = dict_get(state, "arp_table")
        if arp_table is None:
            return False
        return super().available

    @property
    def source_type(self) -> str:
        """Return the source type, eg gps or router, of the device."""
        return SourceType.ROUTER

    @property
    def extra_state_attributes(self) -> Mapping[str, Any] | None:
        """Return extra state attributes."""
        extra_state = dict(self._extra_state)
        entry = self._get_pfsense_arp_entry()
        if entry is not None:
            for property_name in ["interface", "expires", "type"]:
                extra_state[property_name] = entry.get(property_name)

        if self._last_known_hostname is not None:
            extra_state["last_known_hostname"] = self._last_known_hostname

        if self._last_known_ip is not None:
            extra_state["last_known_ip"] = self._last_known_ip

        if self._last_known_connected_time is not None:
            extra_state["last_known_connected_time"] = self._last_known_connected_time

        return extra_state

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        return self._ip_address

    @property
    def _ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            return None

        ip_address = entry.get("ip-address")
        return ip_address if isinstance(ip_address, str) and ip_address else None

    @property
    def mac_address(self) -> str | None:
        """Return the mac address of the device."""
        return self._mac_address

    @property
    def hostname(self) -> str | None:
        """Return hostname of the device."""
        return self._hostname

    @property
    def _hostname(self) -> str | None:
        """Return hostname of the device."""
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            return None
        value = entry.get("hostname")
        if not isinstance(value, str):
            return None
        value = value.strip("?").strip()
        return value or None

    @property
    def name(self) -> str:
        """Return the name of the device."""
        identifier = self.hostname or self._last_known_hostname or self._mac_address
        return f"{self.pfsense_device_name} {identifier}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return the device info."""
        return DeviceInfo(
            connections={(CONNECTION_NETWORK_MAC, self.mac_address)},
            default_manufacturer=self._mac_vendor,
            default_name=self.name,
            via_device=(DOMAIN, self.pfsense_device_unique_id),
        )

    @property
    def icon(self) -> str:
        """Return device icon."""
        return "mdi:lan-connect" if self.is_connected else "mdi:lan-disconnect"

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected to the network."""
        entry = self._get_pfsense_arp_entry()
        if entry is None:
            device_tracker_consider_home = self.config_entry.options.get(
                CONF_DEVICE_TRACKER_CONSIDER_HOME, DEFAULT_DEVICE_TRACKER_CONSIDER_HOME
            )
            if (
                device_tracker_consider_home > 0
                and self._last_known_connected_time is not None
            ):
                current_time = int(time.time())
                elapsed = current_time - self._last_known_connected_time
                if elapsed < device_tracker_consider_home:
                    return True

            return False
        return True

    @callback
    def _handle_coordinator_update(self) -> None:
        self._update_cached_state()
        super()._handle_coordinator_update()

    def _update_cached_state(self) -> None:
        state = self.coordinator.data
        entry = self._get_pfsense_arp_entry()
        if not isinstance(state, dict) or entry is None:
            return

        ip_address = entry.get("ip-address")
        if isinstance(ip_address, str) and ip_address:
            self._last_known_ip = ip_address

        hostname = entry.get("hostname")
        if isinstance(hostname, str) and (hostname := hostname.strip("?").strip()):
            self._last_known_hostname = hostname

        self._last_known_connected_time = int(time.time())

    async def async_added_to_hass(self) -> None:
        """Handle entity which will be added."""
        await super().async_added_to_hass()
        state = await self.async_get_last_state()
        if state is not None and state.attributes is not None:
            for attr in [
                "interface",
                "expires",
                "type",
                "last_known_ip",
                "last_known_hostname",
                "last_known_connected_time",
            ]:
                value = state.attributes.get(attr)
                if value is not None:
                    self._extra_state[attr] = value
                    if attr == "last_known_hostname":
                        self._last_known_hostname = value

                    if attr == "last_known_ip":
                        self._last_known_ip = value

                    if attr == "last_known_connected_time":
                        self._last_known_connected_time = value

        self._update_cached_state()
