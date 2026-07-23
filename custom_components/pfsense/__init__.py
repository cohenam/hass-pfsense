"""Support for pfSense."""

from __future__ import annotations

import asyncio
import copy
from datetime import timedelta
import logging
import math
import time
from typing import Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import (
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_TLS_INSECURE,
    COORDINATOR,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TLS_INSECURE,
    DEFAULT_VERIFY_SSL,
    DEVICE_TRACKER_COORDINATOR,
    DOMAIN,
    LOADED_PLATFORMS,
    PFSENSE_CLIENT,
    PFSENSE_DATA,
    PLATFORMS,
    SHOULD_RELOAD,
)
from .pypfsense import Client as pfSenseClient
from .services import ServiceRegistrar

_LOGGER = logging.getLogger(__name__)
FIRMWARE_REFRESH_INTERVAL = timedelta(hours=2).total_seconds()
SLOW_REFRESH_INTERVAL = timedelta(minutes=5).total_seconds()


def dict_get(data: dict, path: str, default=None):
    path_list = path.split(".")
    result = data
    for key in path_list:
        try:
            key = int(key) if key.isnumeric() else key
            result = result[key]
        except (IndexError, KeyError, TypeError):
            result = default
            break

    return result


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry):
    """Handle options update."""
    if hass.data[DOMAIN][entry.entry_id].get(SHOULD_RELOAD, True):
        hass.async_create_task(hass.config_entries.async_reload(entry.entry_id))
    else:
        hass.data[DOMAIN][entry.entry_id][SHOULD_RELOAD] = True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up pfSense from a config entry."""
    config = entry.data
    options = entry.options

    url = config[CONF_URL]
    username = config[CONF_USERNAME]
    password = config[CONF_PASSWORD]
    verify_ssl = config.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    device_tracker_enabled = options.get(
        CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
    )
    client = pfSenseClient(url, username, password, {"verify_ssl": verify_ssl})
    data = PfSenseData(client, entry, hass)
    scan_interval = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    refresh_lock = asyncio.Lock()

    async def async_update_data():
        """Fetch data from pfSense."""
        try:
            async with refresh_lock:
                await hass.async_add_executor_job(data.update)
        except Exception as err:
            raise UpdateFailed(f"Error fetching {entry.title} pfSense state") from err

        if not data.state:
            raise UpdateFailed(f"Error fetching {entry.title} pfSense state")

        data.async_schedule_firmware_refresh()
        return data.state

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{entry.title} pfSense state",
        update_method=async_update_data,
        update_interval=timedelta(seconds=scan_interval),
    )

    platforms = PLATFORMS.copy()
    device_tracker_coordinator = None
    if not device_tracker_enabled:
        platforms.remove("device_tracker")
    else:
        device_tracker_data = PfSenseData(client, entry, hass)
        device_tracker_scan_interval = options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )

        async def async_update_device_tracker_data():
            """Fetch data from pfSense."""
            try:
                async with refresh_lock:
                    await hass.async_add_executor_job(
                        device_tracker_data.update, {"scope": "device_tracker"}
                    )
            except Exception as err:
                raise UpdateFailed(
                    f"Error fetching {entry.title} pfSense device tracker state"
                ) from err

            if not device_tracker_data.state:
                raise UpdateFailed(
                    f"Error fetching {entry.title} pfSense device tracker state"
                )

            return device_tracker_data.state

        device_tracker_coordinator = DataUpdateCoordinator(
            hass,
            _LOGGER,
            name=f"{entry.title} pfSense device tracker state",
            update_method=async_update_device_tracker_data,
            update_interval=timedelta(seconds=device_tracker_scan_interval),
        )

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        COORDINATOR: coordinator,
        DEVICE_TRACKER_COORDINATOR: device_tracker_coordinator,
        PFSENSE_CLIENT: client,
        PFSENSE_DATA: data,
        LOADED_PLATFORMS: platforms,
    }

    try:
        # Fetch initial data so we have data when entities subscribe
        await coordinator.async_config_entry_first_refresh()
        # Fetch initial data so we have data when entities subscribe
        if device_tracker_enabled:
            await device_tracker_coordinator.async_config_entry_first_refresh()

        await hass.config_entries.async_forward_entry_setups(entry, platforms)
    except Exception:
        data.async_cancel_background_tasks()
        if device_tracker_enabled:
            device_tracker_data.async_cancel_background_tasks()
        hass.data[DOMAIN].pop(entry.entry_id, None)
        raise

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    entry.async_on_unload(data.async_cancel_background_tasks)
    if device_tracker_enabled:
        entry.async_on_unload(device_tracker_data.async_cancel_background_tasks)

    service_registar = ServiceRegistrar(hass)
    service_registar.async_register()

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    platforms = hass.data[DOMAIN][entry.entry_id][LOADED_PLATFORMS]
    unload_ok = await hass.config_entries.async_unload_platforms(entry, platforms)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate an old config entry."""
    version = config_entry.version

    _LOGGER.debug("Migrating from version %s", version)

    # 1 -> 2: tls_insecure to verify_ssl
    if version == 1:
        version = 2
        tls_insecure = config_entry.data.get(CONF_TLS_INSECURE, DEFAULT_TLS_INSECURE)
        data = dict(config_entry.data)

        # remove tls_insecure
        if CONF_TLS_INSECURE in data.keys():
            del data[CONF_TLS_INSECURE]

        # add verify_ssl
        if CONF_VERIFY_SSL not in data.keys():
            data[CONF_VERIFY_SSL] = not tls_insecure

        hass.config_entries.async_update_entry(
            config_entry,
            data=data,
            version=version,
        )

        _LOGGER.info("Migration to version %s successful", version)

    return True


class PfSenseData:
    def __init__(
        self, client: pfSenseClient, config_entry: ConfigEntry, hass: HomeAssistant
    ):
        """Initialize the data object."""
        self._client = client
        self._config_entry = config_entry
        self._hass = hass
        self._state = {}
        self._firmware_update_info = None
        self._firmware_last_attempt_at = 0.0
        self._firmware_task: asyncio.Task | None = None
        self._background_tasks: set[asyncio.Task] = set()
        self._cancelled = False
        self._slow_state = {}
        self._slow_state_updated_at = 0.0

    @property
    def state(self):
        return self._state

    def _log_timing(func):
        def inner(*args, **kwargs):
            begin = time.time()
            response = func(*args, **kwargs)
            end = time.time()
            elapsed = round((end - begin), 3)
            _LOGGER.debug(f"execution time: PfSenseData.{func.__name__} {elapsed}")

            return response

        return inner

    @_log_timing
    def _get_system_info(self):
        return self._client.get_system_info()

    async def _async_refresh_firmware_update_info(self):
        try:
            update_info = await self._hass.async_add_executor_job(
                self._client.get_firmware_update_info
            )
        except Exception as err:
            # pfSense refreshes its pkg-version cache (~2h TTL) by contacting
            # upstream servers, so a timeout must not fail normal telemetry.
            if isinstance(err, TimeoutError) or "timed out" in str(err):
                _LOGGER.debug("Firmware update check timed out; retaining last result")
                return
            _LOGGER.warning("Firmware update check failed; retaining last result")
            return

        if not self._cancelled:
            self._firmware_update_info = update_info

    @callback
    def async_schedule_firmware_refresh(self):
        """Schedule one slow firmware refresh when its cache expires."""
        if self._cancelled:
            return
        if self._firmware_task is not None and not self._firmware_task.done():
            return
        now = time.monotonic()
        if (
            self._firmware_last_attempt_at
            and now - self._firmware_last_attempt_at < FIRMWARE_REFRESH_INTERVAL
        ):
            return

        self._firmware_last_attempt_at = now
        task = self._hass.async_create_task(
            self._async_refresh_firmware_update_info(),
            f"{DOMAIN}-{self._config_entry.entry_id}-firmware-refresh",
        )
        self._firmware_task = task
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    @callback
    def async_cancel_background_tasks(self):
        """Prevent background results from publishing after unload."""
        self._cancelled = True
        for task in self._background_tasks:
            task.cancel()
        self._background_tasks.clear()

    @_log_timing
    def _get_firmware_update_info(self):
        return self._firmware_update_info

    @_log_timing
    def _get_telemetry(self):
        return self._client.get_telemetry()

    @_log_timing
    def _get_host_firmware_version(self):
        return self._client.get_host_firmware_version()

    @_log_timing
    def _get_config(self):
        return self._client.get_config()

    @_log_timing
    def _get_services(self):
        return self._client.get_services()

    @_log_timing
    def _get_carp_interfaces(self):
        return self._client.get_carp_interfaces()

    @_log_timing
    def _get_carp_status(self):
        return self._client.get_carp_status()

    @_log_timing
    def _get_dhcp_leases(self):
        return self._client.get_dhcp_leases(False)

    @_log_timing
    def _get_notices(self):
        return self._client.get_notices()

    @_log_timing
    def _get_arp_table(self):
        return self._client.get_arp_table(True)

    def _get_slow_state(self, include_firewall_config):
        now = time.monotonic()
        if (
            self._slow_state
            and now - self._slow_state_updated_at < SLOW_REFRESH_INTERVAL
        ):
            return self._slow_state

        slow_state = {
            "system_info": self._get_system_info(),
            "host_firmware_version": self._get_host_firmware_version(),
        }
        if include_firewall_config:
            slow_state.update(
                {
                    "config": self._get_config(),
                    "services": self._get_services(),
                    "carp_interfaces": self._get_carp_interfaces(),
                }
            )
        self._slow_state = slow_state
        self._slow_state_updated_at = now
        return self._slow_state

    def invalidate_slow_state(self):
        """Refresh configuration metadata after a service mutation."""
        self._slow_state = {}
        self._slow_state_updated_at = 0.0

    def update(self, opts=None):
        """Fetch the latest state from pfSense."""
        opts = opts or {}
        new_state = {}

        try:
            is_device_tracker = opts.get("scope") == "device_tracker"
            # Selective copy: only copy data needed for delta calculations
            # instead of deep copying the entire state (which can be 1-10MB)
            previous_state = {
                "update_time": self._state.get("update_time"),
            }
            # Copy telemetry data needed for rate calculations
            if "telemetry" in self._state:
                telemetry = self._state["telemetry"]
                previous_state["telemetry"] = {}
                # CPU ticks for usage calculation
                if "cpu" in telemetry:
                    previous_state["telemetry"]["cpu"] = copy.deepcopy(telemetry["cpu"])
                # Interface counters for rate calculations
                if "interfaces" in telemetry:
                    previous_state["telemetry"]["interfaces"] = copy.deepcopy(
                        telemetry["interfaces"]
                    )
                # OpenVPN server bytes for rate calculations
                if "openvpn" in telemetry and "servers" in telemetry["openvpn"]:
                    previous_state["telemetry"]["openvpn"] = {
                        "servers": copy.deepcopy(telemetry["openvpn"]["servers"])
                    }

            new_state.update(self._get_slow_state(not is_device_tracker))

            if is_device_tracker:
                new_state["arp_table"] = self._get_arp_table()
                new_state["arp_table_by_mac"] = {
                    entry.get("mac-address", "").lower(): entry
                    for entry in new_state["arp_table"]
                    if entry.get("mac-address")
                }
            else:
                new_state["firmware_update_info"] = self._get_firmware_update_info()
                new_state["telemetry"] = self._get_telemetry()
                new_state["update_time"] = time.monotonic()
                new_state["previous_state"] = previous_state
                new_state["carp_status"] = self._get_carp_status()
                new_state["dhcp_leases"] = self._get_dhcp_leases()
                new_state["dhcp_stats"] = {}
                pending_notices = self._get_notices()
                new_state["notices"] = {
                    "pending_notices_present": bool(pending_notices),
                    "pending_notices": pending_notices,
                }

                lease_stats = {"total": 0, "online": 0, "idle_offline": 0}
                for lease in new_state["dhcp_leases"]:
                    if "act" in lease.keys() and lease["act"] == "expired":
                        continue

                    lease_stats["total"] += 1
                    if "online" in lease.keys():
                        if lease["online"] in ["active", "active/online", "online"]:
                            lease_stats["online"] += 1
                        if lease["online"] in ["offline", "idle/offline", "idle"]:
                            lease_stats["idle_offline"] += 1

                new_state["dhcp_stats"]["leases"] = lease_stats

                # calcule pps and kbps
                update_time = dict_get(new_state, "update_time")
                previous_update_time = dict_get(new_state, "previous_state.update_time")

                if previous_update_time is not None:
                    elapsed_time = update_time - previous_update_time
                    if elapsed_time <= 0:
                        elapsed_time = 1

                    # calculate CPU Usage based on ticks
                    # /usr/local/www/widgets/widgets/system_information.widget.php
                    previous_cpu = dict_get(new_state, "previous_state.telemetry.cpu")
                    if previous_cpu is not None:
                        current_cpu = dict_get(new_state, "telemetry.cpu")
                        if (
                            dict_get(previous_cpu, "ticks.total")
                            <= dict_get(current_cpu, "ticks.total")
                        ) and (
                            dict_get(previous_cpu, "ticks.idle")
                            <= dict_get(current_cpu, "ticks.idle")
                        ):
                            total_change = dict_get(
                                current_cpu, "ticks.total"
                            ) - dict_get(previous_cpu, "ticks.total")
                            idle_change = dict_get(
                                current_cpu, "ticks.idle"
                            ) - dict_get(previous_cpu, "ticks.idle")
                            # avoid division by 0 issues
                            if total_change > 0:
                                cpu_used_percent = math.floor(
                                    ((total_change - idle_change) / total_change) * 100
                                )
                                new_state["telemetry"]["cpu"][
                                    "used_percent"
                                ] = cpu_used_percent
                            else:
                                new_state["telemetry"]["cpu"]["used_percent"] = (
                                    dict_get(
                                        previous_state, "telemetry.cpu.used_percent"
                                    )
                                )

                    for interface_name in dict_get(
                        new_state, "telemetry.interfaces", {}
                    ).keys():
                        interface = dict_get(
                            new_state, f"telemetry.interfaces.{interface_name}"
                        )
                        previous_interface = dict_get(
                            new_state,
                            f"previous_state.telemetry.interfaces.{interface_name}",
                        )
                        if previous_interface is None:
                            continue

                        for property in [
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
                        ]:

                            current_parent_value = interface[property]
                            previous_parent_value = previous_interface[property]
                            change = current_parent_value - previous_parent_value
                            if change < 0:
                                continue
                            rate = change / elapsed_time

                            value = 0
                            if "pkts" in property:
                                label = "packets_per_second"
                                value = rate
                            if "bytes" in property:
                                label = "kilobytes_per_second"
                                # 1 Byte = 8 bits
                                # 1 byte is equal to 0.001 kilobytes
                                KBs = rate / 1000
                                # Kbs = KBs * 8
                                value = KBs

                            new_property = f"{property}_{label}"
                            interface[new_property] = int(round(value, 0))

                    for server_name in dict_get(
                        new_state, "telemetry.openvpn.servers", {}
                    ).keys():
                        if (
                            server_name
                            not in dict_get(
                                new_state, "telemetry.openvpn.servers", {}
                            ).keys()
                        ):
                            continue

                        if (
                            server_name
                            not in dict_get(
                                new_state,
                                "previous_state.telemetry.openvpn.servers",
                                {},
                            ).keys()
                        ):
                            continue

                        server = new_state["telemetry"]["openvpn"]["servers"][
                            server_name
                        ]
                        previous_server = new_state["previous_state"]["telemetry"][
                            "openvpn"
                        ]["servers"][server_name]

                        for property in [
                            "total_bytes_recv",
                            "total_bytes_sent",
                        ]:

                            current_parent_value = server[property]
                            previous_parent_value = previous_server[property]
                            change = current_parent_value - previous_parent_value
                            if change < 0:
                                continue
                            rate = change / elapsed_time

                            value = 0
                            if "pkts" in property:
                                label = "packets_per_second"
                                value = rate
                            if "bytes" in property:
                                label = "kilobytes_per_second"
                                # 1 Byte = 8 bits
                                # 1 byte is equal to 0.001 kilobytes
                                KBs = rate / 1000
                                # Kbs = KBs * 8
                                value = KBs

                            new_property = f"{property}_{label}"
                            server[new_property] = int(round(value, 0))
        except Exception:
            raise

        self._state = new_state


class CoordinatorEntityManager:
    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: DataUpdateCoordinator,
        config_entry: ConfigEntry,
        process_entities_callback: Callable,
        async_add_entities: AddEntitiesCallback,
    ) -> None:
        self.hass = hass
        self.coordinator = coordinator
        self.config_entry = config_entry
        self.process_entities_callback = process_entities_callback
        self.async_add_entities = async_add_entities
        config_entry.async_on_unload(
            coordinator.async_add_listener(self.process_entities)
        )
        self.entity_unique_ids = set()
        self.entities = {}
        self._last_schema_signature = None

    def _get_schema_signature(self, state):
        """Generate a signature of the data schema to detect when entities need refresh.

        Only recreate entities when the schema changes (new interfaces, gateways, etc.),
        not on every data update. This prevents creating 100-300+ temporary objects
        per update cycle.
        """
        if state is None:
            return None
        signature = []
        # Count interfaces
        interfaces = dict_get(state, "telemetry.interfaces", {})
        signature.append(("interfaces", tuple(sorted(interfaces.keys()))))
        # Count gateways
        gateways = dict_get(state, "telemetry.gateways", {})
        signature.append(("gateways", tuple(sorted(gateways.keys()))))
        # Count filesystems
        filesystems = dict_get(state, "telemetry.filesystems", [])
        fs_devices = tuple(sorted(fs.get("device", "") for fs in filesystems))
        signature.append(("filesystems", fs_devices))
        # Count CARP interfaces
        carp_interfaces = state.get("carp_interfaces", [])
        carp_ids = tuple(sorted(iface.get("uniqid", "") for iface in carp_interfaces))
        signature.append(("carp", carp_ids))
        # Count OpenVPN servers
        openvpn_servers = dict_get(state, "telemetry.openvpn.servers", {})
        signature.append(("openvpn", tuple(sorted(openvpn_servers.keys()))))
        # Count ARP entries (for device tracker)
        arp_table = state.get("arp_table", [])
        signature.append(("arp_count", len(arp_table)))

        # Filter/NAT rules and services also produce switch entities (switch.py) —
        # track their identifiers so ones added after setup appear without a restart.
        def rule_ids(rules, getter):
            if not isinstance(rules, list):
                return ()
            return tuple(
                sorted(getter(rule) or "" for rule in rules if isinstance(rule, dict))
            )

        signature.append(
            (
                "filter_rules",
                rule_ids(
                    dict_get(state, "config.filter.rule"),
                    lambda rule: rule.get("tracker"),
                ),
            )
        )
        signature.append(
            (
                "nat_rules",
                rule_ids(
                    dict_get(state, "config.nat.rule"),
                    lambda rule: dict_get(rule, "created.time"),
                ),
            )
        )
        signature.append(
            (
                "nat_outbound",
                rule_ids(
                    dict_get(state, "config.nat.outbound.rule"),
                    lambda rule: dict_get(rule, "created.time"),
                ),
            )
        )
        signature.append(
            (
                "services",
                rule_ids(
                    state.get("services", []),
                    lambda service: (
                        service.get("name", "") + "-" + service.get("vpnid", "")
                        if service.get("name") == "openvpn"
                        else service.get("name")
                    ),
                ),
            )
        )
        return tuple(signature)

    @callback
    def process_entities(self):
        state = self.coordinator.data
        schema_signature = self._get_schema_signature(state)

        # Skip entity recreation if schema hasn't changed and we have entities
        if (
            self._last_schema_signature is not None
            and schema_signature == self._last_schema_signature
            and len(self.entity_unique_ids) > 0
        ):
            return

        self._last_schema_signature = schema_signature
        entities = self.process_entities_callback(self.hass, self.config_entry)
        current_entity_unique_ids = set()
        for entity in entities:
            unique_id = entity.unique_id
            if unique_id is None:
                raise Exception("unique_id is missing from entity")
            current_entity_unique_ids.add(unique_id)
            if unique_id not in self.entity_unique_ids:
                self.async_add_entities([entity])
                self.entity_unique_ids.add(unique_id)
                self.entities[unique_id] = entity

        for unique_id in self.entity_unique_ids - current_entity_unique_ids:
            entity = self.entities.pop(unique_id)
            self.hass.async_create_task(entity.async_remove())
        self.entity_unique_ids.intersection_update(current_entity_unique_ids)


class PfSenseEntity(CoordinatorEntity, RestoreEntity):
    """base entity for pfSense"""

    @property
    def coordinator_context(self):
        return None

    @property
    def device_info(self):
        """Device info for the firewall."""
        state = self.coordinator.data
        model = state["host_firmware_version"]["platform"]
        manufacturer = "netgate"
        firmware = state["host_firmware_version"]["firmware"]["version"]

        device_info = {
            "identifiers": {(DOMAIN, self.pfsense_device_unique_id)},
            "name": self.pfsense_device_name,
            "configuration_url": self.config_entry.data.get("url", None),
        }

        device_info["model"] = model
        device_info["manufacturer"] = manufacturer
        device_info["sw_version"] = firmware

        return device_info

    @property
    def pfsense_device_name(self):
        if self.config_entry.title and len(self.config_entry.title) > 0:
            return self.config_entry.title
        return "{}.{}".format(
            self._get_pfsense_state_value("system_info.hostname"),
            self._get_pfsense_state_value("system_info.domain"),
        )

    @property
    def pfsense_device_unique_id(self):
        return self._get_pfsense_state_value("system_info.netgate_device_id")

    def _get_pfsense_state_value(self, path, default=None):
        state = self.coordinator.data
        value = dict_get(state, path, default)

        return value

    def _get_pfsense_client(self) -> pfSenseClient:
        return self.hass.data[DOMAIN][self.config_entry.entry_id][PFSENSE_CLIENT]
