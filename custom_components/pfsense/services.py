from __future__ import annotations

import asyncio

from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.service import (
    async_extract_config_entry_ids,
    async_register_admin_service,
    remove_entity_service_fields,
)
import voluptuous as vol

from .const import (
    CONF_ALLOW_UNSAFE_SERVICES,
    COORDINATOR,
    DEFAULT_ALLOW_UNSAFE_SERVICES,
    DOMAIN,
    PFSENSE_CLIENT,
    PFSENSE_DATA,
    SERVICE_CLOSE_NOTICE,
    SERVICE_EXEC_COMMAND,
    SERVICE_EXEC_PHP,
    SERVICE_FILE_NOTICE,
    SERVICE_KILL_STATES,
    SERVICE_RESET_STATE_TABLE,
    SERVICE_RESTART_SERVICE,
    SERVICE_SEND_WOL,
    SERVICE_SET_DEFAULT_GATEWAY,
    SERVICE_START_SERVICE,
    SERVICE_STOP_SERVICE,
    SERVICE_SYSTEM_HALT,
    SERVICE_SYSTEM_REBOOT,
)
from .pypfsense import validate_ip_or_network

_RAW_SERVICES = {SERVICE_EXEC_COMMAND, SERVICE_EXEC_PHP}


def _as_bool(value: bool | int | str) -> bool:
    if isinstance(value, str):
        return value.lower() in {"1", "true"}
    return bool(value)


def _dispatch_client_service(client, service: str, data: dict) -> None:
    if service == SERVICE_CLOSE_NOTICE:
        client.close_notice(data.get("id"))
    elif service == SERVICE_FILE_NOTICE:
        client.file_notice(**data)
    elif service == SERVICE_START_SERVICE:
        client.start_service(data["service_name"], data.get("service"))
    elif service == SERVICE_STOP_SERVICE:
        client.stop_service(data["service_name"], data.get("service"))
    elif service == SERVICE_RESTART_SERVICE:
        method = (
            client.restart_service_if_running
            if _as_bool(data.get("only_if_running", False))
            else client.restart_service
        )
        method(data["service_name"], data.get("service"))
    elif service == SERVICE_RESET_STATE_TABLE:
        client.reset_state_table()
    elif service == SERVICE_KILL_STATES:
        client.kill_states(data["source"], data.get("destination"))
    elif service == SERVICE_SYSTEM_HALT:
        client.system_halt()
    elif service == SERVICE_SYSTEM_REBOOT:
        client.system_reboot()
    elif service == SERVICE_SEND_WOL:
        client.send_wol(data["interface"], data["mac"])
    elif service == SERVICE_SET_DEFAULT_GATEWAY:
        client.set_default_gateway(data["gateway"], data["ip_version"])
    elif service == SERVICE_EXEC_COMMAND:
        client._exec_command(data["command"], data.get("background", False))
    elif service == SERVICE_EXEC_PHP:
        client._exec_php(data["script"])
    else:
        raise ServiceValidationError(f"Unsupported pfSense service: {service}")


class ServiceRegistrar:
    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize with hass object."""
        self.hass = hass

    async def _async_send_service(self, call: ServiceCall) -> None:
        config_entry_ids = {
            entry_id
            for entry_id in await async_extract_config_entry_ids(call)
            if PFSENSE_CLIENT in self.hass.data.get(DOMAIN, {}).get(entry_id, {})
        }
        if not config_entry_ids:
            raise ServiceValidationError(
                "The service target does not contain a loaded pfSense device"
            )

        targets = {
            entry_id: self.hass.data[DOMAIN][entry_id]
            for entry_id in sorted(config_entry_ids)
        }
        entries = {
            entry_id: self.hass.config_entries.async_get_entry(entry_id)
            for entry_id in config_entry_ids
        }
        if call.service in _RAW_SERVICES:
            disabled_entries = [
                entry_id
                for entry_id, entry in entries.items()
                if entry is None
                or not entry.options.get(
                    CONF_ALLOW_UNSAFE_SERVICES,
                    entry.data.get(
                        CONF_ALLOW_UNSAFE_SERVICES, DEFAULT_ALLOW_UNSAFE_SERVICES
                    ),
                )
            ]
            if disabled_entries:
                raise ServiceValidationError(
                    "Raw command and PHP services are disabled for the targeted "
                    "pfSense config entry"
                )

        service_data = remove_entity_service_fields(call)
        results = await asyncio.gather(
            *(
                self.hass.async_add_executor_job(
                    _dispatch_client_service,
                    targets[entry_id][PFSENSE_CLIENT],
                    call.service,
                    service_data,
                )
                for entry_id in targets
            ),
            return_exceptions=True,
        )

        refreshes = []
        for entry_id, result in zip(targets, results, strict=True):
            if isinstance(result, BaseException):
                continue
            runtime_data = targets[entry_id]
            runtime_data[PFSENSE_DATA].invalidate_slow_state()
            refreshes.append(runtime_data[COORDINATOR].async_request_refresh())
        await asyncio.gather(*refreshes)

        for result in results:
            if isinstance(result, BaseException):
                raise result

    @callback
    def async_register(self) -> None:
        if self.hass.services.has_service(DOMAIN, SERVICE_CLOSE_NOTICE):
            return

        schemas = {
            SERVICE_CLOSE_NOTICE: {
                vol.Optional("id", default="all"): vol.Any(cv.positive_int, cv.string),
            },
            SERVICE_FILE_NOTICE: {
                vol.Required("id"): cv.string,
                vol.Required("notice"): cv.string,
                vol.Optional("category", default="HASS"): cv.string,
                vol.Optional("url", default=""): cv.string,
                vol.Optional("priority", default=1): cv.positive_int,
                vol.Optional("local_only", default=False): cv.boolean,
            },
            SERVICE_START_SERVICE: {
                vol.Required("service_name"): cv.string,
                vol.Optional("service"): cv.string,
            },
            SERVICE_STOP_SERVICE: {
                vol.Required("service_name"): cv.string,
                vol.Optional("service"): cv.string,
            },
            SERVICE_RESTART_SERVICE: {
                vol.Required("service_name"): cv.string,
                vol.Optional("only_if_running"): vol.Any(
                    cv.positive_int, cv.string, cv.boolean
                ),
                vol.Optional("service"): cv.string,
            },
            SERVICE_RESET_STATE_TABLE: {},
            SERVICE_KILL_STATES: {
                vol.Required("source"): vol.All(cv.string, validate_ip_or_network),
                vol.Optional("destination"): vol.All(cv.string, validate_ip_or_network),
            },
            SERVICE_SYSTEM_HALT: {},
            SERVICE_SYSTEM_REBOOT: {},
            SERVICE_SEND_WOL: {
                vol.Required("interface"): cv.string,
                vol.Required("mac"): cv.string,
            },
            SERVICE_SET_DEFAULT_GATEWAY: {
                vol.Required("gateway"): cv.string,
                vol.Required("ip_version"): cv.string,
            },
            SERVICE_EXEC_COMMAND: {
                vol.Required("command"): cv.string,
                vol.Optional("background", default=False): cv.boolean,
            },
            SERVICE_EXEC_PHP: {
                vol.Required("script"): cv.string,
            },
        }

        for service, fields in schemas.items():
            async_register_admin_service(
                self.hass,
                DOMAIN,
                service,
                self._async_send_service,
                schema=cv.make_entity_service_schema(fields),
            )
