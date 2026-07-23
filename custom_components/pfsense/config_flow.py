"""Config flow for pfSense integration."""

import logging
from typing import Any
from urllib.parse import quote_plus, urlparse
import xmlrpc

from homeassistant import config_entries
from homeassistant.const import (
    CONF_NAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import AbortFlow
import homeassistant.helpers.config_validation as cv
from homeassistant.util import slugify
import voluptuous as vol

from .const import (
    CONF_ALLOW_UNSAFE_SERVICES,
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICES,
    DEFAULT_ALLOW_UNSAFE_SERVICES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_USERNAME,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def cleanse_sensitive_data(message: str, secrets: list[str] | None = None) -> str:
    for secret in secrets or []:
        if secret:
            message = message.replace(secret, "[redacted]")
            message = message.replace(quote_plus(secret), "[redacted]")
    return message


def _create_client(url: str, username: str, password: str, verify_ssl: bool):
    # These helpers run in the executor so importing the client cannot block HA.
    from .pypfsense import Client

    return Client(url, username, password, {"verify_ssl": verify_ssl})


def _get_system_info(
    url: str, username: str, password: str, verify_ssl: bool
) -> dict[str, Any]:
    return _create_client(url, username, password, verify_ssl).get_system_info()


def _get_arp_table(
    url: str, username: str, password: str, verify_ssl: bool
) -> list[dict[str, Any]]:
    return _create_client(url, username, password, verify_ssl).get_arp_table(True)


class ConfigFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for pfSense."""

    # bumping this is what triggers async_migrate_entry for the component
    VERSION = 2

    # gets invoked without user input initially
    # when user submits has user_input
    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}
        if user_input is not None:
            username = user_input.get(CONF_USERNAME, DEFAULT_USERNAME)
            password = user_input.get(CONF_PASSWORD, "")
            try:
                name = user_input.get(CONF_NAME, False) or None

                url = user_input[CONF_URL].strip()
                # ParseResult(
                #     scheme='', netloc='', path='f', params='', query='', fragment=''
                # )
                try:
                    url_parts = urlparse(url)
                except ValueError as err:
                    raise InvalidURL() from err
                if url_parts.scheme not in {"http", "https"}:
                    raise InvalidURL()

                try:
                    hostname = url_parts.hostname
                except ValueError as err:
                    raise InvalidURL() from err
                if (
                    not hostname
                    or url_parts.username is not None
                    or url_parts.password is not None
                ):
                    raise InvalidURL()

                # remove any path etc details
                url = f"{url_parts.scheme}://{url_parts.netloc}"
                verify_ssl = user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)

                system_info = await self.hass.async_add_executor_job(
                    _get_system_info, url, username, password, verify_ssl
                )

                if name is None:
                    name = "{}.{}".format(
                        system_info["hostname"], system_info["domain"]
                    )

                # https://developers.home-assistant.io/docs/config_entries_config_flow_handler#unique-ids
                await self.async_set_unique_id(
                    slugify(system_info["netgate_device_id"])
                )
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=name,
                    data={
                        CONF_URL: url,
                        CONF_PASSWORD: password,
                        CONF_USERNAME: username,
                        CONF_VERIFY_SSL: verify_ssl,
                    },
                )

            # can be when using http instead of https
            # 2022-08-16 09:43:17.803 ERROR (MainThread) [custom_components.opnsense.config_flow] Unexpected err=RemoteDisconnected('Remote end closed connection without response'), type(err)=<class 'http.client.RemoteDisconnected'>
            # when proper permissions are not setup
            # 2022-08-16 09:43:26.680 ERROR (MainThread) [custom_components.opnsense.config_flow] Unexpected err=TypeError('string indices must be integers'), type(err)=<class 'TypeError'>
            except InvalidURL:
                errors["base"] = "invalid_url_format"
            except xmlrpc.client.Fault as err:
                if "Invalid username or password" in str(err):
                    errors["base"] = "invalid_auth"
                elif "Authentication failed: not enough privileges" in str(err):
                    errors["base"] = "privilege_missing"
                else:
                    message = cleanse_sensitive_data(
                        f"Unexpected {err=}, {type(err)=}", [username, password]
                    )
                    _LOGGER.error(message)
                    errors["base"] = "cannot_connect"
            except xmlrpc.client.ProtocolError as err:
                if "307 Temporary Redirect" in str(err):
                    errors["base"] = "url_redirect"
                elif "301 Moved Permanently" in str(err):
                    errors["base"] = "url_redirect"
                else:
                    message = cleanse_sensitive_data(
                        f"Unexpected {err=}, {type(err)=}", [username, password]
                    )
                    _LOGGER.error(message)
                    errors["base"] = "cannot_connect"
            except OSError as err:
                # bad response from pfSense when creds are valid but authorization is
                # not sufficient non-admin users must have 'System - HA node sync'
                # privilege
                if "unsupported XML-RPC protocol" in str(err):
                    errors["base"] = "privilege_missing"
                elif "timed out" in str(err):
                    errors["base"] = "connect_timeout"
                elif "SSL:" in str(err):
                    """OSError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1129)"""
                    errors["base"] = "cannot_connect_ssl"
                else:
                    message = cleanse_sensitive_data(
                        f"Unexpected {err=}, {type(err)=}", [username, password]
                    )
                    _LOGGER.error(message)
                    errors["base"] = "unknown"
            except AbortFlow:
                raise
            except Exception as err:
                message = cleanse_sensitive_data(
                    f"Unexpected {err=}, {type(err)=}", [username, password]
                )
                _LOGGER.error(message)
                errors["base"] = "unknown"

        if not user_input:
            user_input = {}
        schema = vol.Schema(
            {
                vol.Required(CONF_URL, default=user_input.get(CONF_URL, "")): str,
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                ): bool,
                vol.Optional(
                    CONF_USERNAME,
                    default=user_input.get(CONF_USERNAME, DEFAULT_USERNAME),
                ): str,
                vol.Required(
                    CONF_PASSWORD, default=user_input.get(CONF_PASSWORD, "")
                ): str,
                vol.Optional(CONF_NAME, default=user_input.get(CONF_NAME, "")): str,
            }
        )

        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_import(self, user_input):
        """Handle import."""
        return await self.async_step_user(user_input)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return OptionsFlowHandler()


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle option flow for pfSense."""

    def __init__(self) -> None:
        """Initialize options flow."""
        self.new_options: dict[str, Any] = {}

    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            if user_input.get(CONF_DEVICE_TRACKER_ENABLED):
                self.new_options = dict(user_input)
                return await self.async_step_device_tracker()
            return self.async_create_entry(title="", data=user_input)

        scan_interval = self.config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )
        device_tracker_enabled = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
        )
        device_tracker_scan_interval = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_SCAN_INTERVAL, DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL
        )

        device_tracker_consider_home = self.config_entry.options.get(
            CONF_DEVICE_TRACKER_CONSIDER_HOME, DEFAULT_DEVICE_TRACKER_CONSIDER_HOME
        )
        allow_unsafe_services = self.config_entry.options.get(
            CONF_ALLOW_UNSAFE_SERVICES, DEFAULT_ALLOW_UNSAFE_SERVICES
        )

        base_schema = {
            vol.Optional(CONF_SCAN_INTERVAL, default=scan_interval): vol.All(
                vol.Coerce(int), vol.Clamp(min=10, max=300)
            ),
            vol.Optional(
                CONF_DEVICE_TRACKER_ENABLED, default=device_tracker_enabled
            ): bool,
            vol.Optional(
                CONF_DEVICE_TRACKER_SCAN_INTERVAL, default=device_tracker_scan_interval
            ): vol.All(vol.Coerce(int), vol.Clamp(min=30, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_CONSIDER_HOME, default=device_tracker_consider_home
            ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=600)),
            vol.Optional(
                CONF_ALLOW_UNSAFE_SERVICES, default=allow_unsafe_services
            ): bool,
        }

        return self.async_show_form(step_id="init", data_schema=vol.Schema(base_schema))

    async def async_step_device_tracker(self, user_input=None):
        """Handle device tracker list step."""
        if user_input is not None:
            self.new_options[CONF_DEVICES] = user_input[CONF_DEVICES]
            return self.async_create_entry(title="", data=self.new_options)

        url = self.config_entry.data[CONF_URL].strip()
        username = self.config_entry.data.get(CONF_USERNAME, DEFAULT_USERNAME)
        password = self.config_entry.data[CONF_PASSWORD]
        verify_ssl = self.config_entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
        errors = {}
        try:
            arp_table = await self.hass.async_add_executor_job(
                _get_arp_table, url, username, password, verify_ssl
            )
        except Exception as err:
            message = cleanse_sensitive_data(
                f"Unable to load ARP table: {err=}, {type(err)=}",
                [username, password],
            )
            _LOGGER.error(message)
            errors["base"] = "cannot_connect"
            arp_table = []

        selected_devices = self.config_entry.options.get(CONF_DEVICES, [])

        # Preserve previously selected devices when they are temporarily absent.
        entries = {device: device for device in selected_devices}
        for entry in arp_table:
            mac = entry.get("mac-address", "").lower()
            if not mac:
                continue

            hostname = (entry.get("hostname") or "").strip("? ")
            ip = (entry.get("ip-address") or "").strip()
            entries[mac] = f"{mac} - {hostname or 'unknown'} ({ip})"

        return self.async_show_form(
            step_id="device_tracker",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_DEVICES, default=selected_devices
                    ): cv.multi_select(entries),
                }
            ),
            errors=errors,
        )


class InvalidURL(Exception):
    """Invalid URL."""
