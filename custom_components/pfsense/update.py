"""pfSense integration."""

import asyncio

from homeassistant.components.update import (
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityDescription,
    UpdateEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import slugify

from . import CoordinatorEntityManager, PfSenseEntity, dict_get
from .const import COORDINATOR, DOMAIN

FIRMWARE_INSTALL_POLL_INTERVAL = 10
FIRMWARE_INSTALL_TIMEOUT = 60 * 60


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    """Set up the pfSense update entities."""

    @callback
    def process_entities_callback(hass, config_entry):
        data = hass.data[DOMAIN][config_entry.entry_id]
        coordinator = data[COORDINATOR]
        entities = []
        entity = PfSenseFirmwareUpdatesAvailableUpdate(
            config_entry,
            coordinator,
            UpdateEntityDescription(
                key="firmware.update_available",
                name="Firmware Updates Available",
                entity_category=EntityCategory.DIAGNOSTIC,
            ),
            True,
        )
        entities.append(entity)

        return entities

    cem = CoordinatorEntityManager(
        hass,
        hass.data[DOMAIN][config_entry.entry_id][COORDINATOR],
        config_entry,
        process_entities_callback,
        async_add_entities,
    )
    cem.process_entities()


class PfSenseUpdate(PfSenseEntity, UpdateEntity):
    def __init__(
        self,
        config_entry,
        coordinator: DataUpdateCoordinator,
        entity_description: UpdateEntityDescription,
        enabled_default: bool,
    ) -> None:
        """Initialize the sensor."""
        self.config_entry = config_entry
        self.entity_description = entity_description
        self.coordinator = coordinator
        self._attr_entity_registry_enabled_default = enabled_default
        self._attr_name = f"{self.pfsense_device_name} {entity_description.name}"
        self._attr_unique_id = slugify(
            f"{self.pfsense_device_unique_id}_{entity_description.key}"
        )
        self._install_in_progress = False

        self._attr_supported_features |= UpdateEntityFeature.INSTALL

    @property
    def device_class(self):
        return UpdateDeviceClass.FIRMWARE


class PfSenseFirmwareUpdatesAvailableUpdate(PfSenseUpdate):
    @property
    def available(self):
        info = dict_get(self.coordinator.data, "firmware_update_info.base")
        if not isinstance(info, dict):
            return False

        return super().available

    @property
    def title(self):
        return "pfSense"

    @property
    def installed_version(self):
        """Version installed and in use."""
        state = self.coordinator.data

        try:
            return dict_get(state, "firmware_update_info.base.installed_version")
        except KeyError:
            return None

    @property
    def latest_version(self):
        """Latest version available for install."""
        state = self.coordinator.data

        try:
            # fake a new update
            # return "foobar"
            return dict_get(state, "firmware_update_info.base.version")
        except KeyError:
            return None

    @property
    def in_progress(self):
        """Update installation in progress."""
        return self._install_in_progress

    @property
    def extra_state_attributes(self):
        state = self.coordinator.data
        attrs = {}
        info = dict_get(state, "firmware_update_info.base", {})

        if not isinstance(info, dict):
            return attrs

        for key in info.keys():
            attrs[f"pfsense_base_{key}"] = dict_get(
                state, f"firmware_update_info.base.{key}"
            )

        return attrs

    @property
    def release_url(self):
        return "https://docs.netgate.com/pfsense/en/latest/releases/index.html"

    async def async_install(self, version=None, backup=False, **kwargs):
        """Install an update."""
        if self._install_in_progress:
            raise HomeAssistantError("A pfSense firmware update is already in progress")

        self._install_in_progress = True
        self.async_write_ha_state()
        client = self._get_pfsense_client()
        try:
            pid = await self.hass.async_add_executor_job(client.upgrade_firmware)
            if not pid:
                raise HomeAssistantError("pfSense did not start the firmware update")

            loop = asyncio.get_running_loop()
            deadline = loop.time() + FIRMWARE_INSTALL_TIMEOUT
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise HomeAssistantError(
                        "Timed out waiting for the pfSense firmware update"
                    )

                await asyncio.sleep(min(FIRMWARE_INSTALL_POLL_INTERVAL, remaining))
                if not await self.hass.async_add_executor_job(
                    client.pid_is_running,
                    pid,
                ):
                    break
        finally:
            self._install_in_progress = False
            self.async_write_ha_state()
