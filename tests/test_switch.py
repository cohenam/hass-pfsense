from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from custom_components.pfsense.const import DOMAIN, PFSENSE_DATA
from custom_components.pfsense.switch import PfSenseSwitch


@pytest.mark.asyncio
async def test_refresh_after_mutation_invalidates_slow_metadata():
    data = Mock()
    entity = object.__new__(PfSenseSwitch)
    entity.config_entry = SimpleNamespace(entry_id="entry")
    entity.coordinator = SimpleNamespace(async_refresh=AsyncMock())
    entity.hass = SimpleNamespace(data={DOMAIN: {"entry": {PFSENSE_DATA: data}}})

    await entity._async_refresh_after_mutation()

    data.invalidate_slow_state.assert_called_once_with()
    entity.coordinator.async_refresh.assert_awaited_once_with()
