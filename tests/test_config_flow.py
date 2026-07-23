from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from homeassistant.const import (
    CONF_PASSWORD,
    CONF_URL,
    CONF_USERNAME,
)
from homeassistant.data_entry_flow import AbortFlow
import pytest

from custom_components.pfsense.config_flow import (
    ConfigFlowHandler,
    cleanse_sensitive_data,
)


def test_cleanse_sensitive_data_redacts_raw_and_encoded_secrets():
    message = "admin p%40ss"

    assert cleanse_sensitive_data(message, ["admin", "p@ss"]) == (
        "[redacted] [redacted]"
    )


@pytest.mark.asyncio
async def test_duplicate_entry_abort_is_not_converted_to_connection_error():
    flow = ConfigFlowHandler()
    flow.hass = SimpleNamespace(
        async_add_executor_job=AsyncMock(
            return_value={
                "hostname": "router",
                "domain": "example",
                "netgate_device_id": "device-id",
            }
        )
    )

    with (
        patch.object(flow, "async_set_unique_id", AsyncMock()),
        patch.object(
            flow,
            "_abort_if_unique_id_configured",
            Mock(side_effect=AbortFlow("already_configured")),
        ),
        pytest.raises(AbortFlow, match="already_configured"),
    ):
        await flow.async_step_user(
            {
                CONF_URL: "https://router.example",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
            }
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "ftp://router.example",
        "https://[broken",
        "https://user:password@router.example",
    ],
)
async def test_invalid_or_credential_bearing_url_is_rejected(url):
    flow = ConfigFlowHandler()

    result = await flow.async_step_user(
        {
            CONF_URL: url,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
        }
    )

    assert result["errors"] == {"base": "invalid_url_format"}
