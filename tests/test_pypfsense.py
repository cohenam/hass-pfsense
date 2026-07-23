import base64
from concurrent.futures import ThreadPoolExecutor
import json
import logging
import re
import threading
from urllib.parse import quote_plus
import xmlrpc.client

import pytest

from custom_components.pfsense import pypfsense


def _decode_php_data(script):
    match = re.search(r"base64_decode\('([^']+)'\)", script)
    assert match is not None
    return json.loads(base64.b64decode(match.group(1)).decode("utf-8"))


def _client():
    return pypfsense.Client(
        "https://router.example:8443",
        "audit-user",
        "s3cr'et&value",
    )


def test_php_json_data_round_trips_without_raw_php_literals():
    data = {
        "notice": "owner's router\n'); mwexec('touch /tmp/injected'); //",
        "unicode": "שלום",
        "path": r"C:\temp",
    }

    statement = pypfsense._php_json_data(data)

    assert _decode_php_data(statement) == data
    assert data["notice"] not in statement
    assert data["unicode"] not in statement


def test_xmlrpc_url_is_credential_free_and_transport_uses_authorization_header():
    client = _client()
    proxy = client._get_proxy()
    transport = proxy._ServerProxy__transport
    headers = []
    connection = type(
        "Connection",
        (),
        {"putheader": lambda self, key, value: headers.append((key, value))},
    )()

    transport.send_headers(connection, [("Content-Type", "text/xml")])

    token = base64.b64encode(b"audit-user:s3cr'et&value").decode("ascii")
    assert client._url == "https://router.example:8443/xmlrpc.php"
    assert "audit-user" not in client._url
    assert "s3cr" not in client._url
    assert ("Authorization", f"Basic {token}") in headers
    assert ("Content-Type", "text/xml") in headers


def test_protocol_errors_are_redacted_in_logs_and_raised_error(caplog):
    client = _client()
    encoded_password = quote_plus("s3cr'et&value")
    credential_url = (
        "https://audit-user:" f"{encoded_password}@router.example/xmlrpc.php"
    )
    error = xmlrpc.client.ProtocolError(
        credential_url,
        401,
        "password=s3cr'et&value",
        {},
    )

    class Proxy:
        pfsense = None

        def __init__(self):
            self.pfsense = self

        def host_firmware_version(self, *_args):
            raise error

    client._get_proxy = lambda *_args, **_kwargs: Proxy()

    with (
        caplog.at_level(logging.ERROR),
        pytest.raises(xmlrpc.client.ProtocolError) as raised,
    ):
        client.get_host_firmware_version()

    combined = f"{caplog.text}\n{raised.value!r}"
    assert "audit-user" not in combined
    assert "s3cr'et&value" not in combined
    assert quote_plus("s3cr'et&value") not in combined
    assert "ProtocolError" in combined


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.1; touch /tmp/injected",
        "192.0.2.1\nreboot",
        "not-a-network",
        "",
    ],
)
def test_kill_states_rejects_non_ip_input_before_rpc(value):
    client = _client()
    called = False

    def capture(_script):
        nonlocal called
        called = True

    client._exec_php = capture

    with pytest.raises(ValueError, match="Invalid IP"):
        client.kill_states(value)

    assert called is False


def test_kill_states_validates_and_shell_escapes_both_targets():
    client = _client()
    scripts = []
    client._exec_php = lambda script: scripts.append(script)

    client.kill_states("192.0.2.7/24", "2001:db8::1")

    assert len(scripts) == 1
    assert _decode_php_data(scripts[0]) == {
        "source": "192.0.2.7/24",
        "destination": "2001:db8::1",
    }
    assert scripts[0].count("escapeshellarg") == 2


def test_delete_arp_entries_batches_validated_addresses():
    client = _client()
    scripts = []
    client._exec_php = lambda script: scripts.append(script)

    client.delete_arp_entries(["192.0.2.1", "2001:db8::1"])

    assert len(scripts) == 1
    assert _decode_php_data(scripts[0]) == {"ips": ["192.0.2.1", "2001:db8::1"]}
    assert "foreach" in scripts[0]
    assert "escapeshellarg" in scripts[0]


def test_rule_mutation_is_server_side_and_rejects_duplicate_identifier():
    client = _client()
    scripts = []

    def execute(script, timeout=None):
        assert timeout == 60
        scripts.append(script)
        return {"data": {"matched": 1, "changed": True}}

    client._exec_php = execute
    client.disable_nat_outbound_rule_by_created_time("1700000000")

    assert len(scripts) == 1
    assert _decode_php_data(scripts[0]) == {
        "rule_type": "nat_outbound",
        "identifier": "1700000000",
        "disabled": True,
    }
    assert "write_config" in scripts[0]
    assert "filter_configure" in scripts[0]
    assert "restore_config_section" not in scripts[0]

    client._exec_php = lambda _script, timeout=None: {
        "data": {"matched": 2, "changed": False}
    }
    with pytest.raises(ValueError, match="duplicate identifier"):
        client.enable_filter_rule_by_tracker("duplicate")

    client._exec_php = lambda _script, timeout=None: {
        "data": {"matched": 0, "changed": False}
    }
    with pytest.raises(ValueError, match="no longer exists"):
        client.enable_filter_rule_by_tracker("missing")


def test_rule_mutations_are_serialized_per_client():
    client = _client()
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()
    call_lock = threading.Lock()
    call_count = 0

    def execute(_script, timeout=None):
        assert timeout == 60
        nonlocal call_count
        with call_lock:
            call_count += 1
            current_call = call_count
        if current_call == 1:
            first_entered.set()
            assert release_first.wait(1)
        else:
            second_entered.set()
        return {"data": {"matched": 1, "changed": True}}

    client._exec_php = execute
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.disable_filter_rule_by_tracker, "one")
        assert first_entered.wait(1)
        second = pool.submit(client.disable_filter_rule_by_tracker, "two")
        assert second_entered.wait(0.05) is False
        release_first.set()
        first.result()
        second.result()

    assert second_entered.is_set()


def test_telemetry_supports_old_and_new_get_mbuf_signatures():
    client = _client()
    scripts = []

    def execute(script):
        scripts.append(script)
        return {"filesystems": [], "gateways": []}

    client._exec_php = execute

    client.get_telemetry()

    assert 'new ReflectionFunction("get_mbuf")' in scripts[0]
    assert "get_mbuf()" in scripts[0]
    assert "get_mbuf($mbuf, $mbufpercent)" in scripts[0]
