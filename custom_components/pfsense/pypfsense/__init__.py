"""
note that the xmlrpc api only allows a single request to be handled at a time
likely via some sort of mutex.
"""

import base64
from functools import wraps
import ipaddress
import json
import logging
import ssl
import threading
from urllib.parse import quote, quote_plus, urlparse, urlunparse
from xml.parsers.expat import ExpatError
import xmlrpc.client

# per-connection socket timeout (seconds) for normal API calls
DEFAULT_TIMEOUT = 10
# generous timeout for the firmware update check: when pfSense's 2h
# pkg-version cache is stale it contacts upstream pkg servers (~60s worst case)
FIRMWARE_TIMEOUT = 90

_LOGGER = logging.getLogger(__name__)


def _php_json_data(data):
    payload = base64.b64encode(
        json.dumps(data, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    return f"$data = json_decode(base64_decode('{payload}'), true);"


def validate_ip_or_network(value):
    value = value.strip()
    try:
        if "/" in value:
            ipaddress.ip_interface(value)
        else:
            ipaddress.ip_address(value)
    except ValueError as err:
        raise ValueError(f"Invalid IP address or network: {value}") from err
    return value


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


def normalize_service_data(service):
    service_data_type = type(service).__name__
    if service_data_type == "dict":
        pass
    elif service_data_type == "NoneType":
        service = {}
    elif service_data_type == "str":
        if len(service) > 0:
            service = json.loads(service)
        else:
            service = {}
    else:
        raise TypeError("invalid datatype for variable `service`: " + service_data_type)

    return service


# Timeouts are set per-connection (not via socket.setdefaulttimeout, which is
# process-global and races between concurrent calls). The timeout is applied on
# every make_connection return so the stdlib's connection cache is covered too.
class _AuthenticatedTransport:
    def _set_authorization(self, username, password):
        credentials = f"{username}:{password}".encode("utf-8")
        token = base64.b64encode(credentials).decode("ascii")
        self._authorization = f"Basic {token}"

    def send_headers(self, connection, headers):
        connection.putheader("Authorization", self._authorization)
        super().send_headers(connection, headers)


class _TimeoutTransport(_AuthenticatedTransport, xmlrpc.client.Transport):
    """HTTP transport with a per-connection timeout."""

    def __init__(self, username, password, timeout=DEFAULT_TIMEOUT):
        super().__init__()
        self._set_authorization(username, password)
        self._timeout = timeout

    def make_connection(self, host):
        connection = super().make_connection(host)
        connection.timeout = self._timeout
        return connection


class _TimeoutSafeTransport(_AuthenticatedTransport, xmlrpc.client.SafeTransport):
    """HTTPS transport with a per-connection timeout."""

    def __init__(self, username, password, timeout=DEFAULT_TIMEOUT, context=None):
        super().__init__(context=context)
        self._set_authorization(username, password)
        self._timeout = timeout

    def make_connection(self, host):
        connection = super().make_connection(host)
        connection.timeout = self._timeout
        return connection


class Client(object):
    """pfSense Client"""

    def __init__(self, url, username, password, opts=None):
        """pfSense Client initializer."""

        if opts is None:
            opts = {}

        self._username = username
        self._password = password
        self._opts = opts
        parts = urlparse(url.rstrip("/") + "/xmlrpc.php")
        hostname = parts.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        host = f"{hostname}:{parts.port}" if parts.port else hostname
        self._url = urlunparse((parts.scheme, host, "/xmlrpc.php", "", "", ""))
        self._url_parts = urlparse(self._url)
        self._mutation_lock = threading.Lock()

    # https://stackoverflow.com/questions/64983392/python-multiple-patch-gives-http-client-cannotsendrequest-request-sent
    def _get_proxy(self, timeout=DEFAULT_TIMEOUT):
        # https://docs.python.org/3/library/xmlrpc.client.html#module-xmlrpc.client
        # https://stackoverflow.com/questions/30461969/disable-default-certificate-verification-in-python-2-7-9
        context = None
        verify_ssl = True
        if "verify_ssl" in self._opts.keys():
            verify_ssl = self._opts["verify_ssl"]

        if self._url_parts.scheme == "https" and not verify_ssl:
            context = ssl._create_unverified_context()

        # set to True if necessary during development
        verbose = False

        # with transport= supplied, ServerProxy ignores its own context kwarg —
        # the context must be threaded through the SafeTransport
        if self._url_parts.scheme == "https":
            transport = _TimeoutSafeTransport(
                self._username,
                self._password,
                timeout=timeout,
                context=context,
            )
        else:
            transport = _TimeoutTransport(
                self._username, self._password, timeout=timeout
            )

        proxy = xmlrpc.client.ServerProxy(
            self._url, transport=transport, verbose=verbose
        )
        return proxy

    def _redact(self, value):
        if not isinstance(value, str):
            return value

        credentials = f"{self._username}:{self._password}"
        secrets = (self._username, self._password, credentials)
        for secret in secrets:
            if not secret:
                continue
            for variant in {
                secret,
                quote(secret, safe=""),
                quote_plus(secret),
                base64.b64encode(secret.encode("utf-8")).decode("ascii"),
            }:
                value = value.replace(variant, "[redacted]")
        return value

    def _sanitize_exception(self, err):
        err.args = tuple(self._redact(value) for value in err.args)
        for attribute in ("url", "errmsg", "faultString"):
            value = getattr(err, attribute, None)
            if isinstance(value, str):
                setattr(err, attribute, self._redact(value))
        reason = getattr(err, "reason", None)
        if isinstance(reason, str):
            err.reason = self._redact(reason)
        elif isinstance(reason, Exception):
            self._sanitize_exception(reason)
        return err

    def _log_errors(func):
        @wraps(func)
        def inner(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as err:
                self = args[0]
                safe_error = self._sanitize_exception(err)
                _LOGGER.error(
                    "Unexpected %s error (%s)",
                    func.__name__,
                    type(safe_error).__name__,
                )
                raise safe_error from None

        return inner

    def _get_config_section(self, section):
        response = self._get_proxy().pfsense.backup_config_section([section])
        return response[section]

    def _restore_config_section(self, section_name, data):
        params = {section_name: data}
        response = self._get_proxy(timeout=60).pfsense.restore_config_section(
            params, 60
        )
        return response

    def _exec_php(self, script, timeout=DEFAULT_TIMEOUT):
        script = """
ini_set('display_errors', 0);

{}

// wrapping this in json_encode and then unwrapping in python prevents funny XMLRPC NULL encoding errors
// https://github.com/travisghansen/hass-pfsense/issues/35
$toreturn_real = $toreturn;
$toreturn = [];
$toreturn["real"] = json_encode($toreturn_real);
""".format(script)
        try:
            response = self._get_proxy(timeout=timeout).pfsense.exec_php(script)
            response = json.loads(response["real"])
            return response
        except Exception as err:
            raise self._sanitize_exception(err) from None

    def _exec_command(self, command, background=False):
        script = """
{}
if ($data["background"]) {{
    $ret = mwexec_bg($data["command"]);    
}}
else {{
    $ret = mwexec($data["command"]);
}}

$toreturn = [
  "data" => $ret,
];
""".format(_php_json_data({"command": command, "background": background}))
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_host_firmware_version(self):
        return self._get_proxy().pfsense.host_firmware_version(1, 60)

    def get_firmware_update_info(self):
        """
        # the cache is 2 hours
        get_system_pkg_version($baseonly = false, $use_cache = true)
        # for testing
        rm /var/run/pfSense_version*
        """
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);
//unlock_force("xmlrpc");

require_once '/etc/inc/pkg-utils.inc';

$toreturn = [
  "data" => [
      "base" => get_system_pkg_version(),
      // someday add package updates details here
      "packages" => [],
    ]
];
"""
        try:
            response = self._exec_php(script, timeout=FIRMWARE_TIMEOUT)
        except TimeoutError as err:
            # tolerated: pfSense contacts upstream pkg servers when its 2h
            # cache is stale; the coordinator logs this at DEBUG and retries
            raise self._sanitize_exception(err) from None
        except Exception as err:
            safe_error = self._sanitize_exception(err)
            _LOGGER.error(
                "Unexpected get_firmware_update_info error (%s)",
                type(safe_error).__name__,
            )
            raise safe_error from None
        return response["data"]

    @_log_errors
    def upgrade_firmware(self):
        script = """
$ret = mwexec_bg("pfSense-upgrade -y -l /tmp/hass-upgrade.log -p /tmp/hass-upgrade.sock");
$toreturn = [
  "data" => $ret,
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def pid_is_running(self, pid):
        script = """
{}
$running = posix_kill($data["pid"],0);
$toreturn = [
  "data" => $running,
];
""".format(
            _php_json_data(
                {
                    "pid": pid,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_system_serial(self):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

$toreturn = [
  "data" => system_get_serial(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_netgate_device_id(self):
        script = """
$toreturn = [
  "data" => system_get_uniqueid(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_system_info(self):
        # TODO: add bios details here
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

global $config;

$toreturn = [
  "hostname" => $config["system"]["hostname"],
  "domain" => $config["system"]["domain"],
  "serial" => system_get_serial(),
  "netgate_device_id" => system_get_uniqueid(),
  "platform" => system_identify_specific_platform(),
];
"""
        response = self._exec_php(script)
        return response

    @_log_errors
    def get_config(self):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

global $config;

$toreturn = [
  "data" => $config,
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_interfaces(self):
        return self._get_config_section("interfaces")

    @_log_errors
    def get_interface(self, interface):
        interfaces = self.get_interfaces()
        return interfaces[interface]

    @_log_errors
    def get_interface_by_description(self, interface):
        interfaces = self.get_interfaces()
        for i, i_interface in enumerate(interfaces.keys()):
            if interfaces[i_interface]["descr"] == interface:
                return interfaces[i_interface]

    def _set_rule_disabled(self, rule_type, identifier, disabled):
        script = """
require_once '/etc/inc/config.inc';
require_once '/etc/inc/filter.inc';
global $config;

{}
$rules = [];
switch ($data["rule_type"]) {{
    case "filter":
        if (isset($config["filter"]["rule"]) && is_array($config["filter"]["rule"])) {{
            $rules =& $config["filter"]["rule"];
        }}
        break;
    case "nat_port_forward":
        if (isset($config["nat"]["rule"]) && is_array($config["nat"]["rule"])) {{
            $rules =& $config["nat"]["rule"];
        }}
        break;
    case "nat_outbound":
        if (isset($config["nat"]["outbound"]["rule"]) && is_array($config["nat"]["outbound"]["rule"])) {{
            $rules =& $config["nat"]["outbound"]["rule"];
        }}
        break;
}}

$matching_indexes = [];
foreach ($rules as $index => $rule) {{
    $rule_identifier = $data["rule_type"] === "filter"
        ? ($rule["tracker"] ?? null)
        : ($rule["created"]["time"] ?? null);
    if ($rule_identifier !== null &&
        (string) $rule_identifier === (string) $data["identifier"]) {{
        $matching_indexes[] = $index;
    }}
}}

$changed = false;
if (count($matching_indexes) === 1) {{
    $index = $matching_indexes[0];
    if ($data["disabled"] && !array_key_exists("disabled", $rules[$index])) {{
        $rules[$index]["disabled"] = "";
        $changed = true;
    }} elseif (!$data["disabled"] && array_key_exists("disabled", $rules[$index])) {{
        unset($rules[$index]["disabled"]);
        $changed = true;
    }}
}}

if ($changed) {{
    write_config("Home Assistant: update firewall rule state");
    filter_configure();
}}

$toreturn = [
    "data" => [
        "matched" => count($matching_indexes),
        "changed" => $changed,
    ],
];
""".format(
            _php_json_data(
                {
                    "rule_type": rule_type,
                    "identifier": identifier,
                    "disabled": disabled,
                }
            )
        )

        with self._mutation_lock:
            result = self._exec_php(script, timeout=60)["data"]
        if result["matched"] == 0:
            raise ValueError("Cannot mutate a rule that no longer exists")
        if result["matched"] > 1:
            raise ValueError("Cannot mutate rules with a duplicate identifier")

    @_log_errors
    def enable_filter_rule_by_tracker(self, tracker):
        self._set_rule_disabled("filter", tracker, False)

    @_log_errors
    def disable_filter_rule_by_tracker(self, tracker):
        self._set_rule_disabled("filter", tracker, True)

    # use created_time as a unique_id since none other exists
    @_log_errors
    def enable_nat_port_forward_rule_by_created_time(self, created_time):
        if created_time is None:
            return
        self._set_rule_disabled("nat_port_forward", created_time, False)

    # use created_time as a unique_id since none other exists
    @_log_errors
    def disable_nat_port_forward_rule_by_created_time(self, created_time):
        if created_time is None:
            return
        self._set_rule_disabled("nat_port_forward", created_time, True)

    # use created_time as a unique_id since none other exists
    @_log_errors
    def enable_nat_outbound_rule_by_created_time(self, created_time):
        if created_time is None:
            return
        self._set_rule_disabled("nat_outbound", created_time, False)

    # use created_time as a unique_id since none other exists
    @_log_errors
    def disable_nat_outbound_rule_by_created_time(self, created_time):
        if created_time is None:
            return
        self._set_rule_disabled("nat_outbound", created_time, True)

    @_log_errors
    def get_configured_interface_descriptions(self):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

$toreturn = [
  "data" => get_configured_interface_with_descr(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_gateways(self):
        # {'GW_WAN': {'interface': '<if>', 'gateway': '<ip>', 'name': 'GW_WAN', 'weight': '1', 'ipprotocol': 'inet', 'interval': '', 'descr': 'Interface wan Gateway', 'monitor': '<ip>', 'friendlyiface': 'wan', 'friendlyifdescr': 'WAN', 'isdefaultgw': True, 'attribute': 0, 'tiername': 'Default (IPv4)'}}
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

$toreturn = [
  "data" => return_gateways_array(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_gateway(self, gateway):
        gateways = self.get_gateways()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

    @_log_errors
    def get_gateways_status(self):
        # {'GW_WAN': {'monitorip': '<ip>', 'srcip': '<ip>', 'name': 'GW_WAN', 'delay': '0.387ms', 'stddev': '0.097ms', 'loss': '0.0%', 'status': 'online', 'substatus': 'none'}}
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

$toreturn = [
  // function return_gateways_status($byname = false, $gways = false)
  "data" => return_gateways_status(true),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_gateway_status(self, gateway):
        gateways = self.get_gateways_status()
        for g in gateways.keys():
            if g == gateway:
                return gateways[g]

    @_log_errors
    def get_arp_table(self, resolve_hostnames=False):
        # [{'hostname': '?', 'ip-address': '<ip>', 'mac-address': '<mac>', 'interface': 'em0', 'expires': 1199, 'type': 'ethernet'}, ...]
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

{}
$resolve_hostnames = $data["resolve_hostnames"];
$toreturn = [
  "data" => system_get_arp_table($resolve_hostnames),
];
""".format(
            _php_json_data(
                {
                    "resolve_hostnames": resolve_hostnames,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def set_default_gateway(self, gateway, ip_version="4"):
        ipVersion = str(ip_version)
        key = "defaultgw4"
        if "4" in ipVersion:
            key = "defaultgw4"
        if "6" in ipVersion:
            key = "defaultgw6"

        script = """
require_once '/etc/inc/config.inc';
global $config;

{}
$key = $data["key"];
$config['gateways'][$key] = $data["gateway"];

mark_subsystem_dirty('staticroutes');
write_config("System - Gateways: save default gateway");

$retval = 0;
                    
$retval |= system_routing_configure();
$retval |= system_resolvconf_generate();
$retval |= filter_configure();
/* reconfigure our gateway monitor */
setup_gateways_monitor();
/* Dynamic DNS on gw groups may have changed */
send_event("service reload dyndnsall");

if ($retval == 0) {{
  clear_subsystem_dirty('staticroutes');
}}

$toreturn = [
  "data" => $retval
];
""".format(_php_json_data({"key": key, "gateway": gateway}))

        self._exec_php(script)

    @_log_errors
    def get_services(self):
        # function get_services()
        # Batch all service status checks in a single PHP call to avoid N+1 API calls
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

require_once '/etc/inc/service-utils.inc';
// only returns enabled services currently
$s = get_services();
$services = [];
foreach($s as $service) {
  if (!is_array($service)) {
      continue;
  }
  if (!empty($service)) {
    // Add status check for services that don't have it
    // This avoids extra API calls from the Python side
    if (!isset($service['status'])) {
      $service_name = $service['name'];
      if ($service_name == 'openvpn' && isset($service['vpnid'])) {
        // OpenVPN requires special handling
        $svc = $service;
        if (!isset($svc['vpnmode']) && isset($svc['mode'])) {
          $svc['vpnmode'] = $svc['mode'];
        }
        if (!isset($svc['mode']) && isset($svc['vpnmode'])) {
          $svc['mode'] = $svc['vpnmode'];
        }
        $svc['id'] = $svc['vpnid'];
        $service['status'] = (bool) get_service_status($svc);
      } else {
        $service['status'] = (bool) is_service_running($service_name);
      }
    }
    $services[] = $service;
  }
}

$toreturn = [
  // function get_services()
  "data" => $services,
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_service_is_enabled(self, service_name, service={}):
        service = normalize_service_data(service)

        # function is_service_enabled($service_name)
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

require_once '/etc/inc/service-utils.inc';

{}
$service_name = $data["service_name"];
$toreturn = [
  // always returns true, so mostly useless at this point
  "data" => is_service_enabled($service_name),
];
""".format(
            _php_json_data(
                {
                    "service_name": service_name,
                    "service": service,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_service_is_running(self, service_name, service={}):
        service = normalize_service_data(service)

        # function is_service_running($service, $ps = "")
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

require_once '/etc/inc/service-utils.inc';

{}
$service_name = $data["service_name"];
$service = $data["service"];
if (!$service) {{
  $service = [];
}}

if ($service_name == "openvpn" && $service) {{
  if (!$service["name"]) {{
    $service["name"] = $service_name;
  }}
  if (!$service["vpnmode"] && $service["mode"]) {{
    $service["vpnmode"] = $service["mode"];
  }}
  if (!$service["mode"] && $service["vpnmode"]) {{
    $service["mode"] = $service["vpnmode"];
  }}
  $service["id"] = $service["vpnid"];
  $toreturn = [
    // requires mode and vpnid
    "data" => (bool) get_service_status($service),
  ];
}}
else {{
  $toreturn = [
    "data" => (bool) is_service_running($service_name),
  ];
}}

""".format(
            _php_json_data(
                {
                    "service_name": service_name,
                    "service": service,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def start_service(self, service_name, service={}):
        service = normalize_service_data(service)

        # function start_service($name, $after_sync = false)
        script = """
require_once '/etc/inc/service-utils.inc';

{}
$service_name = $data["service_name"];
$service = $data["service"];
if (!$service) {{
  $service = [];
}}

if ($service_name == "openvpn" && $service) {{
  // requires name, mode and vpnid
  if (!$service["name"]) {{
    $service["name"] = $service_name;
  }}
  if (!$service["vpnmode"] && $service["mode"]) {{
    $service["vpnmode"] = $service["mode"];
  }}
  if (!$service["mode"] && $service["vpnmode"]) {{
    $service["mode"] = $service["vpnmode"];
  }}
  $service["id"] = $service["vpnid"];
  $is_running = (bool) get_service_status($service);
}}
else {{
  $is_running = is_service_running($service_name);
}}

if (!$is_running) {{
  service_control_start($service_name, $service);
}}

$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            _php_json_data(
                {
                    "service_name": service_name,
                    "service": service,
                }
            )
        )
        self._exec_php(script)

    @_log_errors
    def stop_service(self, service_name, service={}):
        service = normalize_service_data(service)

        # function stop_service($name)
        script = """
require_once '/etc/inc/service-utils.inc';

{}
$service_name = $data["service_name"];
$service = $data["service"];
if (!$service) {{
  $service = [];
}}

if ($service_name == "openvpn" && $service) {{
  // requires name, mode, and vpnid
  if (!$service["name"]) {{
    $service["name"] = $service_name;
  }}
  if (!$service["vpnmode"] && $service["mode"]) {{
    $service["vpnmode"] = $service["mode"];
  }}
  if (!$service["mode"] && $service["vpnmode"]) {{
    $service["mode"] = $service["vpnmode"];
  }}
  $service["id"] = $service["vpnid"];
  $is_running = (bool) get_service_status($service);
}}
else {{
  $is_running = is_service_running($service_name);
}}

if ($is_running) {{
  service_control_stop($service_name, $service);
}}
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            _php_json_data(
                {
                    "service_name": service_name,
                    "service": service,
                }
            )
        )
        self._exec_php(script)

    @_log_errors
    def restart_service(self, service_name, service={}):
        service = normalize_service_data(service)

        # function restart_service($name) (if service is not currently running, it will be started)
        script = """
require_once '/etc/inc/service-utils.inc';

{}
$service_name = $data["service_name"];
$service = $data["service"];
if (!$service) {{
  $service = [];
}}

if ($service_name == "openvpn" && $service) {{
  // requires name, mode, and vpnid
  if (!$service["name"]) {{
    $service["name"] = $service_name;
  }}
  if (!$service["vpnmode"] && $service["mode"]) {{
    $service["vpnmode"] = $service["mode"];
  }}
  if (!$service["mode"] && $service["vpnmode"]) {{
    $service["mode"] = $service["vpnmode"];
  }}
  $service["id"] = $service["vpnid"];
}}

service_control_restart($service_name, $service);
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            _php_json_data(
                {
                    "service_name": service_name,
                    "service": service,
                }
            )
        )
        self._exec_php(script)

    @_log_errors
    def restart_service_if_running(self, service_name, service={}):
        service = normalize_service_data(service)

        # function restart_service_if_running($service)
        script = """
require_once '/etc/inc/service-utils.inc';

{}
$service_name = $data["service_name"];
$service = $data["service"];
if (!$service) {{
  $service = [];
}}

if ($service_name == "openvpn" && $service) {{
  // requires name, mode, and vpnid
  if (!$service["name"]) {{
    $service["name"] = $service_name;
  }}
  if (!$service["vpnmode"] && $service["mode"]) {{
    $service["vpnmode"] = $service["mode"];
  }}
  if (!$service["mode"] && $service["vpnmode"]) {{
    $service["mode"] = $service["vpnmode"];
  }}
  $service["id"] = $service["vpnid"];
  $is_running = (bool) get_service_status($service);
}}
else {{
  $is_running = is_service_running($service_name);
}}

if ($is_running) {{
  service_control_restart($service_name, $service);
}}
$toreturn = [
  // no return value
  "data" => true,
];
""".format(
            _php_json_data(
                {
                    "service_name": service_name,
                    "service": service,
                }
            )
        )
        self._exec_php(script)

    @_log_errors
    def get_dhcp_leases(self, dns_lookups=None):
        # function system_get_dhcpleases()
        # {'lease': [], 'failover': []}
        # {"lease":[{"ip":"<ip>","type":"static","mac":"<mac>","if":"lan","starts":"","ends":"","hostname":"<hostname>","descr":"","act":"static","online":"online","staticmap_array_index":48} ...
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

{}

$dns_lookups = null;
if ($data["dns_lookups"] === true || $data["dns_lookups"] === false) {{
  $dns_lookups = $data["dns_lookups"];
}}

$toreturn = [
  "data" => system_get_dhcpleases($dns_lookups),
];
""".format(
            _php_json_data(
                {
                    "dns_lookups": dns_lookups,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]["lease"]

    @_log_errors
    def get_virtual_ips(self):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

global $config;

$vips = [];
if ($config['virtualip'] && is_iterable($config['virtualip']['vip'])) {
  foreach ($config['virtualip']['vip'] as $vip) {
    $vips[] = $vip;
  }
}

$toreturn = [
  "data" => $vips,
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_carp_status(self):
        # carp enabled or not
        # readonly attribute, cannot be set directly
        # function get_carp_status()
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

$toreturn = [
  "data" => get_carp_status(),
];
"""
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_carp_interface_status(self, uniqueid):
        # function get_carp_interface_status($carpid)
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

{}
$uniqueid = $data["uniqueid"];
$carp_if = "_vip{{$uniqueid}}";
$status = get_carp_interface_status($carp_if);
$toreturn = [
  "data" => $status,
];
""".format(
            _php_json_data(
                {
                    "uniqueid": uniqueid,
                }
            )
        )
        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_carp_interfaces(self):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

global $config;

$vips = [];
if ($config['virtualip'] && is_iterable($config['virtualip']['vip'])) {
  foreach ($config['virtualip']['vip'] as $vip) {
    if ($vip["mode"] != "carp") {
      continue;
    }
    $vips[] = $vip;
  }
}

foreach ($vips as &$vip) {
  $status = get_carp_interface_status("_vip{$vip['uniqid']}");
  $vip["status"] = $status;
}

$toreturn = [
  "data" => $vips,
];
"""
        response = self._exec_php(script)
        return response["data"]

    def delete_arp_entry(self, ip):
        self.delete_arp_entries([ip])

    @_log_errors
    def delete_arp_entries(self, ips: list[str]):
        ips = [validate_ip_or_network(ip) for ip in ips]
        if not ips:
            return

        script = """
{}
$results = [];
foreach ($data["ips"] as $ip) {{
    $results[] = mwexec("arp -d " . escapeshellarg($ip), true);
}}
$toreturn = [
  "data" => $results,
];
""".format(
            _php_json_data(
                {
                    "ips": ips,
                }
            )
        )
        self._exec_php(script)

    @_log_errors
    def arp_get_mac_by_ip(self, ip, do_ping=True):
        """function arp_get_mac_by_ip($ip, $do_ping = true)"""
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

{}
$ip = $data["ip"];
$do_ping = $data["do_ping"];
$toreturn = [
  "data" => arp_get_mac_by_ip($ip, $do_ping),
];
""".format(
            _php_json_data(
                {
                    "ip": ip,
                    "do_ping": do_ping,
                }
            )
        )
        response = self._exec_php(script)["data"]
        if not response:
            return None
        return response

    @_log_errors
    def reset_state_table(self):

        script = """
mwexec("/sbin/pfctl -F states");
"""
        # no response is expected on success since all connections are closed
        self._exec_php(script)

    @_log_errors
    def kill_states(self, source, destination=None):
        source = validate_ip_or_network(source)
        if destination is not None:
            destination = validate_ip_or_network(destination)

        script = """
{}
$command = "/sbin/pfctl -k " . escapeshellarg($data["source"]);
if ($data["destination"] !== null) {{
    $command .= " -k " . escapeshellarg($data["destination"]);
}}
mwexec($command);
""".format(
            _php_json_data(
                {
                    "source": source,
                    "destination": destination,
                }
            )
        )
        self._exec_php(script)

    @_log_errors
    def system_reboot(self, type="normal"):
        """
        type = normal = simple reboot
        type = reroot = a reroot reboot
        type = fsck = perform an fsck on next boot
        """
        script = """
{}
$type = $data["type"];
$type = strtolower($type);

switch ($type) {{
    case 'fsck':
        if (php_uname('m') != 'arm') {{
            mwexec('/sbin/nextboot -e "pfsense.fsck.force=5"');
        }}
        system_reboot();
        break;
    case 'reroot':
        system_reboot_sync(true);
        break;
    case 'normal':
        system_reboot();
        break;
    default:
        break;
}}

$toreturn = [
  "data" => true,
];
""".format(
            _php_json_data(
                {
                    "type": type,
                }
            )
        )
        try:
            self._exec_php(script)
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    @_log_errors
    def system_halt(self):
        script = """
system_halt();
$toreturn = [
  "data" => true,
];
"""
        try:
            self._exec_php(script)
        except ExpatError:
            # ignore response failures because the system is going down
            pass

    @_log_errors
    def send_wol(self, interface, mac):
        """
        interface should be wan, lan, opt1, opt2 etc, not the description
        """

        script = """
{}
$if = $data["interface"];
$mac = $data["mac"];
function send_wol($if, $mac) {{
        $ipaddr = get_interface_ip($if);
        if (!is_ipaddr($ipaddr) || !is_macaddr($mac)) {{
                return false;
        }}

        $bcip = gen_subnet_max($ipaddr, get_interface_subnet($if));
        return (bool) !mwexec("/usr/local/bin/wol -i {{$bcip}} {{$mac}}");
}}

$value = send_wol($if, $mac);
$toreturn = [
  "data" => $value,
];
""".format(
            _php_json_data(
                {
                    "interface": interface,
                    "mac": mac,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]

    # TODO: function find_service_by_name($name)
    # TODO: function get_service_status($service) # seems to be higher-level logic than is_service_running, passes in the full service object

    @_log_errors
    def get_telemetry(self):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

require_once '/usr/local/www/includes/functions.inc.php';
require_once '/etc/inc/config.inc';
require_once '/etc/inc/pfsense-utils.inc';
require_once '/etc/inc/system.inc';
require_once '/etc/inc/util.inc';
require_once 'interfaces.inc';
require_once '/etc/inc/openvpn.inc';
require_once '/etc/inc/ipsec.inc';

global $config;
global $g;

function stripalpha($s) {
  return preg_replace("/\\D/", "", $s);
}

$mbuf_function = new ReflectionFunction("get_mbuf");
if ($mbuf_function->getNumberOfParameters() === 0) {
  $mbuf = get_mbuf();
  $mbuf_parts = array_pad(explode("/", (string) $mbuf), 2, 0);
  $mbufpercent = ((int) $mbuf_parts[1] > 0)
    ? round(((int) $mbuf_parts[0] / (int) $mbuf_parts[1]) * 100, 0)
    : 0;
} else {
  $mbuf = null;
  $mbufpercent = null;
  get_mbuf($mbuf, $mbufpercent);
  $mbuf_parts = array_pad(explode("/", (string) $mbuf), 2, 0);
}

$filesystems = get_mounted_filesystems();
$ifdescrs = get_configured_interface_with_descr();

$boottime = exec_command("sysctl kern.boottime");
// kern.boottime: { sec = 1634047554, usec = 237429 } Tue Oct 12 08:05:54 2021
preg_match("/sec = [0-9]*/", $boottime, $matches);
$boottime = $matches[0];
$boottime = explode("=", $boottime)[1];
$boottime = (int) trim($boottime);

$pfstate = get_pfstate();
// <used>/<total>
$pfstate_parts = explode("/", $pfstate);

$cpu_usage = cpu_usage();
// 1112|111
$cpu_usage_parts = explode("|", $cpu_usage);

$system_load_average = get_load_average();
// 0.23, 0.22, 0.21
$system_load_average_parts = explode(",", $system_load_average);

$cpu_frequency = get_cpufreq();
// Current: 800 MHz, Max: 3700 MHz
$cpu_frequency_parts = explode(",", $cpu_frequency);

$memory_info = exec_command("sysctl hw.physmem hw.usermem hw.realmem vm.swap_total vm.swap_reserved");
$memory_parts = explode("\n", $memory_info);

$ovpn_servers = openvpn_get_active_servers();

$toreturn = [

  "pfstate" => [
    "used" => (int) $pfstate_parts[0],
    "total" => (int) $pfstate_parts[1],
    "used_percent" => get_pfstate(true),
  ],

  "mbuf" => [
    "used" => (int) $mbuf_parts[0],
    "total" => (int) $mbuf_parts[1],
    "used_percent" => floatval($mbufpercent),
  ],

  "memory" => [
    "swap_used_percent" => floatval(swap_usage()),
    "used_percent" => floatval(mem_usage()),
    "physmem" => (int) trim(explode(":", $memory_parts[0])[1]),
    "usermem" => (int) trim(explode(":", $memory_parts[1])[1]),
    "realmem" => (int) trim(explode(":", $memory_parts[2])[1]),
    "swap_total" => (int) trim(explode(":", $memory_parts[3])[1]),
    "swap_reserved" => (int) trim(explode(":", $memory_parts[4])[1]),
  ],

  "system" => [
    "boottime" => $boottime,
    "uptime" => (int) get_uptime_sec(),
    "temp" => floatval(get_temp()),
    "load_average" => [
        "one_minute" => floatval(trim($system_load_average_parts[0])),
        "five_minute" => floatval(trim($system_load_average_parts[1])),
        "fifteen_minute" => floatval(trim($system_load_average_parts[2])),
    ],
  ],

  "cpu" => [
    "frequency" => [
        "current" => (int) stripalpha($cpu_frequency_parts[0]),
        "max" => (int) stripalpha($cpu_frequency_parts[1]),
    ],
    "speed" => (int) get_cpu_speed(),
    "count" => (int) get_cpu_count(),
    "ticks" => [
        "total" => (int) $cpu_usage_parts[0],
        "idle" => (int) $cpu_usage_parts[1],
    ],
  ],

  "filesystems" => $filesystems,

  "interfaces" => [],

  "openvpn" => [],

  "ipsec" => [],

  "gateways" => return_gateways_status(true),
  "gateways_detail" => return_gateways_array(),
];

foreach($filesystems as $fs) {
  $key = str_replace("/", "_slash_", $fs["mountpoint"]);
  $key = trim($key, "_");
  //$toreturn["disk_usage_percent_${key}"] = floatval(disk_usage($fs["mountpoint"]));
  //$toreturn["disk_usage_percent_${key}"] = floatval($fs["percent_used"]);
}

foreach ($ifdescrs as $ifdescr => $ifname) {
  $data = get_interface_info("${ifdescr}");
  // I know these look off, but they are indeed correct
  $data["descr"] = $ifname;
  $data["ifname"] = $ifdescr;
  $toreturn["interfaces"]["${ifdescr}"] = $data;
}

foreach ($ovpn_servers as $server) {
  $vpnid = $server["vpnid"];
  $name = $server["name"];
  $conn_count = count($server["conns"]);

  $total_bytes_recv = 0;
  $total_bytes_sent = 0;
  foreach ($server["conns"] as $conn) {
    $total_bytes_recv += $conn["bytes_recv"];
    $total_bytes_sent += $conn["bytes_sent"];
  }
  
  $toreturn["openvpn"]["servers"][$vpnid]["name"] = $name;
  $toreturn["openvpn"]["servers"][$vpnid]["vpnid"] = $vpnid;
  $toreturn["openvpn"]["servers"][$vpnid]["connected_client_count"] = $conn_count;
  $toreturn["openvpn"]["servers"][$vpnid]["total_bytes_recv"] = $total_bytes_recv;
  $toreturn["openvpn"]["servers"][$vpnid]["total_bytes_sent"] = $total_bytes_sent;
}
"""
        data = self._exec_php(script)

        for fs in data["filesystems"]:
            fs["percent_used"] = int(fs["percent_used"])

        if isinstance(data["gateways"], list):
            data["gateways"] = {}

        return data

    @_log_errors
    def are_notices_pending(self, category="all"):
        """
        are_notices_pending($category = "all")
        $category appears to be ignored currently
        """
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

{}
$category = $data["category"];
$toreturn = [
  "data" => are_notices_pending($category),
];
""".format(
            _php_json_data(
                {
                    "category": category,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def get_notices(self, category="all"):
        script = """
// release the mutex immediately so other api calls can go through
// as this one can take a minute
require_once '/etc/inc/util.inc';
global $xmlrpclockkey;
unlock($xmlrpclockkey);

{}
$category = $data["category"];
$value = get_notices($category);
if (!$value) {{
    $value = false;
}}
$toreturn = [
  "data" => $value,
];
""".format(
            _php_json_data(
                {
                    "category": category,
                }
            )
        )

        response = self._exec_php(script)
        value = response["data"]
        if value is False:
            return []

        notices = []
        for key in value.keys():
            notice = value.get(key)
            notice["created_at"] = key
            notices.append(notice)

        return notices

    @_log_errors
    def file_notice(
        self, id, notice, category="General", url="", priority=1, local_only=False
    ):
        """
        /****f* notices/file_notice
        * NAME
        *   file_notice
        * INPUTS
        *       $id, $notice, $category, $url, $priority, $local_only
        * RESULT
        *   Files a notice and kicks off the various alerts, smtp, telegram, pushover, system log, LED's, etc.
        *   If $local_only is true then the notice is not sent to external places (smtp, telegram, pushover)
        ******/
        function file_notice($id, $notice, $category = "General", $url = "", $priority = 1, $local_only = false)
        """

        script = """
{}
$id = $data["id"];
$notice = $data["notice"];
$category = $data["category"];
$url = $data["url"];
$priority = $data["priority"];
$local_only = $data["local_only"];

$value = file_notice($id, $notice, $category, $url, $priority, $local_only);
$toreturn = [
  "data" => $value,
];
""".format(
            _php_json_data(
                {
                    "id": id,
                    "notice": notice,
                    "category": category,
                    "url": url,
                    "priority": priority,
                    "local_only": local_only,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]

    @_log_errors
    def close_notice(self, id):
        """
        id = "all" to wipe everything
        """
        script = """
{}
$id = $data["id"];
close_notice($id);
$toreturn = [
  "data" => true,
];
""".format(
            _php_json_data(
                {
                    "id": id,
                }
            )
        )

        response = self._exec_php(script)
        return response["data"]
