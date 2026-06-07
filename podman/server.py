"""
FortiGate Read-Only MCP Server
==============================
A production-grade Model Context Protocol (MCP) server that exposes
READ-ONLY access to a single FortiGate firewall via the FortiOS REST API v2
over stdio transport.

HARD CONSTRAINTS
----------------
* Every tool maps 1:1 to an HTTP GET against https://<host>/api/v2/ — either
  the `monitor/` (runtime) or `cmdb/` (config DB) namespace.
* No POST, PUT, PATCH, or DELETE is ever issued. There is no helper in this
  file that performs a write verb. The absence of those verbs IS the
  read-only security guarantee. A dedicated `attempt_write_operation` tool
  returns the canonical refusal so the stance is visible in tool catalogs.
* The API token is read from FORTIGATE_API_TOKEN at startup. It is never
  logged and never returned in any tool response or error string.
* The server is pinned to ONE VDOM (FORTIGATE_VDOM). VDOM-scoped tools take
  no vdom parameter — the model cannot target a different VDOM.
* Transport is stdio. The container is invoked directly by an MCP client
  (Claude Desktop / Claude Code).

Read-only invariant lint (must return no matches):
    grep -nE '_session\.(post|put|patch|delete)' podman/server.py
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
from typing import Any

import requests
import urllib3
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration — validated fail-fast at startup
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 30  # seconds

# Cap the JSON size of any single tool response. FortiGate endpoints like
# the session table, log queries, and large policy sets can otherwise return
# megabytes of JSON and blow past the model's context window. Override with
# FORTIGATE_MAX_RESPONSE_BYTES in .env (e.g. 250000 for big-window models).
MAX_RESPONSE_BYTES = max(
    int(os.environ.get("FORTIGATE_MAX_RESPONSE_BYTES", "120000")),
    10_000,
)

# Hard ceiling for any tool's per_page / count parameter. The model can still
# ask for less; it just can't ask for more.
PER_PAGE_CAP = 50

FORTIGATE_API_TOKEN = os.environ.get("FORTIGATE_API_TOKEN", "").strip()
if not FORTIGATE_API_TOKEN:
    print(
        "ERROR: FORTIGATE_API_TOKEN environment variable is not set. "
        "Pass it with `--env-file .env` when running the container.",
        file=sys.stderr,
    )
    sys.exit(1)

FORTIGATE_HOST = os.environ.get("FORTIGATE_HOST", "").strip()
if not FORTIGATE_HOST:
    print(
        "ERROR: FORTIGATE_HOST environment variable is not set. "
        "Set it to the FortiGate management host/IP this instance should serve.",
        file=sys.stderr,
    )
    sys.exit(1)

FORTIGATE_VDOM = os.environ.get("FORTIGATE_VDOM", "").strip()
if not FORTIGATE_VDOM:
    print(
        "ERROR: FORTIGATE_VDOM environment variable is not set. "
        "This server is pinned to a single VDOM; set FORTIGATE_VDOM to the "
        "VDOM this instance should serve (use 'root' if VDOMs are not enabled).",
        file=sys.stderr,
    )
    sys.exit(1)

FORTIGATE_PORT = os.environ.get("FORTIGATE_PORT", "443").strip() or "443"
VERIFY_SSL = os.environ.get("FORTIGATE_VERIFY_SSL", "yes").strip().lower() != "no"

BASE_URL = f"https://{FORTIGATE_HOST}:{FORTIGATE_PORT}/api/v2"

if not VERIFY_SSL:
    # FortiGates commonly ship a self-signed cert. Suppress the noisy warning
    # so it cannot leak onto stdout and corrupt the JSON-RPC stream.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(
        "WARNING: TLS verification is DISABLED (FORTIGATE_VERIFY_SSL=no).",
        file=sys.stderr,
    )

_session = requests.Session()
_session.headers.update(
    {
        "Authorization": f"Bearer {FORTIGATE_API_TOKEN}",
        "Accept": "application/json",
        "User-Agent": "fortigate-readonly-mcp/1.0 (stdio)",
    }
)
_session.verify = VERIFY_SSL


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------


def _handle_sigterm(*_args: Any) -> None:
    print("Received SIGTERM — shutting down", file=sys.stderr)
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


mcp = FastMCP("fortigate-readonly")


# ---------------------------------------------------------------------------
# Input validation — values embedded into REST paths
# ---------------------------------------------------------------------------
# Object names / mkeys embedded in a path segment are validated against this
# pattern to prevent path or query-string breakout (slashes, '?', '&', '..').
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-: ]+$")

# Free-form REST sub-paths for the generic escape-hatch tools. Lowercase
# table paths only — no query string, no traversal, no scheme. This is what
# keeps the model from appending its own `?vdom=` and escaping the pin.
_PATH_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")

# Allowlisted cmdb security-profile tables. The model picks a type; the path
# is assembled here, never taken raw.
ALLOWED_PROFILE_TYPES = {
    "antivirus": "antivirus/profile",
    "ips": "ips/sensor",
    "webfilter": "webfilter/profile",
    "application": "application/list",
    "dnsfilter": "dnsfilter/profile",
    "ssl-ssh": "firewall/ssl-ssh-profile",
    "file-filter": "file-filter/profile",
    "emailfilter": "emailfilter/profile",
}

# Allowlisted log query dimensions (FortiOS log REST: /log/<source>/<type>/<subtype>).
ALLOWED_LOG_SOURCES = {"memory", "disk", "fortianalyzer", "forticloud"}
ALLOWED_LOG_TYPES = {"traffic", "event", "utm", "virus", "webfilter", "ips",
                     "anomaly", "app-ctrl", "dlp", "emailfilter"}


def _validate_name(value: str, label: str) -> str:
    """Strip and validate a value embedded into a REST path segment. Raise ValueError on rejection."""
    name = value.strip()
    if not name:
        raise ValueError(f"{label} is required")
    if len(name) > 128:
        raise ValueError(f"{label} is too long (max 128 chars)")
    if not _NAME_RE.match(name):
        raise ValueError(
            f"{label} contains invalid characters "
            f"(allowed: letters, digits, underscore, dot, hyphen, colon, space)"
        )
    return name


def _validate_path(value: str, label: str = "path") -> str:
    """Validate a free-form REST sub-path for the generic escape-hatch tools."""
    path = value.strip().strip("/")
    if not path:
        raise ValueError(f"{label} is required")
    if len(path) > 256:
        raise ValueError(f"{label} is too long (max 256 chars)")
    if ".." in path:
        raise ValueError(f"{label} must not contain '..'")
    if not _PATH_RE.match(path):
        raise ValueError(
            f"{label} contains invalid characters — provide a bare table path "
            f"like 'firewall/policy' with no query string or scheme"
        )
    return path


# ---------------------------------------------------------------------------
# HTTP helper — READ-ONLY. Every tool routes through _get.
# ---------------------------------------------------------------------------

READ_ONLY_REFUSAL = "This server is read-only. Operation refused."


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Issue a GET to the FortiGate REST API and return parsed JSON.

    The configured VDOM is always pinned into the query string; callers cannot
    override it. Raises ValueError with a descriptive (but token-free) message
    on any non-200 response.
    """
    url = f"{BASE_URL}/{path.lstrip('/')}"
    query: dict[str, Any] = {"vdom": FORTIGATE_VDOM}
    if params:
        # Caller params never get to override the VDOM pin.
        for key, val in params.items():
            if key == "vdom":
                continue
            query[key] = val

    try:
        response = _session.get(url, params=query, timeout=DEFAULT_TIMEOUT)
    except requests.exceptions.SSLError:
        raise ValueError(
            "TLS verification failed. If this FortiGate uses a self-signed "
            "certificate, set FORTIGATE_VERIFY_SSL=no in your .env."
        ) from None
    except requests.RequestException as exc:
        raise ValueError(f"Network error contacting FortiGate: {exc}") from None

    status = response.status_code
    if status == 200:
        try:
            return response.json()
        except ValueError:
            raise ValueError("FortiGate returned a non-JSON 200 response.") from None
    if status == 401:
        raise ValueError(
            "401 Unauthorized: the configured FortiGate API token was rejected. "
            "Check FORTIGATE_API_TOKEN in your .env."
        )
    if status == 403:
        raise ValueError(
            "403 Forbidden: the API token lacks permission for this resource, "
            "or the source IP is outside the API admin's trusthost / VDOM scope."
        )
    if status == 404:
        raise ValueError(f"Not found: {path} (check the object name/id and VDOM).")
    if status == 424:
        raise ValueError("424 Failed Dependency: the requested object has an unmet dependency.")
    if status == 429:
        raise ValueError("FortiGate rate limit hit. Retry after a moment.")
    raise ValueError(f"FortiGate API error {status}: {response.text[:200]}")


def _refuse_write(verb: str, path: str) -> str:
    """Helper used by the explicit write-refusal tool."""
    return f"{READ_ONLY_REFUSAL} (attempted {verb.upper()} {path})"


def _results(data: Any) -> Any:
    """Unwrap the FortiOS response envelope, returning the `results` payload when present."""
    if isinstance(data, dict) and "results" in data:
        return data["results"]
    return data


# ---------------------------------------------------------------------------
# Response-size guardrails
# ---------------------------------------------------------------------------


def _clamp_per_page(per_page: int, cap: int = PER_PAGE_CAP) -> int:
    """Clamp the caller's per_page / count request to a safe maximum."""
    try:
        n = int(per_page)
    except (TypeError, ValueError):
        return cap
    if n < 1:
        return 1
    return min(n, cap)


def _bounded(
    payload: Any,
    hint: str = (
        "Narrow the query: filter by name/id, lower count, "
        "or request a single object."
    ),
) -> Any:
    """Cap the JSON-serialised size of a tool response.

    If the payload fits ``MAX_RESPONSE_BYTES``, return it unchanged.
    Otherwise return a truncation envelope. For lists, include as many
    leading items as fit and report kept-vs-total counts. For other shapes,
    return a string preview so the caller at least sees the schema. The
    ``_hint`` tells the model how to re-query for the part it needs.
    """
    try:
        raw = json.dumps(payload, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return payload  # let the MCP layer surface its own error

    if len(raw) <= MAX_RESPONSE_BYTES:
        return payload

    if isinstance(payload, list):
        kept: list[Any] = []
        running = 0
        for item in payload:
            chunk = len(json.dumps(item, separators=(",", ":"), default=str))
            if running + chunk > MAX_RESPONSE_BYTES:
                break
            kept.append(item)
            running += chunk
        return {
            "_truncated": True,
            "_returned": len(kept),
            "_total": len(payload),
            "_bytes_cap": MAX_RESPONSE_BYTES,
            "_hint": hint,
            "data": kept,
        }

    return {
        "_truncated": True,
        "_original_bytes": len(raw),
        "_bytes_cap": MAX_RESPONSE_BYTES,
        "_hint": hint,
        "preview": raw[:MAX_RESPONSE_BYTES],
    }


def _project(items: Any, keep: set[str], verbose: bool) -> Any:
    """Narrow a list of dicts to the ``keep`` fields unless verbose=True."""
    if verbose or not isinstance(items, list):
        return items
    return [
        {k: v for k, v in item.items() if k in keep}
        for item in items
        if isinstance(item, dict)
    ]


# Field projections for the highest-cardinality cmdb tables. Keep only what
# 90% of troubleshooting questions need; verbose=True returns everything.
_POLICY_KEEP = {
    "policyid", "name", "srcintf", "dstintf", "srcaddr", "dstaddr",
    "service", "action", "status", "schedule", "nat", "logtraffic",
    "utm-status", "comments",
}
_ADDRESS_KEEP = {
    "name", "type", "subnet", "start-ip", "end-ip", "fqdn", "country",
    "interface", "associated-interface", "comment",
}
_ADDRGRP_KEEP = {"name", "member", "comment"}
_SERVICE_KEEP = {
    "name", "protocol", "tcp-portrange", "udp-portrange", "sctp-portrange",
    "icmptype", "category", "comment",
}
_VIP_KEEP = {
    "name", "type", "extip", "extintf", "mappedip", "portforward",
    "protocol", "extport", "mappedport", "comment",
}
_ROUTE_KEEP = {
    "seq-num", "dst", "gateway", "device", "distance", "priority",
    "status", "comment",
}
_ADMIN_KEEP = {
    "name", "accprofile", "trusthost1", "trusthost2", "vdom",
    "remote-auth", "two-factor", "comments",
}
_PHASE1_KEEP = {
    "name", "interface", "ike-version", "remote-gw", "proposal", "dhgrp",
    "authmethod", "peertype", "net-device", "comments",
}
_PHASE2_KEEP = {
    "name", "phase1name", "proposal", "src-subnet", "dst-subnet",
    "auto-negotiate", "comments",
}


# ===========================================================================
# SYSTEM / STATUS / HEALTH  (monitor)
# ===========================================================================


@mcp.tool()
def get_system_status() -> Any:
    """Return FortiGate system status: hostname, serial, model, firmware version, and VDOM mode (monitor/system/status)."""
    return _get("monitor/system/status")


@mcp.tool()
def get_system_resource_usage() -> Any:
    """Return live resource utilisation — CPU, memory, session count, disk (monitor/system/resource/usage)."""
    return _get("monitor/system/resource/usage")


@mcp.tool()
def get_system_performance() -> Any:
    """Return per-CPU/memory performance counters and uptime (monitor/system/resource/usage with all resources)."""
    return _get("monitor/system/resource/usage", params={"resource": "cpu,mem,disk,session,setup_rate"})


@mcp.tool()
def get_system_time() -> Any:
    """Return the firewall's current system time and timezone (monitor/system/time)."""
    return _get("monitor/system/time")


@mcp.tool()
def get_firmware_status() -> Any:
    """Return the running firmware and any available upgrade images (monitor/system/firmware)."""
    return _get("monitor/system/firmware")


@mcp.tool()
def get_system_sensors() -> Any:
    """Return hardware sensor readings — temperature, fan, voltage, PSU (monitor/system/sensor-info)."""
    data = _get("monitor/system/sensor-info")
    return _bounded(data, hint="Sensor lists are short on most models; if truncated the chassis is large.")


@mcp.tool()
def get_ha_status() -> Any:
    """Return high-availability cluster status and per-member statistics (monitor/system/ha-statistics)."""
    return _get("monitor/system/ha-statistics")


@mcp.tool()
def get_ha_peers() -> Any:
    """Return the HA peer members known to this cluster (monitor/system/ha-peer)."""
    return _get("monitor/system/ha-peer")


@mcp.tool()
def get_interfaces_status() -> Any:
    """Return live status (link, speed, IP, tx/rx) for every interface (monitor/system/interface)."""
    data = _get("monitor/system/interface")
    return _bounded(data, hint="High port-count devices: use get_config_object('system/interface') for config, or filter client-side.")


@mcp.tool()
def get_available_licenses() -> Any:
    """Return FortiGuard / support license and contract status (monitor/license/status)."""
    return _get("monitor/license/status")


# ===========================================================================
# NETWORK / ROUTING  (monitor)
# ===========================================================================


@mcp.tool()
def get_routing_table(count: int = 50) -> Any:
    """Return the active IPv4 routing table (monitor/router/ipv4).

    ``count`` is clamped server-side to PER_PAGE_CAP. Large routing tables are
    additionally byte-capped — narrow with a smaller count if truncated.
    """
    count = _clamp_per_page(count)
    data = _results(_get("monitor/router/ipv4", params={"count": count}))
    return _bounded(data, hint="Lower count; full BGP/OSPF tables can be very large.")


@mcp.tool()
def get_arp_table() -> Any:
    """Return the ARP table (IP-to-MAC bindings) for the VDOM (monitor/network/arp)."""
    data = _results(_get("monitor/network/arp"))
    return _bounded(data, hint="Busy segments have large ARP tables; query a smaller scope if truncated.")


@mcp.tool()
def get_dhcp_leases() -> Any:
    """Return current DHCP server leases (monitor/system/dhcp)."""
    data = _results(_get("monitor/system/dhcp"))
    return _bounded(data, hint="Large DHCP scopes return many leases; filter client-side if truncated.")


@mcp.tool()
def get_firewall_sessions(count: int = 25, source_ip: str = "", dest_ip: str = "") -> Any:
    """Return active firewall sessions from the session table (monitor/firewall/session).

    Defaults to 25 rows. ``count`` is clamped to PER_PAGE_CAP. Optionally
    filter by ``source_ip`` and/or ``dest_ip`` to narrow a busy table.
    """
    count = _clamp_per_page(count)
    params: dict[str, Any] = {"count": count, "summary": "true"}
    if source_ip.strip():
        params["srcaddr4"] = _validate_name(source_ip, "source_ip")
    if dest_ip.strip():
        params["dstaddr4"] = _validate_name(dest_ip, "dest_ip")
    data = _results(_get("monitor/firewall/session", params=params))
    return _bounded(data, hint="Lower count or filter by source_ip/dest_ip; the session table can hold millions of rows.")


@mcp.tool()
def get_policy_hit_counts() -> Any:
    """Return per-policy hit counters, byte/packet totals, and last-used time (monitor/firewall/policy)."""
    data = _results(_get("monitor/firewall/policy"))
    return _bounded(data, hint="Many policies: correlate by policyid with get_firewall_policy.")


# ===========================================================================
# FIREWALL POLICY & OBJECTS  (cmdb)
# ===========================================================================


@mcp.tool()
def get_firewall_policies(verbose: bool = False) -> Any:
    """Return the IPv4 firewall policy table (cmdb/firewall/policy).

    Narrowed by default (policyid, name, src/dst intf & addr, service, action,
    status, nat, logging). Pass ``verbose=True`` for the full policy record.
    """
    data = _results(_get("cmdb/firewall/policy"))
    data = _project(data, _POLICY_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields, or fetch one rule via get_firewall_policy(policy_id).")


@mcp.tool()
def get_firewall_policy(policy_id: str) -> Any:
    """Return a single firewall policy by its numeric policyid (cmdb/firewall/policy/<id>)."""
    pid = _validate_name(policy_id, "policy_id")
    return _get(f"cmdb/firewall/policy/{pid}")


@mcp.tool()
def get_address_objects(verbose: bool = False) -> Any:
    """Return IPv4 firewall address objects (cmdb/firewall/address).

    Narrowed by default; pass ``verbose=True`` for full records.
    """
    data = _results(_get("cmdb/firewall/address"))
    data = _project(data, _ADDRESS_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_address_groups(verbose: bool = False) -> Any:
    """Return IPv4 firewall address groups and their members (cmdb/firewall/addrgrp)."""
    data = _results(_get("cmdb/firewall/addrgrp"))
    data = _project(data, _ADDRGRP_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_service_objects(verbose: bool = False) -> Any:
    """Return custom firewall service (protocol/port) objects (cmdb/firewall.service/custom)."""
    data = _results(_get("cmdb/firewall.service/custom"))
    data = _project(data, _SERVICE_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_service_groups() -> Any:
    """Return firewall service groups and their members (cmdb/firewall.service/group)."""
    data = _results(_get("cmdb/firewall.service/group"))
    return _bounded(data, hint="Large service catalogs: query individual members if truncated.")


@mcp.tool()
def get_vip_objects(verbose: bool = False) -> Any:
    """Return virtual IP / port-forwarding (DNAT) objects (cmdb/firewall/vip)."""
    data = _results(_get("cmdb/firewall/vip"))
    data = _project(data, _VIP_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_ippools() -> Any:
    """Return IP pool (source NAT) objects (cmdb/firewall/ippool)."""
    data = _results(_get("cmdb/firewall/ippool"))
    return _bounded(data, hint="If truncated, query a single pool with get_config_object('firewall/ippool/<name>').")


@mcp.tool()
def get_static_routes(verbose: bool = False) -> Any:
    """Return configured IPv4 static routes (cmdb/router/static)."""
    data = _results(_get("cmdb/router/static"))
    data = _project(data, _ROUTE_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields, or use get_routing_table for the active RIB.")


@mcp.tool()
def get_interfaces_config(verbose: bool = False) -> Any:
    """Return interface configuration — addressing, zones, roles, allowaccess (cmdb/system/interface).

    Narrowed by default; pass ``verbose=True`` for the full interface record.
    """
    keep = {"name", "ip", "type", "vdom", "mode", "role", "status",
            "allowaccess", "alias", "description", "interface", "vlanid"}
    data = _results(_get("cmdb/system/interface"))
    data = _project(data, keep, verbose)
    return _bounded(data, hint="Set verbose=True for full fields, or get_config_object('system/interface/<name>').")


@mcp.tool()
def get_zones() -> Any:
    """Return interface zones and their member interfaces (cmdb/system/zone)."""
    return _bounded(_results(_get("cmdb/system/zone")))


# ===========================================================================
# VPN  (cmdb config + monitor runtime)
# ===========================================================================


@mcp.tool()
def get_ipsec_phase1(verbose: bool = False) -> Any:
    """Return IPsec phase-1 (IKE) interface configuration (cmdb/vpn.ipsec/phase1-interface).

    Pre-shared keys and certificates are not exposed by the API. Narrowed by
    default; pass ``verbose=True`` for full records.
    """
    data = _results(_get("cmdb/vpn.ipsec/phase1-interface"))
    data = _project(data, _PHASE1_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_ipsec_phase2(verbose: bool = False) -> Any:
    """Return IPsec phase-2 (IPsec SA) interface configuration (cmdb/vpn.ipsec/phase2-interface)."""
    data = _results(_get("cmdb/vpn.ipsec/phase2-interface"))
    data = _project(data, _PHASE2_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_ipsec_tunnels() -> Any:
    """Return live IPsec tunnel status — up/down, bytes, selectors (monitor/vpn/ipsec)."""
    data = _results(_get("monitor/vpn/ipsec"))
    return _bounded(data, hint="Many tunnels: correlate by name with get_ipsec_phase1.")


@mcp.tool()
def get_ssl_vpn_sessions() -> Any:
    """Return active SSL-VPN user sessions (monitor/vpn/ssl)."""
    data = _results(_get("monitor/vpn/ssl"))
    return _bounded(data, hint="Many concurrent users: filter client-side if truncated.")


# ===========================================================================
# SECURITY PROFILES  (cmdb)
# ===========================================================================


@mcp.tool()
def get_security_profiles(profile_type: str, verbose: bool = False) -> Any:
    """Return security (UTM) profiles of a given type.

    ``profile_type`` must be one of: antivirus, ips, webfilter, application,
    dnsfilter, ssl-ssh, file-filter, emailfilter. Narrowed to name/comment by
    default; pass ``verbose=True`` for the full profile record.
    """
    pt = profile_type.strip().lower()
    if pt not in ALLOWED_PROFILE_TYPES:
        return {
            "error": f"profile_type must be one of: {', '.join(sorted(ALLOWED_PROFILE_TYPES))}"
        }
    data = _results(_get(f"cmdb/{ALLOWED_PROFILE_TYPES[pt]}"))
    if not verbose and isinstance(data, list):
        data = [
            {k: v for k, v in item.items() if k in {"name", "comment"}}
            for item in data
            if isinstance(item, dict)
        ]
    return _bounded(data, hint="Set verbose=True for full profile bodies (these can be very large).")


# ===========================================================================
# ADMINISTRATION  (cmdb)
# ===========================================================================


@mcp.tool()
def get_admin_accounts(verbose: bool = False) -> Any:
    """Return configured administrator accounts and their profiles (cmdb/system/admin).

    Password hashes are not returned by the API. Narrowed by default; pass
    ``verbose=True`` for full records.
    """
    data = _results(_get("cmdb/system/admin"))
    data = _project(data, _ADMIN_KEEP, verbose)
    return _bounded(data, hint="Set verbose=True for full fields.")


@mcp.tool()
def get_admin_profiles() -> Any:
    """Return administrator access profiles (role permission sets) (cmdb/system/accprofile)."""
    return _bounded(_results(_get("cmdb/system/accprofile")))


# ===========================================================================
# LOGS
# ===========================================================================


@mcp.tool()
def get_logs(
    source: str = "memory",
    log_type: str = "event",
    subtype: str = "system",
    rows: int = 25,
) -> Any:
    """Return recent log entries (FortiOS log REST: log/<source>/<type>/<subtype>).

    ``source`` one of: memory, disk, fortianalyzer, forticloud.
    ``log_type`` one of: traffic, event, utm, virus, webfilter, ips, anomaly,
    app-ctrl, dlp, emailfilter.
    ``subtype`` depends on type (e.g. type=traffic -> subtype=forward/local;
    type=event -> subtype=system/vpn/user/router). Defaults to last entries,
    25 rows. ``rows`` is clamped to PER_PAGE_CAP. Requires logging to the
    chosen source to be enabled on the device.
    """
    src = source.strip().lower()
    lt = log_type.strip().lower()
    if src not in ALLOWED_LOG_SOURCES:
        return {"error": f"source must be one of: {', '.join(sorted(ALLOWED_LOG_SOURCES))}"}
    if lt not in ALLOWED_LOG_TYPES:
        return {"error": f"log_type must be one of: {', '.join(sorted(ALLOWED_LOG_TYPES))}"}
    st = _validate_name(subtype, "subtype")
    rows = _clamp_per_page(rows)
    data = _results(
        _get(f"log/{src}/{lt}/{st}", params={"rows": rows, "start": 0})
    )
    return _bounded(data, hint="Lower rows, narrow the subtype, or switch source; log queries can be dense.")


# ===========================================================================
# GENERIC READ ESCAPE HATCHES  (validated, GET-only)
# ===========================================================================


@mcp.tool()
def get_config_object(path: str) -> Any:
    """Read any cmdb configuration object by bare table path (GET cmdb/<path>).

    Example paths: 'firewall/policy', 'system/interface/port1',
    'router/static'. The path is validated (no query string, no traversal)
    and the request is always scoped to the configured VDOM. Read-only.
    """
    p = _validate_path(path)
    return _bounded(_results(_get(f"cmdb/{p}")),
                    hint="Append an object name/id to the path to fetch a single record.")


@mcp.tool()
def get_monitor_resource(path: str) -> Any:
    """Read any monitor (runtime) resource by bare path (GET monitor/<path>).

    Example paths: 'system/status', 'router/ipv4', 'firewall/session'.
    The path is validated and the request is scoped to the configured VDOM.
    Read-only.
    """
    p = _validate_path(path)
    return _bounded(_results(_get(f"monitor/{p}")),
                    hint="Many monitor endpoints accept a 'count' — use the dedicated typed tools for paging.")


# ===========================================================================
# EXPLICIT WRITE REFUSAL
# ===========================================================================


@mcp.tool()
def attempt_write_operation(method: str = "POST", path: str = "/example") -> str:
    """Refuses any write attempt. This server is READ-ONLY by design.

    Use this tool to verify the server's read-only stance; it always returns
    the standard refusal string and performs no network I/O.
    """
    return _refuse_write(method, path)


# ---------------------------------------------------------------------------
# Resource — FortiGate connection info (no secrets)
# ---------------------------------------------------------------------------


@mcp.resource("config://fortigate-info")
def fortigate_info() -> str:
    """Current FortiGate connection details (no secrets)."""
    token_set = "yes" if FORTIGATE_API_TOKEN else "no"
    return (
        f"Host: {FORTIGATE_HOST}:{FORTIGATE_PORT}\n"
        f"VDOM: {FORTIGATE_VDOM}\n"
        f"API token configured: {token_set}\n"
        f"SSL verification: {'yes' if VERIFY_SSL else 'no'}"
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(
        f"FortiGate Read-Only MCP Server starting — host={FORTIGATE_HOST}:{FORTIGATE_PORT} "
        f"vdom={FORTIGATE_VDOM} verify_ssl={'yes' if VERIFY_SSL else 'no'}",
        file=sys.stderr,
    )
    mcp.run(transport="stdio")
