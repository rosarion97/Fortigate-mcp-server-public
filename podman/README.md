# FortiGate Read-Only MCP Server (Podman)

A production-grade, **read-only** Model Context Protocol (MCP) server for the
FortiGate FortiOS REST API v2. Packaged as a Podman container and designed to
be launched directly by an MCP client (Claude Desktop or Claude Code) over the
**stdio** transport.

> New here? Start with the [repo overview](../README.md). Prefer **Docker**?
> The Docker sibling lives in [`../docker/`](../docker/README.md); the
> `server.py` is byte-for-byte identical — only the runtime tooling differs.

> Not affiliated with or endorsed by Fortinet. Use at your own risk.

---

## 1. Overview

This server exposes a curated set of `GET`-only tools that wrap the FortiOS
REST API. It is intentionally constrained to be safe in production: no tool
will ever issue a `POST`, `PUT`, `PATCH`, or `DELETE` against the firewall.
It is pinned to a single **VDOM** so the model cannot read or enumerate any
other virtual domain on the box.

**Coverage**

| Area | What you can read |
|------|-------------------|
| System / health | System status, resource & performance usage, time, firmware, hardware sensors, HA status & peers, interface live status, license status |
| Network / routing | Active routing table, ARP table, DHCP leases, firewall session table, per-policy hit counts |
| Firewall policy & objects | IPv4 policy table (+ single policy), address objects & groups, service objects & groups, VIP/DNAT objects, IP pools, static routes, interface config, zones |
| VPN | IPsec phase-1 & phase-2 config, live IPsec tunnel status, SSL-VPN sessions |
| Security profiles (UTM) | antivirus, ips, webfilter, application, dnsfilter, ssl-ssh, file-filter, emailfilter |
| Administration | Admin accounts, admin access profiles |
| Logs | memory/disk/FortiAnalyzer/FortiCloud log queries (traffic, event, utm, etc.) |
| Generic (validated) | `get_config_object(path)` and `get_monitor_resource(path)` for any GET-only cmdb/monitor table |

**Why read-only?**

* Safe to expose to LLM agents — accidental config changes are physically
  impossible because the corresponding HTTP verbs are never used.
* Predictable blast radius for shared / production firewalls.
* Encourages using a dedicated read-only REST API admin for the token.

---

## 2. Prerequisites

* **Podman 4.x or newer** on `$PATH`. Verify with `podman --version`.
* **A FortiGate REST API token.** Official guide:
  <https://docs.fortinet.com/document/fortigate/latest/administration-guide/940602/rest-api-administrator>
* (Strongly recommended) **A read-only REST API admin** whose token you use
  here. On the FortiGate:
  1. Create an administrator profile (**System → Admin Profiles**) with
     **Read** permission only on the resources you need.
  2. Go to **System → Administrators → Create New → REST API Admin**.
  3. Assign the read-only profile, set the **Trusthost** to the address range
     this container will connect from, and pin the **Virtual Domain**.
  4. Save and copy the **API token** shown once at creation — it is never
     displayed again.

> Even though this server enforces read-only at the application layer, scoping
> the token's admin profile to read-only adds a second line of defense and
> matches least privilege.

---

## 3. Build the container

```bash
git clone <your-fork-or-repo-url>
cd Fortigate-mcp-server
podman build -t fortigate-readonly-mcp:latest podman/
```

The build uses `python:3.12-slim`, installs `mcp[cli]` and `requests`, copies
in `server.py`, and switches to the unprivileged user `fortigate-mcp`
(uid 1001).

---

## 4. Configure credentials

This server requires **three** environment variables. All are validated at
startup; the server refuses to launch if any is missing.

| Variable | Purpose | Where to get it |
|----------|---------|-----------------|
| `FORTIGATE_API_TOKEN` | **Required.** Bearer token used for every API call. | FortiGate → *System → Administrators → Create New → REST API Admin*. Copy the token shown once. |
| `FORTIGATE_HOST` | **Required.** Management host/IP of the firewall. | The address you use to reach the FortiGate admin GUI. |
| `FORTIGATE_VDOM` | **Required.** Pins this server instance to a single VDOM. Every tool uses this value; the model cannot target a different VDOM. | Use `root` if VDOMs are disabled, otherwise the VDOM name. |
| `FORTIGATE_PORT` | *Optional.* HTTPS admin port. Default `443`. | Set if your FortiGate uses a non-standard admin port. |
| `FORTIGATE_VERIFY_SSL` | *Optional.* TLS verification. Default `yes`. Set `no` only for an un-validatable self-signed cert. | — |
| `FORTIGATE_MAX_RESPONSE_BYTES` | *Optional.* Hard cap on the JSON size of any one tool response. Over the cap, the server returns a truncation envelope with a `_hint`. Default `120000` (~30k tokens). | Pick a value based on your model's context window. |

```bash
cp podman/.env.example podman/.env
# Edit podman/.env and set at least:
#   FORTIGATE_API_TOKEN=...
#   FORTIGATE_HOST=...
#   FORTIGATE_VDOM=root
chmod 600 podman/.env   # restrict file perms
```

`.env` is gitignored. Do not commit it.

**Why pin the VDOM statically?**

* The model cannot accidentally enumerate or query an unrelated VDOM that the
  admin's token might also reach.
* Tools take no `vdom` parameter at all — there is no surface for the model to
  get it wrong, and the shared request helper strips any `vdom` a caller tries
  to inject.
* One container = one VDOM. Run a second container with a different `.env` if
  you need to serve a second VDOM.

---

## 5. Test the container manually

```bash
podman run --rm \
  --env-file podman/.env \
  fortigate-readonly-mcp:latest
```

The container starts and silently waits on stdin — correct behaviour for an
MCP stdio server. Press **Ctrl-C** to exit. If any required variable is
missing, the server fails fast with a clear error on stderr and exits 1.

---

## 6. Claude Desktop configuration

Edit your Claude Desktop config file:

* **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Linux:** `~/.claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add (or merge) the `fortigate` entry:

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "podman",
      "args": [
        "run", "--rm", "-i",
        "--env-file", "/absolute/path/to/Fortigate-mcp-server/podman/.env",
        "fortigate-readonly-mcp:latest"
      ]
    }
  }
}
```

Notes:

* `-i` (`--interactive`) is **required** — MCP stdio needs stdin attached.
* `--rm` cleans up the container after each session.
* The path passed to `--env-file` **must be absolute**.

Restart Claude Desktop after editing. The `fortigate` server should appear in
the MCP tools list.

---

## 7. Claude Code configuration

Claude Code uses the same `command` / `args` schema as §6, just in a different
file. Three scopes:

| Scope | File | Sharing |
|---|---|---|
| **local** (default) | `~/.claude.json`, under this project's entry | just you, just this project |
| **project** | `.mcp.json` at the project root | shared via git with collaborators |
| **user** (global) | `~/.claude.json`, top level | just you, every project |

**Easiest path — let the CLI write it for you:**

```bash
claude mcp add -s user fortigate -- \
  podman run --rm -i \
  --env-file /absolute/path/to/podman/.env \
  fortigate-readonly-mcp:latest
```

Use `-s user` for global, `-s project` to commit the entry to `.mcp.json` for
collaborators, or omit `-s` for the default local scope. Verify with
`claude mcp list`.

---

## 7b. Codex configuration

OpenAI Codex reads MCP server config from a TOML file instead of JSON. Two
scopes:

| Scope | File | Trust requirement |
|---|---|---|
| **global** | `~/.codex/config.toml` | none |
| **project** | `.codex/config.toml` at the project root | Codex only loads project files for **trusted** projects — confirm trust in Codex before relying on this scope |

The translation from the §6 JSON is mechanical: `mcpServers.foo` →
`[mcp_servers.foo]`; same `command`, same `args`.

```toml
[mcp_servers.fortigate]
command = "podman"
args = [
  "run", "--rm", "-i",
  "--env-file", "/absolute/path/to/podman/.env",
  "fortigate-readonly-mcp:latest",
]
```

Restart Codex or open a new project thread so the MCP server loads.

---

## 8. Available Tools

> **About `verbose` and response size.** Tools marked with a `verbose` flag
> return a narrowed set of fields by default to keep responses small for the
> model's context window. Pass `verbose=True` to get the full FortiOS record.
> Every tool's response is additionally capped at `FORTIGATE_MAX_RESPONSE_BYTES`
> — over the cap, the server returns a truncation envelope with a `_hint`
> field. See [§10b](#10b-response-size--context-window-safety).

### System / health (monitor)

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_system_status` | — | Hostname, serial, model, firmware, VDOM mode. |
| `get_system_resource_usage` | — | Live CPU, memory, session, disk usage. |
| `get_system_performance` | — | Per-CPU/mem counters, setup rate, uptime. |
| `get_system_time` | — | Current system time and timezone. |
| `get_firmware_status` | — | Running firmware + available upgrades. |
| `get_system_sensors` | — | Temperature/fan/voltage/PSU sensors. |
| `get_ha_status` | — | HA cluster statistics. |
| `get_ha_peers` | — | HA peer members. |
| `get_interfaces_status` | — | Live link/speed/IP/throughput per interface. |
| `get_available_licenses` | — | FortiGuard/support license status. |

### Network / routing (monitor)

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_routing_table` | `count=50` | Active IPv4 routing table. |
| `get_arp_table` | — | IP-to-MAC ARP bindings. |
| `get_dhcp_leases` | — | Current DHCP server leases. |
| `get_firewall_sessions` | `count=25`, `source_ip=""`, `dest_ip=""` | Active session table (optionally filtered). |
| `get_policy_hit_counts` | — | Per-policy hit counters & last-used. |

### Firewall policy & objects (cmdb)

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_firewall_policies` | `verbose=False` | IPv4 firewall policy table. |
| `get_firewall_policy` | `policy_id` | Single policy by policyid. |
| `get_address_objects` | `verbose=False` | IPv4 address objects. |
| `get_address_groups` | `verbose=False` | Address groups & members. |
| `get_service_objects` | `verbose=False` | Custom service (port/proto) objects. |
| `get_service_groups` | — | Service groups & members. |
| `get_vip_objects` | `verbose=False` | Virtual IP / port-forwarding (DNAT). |
| `get_ippools` | — | Source-NAT IP pools. |
| `get_static_routes` | `verbose=False` | Configured static routes. |
| `get_interfaces_config` | `verbose=False` | Interface config (addr/zone/role/allowaccess). |
| `get_zones` | — | Interface zones & members. |

### VPN

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_ipsec_phase1` | `verbose=False` | IPsec phase-1 (IKE) config. |
| `get_ipsec_phase2` | `verbose=False` | IPsec phase-2 (SA) config. |
| `get_ipsec_tunnels` | — | Live IPsec tunnel up/down status. |
| `get_ssl_vpn_sessions` | — | Active SSL-VPN user sessions. |

### Security profiles (UTM, cmdb)

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_security_profiles` | `profile_type`, `verbose=False` | Profiles of one type: antivirus, ips, webfilter, application, dnsfilter, ssl-ssh, file-filter, emailfilter. |

### Administration (cmdb)

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_admin_accounts` | `verbose=False` | Administrator accounts (no password hashes). |
| `get_admin_profiles` | — | Admin access profiles (roles). |

### Logs

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_logs` | `source="memory"`, `log_type="event"`, `subtype="system"`, `rows=25` | Recent log entries from memory/disk/FortiAnalyzer/FortiCloud. |

### Generic read (validated, GET-only)

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_config_object` | `path` | Any cmdb table by bare path, e.g. `firewall/policy`. |
| `get_monitor_resource` | `path` | Any monitor resource by bare path, e.g. `router/ipv4`. |

### Read-only safety

| Tool | Parameters | Description |
|------|------------|-------------|
| `attempt_write_operation` | `method="POST"`, `path="/example"` | Always returns the standard refusal string. Useful for verifying the read-only stance. |

---

## 9. Example prompts to use with Claude

* "What firmware is this FortiGate running, and what's the CPU and memory load?"
* "List the firewall policies and tell me which ones have NAT enabled."
* "Show me policy 12 in full."
* "Which IPsec tunnels are down right now?"
* "How many active sessions are there from 10.0.0.5?"
* "List the address objects and their subnets."
* "Show me the antivirus profiles configured on this box."
* "Are there any HA peers, and what's the cluster state?"
* "Pull the last 25 event/system log entries from memory."
* "What admin accounts exist and what access profiles do they use?"

Claude picks the matching tool, supplies the required identifiers, and
summarises the JSON the FortiOS API returns.

---

## 10. Rate limiting & errors

The FortiGate REST API surfaces standard HTTP status codes. This server maps
them to friendly, **token-free** messages:

| Code | Meaning surfaced |
|------|------------------|
| 401 | API token rejected — check `FORTIGATE_API_TOKEN`. |
| 403 | Token lacks permission, or source IP outside the admin trusthost / VDOM scope. |
| 404 | Object/table not found for this VDOM. |
| 424 | Failed dependency on the requested object. |
| 429 | Rate limit hit — retry after a moment. |

The server does **not** auto-retry — it returns the error so the model and the
user stay in control.

---

## 10b. Response size & context-window safety

FortiGate endpoints such as the session table, log queries, large policy sets,
and full routing tables can return very large JSON. Handing that raw to an LLM
tool call blows past the model's context window. This server has four layers
of protection:

**1. Tighter defaults.** Session and log tools default to small row counts
(25). The model can ask for more by passing a larger value (still capped).

**2. Server-side count cap.** Every tool that accepts `count`/`rows`/`per_page`
is clamped to `PER_PAGE_CAP` (default 50). The model can request less, never
more.

**3. Field projection.** High-cardinality cmdb tables (`get_firewall_policies`,
`get_address_objects`, `get_address_groups`, `get_service_objects`,
`get_vip_objects`, `get_static_routes`, `get_interfaces_config`,
`get_ipsec_phase1`, `get_ipsec_phase2`, `get_admin_accounts`,
`get_security_profiles`) return a curated subset of fields by default. Pass
`verbose=True` for the full record.

**4. A hard byte cap on every response.** `FORTIGATE_MAX_RESPONSE_BYTES`
(default `120000`, ~30k tokens) caps the JSON size of any single tool
response. Over the cap, the server returns a truncation envelope:

```jsonc
{
  "_truncated": true,
  "_returned": 42,            // items included
  "_total": 1850,             // items the API actually returned
  "_bytes_cap": 120000,
  "_hint": "Set verbose=True for full fields, or fetch one rule via get_firewall_policy.",
  "data": [ /* first 42 items */ ]
}
```

The `_hint` is the important part: the model sees data was cut and gets a
one-line nudge on how to re-query.

**Tuning.** Raise the cap for big-window models, lower it for small ones:

```
FORTIGATE_MAX_RESPONSE_BYTES=400000
```

Restart the MCP client (which restarts the container) for the change to take
effect.

---

## 11. Security notes

* **Token handling.** `FORTIGATE_API_TOKEN` is read once at process start from
  the container's environment. It is never written to stdout/stderr, never
  echoed in a tool response, and never included in error strings. It lives
  only in the container's process memory.
* **Single-VDOM pin.** `FORTIGATE_VDOM` is read once at startup. Every tool is
  scoped to it; the shared request helper strips any `vdom` a caller tries to
  pass. To serve a second VDOM, run a second container with its own `.env`.
* **Input validation.** Object names embedded in a path are allowlist-validated;
  the generic `get_config_object` / `get_monitor_resource` tools reject query
  strings, schemes, and `..` traversal so the model cannot escape the VDOM pin.
* **Non-root runtime.** The container drops to `fortigate-mcp` (uid 1001)
  before executing `server.py`.
* **No write paths.** Every tool uses `requests.Session.get`. There is no
  helper in the code that performs `POST`, `PUT`, `PATCH`, or `DELETE` — the
  absence of those verbs is the read-only guarantee. A dedicated
  `attempt_write_operation` tool returns the canonical refusal string.
* **Recommended token scope.** Generate the token under a dedicated REST API
  admin whose profile is **read-only** and whose **Trusthost** is restricted
  to where this container runs.
* **Secret storage.** `.env` is gitignored. Don't commit it. If you rotate the
  token, restart the MCP client so it relaunches the container with the new
  environment.

---

## 12. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Claude doesn't see the server | Confirm `podman` is on `$PATH` for the user running Claude. Confirm the image exists: `podman images \| grep fortigate-readonly-mcp`. |
| Exits with `FORTIGATE_API_TOKEN ... is not set` | `.env` missing, `--env-file` path wrong (must be absolute), or the variable is empty. |
| Exits with `FORTIGATE_HOST`/`FORTIGATE_VDOM ... is not set` | Same root causes; set the missing variable in `.env`. |
| `TLS verification failed` | The FortiGate uses a self-signed cert. Set `FORTIGATE_VERIFY_SSL=no` in `.env` (only if you trust the network path). |
| `401 Unauthorized` | Token invalid/revoked. Re-generate under the REST API admin. |
| `403 Forbidden` | Source IP outside the admin's Trusthost, the profile lacks read on this resource, or the token's VDOM doesn't match `FORTIGATE_VDOM`. |
| `404 Not Found` | Wrong object name/id, or the table doesn't exist in this VDOM. |
| Changed `server.py` but behaviour is stale | Rebuild without cache: `podman build --no-cache -t fortigate-readonly-mcp:latest podman/` and restart the MCP client. |
| stdio framing errors | Ensure the args list contains `-i` (interactive). |

---

## License & contributions

Provided as-is for internal use. PRs that add additional **read-only** FortiOS
endpoints are welcome; any change that would introduce a write-capable verb
against the firewall will be rejected on sight.
