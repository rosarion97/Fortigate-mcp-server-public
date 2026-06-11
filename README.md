# FortiGate Read-Only MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
lets Claude **query — and only query** — a **Fortinet FortiGate firewall** over
stdio, using the FortiOS **REST API v2** (`monitor/` and `cmdb/` namespaces).
It can retrieve system and health info, routing and network state, firewall
policies and objects, VPN status, security profiles, and logs — without making
any configuration changes.

> Not affiliated with or endorsed by Fortinet. Use at your own risk.
> **Read-only is not the same as harmless** — firewall policies, routing
> tables, and logs can contain sensitive operational data; scope the REST API
> admin profile accordingly.

## Container backends

This repository ships a containerised build for both Docker and Podman. They
share a byte-for-byte identical `server.py`; only the runtime tooling differs.

| | When to use | Setup guide |
|---|---|---|
| 🐳 **Docker** | You use Docker Desktop + the MCP Toolkit | [`docker/README.md`](docker/README.md) |
| 🦭 **Podman** | You want rootless containers / no Docker Desktop | [`podman/README.md`](podman/README.md) |

Each guide is self-contained (build → secrets → register with Claude
Desktop / Claude Code → verify).

## Hard read-only guarantee

Every tool maps 1:1 to an HTTP `GET` against
`https://<host>:<port>/api/v2/`. There is no helper in the codebase that
issues `POST`, `PUT`, `PATCH`, or `DELETE` — the absence of those verbs is the
security guarantee. A dedicated `attempt_write_operation` tool sits in the
catalog as model-visible proof of the contract; it performs no I/O and always
refuses.

## Coverage at a glance

37 tools (including the refusal stub) across the REST API v2 surface:

* System — status, resource usage, performance, time, firmware, sensors,
  licenses, admin accounts and profiles
* HA — status and peers
* Network & routing — interface status and config, zones, routing table,
  static routes, ARP table, DHCP leases
* Firewall — sessions, policies and per-policy hit counts, address/service
  objects and groups, VIPs, IP pools
* VPN — IPsec tunnels and SSL-VPN sessions
* Security profiles and logs
* Generic read escape hatches — `get_config_object` (any `cmdb/` path) and
  `get_monitor_resource` (any `monitor/` path), both validated read-only

The server also exposes one MCP info resource (`config://fortigate-info`) —
an env-derived config card that performs no network I/O and never echoes the
token.

The server is pinned to **one VDOM** (`FORTIGATE_VDOM`); the model cannot
target a different one. Run a second container to serve a second VDOM.

## Repository layout

```
.
├── README.md      # you are here — overview + backend chooser
├── docker/        # Docker variant + custom-catalog.yaml (Docker MCP Toolkit)
└── podman/        # Podman variant, rootless
```

`docker/server.py` and `podman/server.py` are kept byte-identical
(`diff -q docker/server.py podman/server.py`).

## Configuration

All configuration is via environment variables (container secrets or an
`--env-file`):

| Variable | Required | Purpose |
|----------|----------|---------|
| `FORTIGATE_HOST` | yes | Management host/IP. Pins this server to one FortiGate. |
| `FORTIGATE_API_TOKEN` | yes | REST API token from a **read-only** API admin (generate out of band; see the backend README). |
| `FORTIGATE_VDOM` | yes | The VDOM this instance is pinned to (`root` if VDOMs are disabled). |
| `FORTIGATE_PORT` | no | Management HTTPS port. |
| `FORTIGATE_VERIFY_SSL` | no | TLS verification; default on. Disable only for self-signed lab certs. |
| `FORTIGATE_MAX_RESPONSE_BYTES` | no | JSON byte cap per tool response. Default `120000` (~30k tokens). |

See `docker/.env.example` for the template. Create the token under a
READ-ONLY accprofile with a Trusthost — never reuse a full-admin token.

## License

Provided as-is for internal use. Not affiliated with or endorsed by Fortinet.
Pull requests that add additional **read-only** FortiOS endpoints are welcome;
any change that introduces a write-capable verb will be rejected.
