# FortiGate Read-Only MCP Server (Docker)

A Model Context Protocol (MCP) server that lets Claude **query** a **Fortinet FortiGate firewall** using the FortiOS REST API v2 in read-only mode. It can retrieve system/health info, routing and network state, firewall policies and objects, VPN status, security profiles, and logs — without making any configuration changes.

This server is designed to run inside a Docker container managed by the **Docker MCP Gateway**. Secrets live in Docker Desktop's encrypted secret store, out of Claude Desktop's config file. A plaintext `.env` option is also available for quick local testing.

> Prefer **Podman**? A rootless Podman variant lives in the [`../podman/`](../podman/README.md) sibling directory.

> Not affiliated with or endorsed by Fortinet. Use at your own risk.

---

## What It Does

The server exposes read-only tools that map onto FortiOS REST endpoints under `/api/v2/`. Every tool is scoped to the single VDOM you pin at startup (`FORTIGATE_VDOM`). Highlights:

- System / health monitor endpoints
- Network and routing state
- Firewall policies and objects (cmdb)
- VPN status
- Security profiles (UTM, cmdb)
- Logs

See `server.py` for the full tool list and the [podman README](../podman/README.md#8-available-tools) for a categorised reference (the tool surface is identical between the Podman and Docker builds).

---

## Prerequisites

- **Docker Desktop** with the [MCP Toolkit](https://docs.docker.com/desktop/features/mcp/) extension installed and enabled (the Toolkit installs the `docker mcp` CLI plugin and the encrypted secret store the gateway resolves against)
- **FortiGate** running FortiOS with REST API enabled
- A REST-API admin account scoped to **read-only**, with a Trusthost matching where this container runs
- A pre-generated **FortiOS REST API token**

---

## Recommended FortiGate Role

This server only reads, but the API token's permissions are still your control of last resort. Create a dedicated **REST API Administrator** (System > Administrators > Create New > REST API Admin) and:

1. Assign an `accprofile` scoped to **read-only** for the data you want Claude to see (System, Network, Router, Firewall, VPN, UTM, Log).
2. Set a **Trusthost** that matches where this container runs.
3. Pin the token to a **single VDOM** — the server is also pinned to one VDOM via `FORTIGATE_VDOM`; matching them avoids ambiguous failures.

---

## Step-by-Step Setup

### Step 0 — Generate the API Token (out of band)

On the FortiGate: *System > Administrators > Create New > REST API Admin*. Assign the read-only profile and Trusthost from the section above, then copy the token shown **once at creation**. Store it securely; FortiOS does not display it again.

### Step 1 — Get the Project Files

Clone or download this repository. The Docker backend lives in `docker/`:

- `Dockerfile`
- `.dockerignore`
- `server.py`
- `requirements.txt`
- `custom-catalog.yaml`
- `.env.example` (template — copy to `.env` only if you use plaintext Option B in Step 3)

### Step 2 — Build the Docker Image

```bash
cd docker
docker build -t fortigate-readonly-mcp .
```

### Step 3 — Provide Secrets

**Option A (the Docker secret store) is strongly recommended.** Option B (a plaintext `.env`) writes your token to disk in clear text; use it only for quick local testing.

#### Option A — Docker secret store (recommended)

```bash
docker mcp secret set FORTIGATE_API_TOKEN="..."
docker mcp secret set FORTIGATE_HOST="fw01.example.com"
docker mcp secret set FORTIGATE_VDOM="root"
# Optional:
docker mcp secret set FORTIGATE_PORT="443"
docker mcp secret set FORTIGATE_VERIFY_SSL="yes"
docker mcp secret set FORTIGATE_MAX_RESPONSE_BYTES="120000"
docker mcp secret ls
```

#### Option B — Plaintext `.env` file (quick testing only)

This path bypasses the Docker MCP gateway and runs the container directly, so you can **skip Steps 4–6**.

> ⚠️ A `.env` file stores your API token in clear text on disk. `chmod 600 .env`, never commit it, and prefer Option A for anything beyond local testing.

```bash
cp .env.example .env
chmod 600 .env
# Edit .env and set FORTIGATE_API_TOKEN, FORTIGATE_HOST, FORTIGATE_VDOM
```

Then add this to Claude Desktop's config (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`) **instead of** Steps 4–6:

```json
{
  "mcpServers": {
    "fortigate-readonly": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", "/absolute/path/to/.env",
        "fortigate-readonly-mcp:latest"
      ]
    }
  }
}
```

Use the **absolute** path. Restart Claude Desktop, then jump to Step 7.

### Step 4 — Install the Custom Catalog

> Steps 4–6 apply to **Option A**. If you used Option B, skip to Step 7.

```bash
mkdir -p ~/.docker/mcp/catalogs
cp custom-catalog.yaml ~/.docker/mcp/catalogs/custom.yaml
```

### Step 5 — Enable the Server in the Registry

`~/.docker/mcp/registry.yaml` lists active servers under a single top-level `registry:` key. Add the `fortigate-readonly` entry — **do not overwrite the file** if it already exists.

```yaml
registry:
  fortigate-readonly:
    catalog: custom
    enabled: true
  # ... any other servers you already had stay here
```

### Step 6 — Point Claude Desktop at the Docker MCP Gateway

Add the gateway block to Claude Desktop's config (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`). The gateway runs as a container, mounts the Docker socket so it can spawn the `fortigate-readonly-mcp` container on demand, mounts your `~/.docker/mcp` directory so it can read the catalog and registry, and mounts the Docker secrets-engine socket so it can resolve the `FORTIGATE_*` secrets you set in Step 3.

Replace `<your-username>` with your macOS username (run `whoami` to check):

```json
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "/Users/<your-username>/.docker/mcp:/mcp",
        "-v", "/Users/<your-username>/Library/Caches/docker-secrets-engine/engine.sock:/root/.cache/docker-secrets-engine/engine.sock",
        "docker/mcp-gateway:latest",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--registry=/mcp/registry.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

All three bind-mounts are required:

1. **`/var/run/docker.sock`** — lets the gateway spawn the `fortigate-readonly-mcp` container.
2. **`~/.docker/mcp`** — the gateway reads the catalog and registry from here.
3. **`docker-secrets-engine/engine.sock`** — the resolver socket Docker Desktop exposes for the secret store. Without it the gateway resolves your secret URLs to empty strings and `docker run -e ""` rejects the env flags, so the server never starts and only the gateway's internal admin tools show up. On Linux Docker Desktop the host path is `~/.docker/desktop/secrets-engine/engine.sock` instead; check with `find ~ -name engine.sock 2>/dev/null`.

Quit and reopen Claude Desktop. `claude_desktop_config.json` never contains `FORTIGATE_API_TOKEN` — the gateway resolves it from Docker's secret store at request time.

> **Shortcut alternative.** `docker mcp client connect claude-desktop` (or **MCP Toolkit > Clients** in Docker Desktop) will write a similar block for you automatically. The explicit JSON above gives you control over which catalogs load and survives Docker Desktop updates that may rewrite the auto-managed entry.

### Step 7 — Verify

```bash
docker mcp server list
docker mcp tools list
```

You should see `fortigate-readonly` enabled and its tools in the second command's output. In Claude Desktop, the tools menu should now include the FortiGate tools.

---

## Using with Claude Code

Claude Code uses the same `mcp-toolkit-gateway` block from Step 6 — same `command`, same `args` — but reads it from a different file. There are three scopes:

| Scope | File | Sharing |
|---|---|---|
| **local** (default) | `~/.claude.json`, under this project's entry | just you, just this project |
| **project** | `.mcp.json` at the project root | shared via git with collaborators |
| **user** (global) | `~/.claude.json`, top level | just you, every project |

**Easiest path — let the CLI write it for you.** Replace `<your-username>` and pick the scope you want:

```bash
claude mcp add -s user mcp-toolkit-gateway -- \
  docker run -i --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /Users/<your-username>/.docker/mcp:/mcp \
  -v /Users/<your-username>/Library/Caches/docker-secrets-engine/engine.sock:/root/.cache/docker-secrets-engine/engine.sock \
  docker/mcp-gateway:latest \
  --catalog=/mcp/catalogs/custom.yaml \
  --registry=/mcp/registry.yaml \
  --transport=stdio
```

Use `-s user` for global, `-s project` to commit the entry to `.mcp.json` for collaborators, or omit `-s` for the default local scope. Everything after `--` is the same docker invocation Claude Desktop uses — the schema is byte-for-byte identical.

Verify with `claude mcp list`. The Step 3 secrets and Step 4 / Step 5 catalog and registry setup all carry over; nothing else changes.

---

## Using with Codex

OpenAI Codex reads MCP server config from a TOML file instead of JSON. Two scopes:

| Scope | File | Trust requirement |
|---|---|---|
| **global** | `~/.codex/config.toml` | none |
| **project** | `.codex/config.toml` at the project root | Codex only loads project files for **trusted** projects — confirm trust in Codex before relying on this scope |

Same gateway invocation as Step 6, mechanically translated from JSON to TOML (`mcpServers.foo` → `[mcp_servers.foo]`; same `command`, same `args`). Replace `<your-username>` with your macOS username (run `whoami` to check):

```toml
[mcp_servers.mcp-toolkit-gateway]
command = "docker"
args = [
  "run",
  "-i",
  "--rm",
  "-v",
  "/var/run/docker.sock:/var/run/docker.sock",
  "-v",
  "/Users/<your-username>/.docker/mcp:/mcp",
  "-v",
  "/Users/<your-username>/Library/Caches/docker-secrets-engine/engine.sock:/root/.cache/docker-secrets-engine/engine.sock",
  "docker/mcp-gateway:latest",
  "--catalog=/mcp/catalogs/custom.yaml",
  "--registry=/mcp/registry.yaml",
  "--transport=stdio",
]
```

Restart Codex or open a new project thread so the MCP server loads. The Step 3 secrets and Step 4 / Step 5 catalog and registry setup all carry over; nothing else changes.

---

## Why pin the VDOM statically?

The model cannot enumerate or query an unrelated VDOM the token also has access to. Tools take no `vdom` parameter at all. One container = one VDOM; run a second container with its own `FORTIGATE_VDOM` secret to serve another VDOM.

---

## Security Design

- **Read-only API surface.** The server only calls GET endpoints; no `cmdb` write or `monitor` POST is implemented.
- **VDOM pinning.** Every request includes the VDOM from `FORTIGATE_VDOM`; the model cannot widen scope.
- **Trusthost binding.** The recommended FortiGate role pins the API token to the container's source IP range, so a leaked token outside that range is rejected by the firewall.
- **Secrets stay out of chat.** Token generation is not a tool; the value lives in the Docker secret store (Option A) or a `chmod 600` `.env` (Option B), never in Claude Desktop's config.
- **Non-root container.** Runs as UID 1000.
- **Response-size cap.** `FORTIGATE_MAX_RESPONSE_BYTES` (default 120000) keeps huge endpoints (session table, log queries) from blowing past the model's context window; the server returns a truncation envelope with a `_hint` field when the cap kicks in.

---

## Troubleshooting

### "Authentication failed" / HTTP 401 / 403
Token expired or scoped wrong. Regenerate the REST API admin token and update the secret.

### "Failed to connect to FortiGate"
`FORTIGATE_HOST` not reachable on HTTPS/`FORTIGATE_PORT` from inside the container; confirm DNS resolves and the Trusthost on the FortiGate admin allows the container's source IP.

### "VDOM not found"
`FORTIGATE_VDOM` doesn't match a VDOM the token can see. Use `root` if VDOMs are not enabled.

### Tools missing in Claude Desktop, only `mcp-*` admin tools visible
The gateway started but couldn't resolve secrets — most likely the `docker-secrets-engine/engine.sock` bind-mount is missing or points to the wrong path. See Step 6.

### "Response exceeded byte cap"
Lower-cardinality query or raise `FORTIGATE_MAX_RESPONSE_BYTES`.

---

## Architecture

```
Claude Desktop  ←→  Docker MCP Gateway  ←→  fortigate-readonly-mcp container  ←→  HTTPS  ←→  FortiOS REST API v2
                                                │
                                                └─ reads FORTIGATE_API_TOKEN / FORTIGATE_HOST /
                                                   FORTIGATE_VDOM / FORTIGATE_PORT / FORTIGATE_VERIFY_SSL /
                                                   FORTIGATE_MAX_RESPONSE_BYTES from secrets at startup
```

---

## License

Provided as-is for integrating Fortinet FortiGate firewalls with Claude Desktop via MCP. Use at your own risk. Not affiliated with or endorsed by Fortinet.
