# mcpmonitor

An MCP server that lets an AI agent (Claude or any MCP client) look at Docker hosts and container logs, with
Docker access going through [Dockhand](https://github.com/Finsys/dockhand). Early stage: the current tools are
**read-only**. Restart and update tools, Uptime Kuma integration, a syslog receiver and Unraid notification
ingest are planned.

## Tools (phase 1, read-only)

| Tool | What it does |
| --- | --- |
| `list_hosts` | Dockhand environments that can be inspected |
| `list_containers` | Containers on a host, filterable by state or name |
| `inspect_container` | Bounded summary of config and state; secret-looking env values hidden |
| `container_logs` | Recent logs with `tail`, `since` and a regex `pattern`; size-limited and redacted |

Log text and environment values are untrusted input to the model. Output is labelled as such, secret-looking
values are redacted, and sizes are capped.

## Configuration

All settings are environment variables.

| Variable | Default | Notes |
| --- | --- | --- |
| `MCPM_DOCKHAND_URL` | required | e.g. `http://10.11.12.3:3003` |
| `MCPM_DOCKHAND_TOKEN` | empty | Dockhand API token (`dh_...`). Use a dedicated Dockhand user: tokens have no scopes and act as their owner |
| `MCPM_DOCKHAND_VERIFY_TLS` | `true` | |
| `MCPM_TRANSPORT` | `stdio` (`http` in the image) | `stdio` or `http` |
| `MCPM_AUTH_TOKEN` | required for `http` | Clients must send `Authorization: Bearer <token>`; the server refuses to start without it |
| `MCPM_HTTP_HOST` / `MCPM_HTTP_PORT` | `0.0.0.0` / `8765` | |
| `MCPM_DATA_DIR` | `/data` | Reserved for the upcoming database |
| `MCPM_LOG_MAX_LINES` / `MCPM_LOG_MAX_BYTES` | `2000` / `65536` | Caps on log output |

`GET /healthz` is unauthenticated and returns the version.

## Run

```sh
# Local, stdio (for Claude Code / Desktop)
pip install .
MCPM_DOCKHAND_URL=http://10.11.12.3:3003 MCPM_DOCKHAND_TOKEN=dh_... mcpmonitor

# Container (pull-only; amd64 and arm64)
docker run -d -p 8765:8765 -v ./data:/data \
  -e MCPM_DOCKHAND_URL=... -e MCPM_DOCKHAND_TOKEN=... -e MCPM_AUTH_TOKEN=... \
  ghcr.io/poag/mcpmonitor:latest
```

`compose.yaml` is a pull-only stack that works with Dockhand. Do not expose port 8765 to the internet without
a TLS-terminating proxy in front.

## Status of the Dockhand integration

Routes and response shapes were taken from Dockhand's source and have not yet been tried against a live
instance. The Bearer header for API tokens is assumed. Expect small fixes on first contact.

## Development

```sh
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
```

## Image publishing

`.github/workflows/docker.yml` builds `linux/amd64` and `linux/arm64` on native runners, merges them into one
manifest and pushes `ghcr.io/poag/mcpmonitor` (`latest` from `main`, version tags from `v*` tags, short SHA).
It also rebuilds monthly, uncached with a fresh base image. After the first push, set the package visibility to
public in the GitHub package settings if the image should be pullable without a login.
