# mcpmonitor

An MCP server that lets an AI agent (Claude or any MCP client) look at Docker hosts and container logs, with
Docker access going through [Dockhand](https://github.com/Finsys/dockhand). Early stage and not yet run against live
systems; see the notes on what is untested below.

## What it does

| Area | Tools / features |
| --- | --- |
| Containers (via Dockhand) | `list_hosts`, `list_containers`, `inspect_container`, `container_logs` (tail, since, regex; size-limited, redacted), `check_updates` (images with a newer digest; informational) |
| Actions (off by default) | `restart_container`, `start_container`, `stop_container`, `update_container` (pull and recreate through Dockhand): only for allowlisted containers, rate limited, `dry_run`, audited. Mapped Uptime Kuma monitors are paused first and resumed after the container is healthy again |
| Uptime Kuma | `list_monitors`, `monitor_history`, `diagnose_monitor` (Kuma status plus container state and error-like log lines) |
| Faults | `list_faults`, `hardware_health`, `search_syslog`: disk, I/O, filesystem, array, memory, network and temperature faults from syslog and Unraid notifications |
| Alerts | Faults go to targets you configure in the UI through [Apprise](https://github.com/caronc/apprise) (Discord, ntfy, email and many more), whether or not an AI session is running |
| Web UI (`/ui`) | Map or ignore Kuma monitors, container action allowlist, faults, log-pattern learning mode, alert targets, audit log |

Log text, environment values and monitor messages are untrusted input to the model. Output is labelled as such,
secret-looking values are redacted, and sizes are capped. Actions and Kuma tools are only registered when enabled.

## Configuration

All settings are environment variables.

| Variable | Default | Notes |
| --- | --- | --- |
| `MCPM_DOCKHAND_URL` | required | e.g. `http://10.11.12.3:3003` |
| `MCPM_DOCKHAND_TOKEN` | empty | Dockhand API token (`dh_...`). Use a dedicated Dockhand user: tokens have no scopes and act as their owner |
| `MCPM_DOCKHAND_VERIFY_TLS` | `true` | |
| `MCPM_TRANSPORT` | `stdio` (`http` in the image) | `stdio` or `http` |
| `MCPM_AUTH_TOKEN` | required for `http` | MCP clients must send `Authorization: Bearer <token>`; the server refuses to start without it |
| `MCPM_UI_PASSWORD` | empty | Enables the web UI at `/ui` (HTTP transport). Separate from the MCP token |
| `MCPM_HTTP_HOST` / `MCPM_HTTP_PORT` | `0.0.0.0` / `8765` | |
| `MCPM_DATA_DIR` | `/data` | SQLite database (`mcpmonitor.db`) lives here |
| `MCPM_LOG_MAX_LINES` / `MCPM_LOG_MAX_BYTES` | `2000` / `65536` | Caps on log output |
| `MCPM_KUMA_URL`, `MCPM_KUMA_USERNAME`, `MCPM_KUMA_PASSWORD` | empty | Enables the Kuma tools. Use a dedicated Kuma user |
| `MCPM_ENABLE_ACTIONS` | `false` | Registers the restart/start/stop tools. Nothing runs until a container is allowlisted in the UI |
| `MCPM_ACTIONS_PER_HOUR` | `3` | Per container |
| `MCPM_SETTLE_TIMEOUT` / `MCPM_SETTLE_GRACE` | `90` / `15` | Seconds to wait for a container to be healthy again, and a grace period before Kuma monitors resume |
| `MCPM_SYSLOG_PORT` | `0` (off) | UDP and TCP port for the syslog receiver (`5514` in the compose file) |
| `MCPM_SYSLOG_ALLOW` | required with syslog | Comma-separated sender IPs/CIDRs. Anything else is dropped |
| `MCPM_SYSLOG_RATE` | `200` | Max lines per second per sender |
| `MCPM_SYSLOG_RETENTION_DAYS` / `MCPM_SYSLOG_MAX_ROWS` | `14` / `500000` | |
| `MCPM_SYSLOG_EXPECT` | empty | `host:minutes,...`: raise a fault if a host stays silent that long |
| `MCPM_INGEST_TOKEN` | empty | Enables `POST /ingest/unraid`; this token is separate from the MCP token |

`GET /healthz` is unauthenticated and returns the version.

## Unraid setup (untested against a real Unraid box)

* **Syslog:** in Unraid, Settings > Syslog Server, set the remote syslog server to this host. The receiver
  listens on UDP and TCP; its parser accepts RFC 3164 and RFC 5424. Whether Unraid allows a custom port is
  unconfirmed, so mapping 514 to the container's 5514 may be needed.
* **Notifications (disk, array, SMART):** install `contrib/unraid-notify-agent.sh` as a notification agent, set its
  URL and `MCPM_INGEST_TOKEN`, and enable it under Settings > Notifications. Check its variable names against an
  existing agent first.
* **Rules:** the built-in fault rules are conservative and have not been tested against real logs. Use the
  "Log patterns" page to see frequent unmatched lines, preview a rule against stored history, and save it.

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

## What has and has not been tested

Covered by the test suite: all tools against fakes, the action sequence (pause, act, resume, including failure
paths), the syslog receiver over real UDP/TCP sockets, rules, the UI flows, and the Unraid agent script against a
local server. **Not yet tried against live systems:** Dockhand (routes and shapes were read from its source; the
Bearer header for API tokens is assumed, and `start`/`stop` routes are assumed to match `restart`), Uptime Kuma 2.5.6
(the client library documents live tests up to 2.5.0), Unraid's actual syslog and notification behaviour, and Apprise
delivery. Expect small fixes on first contact. `update_container` records the previous image reference so a rollback is possible, but there is no automatic rollback.

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
