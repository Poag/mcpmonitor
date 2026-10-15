"""Configuration, read from environment variables (MCPM_*)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    # Dockhand
    dockhand_url: str = ""
    dockhand_token: str = ""
    dockhand_verify_tls: bool = True
    dockhand_timeout: float = 20.0

    # MCP transport
    transport: str = "stdio"  # stdio | http
    http_host: str = "0.0.0.0"
    http_port: int = 8765
    auth_token: str = ""  # bearer token required on the HTTP transport
    ui_password: str = ""  # enables the web UI at /ui when set (HTTP transport only)

    # Syslog receiver and Unraid ingest (both off unless configured)
    syslog_port: int = 0  # 0 = disabled
    syslog_allow: str = ""  # comma-separated sender IPs/CIDRs; required when the receiver is enabled
    syslog_rate: float = 200.0  # max lines per second per sender
    syslog_retention_days: int = 14
    syslog_max_rows: int = 500_000
    syslog_expect: str = ""  # host:minutes,... hosts that must keep sending
    ingest_token: str = ""  # bearer token for POST /ingest/unraid; route disabled when empty

    # Uptime Kuma (optional)
    kuma_url: str = ""
    kuma_username: str = ""
    kuma_password: str = ""

    # Actions (restart/start/stop). Off unless explicitly enabled.
    enable_actions: bool = False
    actions_per_hour: int = 3
    settle_timeout: float = 90.0  # how long to wait for a container to be running/healthy again
    settle_grace: float = 15.0  # extra wait after recovery before Kuma monitors are resumed

    # Storage
    data_dir: Path = field(default_factory=lambda: Path("/data"))

    # Output limits
    log_max_lines: int = 2000
    log_max_bytes: int = 65536

    @classmethod
    def from_env(cls) -> Settings:
        s = cls(
            dockhand_url=os.environ.get("MCPM_DOCKHAND_URL", "").rstrip("/"),
            dockhand_token=os.environ.get("MCPM_DOCKHAND_TOKEN", ""),
            dockhand_verify_tls=os.environ.get("MCPM_DOCKHAND_VERIFY_TLS", "true").lower() not in ("0", "false", "no"),
            dockhand_timeout=float(os.environ.get("MCPM_DOCKHAND_TIMEOUT", "20")),
            transport=os.environ.get("MCPM_TRANSPORT", "stdio").lower(),
            http_host=os.environ.get("MCPM_HTTP_HOST", "0.0.0.0"),
            http_port=_int("MCPM_HTTP_PORT", 8765),
            auth_token=os.environ.get("MCPM_AUTH_TOKEN", ""),
            ui_password=os.environ.get("MCPM_UI_PASSWORD", ""),
            syslog_port=_int("MCPM_SYSLOG_PORT", 0),
            syslog_allow=os.environ.get("MCPM_SYSLOG_ALLOW", ""),
            syslog_rate=float(os.environ.get("MCPM_SYSLOG_RATE", "200")),
            syslog_retention_days=_int("MCPM_SYSLOG_RETENTION_DAYS", 14),
            syslog_max_rows=_int("MCPM_SYSLOG_MAX_ROWS", 500_000),
            syslog_expect=os.environ.get("MCPM_SYSLOG_EXPECT", ""),
            ingest_token=os.environ.get("MCPM_INGEST_TOKEN", ""),
            kuma_url=os.environ.get("MCPM_KUMA_URL", "").rstrip("/"),
            kuma_username=os.environ.get("MCPM_KUMA_USERNAME", ""),
            kuma_password=os.environ.get("MCPM_KUMA_PASSWORD", ""),
            enable_actions=os.environ.get("MCPM_ENABLE_ACTIONS", "false").lower() in ("1", "true", "yes"),
            actions_per_hour=_int("MCPM_ACTIONS_PER_HOUR", 3),
            settle_timeout=float(os.environ.get("MCPM_SETTLE_TIMEOUT", "90")),
            settle_grace=float(os.environ.get("MCPM_SETTLE_GRACE", "15")),
            data_dir=Path(os.environ.get("MCPM_DATA_DIR", "/data")),
            log_max_lines=_int("MCPM_LOG_MAX_LINES", 2000),
            log_max_bytes=_int("MCPM_LOG_MAX_BYTES", 65536),
        )
        s.validate()
        return s

    def expect_hosts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for part in self.syslog_expect.split(","):
            if part.strip():
                host, _, minutes = part.strip().partition(":")
                out[host.strip()] = int(minutes or 30)
        return out

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mcpmonitor.db"

    def validate(self) -> None:
        if self.transport not in ("stdio", "http"):
            raise ConfigError(f"MCPM_TRANSPORT must be 'stdio' or 'http', got {self.transport!r}")
        if not self.dockhand_url:
            raise ConfigError("MCPM_DOCKHAND_URL is required (e.g. http://10.11.12.3:3003)")
        if self.syslog_port and not self.syslog_allow.strip():
            raise ConfigError("MCPM_SYSLOG_ALLOW (sender IPs/CIDRs) is required when MCPM_SYSLOG_PORT is set")
        if self.syslog_port:
            from .syslog_server import parse_allow

            try:
                parse_allow(self.syslog_allow)
                self.expect_hosts()
            except ValueError as exc:
                raise ConfigError(f"invalid syslog setting: {exc}") from exc
        if self.kuma_url and not (self.kuma_username and self.kuma_password):
            raise ConfigError("MCPM_KUMA_USERNAME and MCPM_KUMA_PASSWORD are required with MCPM_KUMA_URL")
        if self.transport == "http" and not self.auth_token:
            raise ConfigError("MCPM_AUTH_TOKEN is required for the HTTP transport (refusing to start unauthenticated)")
