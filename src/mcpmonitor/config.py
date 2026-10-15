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
            dockhand_verify_tls=os.environ.get("MCPM_DOCKHAND_VERIFY_TLS", "true").lower()
            not in ("0", "false", "no"),
            dockhand_timeout=float(os.environ.get("MCPM_DOCKHAND_TIMEOUT", "20")),
            transport=os.environ.get("MCPM_TRANSPORT", "stdio").lower(),
            http_host=os.environ.get("MCPM_HTTP_HOST", "0.0.0.0"),
            http_port=_int("MCPM_HTTP_PORT", 8765),
            auth_token=os.environ.get("MCPM_AUTH_TOKEN", ""),
            ui_password=os.environ.get("MCPM_UI_PASSWORD", ""),
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

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mcpmonitor.db"

    def validate(self) -> None:
        if self.transport not in ("stdio", "http"):
            raise ConfigError(f"MCPM_TRANSPORT must be 'stdio' or 'http', got {self.transport!r}")
        if not self.dockhand_url:
            raise ConfigError("MCPM_DOCKHAND_URL is required (e.g. http://10.11.12.3:3003)")
        if self.kuma_url and not (self.kuma_username and self.kuma_password):
            raise ConfigError("MCPM_KUMA_USERNAME and MCPM_KUMA_PASSWORD are required with MCPM_KUMA_URL")
        if self.transport == "http" and not self.auth_token:
            raise ConfigError(
                "MCPM_AUTH_TOKEN is required for the HTTP transport (refusing to start unauthenticated)"
            )
