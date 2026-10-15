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
            data_dir=Path(os.environ.get("MCPM_DATA_DIR", "/data")),
            log_max_lines=_int("MCPM_LOG_MAX_LINES", 2000),
            log_max_bytes=_int("MCPM_LOG_MAX_BYTES", 65536),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.transport not in ("stdio", "http"):
            raise ConfigError(f"MCPM_TRANSPORT must be 'stdio' or 'http', got {self.transport!r}")
        if not self.dockhand_url:
            raise ConfigError("MCPM_DOCKHAND_URL is required (e.g. http://10.11.12.3:3003)")
        if self.transport == "http" and not self.auth_token:
            raise ConfigError(
                "MCPM_AUTH_TOKEN is required for the HTTP transport (refusing to start unauthenticated)"
            )
