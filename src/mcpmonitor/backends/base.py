"""Backend interface: how mcpmonitor reaches Docker. Dockhand is the first implementation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class BackendError(Exception):
    """The backend could not complete a request."""


class NotFoundError(BackendError):
    """The host or container does not exist."""


@dataclass(frozen=True)
class HostInfo:
    id: str
    name: str
    connection_type: str = ""
    address: str = ""


@dataclass(frozen=True)
class UpdateInfo:
    container: str
    image: str
    has_update: bool
    current_digest: str = ""
    new_digest: str = ""
    newer_version: str = ""  # advisory newer tag, never applied automatically
    hold_hours: float | None = None  # release-age cooldown remaining, if Dockhand is holding it
    disabled: bool = False  # excluded by label
    error: str = ""
    system: str = ""  # dockhand | hawser when the container is part of the management stack itself


@dataclass(frozen=True)
class ContainerSummary:
    host: str
    id: str
    name: str
    image: str
    state: str
    status: str
    health: str = ""
    full_id: str = ""
    compose_project: str = ""
    ports: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)


class Backend(Protocol):
    async def list_hosts(self) -> list[HostInfo]: ...

    async def resolve_host(self, host: str) -> HostInfo: ...

    async def list_containers(self, host: str, *, all: bool = True) -> list[ContainerSummary]: ...

    async def inspect_container(self, host: str, container: str) -> dict[str, Any]: ...

    async def container_logs(self, host: str, container: str, *, tail: int = 200, since: str | None = None) -> str: ...

    async def container_action(self, host: str, container: str, action: str) -> None:
        """Perform ``restart``, ``start``, ``stop`` or ``update`` (pull the image and recreate) on a container."""
        ...

    async def check_updates(self, host: str, *, refresh: bool = False) -> list[UpdateInfo]:
        """Containers with an available image update. ``refresh`` re-checks registries; otherwise cached results."""
        ...

    async def aclose(self) -> None: ...
