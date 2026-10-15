from __future__ import annotations

from typing import Any

from mcpmonitor.backends import BackendError, ContainerSummary, HostInfo, NotFoundError
from mcpmonitor.kuma import KumaError, KumaMonitor


class FakeBackend:
    """In-memory Backend that records the order of calls into a shared event list."""

    def __init__(self, events: list[str], *, fail_action: bool = False, state_after: str = "running") -> None:
        self.events = events
        self.fail_action = fail_action
        self.state_after = state_after
        self.state = "running"
        self.hosts = [HostInfo("1", "Unraid"), HostInfo("2", "PiZero")]

    async def list_hosts(self):
        return self.hosts

    async def resolve_host(self, host: str) -> HostInfo:
        for h in self.hosts:
            if host.lower() in (h.id, h.name.lower()):
                return h
        raise NotFoundError(f"Unknown host {host!r}")

    async def list_containers(self, host: str, *, all: bool = True):
        return [ContainerSummary(host, "abc123def456", "buffarr", "img", self.state, "Up")]

    async def inspect_container(self, host: str, container: str) -> dict[str, Any]:
        return {
            "Name": "/buffarr",
            "State": {"Status": self.state},
            "RestartCount": 2,
            "Config": {"Image": "img"},
        }

    async def container_logs(self, host, container, *, tail=200, since=None):
        return "ok\nERROR connection refused\nok"

    async def container_action(self, host: str, container: str, action: str) -> None:
        self.events.append(f"backend:{action}")
        if self.fail_action:
            raise BackendError("boom")
        self.state = self.state_after

    async def aclose(self) -> None:
        pass


class FakeKuma:
    def __init__(self, events: list[str], monitors: list[KumaMonitor], *, fail_resume: bool = False) -> None:
        self.events = events
        self.monitors = {m.id: m for m in monitors}
        self.fail_resume = fail_resume

    async def list_monitors(self):
        return list(self.monitors.values())

    async def pause(self, monitor_id: int) -> None:
        self.events.append(f"kuma:pause:{monitor_id}")
        m = self.monitors[monitor_id]
        self.monitors[monitor_id] = KumaMonitor(m.id, m.name, m.type, False, m.target)

    async def resume(self, monitor_id: int) -> None:
        if self.fail_resume:
            raise KumaError("socket closed")
        self.events.append(f"kuma:resume:{monitor_id}")
        m = self.monitors[monitor_id]
        self.monitors[monitor_id] = KumaMonitor(m.id, m.name, m.type, True, m.target)

    async def beats(self, monitor_id: int, hours: int = 6):
        return [
            {"time": "t1", "status": "up", "msg": "", "ping": 1},
            {"time": "t2", "status": "down", "msg": "timeout token=abc123", "ping": None},
        ]

    async def aclose(self) -> None:
        pass
