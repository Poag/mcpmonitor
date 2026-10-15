"""Uptime Kuma access. Phase 1: read monitors and heartbeats, pause and resume monitors.

The real client wraps the unofficial ``uptime-kuma-api2`` library (Socket.IO). It is documented as
live-verified against Kuma 2.5.0; the deployment runs 2.5.6, so it has not been tried on that exact version.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from typing import Any, Protocol


class KumaError(Exception):
    """Uptime Kuma could not be reached or refused a request."""


@dataclass(frozen=True)
class KumaMonitor:
    id: int
    name: str
    type: str
    active: bool
    target: str = ""  # url, hostname[:port] or similar, for display and mapping suggestions
    status: str = ""  # up | down | pending | maintenance | "" (unknown)
    tags: tuple[str, ...] = ()


class KumaClient(Protocol):
    async def list_monitors(self) -> list[KumaMonitor]: ...

    async def pause(self, monitor_id: int) -> None: ...

    async def resume(self, monitor_id: int) -> None: ...

    async def beats(self, monitor_id: int, hours: int = 6) -> list[dict[str, Any]]: ...

    async def aclose(self) -> None: ...


_STATUS = {0: "down", 1: "up", 2: "pending", 3: "maintenance"}


class UptimeKumaClient:
    """Thin async adapter over the synchronous ``uptime_kuma_api.UptimeKumaApi``."""

    def __init__(self, url: str, username: str, password: str, *, timeout: float = 20.0) -> None:
        self._url, self._username, self._password, self._timeout = url, username, password, timeout
        self._api: Any = None
        self._lock = threading.Lock()  # the Socket.IO client is not safe for concurrent calls

    def _connect(self) -> Any:
        if self._api is not None:
            return self._api
        try:
            from uptime_kuma_api import UptimeKumaApi

            api = UptimeKumaApi(self._url, timeout=self._timeout)
            api.login(self._username, self._password)
        except Exception as exc:  # the library raises assorted exception types
            raise KumaError(f"cannot connect to Uptime Kuma: {type(exc).__name__}: {exc}") from exc
        self._api = api
        return api

    def _call(self, fn_name: str, *args: Any) -> Any:
        with self._lock:
            for attempt in (1, 2):
                api = self._connect()
                try:
                    return getattr(api, fn_name)(*args)
                except Exception as exc:
                    self._drop()
                    if attempt == 2:
                        raise KumaError(f"Uptime Kuma {fn_name} failed: {type(exc).__name__}: {exc}") from exc
        raise AssertionError("unreachable")

    def _drop(self) -> None:
        api, self._api = self._api, None
        if api is not None:
            try:
                api.disconnect()
            except Exception:
                pass

    async def list_monitors(self) -> list[KumaMonitor]:
        raw = await asyncio.to_thread(self._call, "get_monitors")
        return [monitor_from_raw(m) for m in raw if isinstance(m, dict)]

    async def pause(self, monitor_id: int) -> None:
        await asyncio.to_thread(self._call, "pause_monitor", monitor_id)

    async def resume(self, monitor_id: int) -> None:
        await asyncio.to_thread(self._call, "resume_monitor", monitor_id)

    async def beats(self, monitor_id: int, hours: int = 6) -> list[dict[str, Any]]:
        raw = await asyncio.to_thread(self._call, "get_monitor_beats", monitor_id, hours)
        return [
            {
                "time": b.get("time"),
                "status": _STATUS.get(_int(b.get("status")), "?"),
                "msg": b.get("msg", ""),
                "ping": b.get("ping"),
            }
            for b in raw
            if isinstance(b, dict)
        ]

    async def aclose(self) -> None:
        await asyncio.to_thread(self._drop)


def _int(value: Any) -> int | None:
    if hasattr(value, "value"):  # the library returns an enum for some statuses
        value = value.value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def monitor_from_raw(m: dict[str, Any]) -> KumaMonitor:
    mtype = m.get("type")
    mtype = getattr(mtype, "value", mtype)
    target = m.get("url") or m.get("hostname") or m.get("docker_container") or ""
    if m.get("port") and m.get("hostname"):
        target = f"{m['hostname']}:{m['port']}"
    tags = tuple(
        f"{t.get('name', '')}:{t.get('value', '')}".rstrip(":")
        for t in (m.get("tags") or [])
        if isinstance(t, dict)
    )
    return KumaMonitor(
        id=int(m["id"]),
        name=str(m.get("name", "")),
        type=str(mtype or ""),
        active=bool(m.get("active", True)),
        target=str(target),
        tags=tags,
    )
