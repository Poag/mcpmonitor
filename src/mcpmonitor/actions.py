"""Controlled container actions with Kuma pause/resume around them.

Order of operations for a real action:
  1. gate: actions enabled, container allowlisted for this action, rate limit not exceeded
  2. pause the active Kuma monitors mapped to the container (recorded in the store first)
  3. perform the action through the backend
  4. wait for the container to be running (and healthy, if it has a health check), then a short grace period
  5. resume exactly the monitors this call paused, whatever happened above (try/finally)

A crash between 2 and 5 leaves rows in ``pauses``; ``reconcile`` resumes them at startup.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .backends import Backend, BackendError
from .config import Settings
from .kuma import KumaClient, KumaError
from .store import ACTIONS, Store

log = logging.getLogger(__name__)


class ActionRefused(Exception):
    """The action was not allowed to run (policy), as opposed to failing while running."""


@dataclass
class ActionResult:
    action: str
    host: str
    container: str
    dry_run: bool
    ok: bool = True
    monitors_paused: list[str] = field(default_factory=list)
    monitors_resumed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    final_state: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class ActionService:
    def __init__(self, settings: Settings, backend: Backend, store: Store, kuma: KumaClient | None) -> None:
        self.settings, self.backend, self.store, self.kuma = settings, backend, store, kuma
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    async def reconcile(self) -> list[int]:
        """Resume monitors left paused by an interrupted action. Returns the ids resumed."""
        resumed: list[int] = []
        pending = await self.store.pending_pauses()
        if not pending:
            return resumed
        if self.kuma is None:
            log.warning("pending Kuma pauses exist but Kuma is not configured")
            return resumed
        for row in pending:
            try:
                await self.kuma.resume(row["monitor_id"])
                await self.store.clear_pause(row["monitor_id"])
                resumed.append(row["monitor_id"])
                await self.store.audit(
                    "reconcile",
                    "ok",
                    args={"monitor_id": row["monitor_id"]},
                    detail=f"resumed monitor left paused by {row['action']}",
                )
            except KumaError as exc:
                log.error("could not resume monitor %s: %s", row["monitor_id"], exc)
        return resumed

    async def run(
        self, action: str, host: str, container: str, *, dry_run: bool = False, reason: str = ""
    ) -> ActionResult:
        if action not in ACTIONS:
            raise ActionRefused(f"unknown action {action!r}")
        if not self.settings.enable_actions:
            raise ActionRefused("actions are disabled (set MCPM_ENABLE_ACTIONS=true to enable)")

        info = await self.backend.resolve_host(host)
        host_name = info.name
        name = await self._canonical_name(host_name, container)

        allowed = await self.store.allowed_actions(host_name, name)
        if action not in allowed:
            await self.store.audit(
                action,
                "refused",
                host=host_name,
                container=name,
                args={"reason": reason},
                detail="not allowlisted",
            )
            raise ActionRefused(
                f"{action} is not allowed for {name} on {host_name}. "
                f"Allowed actions: {', '.join(sorted(allowed)) or 'none'}. Add it to the allowlist first."
            )

        used = await self.store.count_actions_since(host_name, name, time.time() - 3600)
        if used >= self.settings.actions_per_hour and not dry_run:
            await self.store.audit(
                action,
                "refused",
                host=host_name,
                container=name,
                args={"reason": reason},
                detail="rate limit",
            )
            raise ActionRefused(
                f"rate limit: {used} actions on {name} in the last hour "
                f"(limit {self.settings.actions_per_hour})"
            )

        monitors = await self._active_mapped_monitors(host_name, name)
        result = ActionResult(action, host_name, name, dry_run)
        result.monitors_paused = [m[1] for m in monitors]
        if not monitors:
            result.notes.append("no active Kuma monitors are mapped to this container; nothing to pause")

        if dry_run:
            result.notes.append("dry run: nothing was changed")
            await self.store.audit(action, "dry-run", host=host_name, container=name, args={"reason": reason})
            return result

        lock = self._locks.setdefault((host_name.lower(), name.lower()), asyncio.Lock())
        if lock.locked():
            raise ActionRefused(f"another action on {name} is already in progress")
        async with lock:
            paused: list[tuple[int, str]] = []
            try:
                for mid, mname in monitors:
                    await self.store.record_pause(mid, action)  # record first, so a crash can be reconciled
                    try:
                        assert self.kuma is not None
                        await self.kuma.pause(mid)
                        paused.append((mid, mname))
                    except KumaError as exc:
                        await self.store.clear_pause(mid)
                        result.warnings.append(f"could not pause monitor {mname!r}: {exc}")
                result.monitors_paused = [m[1] for m in paused]

                try:
                    await self.backend.container_action(host_name, name, action)
                except BackendError as exc:
                    result.ok = False
                    result.warnings.append(f"{action} failed: {exc}")
                    await self.store.audit(
                        action,
                        "error",
                        host=host_name,
                        container=name,
                        args={"reason": reason},
                        detail=str(exc),
                    )
                    return result

                if action != "stop":
                    result.final_state = await self._wait_settled(host_name, name, result)
                    if result.final_state != "healthy" and result.final_state != "running":
                        result.ok = False
                else:
                    result.final_state = await self._current_state(host_name, name)
                await self.store.audit(
                    action,
                    "ok" if result.ok else "unsettled",
                    host=host_name,
                    container=name,
                    args={"reason": reason},
                    detail=result.final_state,
                )
                return result
            finally:
                for mid, mname in paused:
                    try:
                        assert self.kuma is not None
                        await self.kuma.resume(mid)
                        await self.store.clear_pause(mid)
                        result.monitors_resumed.append(mname)
                    except KumaError as exc:
                        # leave the pause row in place so reconcile() retries; make the failure visible
                        result.warnings.append(f"FAILED TO RESUME monitor {mname!r}: {exc}")
                        log.error("failed to resume monitor %s (%s): %s", mid, mname, exc)

    # -- helpers -----------------------------------------------------------------------------------

    async def _canonical_name(self, host: str, container: str) -> str:
        ref = container.strip().lstrip("/").lower()
        for c in await self.backend.list_containers(host, all=True):
            if c.name.lower() == ref or (len(ref) >= 4 and c.id.lower().startswith(ref)):
                return c.name
        raise ActionRefused(f"no container {container!r} on {host}")

    async def _active_mapped_monitors(self, host: str, name: str) -> list[tuple[int, str]]:
        ids = await self.store.monitors_for_container(host, name)
        if not ids or self.kuma is None:
            return []
        try:
            current = {m.id: m for m in await self.kuma.list_monitors()}
        except KumaError:
            return []
        return [(i, current[i].name) for i in ids if i in current and current[i].active]

    async def _current_state(self, host: str, name: str) -> str:
        for c in await self.backend.list_containers(host, all=True):
            if c.name.lower() == name.lower():
                return c.health.lower() if c.health and c.state == "running" else c.state.lower()
        return "missing"

    async def _wait_settled(self, host: str, name: str, result: ActionResult) -> str:
        deadline = time.monotonic() + self.settings.settle_timeout
        state = "unknown"
        while time.monotonic() < deadline:
            try:
                state = await self._current_state(host, name)
            except BackendError as exc:
                result.warnings.append(f"could not read state while waiting: {exc}")
                break
            if state in ("healthy", "running"):
                await asyncio.sleep(self.settings.settle_grace)
                return state
            await asyncio.sleep(min(2.0, max(0.05, self.settings.settle_timeout / 20)))
        result.warnings.append(
            f"container did not settle within {self.settings.settle_timeout:.0f}s (last: {state})"
        )
        return state
