"""User-configurable alert targets via Apprise (https://github.com/caronc/apprise).

Targets are stored in the database; their URLs usually embed tokens, so they are never shown in full and never
returned by any MCP tool.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from .faults import FaultEvent
from .redact import redact_text
from .rules import SEVERITY_ORDER
from .store import Store

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS notify_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL,
    min_severity TEXT NOT NULL DEFAULT 'warning', categories TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1
);
"""


@dataclass(frozen=True)
class Target:
    id: int
    name: str
    url: str
    min_severity: str
    categories: tuple[str, ...]
    enabled: bool

    @property
    def masked(self) -> str:
        return mask_url(self.url)


def mask_url(url: str) -> str:
    """Keep only the scheme and a hint of the host: enough to recognise the target, nothing secret."""
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", url, re.I)
    return f"{m.group(1)}://***" if m else "***"


class NotifyStore:
    def __init__(self, store: Store) -> None:
        self.store = store
        with store._lock:
            store._db.executescript(_SCHEMA)
            store._db.commit()

    async def list(self) -> list[Target]:
        rows = await self.store._run(
            lambda: [dict(r) for r in self.store._db.execute("SELECT * FROM notify_targets ORDER BY name")]
        )
        return [
            Target(
                r["id"],
                r["name"],
                r["url"],
                r["min_severity"],
                tuple(c for c in r["categories"].split(",") if c),
                bool(r["enabled"]),
            )
            for r in rows
        ]

    async def add(
        self, name: str, url: str, min_severity: str = "warning", categories: list[str] | None = None
    ) -> None:
        if min_severity not in SEVERITY_ORDER:
            raise ValueError("bad severity")
        if not name.strip() or not valid_url(url):
            raise ValueError("name required and the URL must be a valid Apprise URL")
        await self.store._run(
            lambda: self.store._db.execute(
                "INSERT INTO notify_targets (name, url, min_severity, categories) VALUES (?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET url=excluded.url, min_severity=excluded.min_severity, "
                "categories=excluded.categories",
                (name.strip(), url.strip(), min_severity, ",".join(categories or [])),
            )
        )

    async def remove(self, target_id: int) -> None:
        await self.store._run(lambda: self.store._db.execute("DELETE FROM notify_targets WHERE id=?", (target_id,)))


def valid_url(url: str) -> bool:
    import apprise

    return bool(apprise.Apprise().add(url.strip()))


async def send(url: str, title: str, body: str, severity: str) -> bool:
    import apprise

    kind = {
        "critical": apprise.NotifyType.FAILURE,
        "warning": apprise.NotifyType.WARNING,
    }.get(severity, apprise.NotifyType.INFO)
    ap = apprise.Apprise()
    if not ap.add(url):
        return False
    return bool(await ap.async_notify(title=title, body=body, notify_type=kind))


class Notifier:
    """Routes a fault event to every enabled target whose severity and category filters accept it."""

    def __init__(self, targets: NotifyStore, store: Store) -> None:
        self.targets, self.store = targets, store

    async def __call__(self, ev: FaultEvent) -> None:
        sent = failed = 0
        for t in await self.targets.list():
            if not t.enabled or SEVERITY_ORDER[ev.severity] < SEVERITY_ORDER[t.min_severity]:
                continue
            if t.categories and ev.category not in t.categories:
                continue
            title = f"[{ev.severity.upper()}] {ev.category} on {ev.host}: {ev.title}"
            body = f"{ev.title}\nHost: {ev.host}\nSource: {ev.source}\nSeen: {ev.count} time(s)\n\n{redact_text(ev.sample)[:1200]}"
            try:
                ok = await send(t.url, title, body, ev.severity)
            except Exception as exc:
                log.warning("notify target %s raised %s", t.name, type(exc).__name__)
                ok = False
            sent += ok
            failed += not ok
        if failed or not (sent or failed):
            await self.store.audit(
                "notify",
                "error" if failed else "no-target",
                host=ev.host,
                detail=f"{ev.title}: sent={sent} failed={failed}",
            )

    async def test(self, target_id: int) -> bool:
        for t in await self.targets.list():
            if t.id == target_id:
                return await send(t.url, "mcpmonitor test", "If you can read this, alerts to this target work.", "info")
        return False


def describe(targets: list[Target]) -> list[dict[str, Any]]:
    return [
        {
            "id": t.id,
            "name": t.name,
            "target": t.masked,
            "min_severity": t.min_severity,
            "categories": list(t.categories),
            "enabled": t.enabled,
        }
        for t in targets
    ]
