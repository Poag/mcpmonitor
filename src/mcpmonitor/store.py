"""SQLite store: monitor-to-container map, action allowlist, audit log and active Kuma pauses."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

ACTIONS = ("restart", "start", "stop")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS monitor_map (
    monitor_id   INTEGER PRIMARY KEY,
    monitor_name TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL CHECK (state IN ('mapped', 'ignored')),
    updated_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS monitor_containers (
    monitor_id INTEGER NOT NULL,
    host       TEXT NOT NULL,
    container  TEXT NOT NULL,
    PRIMARY KEY (monitor_id, host, container)
);
CREATE TABLE IF NOT EXISTS action_allow (
    host      TEXT NOT NULL,
    container TEXT NOT NULL,
    actions   TEXT NOT NULL,
    PRIMARY KEY (host, container)
);
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    tool      TEXT NOT NULL,
    host      TEXT NOT NULL DEFAULT '',
    container TEXT NOT NULL DEFAULT '',
    args      TEXT NOT NULL DEFAULT '{}',
    outcome   TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
CREATE TABLE IF NOT EXISTS pauses (
    monitor_id INTEGER PRIMARY KEY,
    paused_at  REAL NOT NULL,
    action     TEXT NOT NULL DEFAULT ''
);
"""


class Store:
    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    async def _run(self, fn: Callable[[], T]) -> T:
        def locked() -> T:
            with self._lock:
                result = fn()
                self._db.commit()
                return result

        return await asyncio.to_thread(locked)

    def close(self) -> None:
        self._db.close()

    # -- monitor map ------------------------------------------------------------------------------

    async def set_mapped(self, monitor_id: int, name: str, targets: list[tuple[str, str]]) -> None:
        def go() -> None:
            self._db.execute(
                "INSERT INTO monitor_map (monitor_id, monitor_name, state, updated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(monitor_id) DO UPDATE SET monitor_name=excluded.monitor_name, "
                "state=excluded.state, updated_at=excluded.updated_at",
                (monitor_id, name, "mapped", time.time()),
            )
            self._db.execute("DELETE FROM monitor_containers WHERE monitor_id=?", (monitor_id,))
            self._db.executemany(
                "INSERT OR IGNORE INTO monitor_containers (monitor_id, host, container) VALUES (?,?,?)",
                [(monitor_id, h, c) for h, c in targets],
            )

        await self._run(go)

    async def set_ignored(self, monitor_id: int, name: str) -> None:
        def go() -> None:
            self._db.execute(
                "INSERT INTO monitor_map (monitor_id, monitor_name, state, updated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(monitor_id) DO UPDATE SET monitor_name=excluded.monitor_name, "
                "state=excluded.state, updated_at=excluded.updated_at",
                (monitor_id, name, "ignored", time.time()),
            )
            self._db.execute("DELETE FROM monitor_containers WHERE monitor_id=?", (monitor_id,))

        await self._run(go)

    async def clear_monitor(self, monitor_id: int) -> None:
        def go() -> None:
            self._db.execute("DELETE FROM monitor_map WHERE monitor_id=?", (monitor_id,))
            self._db.execute("DELETE FROM monitor_containers WHERE monitor_id=?", (monitor_id,))

        await self._run(go)

    async def monitor_states(self) -> dict[int, dict[str, Any]]:
        """monitor_id -> {state, targets: [(host, container)]} for every monitor with a decision."""

        def go() -> dict[int, dict[str, Any]]:
            out: dict[int, dict[str, Any]] = {
                r["monitor_id"]: {"state": r["state"], "name": r["monitor_name"], "targets": []}
                for r in self._db.execute("SELECT * FROM monitor_map")
            }
            for r in self._db.execute("SELECT * FROM monitor_containers"):
                if r["monitor_id"] in out:
                    out[r["monitor_id"]]["targets"].append((r["host"], r["container"]))
            return out

        return await self._run(go)

    async def monitors_for_container(self, host: str, container: str) -> list[int]:
        def go() -> list[int]:
            rows = self._db.execute(
                "SELECT mc.monitor_id FROM monitor_containers mc "
                "JOIN monitor_map mm ON mm.monitor_id = mc.monitor_id AND mm.state = 'mapped' "
                "WHERE lower(mc.host)=lower(?) AND lower(mc.container)=lower(?)",
                (host, container),
            )
            return [r["monitor_id"] for r in rows]

        return await self._run(go)

    # -- allowlist ---------------------------------------------------------------------------------

    async def allow(self, host: str, container: str, actions: list[str]) -> None:
        bad = [a for a in actions if a not in ACTIONS]
        if bad or not actions:
            raise ValueError(f"actions must be a non-empty subset of {ACTIONS}, got {actions}")
        value = ",".join(sorted(set(actions)))

        def go() -> None:
            self._db.execute(
                "INSERT INTO action_allow (host, container, actions) VALUES (?,?,?) "
                "ON CONFLICT(host, container) DO UPDATE SET actions=excluded.actions",
                (host.lower(), container.lower(), value),
            )

        await self._run(go)

    async def disallow(self, host: str, container: str) -> None:
        await self._run(
            lambda: self._db.execute(
                "DELETE FROM action_allow WHERE host=? AND container=?", (host.lower(), container.lower())
            )
        )

    async def allowed_actions(self, host: str, container: str) -> set[str]:
        def go() -> set[str]:
            row = self._db.execute(
                "SELECT actions FROM action_allow WHERE host=? AND container=?",
                (host.lower(), container.lower()),
            ).fetchone()
            return set(row["actions"].split(",")) if row else set()

        return await self._run(go)

    async def list_allowed(self) -> list[dict[str, str]]:
        def go() -> list[dict[str, str]]:
            rows = self._db.execute(
                "SELECT host, container, actions FROM action_allow ORDER BY host, container"
            )
            return [dict(r) for r in rows]

        return await self._run(go)

    # -- audit -------------------------------------------------------------------------------------

    async def audit(
        self,
        tool: str,
        outcome: str,
        *,
        host: str = "",
        container: str = "",
        args: dict[str, Any] | None = None,
        detail: str = "",
    ) -> None:
        await self._run(
            lambda: self._db.execute(
                "INSERT INTO audit (ts, tool, host, container, args, outcome, detail) VALUES (?,?,?,?,?,?,?)",
                (
                    time.time(),
                    tool,
                    host,
                    container,
                    json.dumps(args or {}, default=str),
                    outcome,
                    detail[:2000],
                ),
            )
        )

    async def recent_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        def go() -> list[dict[str, Any]]:
            rows = self._db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(r) for r in rows]

        return await self._run(go)

    async def count_actions_since(self, host: str, container: str, since: float) -> int:
        def go() -> int:
            row = self._db.execute(
                "SELECT COUNT(*) AS n FROM audit WHERE tool IN ('restart','start','stop') AND outcome='ok' "
                "AND lower(host)=lower(?) AND lower(container)=lower(?) AND ts>=?",
                (host, container, since),
            ).fetchone()
            return int(row["n"])

        return await self._run(go)

    # -- pauses ------------------------------------------------------------------------------------

    async def record_pause(self, monitor_id: int, action: str) -> None:
        await self._run(
            lambda: self._db.execute(
                "INSERT OR REPLACE INTO pauses (monitor_id, paused_at, action) VALUES (?,?,?)",
                (monitor_id, time.time(), action),
            )
        )

    async def clear_pause(self, monitor_id: int) -> None:
        await self._run(lambda: self._db.execute("DELETE FROM pauses WHERE monitor_id=?", (monitor_id,)))

    async def pending_pauses(self) -> list[dict[str, Any]]:
        def go() -> list[dict[str, Any]]:
            return [dict(r) for r in self._db.execute("SELECT * FROM pauses")]

        return await self._run(go)
