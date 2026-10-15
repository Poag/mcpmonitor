"""Fault history, syslog line storage and learning-mode templates, plus the service that ties rules to alerts."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .rules import CATEGORIES, SEVERITY_ORDER, Match, RuleEngine
from .store import Store
from .syslog_parse import SyslogMessage, template_of

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS syslog_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, host TEXT NOT NULL, program TEXT NOT NULL DEFAULT '',
    facility TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '', message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS syslog_host_ts ON syslog_lines (host, ts);
CREATE INDEX IF NOT EXISTS syslog_ts ON syslog_lines (ts);
CREATE TABLE IF NOT EXISTS hosts_seen (host TEXT PRIMARY KEY, last_seen REAL NOT NULL, lines INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS faults (
    id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
    rule TEXT NOT NULL, title TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 1, sample TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'syslog',
    status TEXT NOT NULL DEFAULT 'open', notified_at REAL
);
CREATE INDEX IF NOT EXISTS faults_lookup ON faults (host, rule, status);
CREATE TABLE IF NOT EXISTS templates (
    template TEXT PRIMARY KEY, count INTEGER NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    sample TEXT NOT NULL, program TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS custom_rules (
    id TEXT PRIMARY KEY, category TEXT NOT NULL, severity TEXT NOT NULL, pattern TEXT NOT NULL,
    title TEXT NOT NULL, threshold INTEGER NOT NULL DEFAULT 1, window INTEGER NOT NULL DEFAULT 600,
    enabled INTEGER NOT NULL DEFAULT 1
);
"""

MAX_TEMPLATES = 5000
REOPEN_WINDOW = 6 * 3600  # a new match within this long of the last one extends the same fault

Notify = Callable[["FaultEvent"], Awaitable[None]]


@dataclass(frozen=True)
class FaultEvent:
    id: int
    host: str
    category: str
    severity: str
    title: str
    count: int
    sample: str
    source: str
    is_new: bool


class FaultStore:
    def __init__(self, store: Store) -> None:
        self.store = store
        with store._lock:
            store._db.executescript(_SCHEMA)
            store._db.commit()

    # -- lines ---------------------------------------------------------------------------------------

    async def add_lines(self, rows: list[tuple[float, SyslogMessage]]) -> None:
        if not rows:
            return
        templates: dict[str, tuple[int, float, str, str]] = {}
        hosts: dict[str, tuple[float, int]] = {}
        for ts, m in rows:
            key = template_of(m.program, m.message)
            count, _, sample, prog = templates.get(key, (0, ts, m.message, m.program))
            templates[key] = (count + 1, ts, sample, prog)
            last, n = hosts.get(m.host, (ts, 0))
            hosts[m.host] = (max(last, ts), n + 1)

        def go() -> None:
            db = self.store._db
            db.executemany(
                "INSERT INTO syslog_lines (ts, host, program, facility, severity, message) VALUES (?,?,?,?,?,?)",
                [(ts, m.host, m.program, m.facility, m.severity, m.message[:4000]) for ts, m in rows],
            )
            for host, (last, n) in hosts.items():
                db.execute(
                    "INSERT INTO hosts_seen (host, last_seen, lines) VALUES (?,?,?) ON CONFLICT(host) DO UPDATE "
                    "SET last_seen=MAX(last_seen, excluded.last_seen), lines=lines+excluded.lines",
                    (host, last, n),
                )
            for key, (count, last, sample, prog) in templates.items():
                db.execute(
                    "INSERT INTO templates (template, count, first_seen, last_seen, sample, program) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(template) DO UPDATE SET count=count+excluded.count, last_seen=excluded.last_seen",
                    (key, count, last, last, sample[:500], prog),
                )
            over = db.execute("SELECT COUNT(*) FROM templates").fetchone()[0] - MAX_TEMPLATES
            if over > 0:
                db.execute(
                    "DELETE FROM templates WHERE template IN (SELECT template FROM templates ORDER BY count ASC, "
                    "last_seen ASC LIMIT ?)",
                    (over,),
                )

        await self.store._run(go)

    async def prune(self, max_age_days: int, max_rows: int) -> int:
        cutoff = time.time() - max_age_days * 86400

        def go() -> int:
            db = self.store._db
            n = db.execute("DELETE FROM syslog_lines WHERE ts < ?", (cutoff,)).rowcount
            total = db.execute("SELECT COUNT(*) FROM syslog_lines").fetchone()[0]
            if total > max_rows:
                n += db.execute(
                    "DELETE FROM syslog_lines WHERE id IN (SELECT id FROM syslog_lines ORDER BY id ASC LIMIT ?)",
                    (total - max_rows,),
                ).rowcount
            db.execute("DELETE FROM faults WHERE status='resolved' AND last_seen < ?", (cutoff,))
            return n

        return await self.store._run(go)

    async def search_lines(
        self, *, host: str | None, since: float, min_severity: str | None, limit: int
    ) -> list[dict[str, Any]]:
        sev_rank = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

        def go() -> list[dict[str, Any]]:
            q, args = "SELECT ts, host, program, severity, message FROM syslog_lines WHERE ts >= ?", [since]
            if host:
                q += " AND lower(host)=lower(?)"
                args.append(host)
            if min_severity in sev_rank:
                allowed = sev_rank[: sev_rank.index(min_severity) + 1]
                q += f" AND severity IN ({','.join('?' * len(allowed))})"
                args += allowed
            q += " ORDER BY id DESC LIMIT ?"
            args.append(limit)
            return [dict(r) for r in self.store._db.execute(q, args)][::-1]

        return await self.store._run(go)

    async def hosts(self) -> list[dict[str, Any]]:
        return await self.store._run(
            lambda: [dict(r) for r in self.store._db.execute("SELECT * FROM hosts_seen ORDER BY host")]
        )

    # -- faults --------------------------------------------------------------------------------------

    async def record_fault(
        self,
        host: str,
        category: str,
        severity: str,
        rule: str,
        title: str,
        sample: str,
        source: str,
        now: float,
    ) -> tuple[int, int, bool]:
        """Create or extend an open fault. Returns (id, count, is_new)."""

        def go() -> tuple[int, int, bool]:
            db = self.store._db
            row = db.execute(
                "SELECT id, count FROM faults WHERE lower(host)=lower(?) AND rule=? AND status='open' AND last_seen>=?",
                (host, rule, now - REOPEN_WINDOW),
            ).fetchone()
            if row:
                db.execute(
                    "UPDATE faults SET count=count+1, last_seen=?, sample=?, severity=? WHERE id=?",
                    (now, sample[:1000], severity, row["id"]),
                )
                return row["id"], row["count"] + 1, False
            cur = db.execute(
                "INSERT INTO faults (host, category, severity, rule, title, first_seen, last_seen, sample, source) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (host, category, severity, rule, title, now, now, sample[:1000], source),
            )
            return int(cur.lastrowid or 0), 1, True

        return await self.store._run(go)

    async def mark_notified(self, fault_id: int) -> None:
        await self.store._run(
            lambda: self.store._db.execute("UPDATE faults SET notified_at=? WHERE id=?", (time.time(), fault_id))
        )

    async def set_status(self, fault_id: int, status: str) -> None:
        if status not in ("open", "acked", "resolved"):
            raise ValueError("bad status")
        await self.store._run(
            lambda: self.store._db.execute("UPDATE faults SET status=? WHERE id=?", (status, fault_id))
        )

    async def list_faults(
        self, *, since: float, category: str | None = None, host: str | None = None, status: str | None = None
    ) -> list[dict[str, Any]]:
        def go() -> list[dict[str, Any]]:
            q, args = "SELECT * FROM faults WHERE last_seen >= ?", [since]
            if category:
                q += " AND category=?"
                args.append(category)
            if host:
                q += " AND lower(host)=lower(?)"
                args.append(host)
            if status:
                q += " AND status=?"
                args.append(status)
            q += " ORDER BY last_seen DESC LIMIT 200"
            return [dict(r) for r in self.store._db.execute(q, args)]

        return await self.store._run(go)

    # -- learning mode -------------------------------------------------------------------------------

    async def top_templates(self, limit: int = 50) -> list[dict[str, Any]]:
        return await self.store._run(
            lambda: [
                dict(r)
                for r in self.store._db.execute("SELECT * FROM templates ORDER BY count DESC LIMIT ?", (limit * 4,))
            ]
        )

    async def replay_count(self, pattern: str, since: float) -> tuple[int, list[str]]:
        """How many stored lines a pattern would have matched (bounded scan) and a few examples."""
        import re

        rx = re.compile(pattern, re.IGNORECASE)

        def go() -> tuple[int, list[str]]:
            n, examples = 0, []
            for r in self.store._db.execute(
                "SELECT program, message FROM syslog_lines WHERE ts >= ? ORDER BY id DESC LIMIT 200000",
                (since,),
            ):
                line = f"{r['program']}: {r['message']}"
                if rx.search(line):
                    n += 1
                    if len(examples) < 5:
                        examples.append(line[:300])
            return n, examples

        return await self.store._run(go)

    async def custom_rules(self) -> list[dict[str, Any]]:
        return await self.store._run(
            lambda: [dict(r) for r in self.store._db.execute("SELECT * FROM custom_rules ORDER BY id")]
        )

    async def save_custom_rule(self, rule: dict[str, Any]) -> None:
        if rule["category"] not in CATEGORIES or rule["severity"] not in SEVERITY_ORDER:
            raise ValueError("bad category or severity")
        await self.store._run(
            lambda: self.store._db.execute(
                "INSERT OR REPLACE INTO custom_rules (id, category, severity, pattern, title, threshold, window, enabled) "
                "VALUES (:id,:category,:severity,:pattern,:title,:threshold,:window,:enabled)",
                rule,
            )
        )

    async def delete_custom_rule(self, rule_id: str) -> None:
        await self.store._run(lambda: self.store._db.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,)))


class FaultService:
    """Feeds syslog messages through the rule engine, records faults and triggers notifications."""

    def __init__(self, faults: FaultStore, engine: RuleEngine, notify: Notify | None = None) -> None:
        self.faults, self.engine, self.notify = faults, engine, notify

    async def reload_rules(self) -> None:
        from .rules import DEFAULT_RULES, Rule

        custom = [
            Rule(
                r["id"],
                r["category"],
                r["severity"],
                r["pattern"],
                r["title"],
                r["threshold"],
                r["window"],
                bool(r["enabled"]),
            )
            for r in await self.faults.custom_rules()
        ]
        self.engine.set_rules(DEFAULT_RULES + custom)

    async def ingest(self, rows: list[tuple[float, SyslogMessage]]) -> list[FaultEvent]:
        await self.faults.add_lines(rows)
        events: list[FaultEvent] = []
        for ts, m in rows:
            line = f"{m.program}: {m.message}"
            for match in self.engine.evaluate(m.host, line, ts):
                events.append(await self._fault(m.host, match, ts, "syslog"))
        for ev in events:
            if ev.is_new and self.notify:
                try:
                    await self.notify(ev)
                    await self.faults.mark_notified(ev.id)
                except Exception:
                    log.exception("notification failed for fault %s", ev.id)
        return events

    async def raise_fault(
        self, host: str, category: str, severity: str, rule: str, title: str, sample: str, source: str
    ) -> FaultEvent:
        """Record a fault from a non-syslog source (e.g. an Unraid notification) and notify if new."""
        fid, count, is_new = await self.faults.record_fault(
            host, category, severity, rule, title, sample, source, time.time()
        )
        ev = FaultEvent(fid, host, category, severity, title, count, sample, source, is_new)
        if is_new and self.notify:
            try:
                await self.notify(ev)
                await self.faults.mark_notified(fid)
            except Exception:
                log.exception("notification failed for fault %s", fid)
        return ev

    async def _fault(self, host: str, match: Match, ts: float, source: str) -> FaultEvent:
        r = match.rule
        fid, count, is_new = await self.faults.record_fault(
            host, r.category, r.severity, r.id, r.title, match.line, source, ts
        )
        return FaultEvent(fid, host, r.category, r.severity, r.title, count, match.line, source, is_new)
