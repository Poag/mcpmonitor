"""Fault rules: regexes over syslog lines with a threshold, grouped by category.

The default set is conservative and UNTESTED against real logs from these machines (no samples existed when it
was written). Patterns come from common Linux kernel/driver message shapes; expect to tune them using the
learning-mode pages (frequent unmatched patterns, replay before enabling).
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}
CATEGORIES = ("disk", "filesystem", "array", "memory", "network", "temperature", "hardware", "other")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str  # info | warning | critical
    pattern: str
    title: str
    threshold: int = 1  # matches needed ...
    window: int = 600  # ... within this many seconds
    enabled: bool = True

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE)


DEFAULT_RULES: list[Rule] = [
    Rule("disk-io-error", "disk", "critical", r"blk_update_request: (critical )?(medium |I/O )error|Buffer I/O error on dev|end_request: I/O error", "Disk I/O error", 1),
    Rule("disk-ata-error", "disk", "critical", r"\bata\d+(\.\d+)?: (exception Emask|failed command:|status: \{ .*ERR)", "ATA error on a disk or SATA link", 1),
    Rule("disk-ata-reset", "disk", "warning", r"\bata\d+(\.\d+)?: (hard resetting link|COMRESET failed|link is slow|limiting SATA link speed)", "SATA link resets or speed downgrade", 3, 900),
    Rule("disk-scsi-error", "disk", "critical", r"Unrecovered read error|Medium Error|\[sd[a-z]+\].*(Sense Key : (Medium|Hardware) Error|FAILED Result)", "SCSI/SATA medium or hardware error", 1),
    Rule("disk-smart", "disk", "critical", r"smartd?\b.*(FAILED|Prefailure|Currently unreadable|Offline uncorrectable|pending sector)", "SMART warning", 1),
    Rule("fs-xfs", "filesystem", "critical", r"XFS \(\S+\): .*(metadata I/O error|Corruption detected|Filesystem has been shut down|xfs_do_force_shutdown)", "XFS error", 1),
    Rule("fs-btrfs", "filesystem", "critical", r"BTRFS (error|critical)", "btrfs error", 1),
    Rule("fs-ext4", "filesystem", "critical", r"EXT4-fs error|Remounting filesystem read-only", "ext4 error or read-only remount", 1),
    Rule("fs-full", "filesystem", "warning", r"No space left on device", "A filesystem is full", 3, 900),
    Rule("array-md", "array", "critical", r"\bmd\d*[:\s].*(read|write) error|disk\d+ (is )?disabled", "Array (md) disk error or disabled disk", 1),
    Rule("mem-oom", "memory", "warning", r"Out of memory: Killed process|invoked oom-killer|oom-kill:", "Out-of-memory kill", 1),
    Rule("net-link-down", "network", "warning", r"(NIC |)Link is Down|link down\b", "Network link down", 1),
    Rule("net-link-flap", "network", "critical", r"(NIC |)Link is (Down|Up)", "Network link flapping", 6, 600),
    Rule("net-watchdog", "network", "critical", r"NETDEV WATCHDOG: \S+ .*transmit queue \d+ timed out", "NIC transmit timeout (driver reset)", 1),
    Rule("temp-high", "temperature", "warning", r"temperature above threshold|over[- ]?temp|Package temperature|thermal.*(critical|shutdown)", "High temperature", 1),
    Rule("hw-mce", "hardware", "critical", r"mce: .*Hardware Error|Machine check events logged", "CPU/memory hardware error (MCE)", 1),
]  # fmt: skip


@dataclass
class Match:
    rule: Rule
    count: int
    line: str


class RuleEngine:
    """Evaluate lines against rules, applying each rule's threshold within its window per host."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.set_rules(rules if rules is not None else DEFAULT_RULES)
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def set_rules(self, rules: list[Rule]) -> None:
        self._rules = [(r, r.compiled()) for r in rules if r.enabled]

    @property
    def rules(self) -> list[Rule]:
        return [r for r, _ in self._rules]

    def evaluate(self, host: str, line: str, now: float | None = None) -> list[Match]:
        now = time.time() if now is None else now
        out: list[Match] = []
        for rule, rx in self._rules:
            if not rx.search(line):
                continue
            hits = self._hits[(host.lower(), rule.id)]
            hits.append(now)
            while hits and now - hits[0] > rule.window:
                hits.popleft()
            if len(hits) >= rule.threshold:
                out.append(Match(rule, len(hits), line))
        return out

    def matches_any(self, line: str) -> bool:
        return any(rx.search(line) for _, rx in self._rules)
