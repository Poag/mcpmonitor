"""Parse syslog messages (RFC 3164 and RFC 5424, plus tolerant fallbacks) and normalise lines to templates."""

from __future__ import annotations

import re
from dataclasses import dataclass

FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
    "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]  # fmt: skip
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

_PRI = re.compile(r"^<(\d{1,3})>")
_RFC5424 = re.compile(r"^<\d{1,3}>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\](?:\[.*?\])*)? ?(.*)$", re.DOTALL)
_RFC3164 = re.compile(
    r"^<\d{1,3}>(?:(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d) )?(?:(?P<host>[^\s:\[]+) )?"
    r"(?P<tag>[^\s:\[]+)?(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$",
    re.DOTALL,
)


@dataclass(frozen=True)
class SyslogMessage:
    host: str
    program: str
    facility: str
    severity: str
    message: str
    raw: str


def parse(raw: str, sender: str = "") -> SyslogMessage:
    raw = raw.rstrip("\r\n\x00")
    facility, severity = "user", "notice"
    m = _PRI.match(raw)
    if m:
        pri = int(m.group(1))
        if pri < 192:
            facility, severity = FACILITIES[pri >> 3], SEVERITIES[pri & 7]
    host, program, message = sender, "", raw

    m5 = _RFC5424.match(raw)
    if m5 and m5.group(1).isdigit():
        _, _ts, h, app, _pid, _msgid, _sd, msg = m5.groups()
        host = h if h != "-" else sender
        program = app if app != "-" else ""
        message = msg
    else:
        m3 = _RFC3164.match(raw)
        if m3:
            host = m3.group("host") or sender
            program = m3.group("tag") or ""
            message = m3.group("msg")
        elif m:
            message = raw[m.end() :]
    return SyslogMessage(host or sender or "unknown", program, facility, severity, message.strip(), raw)


_NORMALISE = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I), "<mac>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\[\s*\d+\.\d+\]"), ""),  # kernel uptime stamps
    (re.compile(r"\b\d+\b"), "<n>"),
]


def template_of(program: str, message: str) -> str:
    """Collapse the variable parts of a line so repeats of the same kind of message group together."""
    text = message
    for pattern, repl in _NORMALISE:
        text = pattern.sub(repl, text)
    return f"{program}: {re.sub(r'\s+', ' ', text).strip()}"[:300]
