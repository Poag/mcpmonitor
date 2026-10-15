"""Unraid notification ingest, plus the silent-host watchdog.

Unraid notification agents are shell scripts that receive the notification (event, subject, description,
importance, ...) and can POST it here. Every field is optional and the raw text is kept, so a wrong guess about
Unraid's variable names costs classification quality, not delivery.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import re
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .faults import FaultService
from .redact import redact_text
from .syslog_parse import SyslogMessage

log = logging.getLogger(__name__)

MAX_BODY = 32 * 1024

_CATEGORY_WORDS = [
    ("disk", r"smart|disk|drive|sector|read error|write error|reallocat|pending|uncorrect|ata\d|i/o error"),
    ("array", r"array|parity|rebuild|disabled|emulated|sync|md\d"),
    ("temperature", r"temperature|overheat|too hot|\bhot\b|thermal"),
    ("filesystem", r"file ?system|btrfs|xfs|cache pool|no space|\bfull\b|read-only"),
    ("network", r"network|\blink\b|\bnic\b|ethernet|dns"),
    ("memory", r"memory|\bram\b|out of memory|oom"),
]
_SEVERITY = {"alert": "critical", "warning": "warning", "normal": "info"}


def classify(payload: dict[str, Any]) -> tuple[str, str, str, str]:
    """-> (category, severity, rule_id, title) for an Unraid notification payload."""
    text = " ".join(str(payload.get(k, "")) for k in ("event", "subject", "description", "content")).lower()
    category = "other"
    for cat, words in _CATEGORY_WORDS:
        if re.search(words, text):
            category = cat
            break
    severity = _SEVERITY.get(str(payload.get("importance", "")).lower(), "warning")
    label = str(payload.get("event") or payload.get("subject") or "notification")
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40] or "notification"
    title = str(payload.get("subject") or payload.get("event") or "Unraid notification")[:150]
    return category, severity, f"unraid:{category}:{slug}", title


def register_ingest(mcp: MCPServer, service: FaultService, token: str) -> None:
    secret = token.encode()

    @mcp.custom_route("/ingest/unraid", methods=["POST"])
    async def unraid(request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        scheme, _, supplied = auth.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(supplied.strip().encode(), secret):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.body()
        if len(body) > MAX_BODY:
            return JSONResponse({"error": "payload too large"}, status_code=413)
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse({"error": "expected a JSON object"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": "expected a JSON object"}, status_code=400)

        host = str(
            payload.get("host") or payload.get("hostname") or (request.client.host if request.client else "unraid")
        )
        category, severity, rule, title = classify(payload)
        message = (
            " | ".join(str(payload[k])[:500] for k in ("subject", "description", "content") if payload.get(k)) or title
        )
        # always keep the raw notification searchable alongside syslog
        now = time.time()
        await service.faults.add_lines(
            [
                (
                    now,
                    SyslogMessage(
                        host, "unraid-notify", "user", severity if severity != "info" else "notice", message, message
                    ),
                )
            ]
        )
        fault_id = None
        if severity in ("warning", "critical"):
            ev = await service.raise_fault(host, category, severity, rule, title, redact_text(message), "unraid")
            fault_id = ev.id
        return JSONResponse({"ok": True, "fault_id": fault_id, "category": category, "severity": severity})


async def watchdog(service: FaultService, expect: dict[str, int], *, interval: float = 60.0) -> None:
    """Raise a fault when an expected host has sent nothing for its allowed silence, resolve when it returns."""
    while True:
        await asyncio.sleep(interval)
        try:
            await check_silence(service, expect)
        except Exception:
            log.exception("silence check failed")


async def check_silence(service: FaultService, expect: dict[str, int], now: float | None = None) -> list[str]:
    now = time.time() if now is None else now
    seen = {h["host"].lower(): h["last_seen"] for h in await service.faults.hosts()}
    silent: list[str] = []
    for host, minutes in expect.items():
        last = seen.get(host.lower())
        quiet = last is None or now - last > minutes * 60
        open_faults = await service.faults.list_faults(since=0, host=host, status="open")
        open_silent = [f for f in open_faults if f["rule"] == "host-silent"]
        if quiet:
            silent.append(host)
            if not open_silent:
                when = "never" if last is None else f"{int((now - last) // 60)} min ago"
                await service.raise_fault(
                    host,
                    "network",
                    "critical",
                    "host-silent",
                    f"No logs from {host} (last seen {when})",
                    f"Expected a message at least every {minutes} minutes.",
                    "watchdog",
                )
        else:
            for f in open_silent:
                await service.faults.set_status(f["id"], "resolved")
    return silent
