"""Suggest which containers a Kuma monitor probably watches, from names and targets."""

from __future__ import annotations

import re

from .backends import ContainerSummary
from .kuma import KumaMonitor

_STOP = {"http", "https", "www", "the", "app", "web", "server", "service", "check", "monitor", "local", "lan"}


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3 and t not in _STOP}


def suggest(
    monitor: KumaMonitor, containers: list[ContainerSummary], limit: int = 3
) -> list[ContainerSummary]:
    """Containers whose name (or compose project) shares a token with the monitor's name or target."""
    mon = _tokens(monitor.name) | _tokens(monitor.target)
    scored: list[tuple[int, ContainerSummary]] = []
    for c in containers:
        names = _tokens(c.name) | _tokens(c.compose_project)
        score = len(mon & names)
        if c.name.lower() in monitor.name.lower() or c.name.lower() in monitor.target.lower():
            score += 2
        if score:
            scored.append((score, c))
    scored.sort(key=lambda sc: (-sc[0], sc[1].name))
    return [c for _, c in scored[:limit]]
