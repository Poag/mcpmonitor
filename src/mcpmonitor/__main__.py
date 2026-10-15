"""Entry point: ``python -m mcpmonitor`` or the ``mcpmonitor`` script."""

from __future__ import annotations

import asyncio
import logging
import sys

from .actions import ActionService
from .backends.dockhand import DockhandBackend
from .config import ConfigError, Settings
from .faults import FaultService, FaultStore
from .ingest import watchdog
from .kuma import UptimeKumaClient
from .notify import Notifier, NotifyStore
from .rules import RuleEngine
from .server import build_http_app, build_server
from .store import Store
from .syslog_server import SyslogReceiver, parse_allow


async def _run(settings: Settings) -> None:
    backend = DockhandBackend(
        settings.dockhand_url,
        settings.dockhand_token,
        verify_tls=settings.dockhand_verify_tls,
        timeout=settings.dockhand_timeout,
    )
    store = Store(settings.db_path)
    kuma = (
        UptimeKumaClient(settings.kuma_url, settings.kuma_username, settings.kuma_password)
        if settings.kuma_url
        else None
    )
    actions = ActionService(settings, backend, store, kuma)

    fault_store = FaultStore(store)
    notify_store = NotifyStore(store)
    notifier = Notifier(notify_store, store)
    fault_service = FaultService(fault_store, RuleEngine(), notifier)
    await fault_service.reload_rules()
    receiver = (
        SyslogReceiver(
            fault_service,
            parse_allow(settings.syslog_allow),
            port=settings.syslog_port,
            rate_per_sec=settings.syslog_rate,
        )
        if settings.syslog_port
        else None
    )
    mcp = build_server(settings, backend, store, kuma, actions, fault_service, notify_store, notifier, receiver)
    background: list[asyncio.Task] = []
    try:
        if receiver is not None:
            await receiver.start()
            background.append(asyncio.create_task(_prune_loop(fault_store, settings)))
        if settings.expect_hosts():
            background.append(asyncio.create_task(watchdog(fault_service, settings.expect_hosts())))
        resumed = await actions.reconcile()
        if resumed:
            logging.getLogger("mcpmonitor").warning("resumed %d Kuma monitor(s) left paused", len(resumed))
        if settings.transport == "stdio":
            await mcp.run_stdio_async()
        else:
            import uvicorn

            app = build_http_app(settings, mcp)
            config = uvicorn.Config(app, host=settings.http_host, port=settings.http_port, log_level="info")
            await uvicorn.Server(config).serve()
    finally:
        for task in background:
            task.cancel()
        if receiver is not None:
            await receiver.stop()
        await backend.aclose()
        if kuma is not None:
            await kuma.aclose()
        store.close()


async def _prune_loop(faults: FaultStore, settings: Settings) -> None:
    while True:
        try:
            await faults.prune(settings.syslog_retention_days, settings.syslog_max_rows)
        except Exception:
            logging.getLogger("mcpmonitor").exception("syslog prune failed")
        await asyncio.sleep(3600)


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)  # stdout is the MCP channel on stdio
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"mcpmonitor: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    asyncio.run(_run(settings))


if __name__ == "__main__":
    main()
