"""Entry point: ``python -m mcpmonitor`` or the ``mcpmonitor`` script."""

from __future__ import annotations

import asyncio
import logging
import sys

from .actions import ActionService
from .backends.dockhand import DockhandBackend
from .config import ConfigError, Settings
from .kuma import UptimeKumaClient
from .server import build_http_app, build_server
from .store import Store


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
    mcp = build_server(settings, backend, store, kuma, actions)
    try:
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
        await backend.aclose()
        if kuma is not None:
            await kuma.aclose()
        store.close()


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
