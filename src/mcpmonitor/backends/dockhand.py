"""Dockhand REST backend.

Routes and shapes were read from Dockhand's source (Finsys/dockhand, src/routes/api) on 15 Oct 2026 and
have not yet been exercised against a live instance. Dockhand addresses hosts as numeric "environments"
(``?env=<id>``); this backend lets callers use the environment name or id interchangeably.

Auth: ``Authorization: Bearer dh_...``. Dockhand's own docs/code describe API tokens (``dh_`` prefix) but the
exact header handling was not visible in the files read, so Bearer is an assumption to confirm.
Dockhand tokens carry no scopes (they act as their owning user), so mcpmonitor's own allowlist is the
real safety boundary; use a dedicated Dockhand user.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .base import BackendError, ContainerSummary, HostInfo, NotFoundError

_ENV_CACHE_SECONDS = 30.0


class DockhandBackend:
    def __init__(
        self,
        base_url: str,
        token: str = "",
        *,
        verify_tls: bool = True,
        timeout: float = 20.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            verify=verify_tls,
            timeout=timeout,
            transport=transport,
        )
        self._envs: list[HostInfo] = []
        self._envs_at = 0.0

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- helpers ---------------------------------------------------------------------------------

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise BackendError(f"Dockhand unreachable: {type(exc).__name__}: {exc}") from exc
        if resp.status_code == 404:
            raise NotFoundError(_error_text(resp) or "not found")
        if resp.status_code in (401, 403):
            raise BackendError(f"Dockhand refused the request ({resp.status_code}): {_error_text(resp)}")
        if resp.status_code >= 400:
            raise BackendError(f"Dockhand error {resp.status_code}: {_error_text(resp)}")
        try:
            return resp.json()
        except ValueError as exc:
            raise BackendError("Dockhand returned a non-JSON response") from exc

    async def _env_id(self, host: str) -> int:
        """Resolve a host given as environment name or numeric id."""
        hosts = await self.list_hosts()
        needle = str(host).strip().lower()
        for h in hosts:
            if h.id == needle or h.name.lower() == needle:
                return int(h.id)
        known = ", ".join(f"{h.name} ({h.id})" for h in hosts) or "none"
        raise NotFoundError(f"Unknown host {host!r}. Known hosts: {known}")

    # -- Backend interface -----------------------------------------------------------------------

    async def list_hosts(self) -> list[HostInfo]:
        now = time.monotonic()
        if self._envs and now - self._envs_at < _ENV_CACHE_SECONDS:
            return self._envs
        data = await self._request("GET", "/api/environments")
        if not isinstance(data, list):
            raise BackendError("Unexpected /api/environments response")
        hosts = [
            HostInfo(
                id=str(e.get("id")),
                name=str(e.get("name", e.get("id"))),
                connection_type=str(e.get("connectionType", "")),
                address=_address(e),
            )
            for e in data
            if isinstance(e, dict)
        ]
        self._envs, self._envs_at = hosts, now
        return hosts

    async def list_containers(self, host: str, *, all: bool = True) -> list[ContainerSummary]:
        env = await self._env_id(host)
        data = await self._request(
            "GET", "/api/containers", params={"env": env, "all": "true" if all else "false"}
        )
        if not isinstance(data, list):
            raise BackendError("Unexpected /api/containers response")
        host_name = next((h.name for h in await self.list_hosts() if h.id == str(env)), str(env))
        return [_container(host_name, c) for c in data if isinstance(c, dict)]

    async def inspect_container(self, host: str, container: str) -> dict[str, Any]:
        env = await self._env_id(host)
        data = await self._request("GET", f"/api/containers/{_seg(container)}/inspect", params={"env": env})
        if not isinstance(data, dict):
            raise BackendError("Unexpected inspect response")
        return data

    async def container_logs(
        self, host: str, container: str, *, tail: int = 200, since: str | None = None
    ) -> str:
        env = await self._env_id(host)
        params: dict[str, Any] = {"env": env, "tail": tail}
        if since:
            params["since"] = since
        data = await self._request("GET", f"/api/containers/{_seg(container)}/logs", params=params)
        logs = data.get("logs") if isinstance(data, dict) else None
        if not isinstance(logs, str):
            raise BackendError("Unexpected logs response")
        return logs


def _seg(container: str) -> str:
    """A container id or name as a single URL path segment."""
    from urllib.parse import quote

    c = container.strip().lstrip("/")
    if not c or "/" in c:
        raise BackendError(f"Invalid container reference {container!r}")
    return quote(c, safe="")


def _error_text(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:200]
    if isinstance(body, dict):
        return str(body.get("error") or body.get("details") or "")[:200]
    return ""


def _address(env: dict[str, Any]) -> str:
    host, port = env.get("host"), env.get("port")
    if host and port:
        return f"{host}:{port}"
    return str(host or "")


def _container(host: str, c: dict[str, Any]) -> ContainerSummary:
    labels = c.get("labels") or c.get("Labels") or {}
    if not isinstance(labels, dict):
        labels = {}
    ports = c.get("ports") or []
    return ContainerSummary(
        host=host,
        id=str(c.get("id", ""))[:12],
        name=str(c.get("name", "")).lstrip("/"),
        image=str(c.get("image", "")),
        state=str(c.get("state", "")),
        status=str(c.get("status", "")),
        health=str(c.get("health", "") or ""),
        compose_project=str(labels.get("com.docker.compose.project", "")),
        ports=[str(p) for p in ports] if isinstance(ports, list) else [],
        labels={str(k): str(v) for k, v in labels.items()},
    )
