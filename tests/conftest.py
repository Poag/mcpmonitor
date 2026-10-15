from __future__ import annotations

import json
from collections.abc import Callable

import httpx
import pytest

from mcpmonitor.backends.dockhand import DockhandBackend
from mcpmonitor.config import Settings

ENVIRONMENTS = [
    {"id": 1, "name": "Unraid", "connectionType": "socket"},
    {"id": 2, "name": "PiZero", "connectionType": "hawser-standard", "host": "10.0.0.5", "port": 2376},
]

CONTAINERS = {
    1: [
        {
            "id": "a1b2c3d4e5f6a7b8",
            "name": "/buffarr",
            "image": "ghcr.io/poag/buffarr:latest",
            "state": "running",
            "status": "Up 3 days (healthy)",
            "labels": {"com.docker.compose.project": "media", "api_key": "hunter2"},
        },
        {"id": "ffeeddccbbaa", "name": "/watchable", "image": "x", "state": "exited", "status": "Exited (1)"},
    ],
    2: [],
}


@pytest.fixture
def calls() -> list[httpx.Request]:
    return []


@pytest.fixture
def make_backend(calls: list[httpx.Request]) -> Callable[..., DockhandBackend]:
    def build(logs: str = "line one\nline two\n", overrides: dict | None = None) -> DockhandBackend:
        overrides = overrides or {}

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            path = request.url.path
            if path in overrides:
                return overrides[path](request)
            if path == "/api/environments":
                return httpx.Response(200, json=ENVIRONMENTS)
            if path == "/api/containers":
                return httpx.Response(200, json=CONTAINERS[int(request.url.params["env"])])
            if path.endswith("/logs"):
                return httpx.Response(200, json={"logs": logs})
            if path.endswith("/inspect"):
                return httpx.Response(200, json=INSPECT)
            return httpx.Response(404, json={"error": "nope"})

        return DockhandBackend("http://dockhand.test", "dh_token", transport=httpx.MockTransport(handler))

    return build


@pytest.fixture
def settings() -> Settings:
    return Settings(dockhand_url="http://dockhand.test", log_max_lines=50, log_max_bytes=2000)


INSPECT = json.loads(
    """
{
  "Id": "a1b2c3d4e5f6a7b8c9",
  "Name": "/buffarr",
  "Created": "2026-10-01T00:00:00Z",
  "RestartCount": 3,
  "State": {"Status": "running", "Running": true, "OOMKilled": false, "ExitCode": 0,
            "Health": {"Status": "healthy", "FailingStreak": 0}},
  "Config": {"Image": "ghcr.io/poag/buffarr:latest",
             "Env": ["TZ=Europe/London", "SONARR_API_KEY=abc123", "DB=postgres://user:pw@db/x"],
             "Labels": {"app": "buffarr", "secret_label": "x"}},
  "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "Memory": 0},
  "NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},
                      "Networks": {"bridge": {}}},
  "Mounts": [{"Source": "/mnt/cache/appdata/buffarr", "Destination": "/config", "RW": true}]
}
"""
)
