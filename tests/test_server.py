from __future__ import annotations

import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcpmonitor.config import ConfigError, Settings
from mcpmonitor.server import build_http_app, build_server


def payload(result):
    if getattr(result, "structured_content", None):
        sc = result.structured_content
        return sc.get("result", sc)
    return json.loads(result.content[0].text)


async def test_tools_registered_and_all_read_only(make_backend, settings):
    mcp = build_server(settings, make_backend())
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == {"list_hosts", "list_containers", "inspect_container", "container_logs"}
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)


async def test_list_containers_filters(make_backend, settings):
    mcp = build_server(settings, make_backend())
    res = await mcp.call_tool("list_containers", {"host": "Unraid", "state": "running"})
    names = [c["name"] for c in payload(res)]
    assert names == ["buffarr"]


async def test_container_logs_filters_redacts_and_labels_untrusted(make_backend, settings):
    logs = "ok\nERROR token=abc123 failed\nok again"
    mcp = build_server(settings, make_backend(logs=logs))
    res = await mcp.call_tool(
        "container_logs", {"host": "Unraid", "container": "buffarr", "pattern": "error"}
    )
    data = payload(res)
    assert data["logs"] == "ERROR token=*** failed"
    assert "untrusted" in data["note"].lower()


async def test_container_logs_clamps_tail(make_backend, settings, calls):
    mcp = build_server(settings, make_backend())
    await mcp.call_tool("container_logs", {"host": "Unraid", "container": "buffarr", "tail": 999999})
    req = [c for c in calls if c.url.path.endswith("/logs")][0]
    assert req.url.params["tail"] == str(settings.log_max_lines)


async def test_bad_regex_is_a_tool_error(make_backend, settings):
    mcp = build_server(settings, make_backend())
    with pytest.raises(ToolError, match="regex"):
        await mcp.call_tool("container_logs", {"host": "Unraid", "container": "b", "pattern": "("})


async def test_unknown_host_is_a_tool_error(make_backend, settings):
    mcp = build_server(settings, make_backend())
    with pytest.raises(ToolError, match="Unknown host"):
        await mcp.call_tool("list_containers", {"host": "nope"})


async def test_inspect_is_summarised_and_redacted(make_backend, settings):
    mcp = build_server(settings, make_backend())
    data = payload(await mcp.call_tool("inspect_container", {"host": "Unraid", "container": "buffarr"}))
    assert data["restart_count"] == 3 and data["state"]["health"] == "healthy"
    assert "SONARR_API_KEY=***" in data["env"]
    assert "DB=postgres://user:***@db/x" in data["env"]
    assert data["labels"]["secret_label"] == "***"
    assert data["mounts"][0]["destination"] == "/config"


def test_http_requires_token():
    with pytest.raises(ConfigError):
        Settings(dockhand_url="http://x", transport="http").validate()


def test_http_auth_middleware(make_backend):
    from starlette.testclient import TestClient

    s = Settings(dockhand_url="http://x", transport="http", auth_token="s3cret")
    app = build_http_app(s, build_server(s, make_backend()))
    with TestClient(app) as client:  # runs the app lifespan
        assert client.get("/healthz").status_code == 200
        assert client.post("/mcp", json={}).status_code == 401
        assert client.post("/mcp", json={}, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.post("/mcp", json={}, headers={"Authorization": "Basic s3cret"}).status_code == 401
        ok = client.post("/mcp", json={}, headers={"Authorization": "Bearer s3cret"})
        assert ok.status_code != 401
