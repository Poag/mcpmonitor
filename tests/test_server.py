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
    assert {t.name for t in tools} == {
        "list_hosts",
        "list_containers",
        "inspect_container",
        "container_logs",
        "check_updates",
    }
    # everything but check_updates (which refreshes Dockhand's own cache) is strictly read-only
    assert all(t.annotations and t.annotations.read_only_hint for t in tools if t.name != "check_updates")
    check = next(t for t in tools if t.name == "check_updates")
    assert check.annotations.destructive_hint is False


async def test_list_containers_filters(make_backend, settings):
    mcp = build_server(settings, make_backend())
    res = await mcp.call_tool("list_containers", {"host": "Unraid", "state": "running"})
    names = [c["name"] for c in payload(res)]
    assert names == ["buffarr"]


async def test_container_logs_filters_redacts_and_labels_untrusted(make_backend, settings):
    logs = "ok\nERROR token=abc123 failed\nok again"
    mcp = build_server(settings, make_backend(logs=logs))
    res = await mcp.call_tool("container_logs", {"host": "Unraid", "container": "buffarr", "pattern": "error"})
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


async def test_action_and_kuma_tools_hidden_unless_enabled(make_backend, settings):
    mcp = build_server(settings, make_backend())
    names = {t.name for t in await mcp.list_tools()}
    assert not names & {"restart_container", "list_monitors", "recent_audit"}


async def test_action_tools_registered_when_enabled(make_backend):
    from mcpmonitor.actions import ActionService
    from mcpmonitor.store import Store

    from .fakes import FakeBackend, FakeKuma

    s = Settings(dockhand_url="http://x", enable_actions=True, settle_grace=0, settle_timeout=1)
    events: list[str] = []
    store, backend = Store(":memory:"), FakeBackend(events)
    kuma = FakeKuma(events, [])
    mcp = build_server(s, backend, store, kuma, ActionService(s, backend, store, kuma))
    tools = {t.name: t for t in await mcp.list_tools()}
    for name in ("restart_container", "start_container", "stop_container"):
        assert tools[name].annotations.destructive_hint is True
    assert {"list_monitors", "monitor_history", "diagnose_monitor", "recent_audit"} <= set(tools)
    with pytest.raises(ToolError, match="not allowed"):
        await mcp.call_tool("restart_container", {"host": "Unraid", "container": "buffarr"})


async def test_diagnose_monitor_joins_kuma_and_container_evidence():
    from mcpmonitor.kuma import KumaMonitor
    from mcpmonitor.store import Store

    from .fakes import FakeBackend, FakeKuma

    s = Settings(dockhand_url="http://x")
    events: list[str] = []
    store, backend = Store(":memory:"), FakeBackend(events)
    await store.set_mapped(10, "web", [("Unraid", "buffarr")])
    kuma = FakeKuma(events, [KumaMonitor(10, "web", "http", True)])
    mcp = build_server(s, backend, store, kuma)
    data = payload(await mcp.call_tool("diagnose_monitor", {"monitor_id": 10}))
    assert data["history"]["changes"][-1]["status"] == "down"
    assert "token=***" in data["history"]["changes"][-1]["msg"]
    c = data["containers"][0]
    assert c["inspect"]["restart_count"] == 2
    assert "connection refused" in c["error_like_logs"]["logs"]
    listed = payload(await mcp.call_tool("list_monitors", {}))
    assert listed[0]["mapping"] == "mapped" and listed[0]["status"] == "down"


async def test_check_updates_tool_hides_management_containers(make_backend, settings):
    from .fakes import FakeBackend

    mcp = build_server(settings, FakeBackend([]))
    data = payload(await mcp.call_tool("check_updates", {"host": "Unraid"}))
    assert [d["container"] for d in data] == ["buffarr"]
    assert data[0]["update_available"] is True
