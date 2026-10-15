from __future__ import annotations

import time

import pytest
from starlette.testclient import TestClient

from mcpmonitor import notify as notify_mod
from mcpmonitor.config import Settings
from mcpmonitor.faults import FaultService, FaultStore
from mcpmonitor.notify import Notifier, NotifyStore
from mcpmonitor.rules import RuleEngine
from mcpmonitor.server import build_http_app, build_server
from mcpmonitor.store import Store
from mcpmonitor.syslog_parse import parse

from .fakes import FakeBackend
from .test_server import payload


@pytest.fixture
def env():
    s = Settings(dockhand_url="http://x", transport="http", auth_token="b", ui_password="pw")
    store = Store(":memory:")
    fs, ns = FaultStore(store), None
    ns = NotifyStore(store)
    svc = FaultService(fs, RuleEngine(), Notifier(ns, store))
    mcp = build_server(s, FakeBackend([]), store, None, None, svc, ns, svc.notify)
    return s, store, svc, ns, mcp


async def seed(svc):
    now = time.time()
    await svc.ingest(
        [
            (
                now,
                parse("<4>Oct 15 17:00:00 Tower kernel: blk_update_request: I/O error, dev sdb, sector 5", "10.0.0.9"),
            ),
            (now, parse("<14>Oct 15 17:00:00 Tower myapp: weird failure code 12 token=abc123", "10.0.0.9")),
        ]
    )


async def test_fault_tools(env):
    s, store, svc, ns, mcp = env
    await seed(svc)
    tools = {t.name for t in await mcp.list_tools()}
    assert {"list_faults", "hardware_health", "search_syslog", "list_alert_targets"} <= tools

    faults = payload(await mcp.call_tool("list_faults", {"category": "disk"}))
    assert faults[0]["host"] == "Tower" and faults[0]["severity"] == "critical"

    health = payload(await mcp.call_tool("hardware_health", {}))
    assert health["hosts"][0]["open_faults"] == {"disk": 1} and health["hosts"][0]["worst"] == "critical"

    found = payload(await mcp.call_tool("search_syslog", {"pattern": "weird failure"}))
    assert "token=***" in found["logs"] and "abc123" not in found["logs"]
    assert "untrusted" in found["note"].lower()


async def test_alert_targets_never_expose_urls(env):
    _, _, _, ns, mcp = env
    await ns.add("discord", "json://user:supersecret@host/path", "warning")
    out = str(payload(await mcp.call_tool("list_alert_targets", {})))
    assert "supersecret" not in out and "json://***" in out


async def test_ui_pages(env, monkeypatch):
    s, store, svc, ns, mcp = env
    await seed(svc)
    sent = []

    async def fake_send(url, title, body, severity):
        sent.append(title)
        return True

    monkeypatch.setattr(notify_mod, "send", fake_send)
    app = build_http_app(s, mcp)
    with TestClient(app, follow_redirects=False) as c:
        assert c.get("/ui/faults").status_code == 303  # needs login
        c.post("/ui/login", data={"password": "pw"})
        page = c.get("/ui/faults").text
        assert "Disk I/O error" in page and "Tower" in page
        csrf = page.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        fid = (await svc.faults.list_faults(since=0))[0]["id"]

        assert c.post(f"/ui/faults/{fid}/ack", data={"csrf": "bad"}).status_code == 403
        c.post(f"/ui/faults/{fid}/ack", data={"csrf": csrf})
        assert await svc.faults.list_faults(since=0, status="acked")

        patterns = c.get("/ui/patterns").text
        assert (
            "weird failure code" in patterns and "dev sdb, sector" not in patterns
        )  # lines matched by a rule are hidden

        prev = c.post(
            "/ui/rules/preview",
            data={
                "csrf": csrf,
                "pattern": r"weird failure code \d+",
                "category": "other",
                "severity": "warning",
                "threshold": "1",
                "window": "600",
                "title": "Weird",
            },
        )
        assert "matched <b>1</b>" in prev.text
        rid = prev.text.split("name=id value='", 1)[1].split("'", 1)[0]
        c.post(
            "/ui/rules/save",
            data={
                "csrf": csrf,
                "id": rid,
                "pattern": r"weird failure code \d+",
                "category": "other",
                "severity": "warning",
                "threshold": "1",
                "window": "600",
                "title": "Weird",
            },
        )
        assert rid in c.get("/ui/patterns").text
        bad = c.post(
            "/ui/rules/preview", data={"csrf": csrf, "pattern": "(", "category": "other", "severity": "warning"}
        )
        assert "Invalid pattern" in bad.text
        c.post("/ui/rules/delete", data={"csrf": csrf, "id": rid})
        assert not await svc.faults.custom_rules()

        c.post(
            "/ui/notify/add",
            data={"csrf": csrf, "name": "hook", "url": "json://a.example/x", "min_severity": "warning"},
        )
        notify_page = c.get("/ui/notify").text
        assert "hook" in notify_page and "json://***" in notify_page and "a.example" not in notify_page
        tid = (await ns.list())[0].id
        r = c.post("/ui/notify/test", data={"csrf": csrf, "id": str(tid)})
        assert "Test%20sent" in r.headers["location"] and sent == ["mcpmonitor test"]
        r = c.post("/ui/notify/add", data={"csrf": csrf, "name": "bad", "url": "nonsense", "min_severity": "warning"})
        assert "valid" in r.headers["location"].lower()
        c.post("/ui/notify/remove", data={"csrf": csrf, "id": str(tid)})
        assert await ns.list() == []
