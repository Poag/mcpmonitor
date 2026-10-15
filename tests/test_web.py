from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from mcpmonitor.config import Settings
from mcpmonitor.kuma import KumaMonitor
from mcpmonitor.server import build_http_app, build_server
from mcpmonitor.store import Store
from mcpmonitor.suggest import suggest

from .fakes import FakeBackend, FakeKuma


@pytest.fixture
def ui():
    events: list[str] = []
    s = Settings(dockhand_url="http://x", transport="http", auth_token="bearer", ui_password="pw")
    store, backend = Store(":memory:"), FakeBackend(events)
    kuma = FakeKuma(
        events,
        [
            KumaMonitor(10, "buffarr web", "http", True, "http://nas:8080"),
            KumaMonitor(12, "wan", "ping", True, "1.1.1.1"),
        ],
    )
    app = build_http_app(s, build_server(s, backend, store, kuma))
    with TestClient(app, follow_redirects=False) as client:
        yield client, store


def login(client):
    r = client.post("/ui/login", data={"password": "pw"})
    assert r.status_code == 303
    return r


def csrf_of(client) -> str:
    html = client.get("/ui").text
    marker = 'name="csrf" value="'
    return html.split(marker, 1)[1].split('"', 1)[0]


def test_ui_requires_login_but_not_bearer(ui):
    client, _ = ui
    r = client.get("/ui")
    assert r.status_code == 303 and r.headers["location"] == "/ui/login"
    assert client.get("/ui/login").status_code == 200


def test_mcp_endpoint_still_needs_bearer(ui):
    client, _ = ui
    assert client.post("/mcp", json={}).status_code == 401


def test_wrong_password_and_throttle(ui):
    client, _ = ui
    for _ in range(5):
        assert "Wrong password" in client.post("/ui/login", data={"password": "no"}).text
    assert "Too many attempts" in client.post("/ui/login", data={"password": "pw"}).text


def test_cookie_flags(ui):
    client, _ = ui
    header = login(client).headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=strict" in header


def test_ui_disabled_without_password():
    events: list[str] = []
    s = Settings(dockhand_url="http://x", transport="http", auth_token="b")
    app = build_http_app(s, build_server(s, FakeBackend(events), Store(":memory:"), None))
    with TestClient(app, follow_redirects=False) as client:
        assert client.get("/ui").status_code in (401, 404)


async def test_map_ignore_flow(ui):
    client, store = ui
    login(client)
    page = client.get("/ui").text
    assert "buffarr web" in page and "unmapped" in page and "Suggested" in page
    csrf = csrf_of(client)

    r = client.post("/ui/monitors/10/map", data={"csrf": csrf, "name": "buffarr web", "targets": "Unraid|buffarr"})
    assert r.status_code == 303
    r = client.post("/ui/monitors/12/ignore", data={"csrf": csrf, "name": "wan"})
    assert r.status_code == 303

    states = await store.monitor_states()
    assert states[10]["state"] == "mapped" and states[10]["targets"] == [("Unraid", "buffarr")]
    assert states[12]["state"] == "ignored"
    assert "0 unmapped" in client.get("/ui").text


def test_post_without_csrf_rejected(ui):
    client, _ = ui
    login(client)
    r = client.post("/ui/monitors/10/ignore", data={"name": "x"})
    assert r.status_code == 403
    r = client.post("/ui/allowlist/set", data={"csrf": "wrong", "target": "Unraid|buffarr", "actions": "restart"})
    assert r.status_code == 403


def test_post_without_session_redirects(ui):
    client, _ = ui
    r = client.post("/ui/monitors/10/ignore", data={"csrf": "x"})
    assert r.status_code == 303 and r.headers["location"] == "/ui/login"


async def test_allowlist_flow_and_audit(ui):
    client, store = ui
    login(client)
    csrf = csrf_of(client)
    client.post(
        "/ui/allowlist/set",
        data={"csrf": csrf, "target": "Unraid|buffarr", "actions": ["restart", "stop", "bogus"]},
    )
    assert await store.allowed_actions("Unraid", "buffarr") == {"restart", "stop"}
    assert "restart,stop" in client.get("/ui/allowlist").text
    client.post("/ui/allowlist/remove", data={"csrf": csrf, "target": "Unraid|buffarr"})
    assert await store.allowed_actions("Unraid", "buffarr") == set()
    assert "allowlist" in client.get("/ui/audit").text


def test_html_is_escaped(ui):
    client, _ = ui
    login(client)
    client.get("/ui")  # monitors come from the fake; escaping is exercised through suggest/page helpers
    from mcpmonitor.web import _e

    assert _e("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_suggest_matches_names_and_targets():
    from mcpmonitor.backends import ContainerSummary

    cs = [
        ContainerSummary("Unraid", "1", "buffarr", "i", "running", ""),
        ContainerSummary("Unraid", "2", "plex", "i", "running", ""),
    ]
    got = suggest(KumaMonitor(1, "Buffarr web UI", "http", True, "http://nas:8080"), cs)
    assert [c.name for c in got] == ["buffarr"]
    assert suggest(KumaMonitor(2, "WAN", "ping", True, "1.1.1.1"), cs) == []
