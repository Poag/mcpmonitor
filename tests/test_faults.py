from __future__ import annotations

import asyncio
import ipaddress
import socket
import time

import pytest
from starlette.testclient import TestClient

from mcpmonitor import notify as notify_mod
from mcpmonitor.config import ConfigError, Settings
from mcpmonitor.faults import FaultService, FaultStore
from mcpmonitor.ingest import check_silence, classify
from mcpmonitor.notify import Notifier, NotifyStore, mask_url
from mcpmonitor.rules import DEFAULT_RULES, RuleEngine
from mcpmonitor.server import build_http_app, build_server
from mcpmonitor.store import Store
from mcpmonitor.syslog_parse import parse, template_of
from mcpmonitor.syslog_server import SyslogReceiver, parse_allow

from .fakes import FakeBackend


def make_service(notify=None):
    store = Store(":memory:")
    fs = FaultStore(store)
    return store, FaultService(fs, RuleEngine(), notify)


# -- parsing ---------------------------------------------------------------------------------------------


def test_parse_rfc3164_kernel_line():
    m = parse("<4>Oct 15 17:00:00 Tower kernel: blk_update_request: I/O error, dev sdb", "10.0.0.9")
    assert (m.host, m.program, m.facility, m.severity) == ("Tower", "kernel", "kern", "warning")
    assert m.message.startswith("blk_update_request")


def test_parse_rfc5424():
    m = parse("<11>1 2026-10-15T17:00:00Z tower smartd 123 - - Device: /dev/sdb FAILED", "10.0.0.9")
    assert (m.host, m.program, m.severity) == ("tower", "smartd", "err")


def test_parse_garbage_falls_back_to_sender():
    m = parse("just some text", "10.0.0.9")
    assert m.host == "10.0.0.9" and m.message == "just some text"


def test_template_collapses_variables():
    a = template_of("kernel", "[ 123.456] blk_update_request: I/O error, dev sdb, sector 12345 op 0x0")
    b = template_of("kernel", "[ 999.100] blk_update_request: I/O error, dev sdb, sector 777 op 0x1")
    assert a == b


# -- rules -----------------------------------------------------------------------------------------------

SAMPLES = {
    "disk-io-error": "kernel: blk_update_request: I/O error, dev sdb, sector 1 op 0x0:(READ)",
    "disk-ata-error": "kernel: ata3.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x0",
    "fs-xfs": "kernel: XFS (md1): metadata I/O error in xfs_buf_ioend",
    "mem-oom": "kernel: Out of memory: Killed process 1234 (java)",
    "net-watchdog": "kernel: NETDEV WATCHDOG: eth0 (r8169): transmit queue 0 timed out",
    "net-link-down": "kernel: r8169 0000:02:00.0 eth0: Link is Down",
    "hw-mce": "kernel: mce: [Hardware Error]: Machine check events logged",
}


@pytest.mark.parametrize("rule_id,line", SAMPLES.items())
def test_default_rules_match_samples(rule_id, line):
    got = {m.rule.id for m in RuleEngine().evaluate("tower", line)}
    assert rule_id in got


def test_default_rule_ids_unique_and_valid():
    ids = [r.id for r in DEFAULT_RULES]
    assert len(ids) == len(set(ids))
    for r in DEFAULT_RULES:
        r.compiled()


def test_threshold_and_window():
    eng = RuleEngine()
    line = "kernel: ata2: hard resetting link"
    assert eng.evaluate("t", line, now=0) == []
    assert eng.evaluate("t", line, now=10) == []
    assert [m.rule.id for m in eng.evaluate("t", line, now=20)] == ["disk-ata-reset"]
    eng2 = RuleEngine()
    eng2.evaluate("t", line, now=0)
    eng2.evaluate("t", line, now=10)
    assert eng2.evaluate("t", line, now=2000) == []  # earlier hits aged out of the 900s window


def test_thresholds_are_per_host():
    eng = RuleEngine()
    line = "kernel: ata2: hard resetting link"
    for i in range(2):
        eng.evaluate("a", line, now=i)
    assert eng.evaluate("b", line, now=3) == []


def test_normal_lines_do_not_match():
    eng = RuleEngine()
    for line in ("sshd: Accepted publickey for root", "crond: running job", "kernel: eth0: Link is Up 1000Mbps"):
        assert not [m for m in eng.evaluate("t", line) if m.rule.id != "net-link-flap"]


# -- service ---------------------------------------------------------------------------------------------


async def test_ingest_records_fault_notifies_once_and_extends():
    sent = []

    async def notify(ev):
        sent.append(ev)

    store, svc = make_service(notify)
    msg = parse("<4>Oct 15 17:00:00 Tower kernel: blk_update_request: I/O error, dev sdb", "10.0.0.9")
    now = time.time()
    await svc.ingest([(now, msg)])
    await svc.ingest([(now + 5, msg)])
    faults = await svc.faults.list_faults(since=0)
    assert len(faults) == 1 and faults[0]["count"] == 2 and faults[0]["category"] == "disk"
    assert len(sent) == 1 and sent[0].is_new  # second match did not re-alert
    assert faults[0]["notified_at"] is not None


async def test_failing_notifier_does_not_lose_the_fault():
    async def notify(ev):
        raise RuntimeError("discord down")

    _, svc = make_service(notify)
    await svc.ingest([(time.time(), parse("<4>kernel: Out of memory: Killed process 1 (x)", "h"))])
    assert len(await svc.faults.list_faults(since=0)) == 1


async def test_lines_hosts_and_search_stored():
    _, svc = make_service()
    now = time.time()
    await svc.ingest(
        [
            (now, parse("<14>Oct 15 17:00:00 Tower sshd[1]: hello", "h")),
            (now, parse("<3>Oct 15 17:00:00 Tower app: bad", "h")),
        ]
    )
    assert [h["host"] for h in await svc.faults.hosts()] == ["Tower"]
    rows = await svc.faults.search_lines(host="tower", since=0, min_severity="err", limit=10)
    assert [r["message"] for r in rows] == ["bad"]


async def test_prune_by_age_and_rows():
    _, svc = make_service()
    old = time.time() - 40 * 86400
    await svc.faults.add_lines(
        [
            (old, parse("<14>x: old", "h")),
            (time.time(), parse("<14>x: new1", "h")),
            (time.time(), parse("<14>x: new2", "h")),
        ]
    )
    await svc.faults.prune(max_age_days=14, max_rows=1)
    rows = await svc.faults.search_lines(host=None, since=0, min_severity=None, limit=10)
    assert [r["message"] for r in rows] == ["new2"]


async def test_custom_rule_learning_flow():
    _, svc = make_service()
    now = time.time()
    await svc.ingest([(now, parse("<14>myapp: weird failure code 77", "h"))])
    n, examples = await svc.faults.replay_count(r"weird failure code \d+", since=0)
    assert n == 1 and "weird failure" in examples[0]
    await svc.faults.save_custom_rule(
        {
            "id": "custom-1",
            "category": "other",
            "severity": "warning",
            "pattern": r"weird failure code \d+",
            "title": "Weird",
            "threshold": 1,
            "window": 600,
            "enabled": 1,
        }
    )
    await svc.reload_rules()
    events = await svc.ingest([(now + 1, parse("<14>myapp: weird failure code 78", "h"))])
    assert [e.title for e in events] == ["Weird"]
    with pytest.raises(ValueError):
        await svc.faults.save_custom_rule(
            {
                "id": "x",
                "category": "bogus",
                "severity": "warning",
                "pattern": "x",
                "title": "x",
                "threshold": 1,
                "window": 1,
                "enabled": 1,
            }
        )


# -- unraid ingest ---------------------------------------------------------------------------------------


def test_classify_unraid():
    assert classify({"subject": "Disk 3 in error state (disk SMART)", "importance": "alert"})[:2] == (
        "disk",
        "critical",
    )
    assert classify({"event": "Array has 1 disk with read errors", "importance": "warning"})[1] == "warning"
    assert classify({"subject": "Parity check finished", "importance": "normal"})[1] == "info"
    assert classify({})[1] == "warning"  # unknown importance is treated as worth looking at
    a = classify({"event": "Disk SMART health", "subject": "x"})[2]
    assert a == classify({"event": "Disk SMART health", "subject": "y"})[2]  # same kind, same rule id: dedupes


def make_client(token="ingest-secret"):
    s = Settings(dockhand_url="http://x", transport="http", auth_token="b", ingest_token=token)
    store = Store(":memory:")
    fs = FaultStore(store)
    svc = FaultService(fs, RuleEngine())
    app = build_http_app(s, build_server(s, FakeBackend([]), store, None, None, svc))
    return TestClient(app), svc


def test_ingest_endpoint_auth_and_flow():
    client, svc = make_client()
    with client:
        assert client.post("/ingest/unraid", json={}).status_code == 401
        assert client.post("/ingest/unraid", json={}, headers={"Authorization": "Bearer nope"}).status_code == 401
        h = {"Authorization": "Bearer ingest-secret"}
        assert client.post("/ingest/unraid", content="not json", headers=h).status_code == 400
        assert client.post("/ingest/unraid", json=[1], headers=h).status_code == 400
        r = client.post(
            "/ingest/unraid",
            json={
                "host": "Tower",
                "event": "SMART health",
                "subject": "Disk 2 SMART error",
                "importance": "alert",
                "description": "token=abc123 pending sectors",
            },
            headers=h,
        )
        assert r.status_code == 200 and r.json()["severity"] == "critical" and r.json()["fault_id"]
        info = client.post(
            "/ingest/unraid",
            json={"host": "Tower", "subject": "Parity check started", "importance": "normal"},
            headers=h,
        )
        assert info.json()["fault_id"] is None


def test_ingest_disabled_without_token():
    client, _ = make_client(token="")
    with client:
        assert client.post("/ingest/unraid", json={}).status_code in (401, 404)


# -- watchdog --------------------------------------------------------------------------------------------


async def test_silence_raises_then_resolves():
    _, svc = make_service()
    now = time.time()
    await svc.faults.add_lines([(now - 7200, parse("<14>x: hi", "tower"))])
    assert await check_silence(svc, {"tower": 30}, now=now) == ["tower"]
    assert await check_silence(svc, {"tower": 30}, now=now + 60) == ["tower"]
    faults = await svc.faults.list_faults(since=0)
    assert len(faults) == 1 and faults[0]["rule"] == "host-silent"
    await svc.faults.add_lines([(now + 120, parse("<14>x: back", "tower"))])
    assert await check_silence(svc, {"tower": 30}, now=now + 130) == []
    assert (await svc.faults.list_faults(since=0))[0]["status"] == "resolved"


# -- receiver --------------------------------------------------------------------------------------------


def test_receiver_requires_allowlist():
    _, svc = make_service()
    with pytest.raises(ValueError):
        SyslogReceiver(svc, [], port=0)


def test_config_requires_allowlist_for_syslog():
    with pytest.raises(ConfigError):
        Settings(dockhand_url="http://x", syslog_port=5514).validate()
    with pytest.raises(ConfigError):
        Settings(dockhand_url="http://x", syslog_port=5514, syslog_allow="not-an-ip").validate()
    Settings(dockhand_url="http://x", syslog_port=5514, syslog_allow="10.0.0.0/24").validate()


async def test_receiver_filters_senders_and_rate_limits():
    _, svc = make_service()
    r = SyslogReceiver(svc, parse_allow("10.0.0.0/24"), port=0, rate_per_sec=2)
    assert r.accept("<14>x: a", "10.0.0.5") and r.accept("<14>x: b", "10.0.0.5")
    assert not r.accept("<14>x: c", "10.0.0.5")  # bucket empty
    assert not r.accept("<14>x: d", "192.168.1.1")
    assert not r.accept("<14>x: d", "not-an-ip")
    assert (r.stats.received, r.stats.rate_dropped, r.stats.rejected) == (2, 1, 2)
    await r.flush()
    assert len(await svc.faults.search_lines(host=None, since=0, min_severity=None, limit=10)) == 2


async def test_receiver_udp_and_tcp_end_to_end():
    _, svc = make_service()
    r = SyslogReceiver(svc, [ipaddress.ip_network("127.0.0.0/8")], port=0, host="127.0.0.1", flush_interval=0.05)
    await r.start()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(
            b"<4>Oct 15 17:00:00 Tower kernel: blk_update_request: I/O error, dev sdb", ("127.0.0.1", r.udp_port)
        )
        sock.close()
        reader, writer = await asyncio.open_connection("127.0.0.1", r.tcp_port)
        writer.write(b"<14>Oct 15 17:00:01 Tower sshd[9]: tcp line\n")
        await writer.drain()
        writer.close()
        for _ in range(60):
            await asyncio.sleep(0.05)
            if len(await svc.faults.search_lines(host=None, since=0, min_severity=None, limit=10)) >= 2:
                break
        msgs = {x["message"] for x in await svc.faults.search_lines(host=None, since=0, min_severity=None, limit=10)}
        assert any("tcp line" in m for m in msgs) and any("I/O error" in m for m in msgs)
        assert (await svc.faults.list_faults(since=0))[0]["category"] == "disk"
    finally:
        await r.stop()


# -- notify ----------------------------------------------------------------------------------------------


def test_mask_url_hides_everything_but_scheme():
    assert mask_url("discord://123/secrettoken") == "discord://***"
    assert "secret" not in mask_url("tgram://bottoken/chatid")


async def test_notifier_routes_by_severity_and_category(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def fake_send(url, title, body, severity):
        sent.append((url, title))
        return True

    monkeypatch.setattr(notify_mod, "send", fake_send)
    store, svc = make_service()
    ns = NotifyStore(store)
    await ns.add("all", "json://a/", "warning")
    await ns.add("disk-only", "json://b/", "critical", ["disk"])
    notifier = Notifier(ns, store)
    svc.notify = notifier

    await svc.ingest([(time.time(), parse("<4>kernel: Out of memory: Killed process 1 (x)", "h"))])  # warning, memory
    assert [u for u, _ in sent] == ["json://a/"]
    sent.clear()
    await svc.ingest([(time.time(), parse("<4>kernel: blk_update_request: I/O error, dev sdb", "h"))])  # critical, disk
    assert sorted(u for u, _ in sent) == ["json://a/", "json://b/"]
    assert "[CRITICAL] disk on h" in sent[0][1]


async def test_notifier_failure_is_audited(monkeypatch):
    async def fail(*a, **k):
        return False

    monkeypatch.setattr(notify_mod, "send", fail)
    store, svc = make_service()
    ns = NotifyStore(store)
    await ns.add("x", "json://a/", "info")
    svc.notify = Notifier(ns, store)
    await svc.ingest([(time.time(), parse("<4>kernel: Out of memory: Killed process 1 (x)", "h"))])
    assert (await store.recent_audit())[0]["tool"] == "notify"


async def test_notify_store_validates_urls():
    store = Store(":memory:")
    ns = NotifyStore(store)
    with pytest.raises(ValueError):
        await ns.add("bad", "definitely not a url")
    with pytest.raises(ValueError):
        await ns.add("bad", "json://a/", "extreme")
