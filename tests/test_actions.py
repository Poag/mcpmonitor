from __future__ import annotations

import pytest

from mcpmonitor.actions import ActionRefused, ActionService
from mcpmonitor.config import Settings
from mcpmonitor.kuma import KumaMonitor
from mcpmonitor.store import Store

from .fakes import FakeBackend, FakeKuma


def make(events, *, enable=True, kuma_monitors=None, fail_action=False, fail_resume=False, per_hour=3):
    settings = Settings(
        dockhand_url="http://x",
        enable_actions=enable,
        actions_per_hour=per_hour,
        settle_timeout=1.0,
        settle_grace=0.0,
    )
    store = Store(":memory:")
    backend = FakeBackend(events, fail_action=fail_action)
    monitors = (
        kuma_monitors
        if kuma_monitors is not None
        else [
            KumaMonitor(10, "buffarr web", "http", True),
            KumaMonitor(11, "paused by hand", "http", False),
            KumaMonitor(12, "wan check", "ping", True),
        ]
    )
    kuma = FakeKuma(events, monitors, fail_resume=fail_resume)
    return ActionService(settings, backend, store, kuma), store, backend, kuma


async def setup_policy(store):
    await store.allow("Unraid", "buffarr", ["restart", "stop"])
    await store.set_mapped(10, "buffarr web", [("Unraid", "buffarr")])
    await store.set_mapped(11, "paused by hand", [("Unraid", "buffarr")])
    await store.set_ignored(12, "wan check")


async def test_disabled_by_default():
    svc, *_ = make([], enable=False)
    with pytest.raises(ActionRefused, match="disabled"):
        await svc.run("restart", "Unraid", "buffarr")


async def test_refused_when_not_allowlisted_and_audited():
    events: list[str] = []
    svc, store, *_ = make(events)
    with pytest.raises(ActionRefused, match="not allowed"):
        await svc.run("restart", "Unraid", "buffarr")
    assert events == []  # nothing touched
    audit = await store.recent_audit()
    assert audit[0]["outcome"] == "refused"


async def test_only_allowed_actions():
    svc, store, *_ = make([])
    await store.allow("Unraid", "buffarr", ["restart"])
    with pytest.raises(ActionRefused, match="stop is not allowed"):
        await svc.run("stop", "Unraid", "buffarr")


async def test_unknown_container_refused():
    svc, store, *_ = make([])
    with pytest.raises(ActionRefused, match="no container"):
        await svc.run("restart", "Unraid", "nothing-here")


async def test_dry_run_changes_nothing_and_lists_plan():
    events: list[str] = []
    svc, store, *_ = make(events)
    await setup_policy(store)
    res = await svc.run("restart", "unraid", "BUFFARR", dry_run=True)
    assert res.dry_run and events == []
    assert res.monitors_paused == ["buffarr web"]  # active+mapped only


async def test_pause_action_resume_in_order():
    events: list[str] = []
    svc, store, *_ = make(events)
    await setup_policy(store)
    res = await svc.run("restart", "Unraid", "buffarr", reason="stuck")
    assert events == ["kuma:pause:10", "backend:restart", "kuma:resume:10"]
    assert res.ok and res.final_state == "running"
    assert res.monitors_resumed == ["buffarr web"]
    assert await store.pending_pauses() == []


async def test_user_paused_and_ignored_monitors_untouched():
    events: list[str] = []
    svc, store, *_ = make(events)
    await setup_policy(store)
    await svc.run("restart", "Unraid", "buffarr")
    assert not any(e.endswith(":11") or e.endswith(":12") for e in events)


async def test_monitors_resumed_even_when_action_fails():
    events: list[str] = []
    svc, store, *_ = make(events, fail_action=True)
    await setup_policy(store)
    res = await svc.run("restart", "Unraid", "buffarr")
    assert not res.ok
    assert events == ["kuma:pause:10", "backend:restart", "kuma:resume:10"]
    assert (await store.recent_audit())[0]["outcome"] == "error"


async def test_resume_failure_is_loud_and_kept_for_reconcile():
    events: list[str] = []
    svc, store, backend, kuma = make(events, fail_resume=True)
    await setup_policy(store)
    res = await svc.run("restart", "Unraid", "buffarr")
    assert any("FAILED TO RESUME" in w for w in res.warnings)
    assert [p["monitor_id"] for p in await store.pending_pauses()] == [10]
    kuma.fail_resume = False
    assert await svc.reconcile() == [10]
    assert await store.pending_pauses() == []
    assert kuma.monitors[10].active


async def test_rate_limit():
    events: list[str] = []
    svc, store, *_ = make(events, per_hour=2)
    await store.allow("Unraid", "buffarr", ["restart"])
    await svc.run("restart", "Unraid", "buffarr")
    await svc.run("restart", "Unraid", "buffarr")
    with pytest.raises(ActionRefused, match="rate limit"):
        await svc.run("restart", "Unraid", "buffarr")


async def test_unsettled_container_reported():
    events: list[str] = []
    svc, store, backend, _ = make(events)
    backend.state_after = "restarting"
    await setup_policy(store)
    res = await svc.run("restart", "Unraid", "buffarr")
    assert not res.ok and res.final_state == "restarting"
    assert any("did not settle" in w for w in res.warnings)
    assert events[-1] == "kuma:resume:10"  # still resumed
