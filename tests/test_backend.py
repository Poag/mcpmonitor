from __future__ import annotations

import httpx
import pytest

from mcpmonitor.backends import BackendError, NotFoundError


async def test_list_hosts(make_backend):
    hosts = await make_backend().list_hosts()
    assert [h.name for h in hosts] == ["Unraid", "PiZero"]
    assert hosts[1].address == "10.0.0.5:2376"


async def test_sends_bearer_token(make_backend, calls):
    await make_backend().list_hosts()
    assert calls[0].headers["authorization"] == "Bearer dh_token"


async def test_host_resolved_by_name_case_insensitive_and_id(make_backend, calls):
    b = make_backend()
    by_name = await b.list_containers("unraid")
    by_id = await b.list_containers("1")
    assert by_name == by_id
    assert by_name[0].name == "buffarr"  # leading slash stripped
    assert by_name[0].id == "a1b2c3d4e5f6"  # shortened
    assert by_name[0].compose_project == "media"
    assert by_name[1].state == "exited"
    container_calls = [c for c in calls if c.url.path == "/api/containers"]
    assert container_calls[0].url.params["env"] == "1"


async def test_environments_cached(make_backend, calls):
    b = make_backend()
    await b.list_containers("Unraid")
    await b.list_containers("Unraid")
    assert sum(1 for c in calls if c.url.path == "/api/environments") == 1


async def test_unknown_host_lists_known_ones(make_backend):
    with pytest.raises(NotFoundError, match="Unraid"):
        await make_backend().list_containers("nope")


async def test_logs_passes_tail_and_since(make_backend, calls):
    text = await make_backend(logs="a\nb").container_logs("Unraid", "buffarr", tail=5, since="10m")
    assert text == "a\nb"
    req = [c for c in calls if c.url.path.endswith("/logs")][0]
    assert req.url.path == "/api/containers/buffarr/logs"
    assert req.url.params["tail"] == "5" and req.url.params["since"] == "10m"
    assert req.url.params["env"] == "1"


async def test_container_reference_is_one_path_segment(make_backend):
    b = make_backend()
    with pytest.raises(BackendError):
        await b.container_logs("Unraid", "../../etc")
    with pytest.raises(BackendError):
        await b.container_logs("Unraid", "  ")


async def test_forbidden_is_a_backend_error(make_backend):
    b = make_backend(
        overrides={"/api/environments": lambda r: httpx.Response(403, json={"error": "Permission denied"})}
    )
    with pytest.raises(BackendError, match="403"):
        await b.list_hosts()


async def test_unreachable_is_a_backend_error():
    from mcpmonitor.backends.dockhand import DockhandBackend

    def boom(request):
        raise httpx.ConnectError("refused")

    b = DockhandBackend("http://x.test", transport=httpx.MockTransport(boom))
    with pytest.raises(BackendError, match="unreachable"):
        await b.list_hosts()
