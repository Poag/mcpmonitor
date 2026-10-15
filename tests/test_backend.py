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


async def test_update_uses_batch_update_with_full_id(make_backend, calls):
    import json

    def batch(request):
        body = json.loads(request.content)
        assert body == {"containerIds": ["a1b2c3d4e5f6a7b8"]}
        return httpx.Response(200, json={"success": True, "results": [{"containerId": "x", "success": True}]})

    b = make_backend(overrides={"/api/containers/batch-update": batch})
    await b.container_action("Unraid", "BUFFARR", "update")
    req = [c for c in calls if c.url.path == "/api/containers/batch-update"][0]
    assert req.method == "POST" and req.url.params["env"] == "1"


@pytest.mark.parametrize(
    "results,match",
    [
        ([{"success": False, "error": "Pull failed: denied"}], "Pull failed"),
        ([{"success": True, "error": "Skipped (dockhand.update=false)"}], "skipped"),
        ([], "Unexpected"),
    ],
)
async def test_update_failures_become_backend_errors(make_backend, results, match):
    b = make_backend(
        overrides={
            "/api/containers/batch-update": lambda r: httpx.Response(200, json={"success": False, "results": results})
        }
    )
    with pytest.raises(BackendError, match=match):
        await b.container_action("Unraid", "buffarr", "update")


async def test_update_unknown_container(make_backend):
    with pytest.raises(NotFoundError):
        await make_backend().container_action("Unraid", "ghost", "update")


async def test_check_updates_refresh_and_cached(make_backend, calls):
    refreshed = {
        "total": 2,
        "updatesFound": 1,
        "results": [
            {
                "containerName": "buffarr",
                "imageName": "ghcr.io/poag/buffarr:latest",
                "hasUpdate": True,
                "currentDigest": "sha256:aaaaaaaaaaaaaaaa",
                "newDigest": "sha256:bbbbbbbbbbbbbbbb",
                "newerVersion": {"tag": "1.2.0"},
            },
            {"containerName": "plex", "imageName": "plex", "hasUpdate": False},
        ],
    }
    cached = {"environmentId": 1, "pendingUpdates": [{"containerName": "buffarr", "currentImage": "x:latest"}]}
    b = make_backend(
        overrides={
            "/api/containers/check-updates": lambda r: httpx.Response(
                200, json=refreshed if r.method == "POST" else cached
            )
        }
    )
    fresh = await b.check_updates("Unraid", refresh=True)
    assert [(u.container, u.newer_version) for u in fresh] == [("buffarr", "1.2.0")]
    assert (await b.check_updates("Unraid"))[0].image == "x:latest"
    assert {c.method for c in calls if c.url.path.endswith("check-updates")} == {"POST", "GET"}
