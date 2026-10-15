"""Small server-rendered admin UI: map or ignore Uptime Kuma monitors, manage the action allowlist.

Authentication is a single password (MCPM_UI_PASSWORD) giving a signed, expiring, HttpOnly, SameSite=Strict
cookie. State-changing forms carry a CSRF token derived from the session. The UI is disabled when no
password is set. It changes what the agent is allowed to do, so keep it on the LAN.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import time
from collections import defaultdict
from typing import Any
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .backends import Backend, BackendError, ContainerSummary
from .config import Settings
from .kuma import KumaClient, KumaError
from .store import ACTIONS, Store
from .suggest import suggest

COOKIE = "mcpm_session"
SESSION_SECONDS = 12 * 3600

STYLE = """
:root{--bg:#fff;--fg:#1c1f24;--mut:#667;--line:#d8dce2;--card:#f6f7f9;--acc:#2f6fed;--bad:#c0392b;--ok:#1f8a4c}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e6e8eb;--mut:#9aa3ad;--line:#2b3037;--card:#1c1f25;--acc:#6b9bff;--bad:#ff7a6b;--ok:#52c47f}}
*{box-sizing:border-box}body{margin:0 auto;max-width:1100px;padding:16px;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
nav{display:flex;gap:16px;align-items:center;margin-bottom:16px;flex-wrap:wrap}nav a{color:var(--acc);text-decoration:none}nav form{margin-left:auto}
h1{font-size:1.3rem;margin:.2rem 0 1rem}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:.85rem}.tag{padding:1px 8px;border-radius:10px;background:var(--card);border:1px solid var(--line);font-size:.8rem}
.mapped{color:var(--ok)}.unmapped{color:var(--bad)}.ignored{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);padding:12px;border-radius:8px;margin-bottom:16px}
button,select,input{font:inherit;padding:4px 8px;border-radius:6px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}button{cursor:pointer}
.warn{border-left:4px solid var(--bad)}.mut{color:var(--mut)}details summary{cursor:pointer;color:var(--acc)}select[multiple]{min-width:240px}
@media (max-width:700px){th:nth-child(3),td:nth-child(3){display:none}}
"""


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


class Auth:
    def __init__(self, password: str, secret_extra: str = "") -> None:
        self._key = hashlib.sha256(f"mcpm-ui|{password}|{secret_extra}".encode()).digest()
        self._password = password
        self._fails: dict[str, list[float]] = defaultdict(list)

    def check_password(self, supplied: str) -> bool:
        return hmac.compare_digest(supplied.encode(), self._password.encode())

    def throttled(self, ip: str) -> bool:
        now = time.time()
        self._fails[ip] = [t for t in self._fails[ip] if now - t < 60]
        return len(self._fails[ip]) >= 5

    def record_failure(self, ip: str) -> None:
        self._fails[ip].append(time.time())

    def _sig(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def new_session(self) -> str:
        issued = str(int(time.time()))
        return f"{issued}.{self._sig(issued)}"

    def valid_session(self, cookie: str | None) -> bool:
        if not cookie or "." not in cookie:
            return False
        issued, _, sig = cookie.partition(".")
        if not hmac.compare_digest(sig, self._sig(issued)):
            return False
        try:
            return time.time() - int(issued) < SESSION_SECONDS
        except ValueError:
            return False

    def csrf(self, cookie: str) -> str:
        return self._sig("csrf|" + cookie)[:32]


def register_ui(
    mcp: MCPServer,
    settings: Settings,
    backend: Backend,
    store: Store,
    kuma: KumaClient | None,
    faults: Any = None,  # FaultService | None
    notifier: Any = None,  # Notifier | None
    notify_store: Any = None,  # NotifyStore | None
) -> None:
    auth = Auth(settings.ui_password, settings.auth_token)

    def session(request: Request) -> str | None:
        cookie = request.cookies.get(COOKIE)
        return cookie if auth.valid_session(cookie) else None

    def login_redirect() -> Response:
        return RedirectResponse("/ui/login", status_code=303)

    def page(title: str, body: str, cookie: str | None, flash: str = "") -> HTMLResponse:
        nav = ""
        if cookie:
            nav = (
                '<nav><a href="/ui">Monitors</a><a href="/ui/allowlist">Allowlist</a>'
                '<a href="/ui/faults">Faults</a><a href="/ui/patterns">Log patterns</a>'
                '<a href="/ui/notify">Alerts</a><a href="/ui/faults">Faults</a><a href="/ui/patterns">Log patterns</a><a href="/ui/notify">Alerts</a><a href="/ui/audit">Audit</a>'
                f'<form method="post" action="/ui/logout"><input type="hidden" name="csrf" value="{auth.csrf(cookie)}">'
                "<button>Log out</button></form></nav>"
            )
        banner = f'<div class="card">{_e(flash)}</div>' if flash else ""
        doc = (
            f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{_e(title)} - mcpmonitor</title><style>{STYLE}</style></head><body>{nav}{banner}"
            f"<h1>{_e(title)}</h1>{body}</body></html>"
        )
        return HTMLResponse(
            doc,
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
            },
        )

    async def form(request: Request) -> tuple[Any, str | None]:
        """Parsed form if the session and CSRF token are valid, else (None, None)."""
        cookie = session(request)
        if not cookie:
            return None, None
        data = await request.form()
        if not hmac.compare_digest(str(data.get("csrf", "")), auth.csrf(cookie)):
            return None, cookie
        return data, cookie

    async def all_containers() -> tuple[list[ContainerSummary], list[str]]:
        containers: list[ContainerSummary] = []
        problems: list[str] = []
        try:
            hosts = await backend.list_hosts()
        except BackendError as exc:
            return [], [str(exc)]
        for h in hosts:
            try:
                containers += await backend.list_containers(h.name)
            except BackendError as exc:
                problems.append(f"{h.name}: {exc}")
        return containers, problems

    # -- login ---------------------------------------------------------------------------------------

    @mcp.custom_route("/ui/login", methods=["GET", "POST"])
    async def login(request: Request) -> Response:
        if request.method == "GET":
            body = (
                '<form method="post"><p><input type="password" name="password" autofocus placeholder="Password" '
                "required> <button>Log in</button></p></form>"
            )
            return page("Log in", body, None)
        ip = request.client.host if request.client else "?"
        if auth.throttled(ip):
            return page("Log in", "<p>Too many attempts. Wait a minute.</p>", None)
        data = await request.form()
        if auth.check_password(str(data.get("password", ""))):
            resp = RedirectResponse("/ui", status_code=303)
            resp.set_cookie(
                COOKIE,
                auth.new_session(),
                max_age=SESSION_SECONDS,
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https",
            )
            return resp
        auth.record_failure(ip)
        return page("Log in", '<p class="unmapped">Wrong password.</p>', None)

    @mcp.custom_route("/ui/logout", methods=["POST"])
    async def logout(request: Request) -> Response:
        resp = RedirectResponse("/ui/login", status_code=303)
        resp.delete_cookie(COOKIE)
        return resp

    # -- monitors ------------------------------------------------------------------------------------

    @mcp.custom_route("/ui", methods=["GET"])
    async def monitors_page(request: Request) -> Response:
        cookie = session(request)
        if not cookie:
            return login_redirect()
        if kuma is None:
            return page("Monitors", "<p>Uptime Kuma is not configured (MCPM_KUMA_URL).</p>", cookie)
        flash = request.query_params.get("msg", "")
        try:
            monitors = await kuma.list_monitors()
        except KumaError as exc:
            return page("Monitors", f'<p class="unmapped">{_e(exc)}</p>', cookie)
        containers, problems = await all_containers()
        states = await store.monitor_states()
        csrf = auth.csrf(cookie)

        def options_for(selected: set[str]) -> str:
            return "".join(
                f'<option value="{_e(c.host)}|{_e(c.name)}"'
                f"{' selected' if f'{c.host}|{c.name}'.lower() in selected else ''}>"
                f"{_e(c.host)} / {_e(c.name)}</option>"
                for c in containers
            )

        unmapped = [m for m in monitors if m.id not in states]
        rows = []
        for m in sorted(monitors, key=lambda m: (m.id in states, m.name.lower())):
            st = states.get(m.id)
            state = st["state"] if st else "unmapped"
            current = ", ".join(f"{_e(h)} / {_e(c)}" for h, c in (st["targets"] if st else [])) or "-"
            hint = ""
            selected = {f"{h}|{c}".lower() for h, c in (st["targets"] if st else [])}
            if state == "unmapped":
                sugg = suggest(m, containers)
                if sugg:
                    hint = (
                        '<div class="mut">Suggested: '
                        + ", ".join(
                            f"<form style='display:inline' method=post action='/ui/monitors/{m.id}/map'>"
                            f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=name value='{_e(m.name)}'>"
                            f"<input type=hidden name=targets value='{_e(c.host)}|{_e(c.name)}'>"
                            f"<button>{_e(c.host)} / {_e(c.name)}</button></form>"
                            for c in sugg
                        )
                        + "</div>"
                    )
            rows.append(
                f"<tr><td><b>{_e(m.name)}</b><div class='mut'>{_e(m.type)} {_e(m.target)}"
                f"{'' if m.active else ' (paused)'}</div></td>"
                f"<td><span class='tag {state}'>{state}</span></td><td>{current}{hint}</td>"
                f"<td><details><summary>Edit</summary>"
                f"<form method=post action='/ui/monitors/{m.id}/map'><input type=hidden name=csrf value='{csrf}'>"
                f"<input type=hidden name=name value='{_e(m.name)}'>"
                f"<select name=targets multiple size=5>{options_for(selected)}</select>"
                f"<p><button>Map to selected</button></p></form>"
                f"<form method=post action='/ui/monitors/{m.id}/ignore' style='display:inline'>"
                f"<input type=hidden name=csrf value='{csrf}'><input type=hidden name=name value='{_e(m.name)}'>"
                f"<button>Ignore</button></form> "
                f"<form method=post action='/ui/monitors/{m.id}/clear' style='display:inline'>"
                f"<input type=hidden name=csrf value='{csrf}'><button>Reset</button></form>"
                f"</details></td></tr>"
            )
        warn = "".join(f'<div class="card warn">{_e(p)}</div>' for p in problems)
        summary = f"<p class='mut'>{len(monitors)} monitors, {len(unmapped)} unmapped.</p>"
        table = (
            "<table><thead><tr><th>Monitor</th><th>State</th><th>Containers</th><th></th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
        return page("Monitors", warn + summary + table, cookie, flash)

    @mcp.custom_route("/ui/monitors/{monitor_id:int}/map", methods=["POST"])
    async def monitor_map(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        targets = []
        for raw in data.getlist("targets"):
            host, sep, container = str(raw).partition("|")
            if sep and host and container:
                targets.append((host, container))
        mid = int(request.path_params["monitor_id"])
        if not targets:
            return RedirectResponse("/ui?msg=" + quote("Pick at least one container."), status_code=303)
        await store.set_mapped(mid, str(data.get("name", "")), targets)
        return RedirectResponse("/ui?msg=" + quote("Mapped."), status_code=303)

    @mcp.custom_route("/ui/monitors/{monitor_id:int}/ignore", methods=["POST"])
    async def monitor_ignore(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        await store.set_ignored(int(request.path_params["monitor_id"]), str(data.get("name", "")))
        return RedirectResponse("/ui?msg=" + quote("Ignored."), status_code=303)

    @mcp.custom_route("/ui/monitors/{monitor_id:int}/clear", methods=["POST"])
    async def monitor_clear(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        await store.clear_monitor(int(request.path_params["monitor_id"]))
        return RedirectResponse("/ui?msg=" + quote("Reset to unmapped."), status_code=303)

    # -- allowlist -----------------------------------------------------------------------------------

    @mcp.custom_route("/ui/allowlist", methods=["GET"])
    async def allowlist_page(request: Request) -> Response:
        cookie = session(request)
        if not cookie:
            return login_redirect()
        csrf = auth.csrf(cookie)
        containers, problems = await all_containers()
        allowed = await store.list_allowed()
        enabled = (
            ""
            if settings.enable_actions
            else '<div class="card warn">Actions are disabled (MCPM_ENABLE_ACTIONS is not set). The allowlist is stored but nothing can run.</div>'
        )
        rows = (
            "".join(
                f"<tr><td>{_e(a['host'])}</td><td>{_e(a['container'])}</td><td>{_e(a['actions'])}</td>"
                f"<td><form method=post action='/ui/allowlist/remove'><input type=hidden name=csrf value='{csrf}'>"
                f"<input type=hidden name=target value='{_e(a['host'])}|{_e(a['container'])}'><button>Remove</button></form></td></tr>"
                for a in allowed
            )
            or "<tr><td colspan=4 class='mut'>Nothing is allowlisted: the agent cannot change any container.</td></tr>"
        )
        options = "".join(
            f'<option value="{_e(c.host)}|{_e(c.name)}">{_e(c.host)} / {_e(c.name)}</option>' for c in containers
        )
        boxes = " ".join(f"<label><input type=checkbox name=actions value={a}> {a}</label>" for a in ACTIONS)
        add = (
            f"<div class=card><form method=post action='/ui/allowlist/set'><input type=hidden name=csrf value='{csrf}'>"
            f"<p><select name=target>{options}</select></p><p>{boxes}</p><p><button>Allow</button></p></form></div>"
        )
        warn = "".join(f'<div class="card warn">{_e(p)}</div>' for p in problems)
        table = f"<table><thead><tr><th>Host</th><th>Container</th><th>Actions</th><th></th></tr></thead><tbody>{rows}</tbody></table>"
        return page("Action allowlist", enabled + warn + add + table, cookie, request.query_params.get("msg", ""))

    @mcp.custom_route("/ui/allowlist/set", methods=["POST"])
    async def allowlist_set(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        host, _, container = str(data.get("target", "")).partition("|")
        actions = [a for a in data.getlist("actions") if a in ACTIONS]
        if not (host and container and actions):
            return RedirectResponse(
                "/ui/allowlist?msg=" + quote("Pick a container and at least one action."), status_code=303
            )
        await store.allow(host, container, actions)
        await store.audit(
            "allowlist", "ok", host=host, container=container, args={"actions": actions}, detail="set via UI"
        )
        return RedirectResponse("/ui/allowlist?msg=" + quote("Saved."), status_code=303)

    @mcp.custom_route("/ui/allowlist/remove", methods=["POST"])
    async def allowlist_remove(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        host, _, container = str(data.get("target", "")).partition("|")
        await store.disallow(host, container)
        await store.audit("allowlist", "ok", host=host, container=container, detail="removed via UI")
        return RedirectResponse("/ui/allowlist?msg=" + quote("Removed."), status_code=303)

    # -- audit ---------------------------------------------------------------------------------------

    @mcp.custom_route("/ui/audit", methods=["GET"])
    async def audit_page(request: Request) -> Response:
        cookie = session(request)
        if not cookie:
            return login_redirect()
        rows = (
            "".join(
                f"<tr><td>{_e(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts'])))}</td><td>{_e(r['tool'])}</td>"
                f"<td>{_e(r['host'])} / {_e(r['container'])}</td><td>{_e(r['outcome'])}</td><td>{_e(r['detail'])}</td></tr>"
                for r in await store.recent_audit(200)
            )
            or "<tr><td colspan=5 class=mut>No entries yet.</td></tr>"
        )
        table = f"<table><thead><tr><th>Time</th><th>Tool</th><th>Target</th><th>Outcome</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>"
        return page("Audit log", table, cookie)

    # -- faults, learning mode, alert targets ----------------------------------------------------------

    if faults is None:
        return

    from .notify import describe
    from .rules import CATEGORIES, SEVERITY_ORDER

    def hidden(csrf: str, **fields: Any) -> str:
        extra = "".join(f"<input type=hidden name={_e(k)} value='{_e(v)}'>" for k, v in fields.items())
        return f"<input type=hidden name=csrf value='{csrf}'>{extra}"

    @mcp.custom_route("/ui/faults", methods=["GET"])
    async def faults_page(request: Request) -> Response:
        cookie = session(request)
        if not cookie:
            return login_redirect()
        csrf = auth.csrf(cookie)
        rows = []
        for f in await faults.faults.list_faults(since=time.time() - 7 * 86400):
            when = time.strftime("%m-%d %H:%M", time.localtime(f["last_seen"]))
            btns = "".join(
                f"<form method=post action='/ui/faults/{f['id']}/{act}' style='display:inline'>{hidden(csrf)}<button>{label}</button></form> "
                for act, label in (("ack", "Ack"), ("resolve", "Resolve"))
                if f["status"] == "open" or act == "resolve" and f["status"] == "acked"
            )
            rows.append(
                f"<tr><td>{when}</td><td>{_e(f['host'])}</td><td><span class='tag'>{_e(f['category'])}</span> "
                f"<b class='{'unmapped' if f['severity'] == 'critical' else ''}'>{_e(f['severity'])}</b></td>"
                f"<td>{_e(f['title'])} <span class='mut'>x{f['count']} ({_e(f['source'])})</span>"
                f"<div class='mut'>{_e(f['sample'][:200])}</div></td><td>{_e(f['status'])} {btns}</td></tr>"
            )
        table = (
            "<table><thead><tr><th>Last</th><th>Host</th><th>Kind</th><th>Fault</th><th>Status</th></tr></thead><tbody>"
            + ("".join(rows) or "<tr><td colspan=5 class=mut>No faults in the last 7 days.</td></tr>")
            + "</tbody></table>"
        )
        hosts = (
            "".join(
                f"<tr><td>{_e(h['host'])}</td><td>{time.strftime('%m-%d %H:%M:%S', time.localtime(h['last_seen']))}</td><td>{h['lines']}</td></tr>"
                for h in await faults.faults.hosts()
            )
            or "<tr><td colspan=3 class=mut>No syslog received yet.</td></tr>"
        )
        hosts_t = f"<h2>Hosts sending logs</h2><table><thead><tr><th>Host</th><th>Last message</th><th>Lines</th></tr></thead><tbody>{hosts}</tbody></table>"
        return page("Faults", table + hosts_t, cookie, request.query_params.get("msg", ""))

    for _act, _status in (("ack", "acked"), ("resolve", "resolved")):

        def _make(act: str = _act, status: str = _status) -> None:
            @mcp.custom_route(f"/ui/faults/{{fault_id:int}}/{act}", methods=["POST"], name=f"fault_{act}")
            async def fault_status(request: Request) -> Response:
                data, cookie = await form(request)
                if data is None:
                    return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
                await faults.faults.set_status(int(request.path_params["fault_id"]), status)
                return RedirectResponse("/ui/faults", status_code=303)

        _make()

    @mcp.custom_route("/ui/patterns", methods=["GET"])
    async def patterns_page(request: Request) -> Response:
        cookie = session(request)
        if not cookie:
            return login_redirect()
        csrf = auth.csrf(cookie)
        import re as _re

        shown = []
        for t in await faults.faults.top_templates(60):
            line = t["sample"] if not t["program"] else f"{t['program']}: {t['sample']}"
            if faults.engine.matches_any(line):
                continue
            shown.append((t, line))
            if len(shown) >= 40:
                break
        rows = []
        for t, line in shown:
            guess = _re.sub(r"\d+", r"\\d+", _re.escape(t["sample"][:160]))
            rows.append(
                f"<tr><td>{t['count']}</td><td><code>{_e(line[:220])}</code></td><td><details><summary>Make rule</summary>"
                f"<form method=post action='/ui/rules/preview'>{hidden(csrf)}"
                f"<p><input name=pattern value='{_e(guess)}' size=60></p>"
                f"<p><select name=category>{''.join(f'<option>{c}</option>' for c in CATEGORIES)}</select> "
                f"<select name=severity>{''.join(f'<option>{s_}</option>' for s_ in SEVERITY_ORDER)}</select> "
                f"threshold <input name=threshold value=1 size=3> in <input name=window value=600 size=5>s</p>"
                f"<p><input name=title placeholder='Title shown in alerts' size=40></p>"
                f"<p><button>Preview matches</button></p></form></details></td></tr>"
            )
        info = (
            "<p class='mut'>Most frequent log patterns that no rule matches yet (numbers, addresses and ids collapsed). "
            "Promote one to a rule after previewing how often it would have matched your stored history.</p>"
        )
        table = (
            "<table><thead><tr><th>Count</th><th>Pattern</th><th></th></tr></thead><tbody>"
            + (
                "".join(rows)
                or "<tr><td colspan=3 class=mut>Nothing yet. Patterns appear once syslog arrives.</td></tr>"
            )
            + "</tbody></table>"
        )
        custom = await faults.faults.custom_rules()
        crows = (
            "".join(
                f"<tr><td>{_e(r['id'])}</td><td>{_e(r['category'])}/{_e(r['severity'])}</td><td><code>{_e(r['pattern'])}</code></td>"
                f"<td>{r['threshold']}/{r['window']}s</td><td><form method=post action='/ui/rules/delete'>{hidden(csrf, id=r['id'])}<button>Delete</button></form></td></tr>"
                for r in custom
            )
            or "<tr><td colspan=5 class=mut>No custom rules. The built-in defaults are untested against real logs.</td></tr>"
        )
        ctable = f"<h2>Custom rules</h2><table><thead><tr><th>Id</th><th>Kind</th><th>Pattern</th><th>Threshold</th><th></th></tr></thead><tbody>{crows}</tbody></table>"
        builtin = "".join(
            f"<tr><td>{_e(r.id)}</td><td>{_e(r.category)}/{_e(r.severity)}</td><td><code>{_e(r.pattern)}</code></td><td>{r.threshold}/{r.window}s</td></tr>"
            for r in faults.engine.rules
            if not any(c["id"] == r.id for c in custom)
        )
        btable = (
            f"<details><summary>Built-in rules in effect</summary><table><tbody>{builtin}</tbody></table></details>"
        )
        return page("Log patterns", info + table + ctable + btable, cookie, request.query_params.get("msg", ""))

    @mcp.custom_route("/ui/rules/preview", methods=["POST"])
    async def rules_preview(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        pattern = str(data.get("pattern", ""))
        try:
            n, examples = await faults.faults.replay_count(pattern, time.time() - 7 * 86400)
        except Exception as exc:  # bad regex
            return page("Preview", f"<p class=unmapped>Invalid pattern: {_e(exc)}</p>", cookie)
        csrf = auth.csrf(cookie)
        rid = "custom-" + hashlib.sha256(pattern.encode()).hexdigest()[:8]
        fields = {k: str(data.get(k, "")) for k in ("pattern", "category", "severity", "threshold", "window", "title")}
        fields["id"] = rid
        body = (
            f"<p>Over the last 7 days this pattern would have matched <b>{n}</b> stored lines.</p>"
            f"<pre>{_e(chr(10).join(examples)) or 'no examples'}</pre>"
            f"<form method=post action='/ui/rules/save'>{hidden(csrf, **fields)}<button>Save rule</button></form>"
            "<p class=mut>A rule that matches thousands of lines will alert constantly; raise the threshold or narrow the pattern first.</p>"
        )
        return page("Preview rule", body, cookie)

    @mcp.custom_route("/ui/rules/save", methods=["POST"])
    async def rules_save(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        try:
            await faults.faults.save_custom_rule(
                {
                    "id": str(data["id"])[:40],
                    "category": str(data["category"]),
                    "severity": str(data["severity"]),
                    "pattern": str(data["pattern"])[:300],
                    "title": str(data.get("title") or "Custom rule")[:120],
                    "threshold": max(1, int(str(data.get("threshold") or 1))),
                    "window": max(1, int(str(data.get("window") or 600))),
                    "enabled": 1,
                }
            )
            await faults.reload_rules()
        except (ValueError, KeyError) as exc:
            return RedirectResponse("/ui/patterns?msg=" + quote(f"Could not save: {exc}"), status_code=303)
        await store.audit("rule", "ok", detail=f"saved {data['id']}")
        return RedirectResponse("/ui/patterns?msg=" + quote("Rule saved."), status_code=303)

    @mcp.custom_route("/ui/rules/delete", methods=["POST"])
    async def rules_delete(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        await faults.faults.delete_custom_rule(str(data.get("id", "")))
        await faults.reload_rules()
        return RedirectResponse("/ui/patterns?msg=" + quote("Rule deleted."), status_code=303)

    if notify_store is None:
        return

    @mcp.custom_route("/ui/notify", methods=["GET"])
    async def notify_page(request: Request) -> Response:
        cookie = session(request)
        if not cookie:
            return login_redirect()
        csrf = auth.csrf(cookie)
        rows = (
            "".join(
                f"<tr><td>{_e(t['name'])}</td><td class=mut>{_e(t['target'])}</td><td>{_e(t['min_severity'])}+ {_e(', '.join(t['categories']) or 'all categories')}</td>"
                f"<td><form method=post action='/ui/notify/test' style='display:inline'>{hidden(csrf, id=t['id'])}<button>Test</button></form> "
                f"<form method=post action='/ui/notify/remove' style='display:inline'>{hidden(csrf, id=t['id'])}<button>Remove</button></form></td></tr>"
                for t in describe(await notify_store.list())
            )
            or "<tr><td colspan=4 class=mut>No alert targets: faults are recorded but nobody is told.</td></tr>"
        )
        cats = " ".join(f"<label><input type=checkbox name=categories value={c}> {c}</label>" for c in CATEGORIES)
        add = (
            f"<div class=card><form method=post action='/ui/notify/add'>{hidden(csrf)}"
            "<p><input name=name placeholder='Name (e.g. Discord)' required> "
            "<input name=url placeholder='Apprise URL, e.g. discord://webhook_id/webhook_token' size=50 required></p>"
            f"<p>Minimum severity <select name=min_severity>{''.join(f'<option>{s_}</option>' for s_ in SEVERITY_ORDER)}</select></p>"
            f"<p class=mut>Only these categories (none ticked = all):</p><p>{cats}</p><p><button>Add or update</button></p></form>"
            "<p class=mut>The URL contains a secret and is never displayed again. Adding a target with an existing name replaces it.</p></div>"
        )
        table = f"<table><thead><tr><th>Name</th><th>Target</th><th>Sends</th><th></th></tr></thead><tbody>{rows}</tbody></table>"
        return page("Alert targets", add + table, cookie, request.query_params.get("msg", ""))

    @mcp.custom_route("/ui/notify/add", methods=["POST"])
    async def notify_add(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        try:
            cats = [c for c in data.getlist("categories") if c in CATEGORIES]
            await notify_store.add(
                str(data.get("name", "")), str(data.get("url", "")), str(data.get("min_severity", "warning")), cats
            )
        except ValueError as exc:
            return RedirectResponse("/ui/notify?msg=" + quote(str(exc)), status_code=303)
        await store.audit("notify-target", "ok", detail=f"saved {str(data.get('name', ''))[:60]}")
        return RedirectResponse("/ui/notify?msg=" + quote("Saved. Use Test to check it works."), status_code=303)

    @mcp.custom_route("/ui/notify/remove", methods=["POST"])
    async def notify_remove(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        await notify_store.remove(int(str(data.get("id", "0"))))
        return RedirectResponse("/ui/notify?msg=" + quote("Removed."), status_code=303)

    @mcp.custom_route("/ui/notify/test", methods=["POST"])
    async def notify_test(request: Request) -> Response:
        data, cookie = await form(request)
        if data is None:
            return login_redirect() if cookie is None else Response("bad csrf token", status_code=403)
        ok = await notifier.test(int(str(data.get("id", "0"))))
        return RedirectResponse(
            "/ui/notify?msg=" + quote("Test sent." if ok else "Test FAILED: check the URL."), status_code=303
        )
