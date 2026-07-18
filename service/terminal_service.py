"""wiki-plugin-terminal — FastAPI pty service.

An APIRouter so it can be included in an existing local-first app:

    from terminal_service import router as terminal_router
    app.include_router(terminal_router)

or run standalone:

    uvicorn terminal_service:app --port 4248

Endpoints (all under /terminal):
    GET  /terminal/health           service check; lists live sessions
    POST /terminal/run              run a script, capture {stdout, stderr, exit}
    WS   /terminal/pty/{session}    attach to a named pty session (created on
                                    first attach; survives detach, tmux-style)
    GET  /terminal/page?session=    standalone full-bleed terminal page

Security: local-first only. Bind uvicorn to 127.0.0.1 and the websocket
checks the Origin header against local wiki hosts.
"""

import asyncio
import fcntl
import json
import os
import re
import signal
import struct
import subprocess
import termios

import pty as pty_module

from fastapi import APIRouter, FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/terminal")

SESSION_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# ── ssh targets ───────────────────────────────────────────────────────────────
#
# A HOST/SSH directive routes a run through ssh on the named host, so a wiki page
# can drive commands on another machine (e.g. pi5.local) — but the pty ssh's out
# with the *service user's own key* (BatchMode = key-only, no password prompt),
# and only to an allowlisted host, so an arbitrary destination can't be injected
# by a page. Configurable via WIKI_TERMINAL_SSH_HOSTS (comma-separated).
SSH_HOSTS = {
    h.strip()
    for h in os.environ.get("WIKI_TERMINAL_SSH_HOSTS", "pi5.local,MacMini.local").split(",")
    if h.strip()
}

SSH_TARGET = re.compile(r"^(?:([A-Za-z0-9_.-]+)@)?([A-Za-z0-9_.-]+)$")


def resolve_ssh_target(host: str | None) -> str | None:
    """Validate a HOST/SSH directive value to an ssh destination, or None.

    Accepts `host` or `user@host`; the host part must be in the allowlist.
    Returns the sanitized `user@host` (or `host`), else None (reject).
    """
    if not host:
        return None
    m = SSH_TARGET.match(host.strip())
    if not m:
        return None
    user, hostname = m.group(1), m.group(2)
    if hostname not in SSH_HOSTS:
        return None
    return f"{user}@{hostname}" if user else hostname

# OSC 133 shell-integration hooks so clients can capture per-command output.
# Written to ZDOTDIR so the spawned zsh picks them up without touching ~/.zshrc.
ZSHRC_HOOKS = r"""
[ -f ~/.zshrc ] && source ~/.zshrc
precmd()  { print -n "\e]133;D;$?\a\e]133;A\a" }
preexec() { print -n "\e]133;C\a" }
"""

sessions: dict[str, "Session"] = {}


class Session:
    """One forked zsh on a pty; many websocket clients may attach."""

    def __init__(self, name: str, ssh_target: str | None = None):
        zdotdir = os.path.expanduser("~/.cache/wiki-plugin-terminal")
        os.makedirs(zdotdir, exist_ok=True)
        with open(os.path.join(zdotdir, ".zshrc"), "w") as f:
            f.write(ZSHRC_HOOKS)

        pid, fd = pty_module.fork()
        if pid == 0:  # child
            os.environ["TERM"] = "xterm-256color"
            os.environ["ZDOTDIR"] = zdotdir
            if ssh_target:
                # ssh out with the service user's key; BatchMode = key-only, no
                # password prompt. The remote shell won't source our OSC-133
                # hooks, so per-command capture is local-shell only.
                os.execvp("ssh", ["ssh", "-tt", "-o", "BatchMode=yes", ssh_target])
            os.execvp("zsh", ["zsh"])

        self.name, self.pid, self.fd = name, pid, fd
        self.clients: set[WebSocket] = set()
        asyncio.get_event_loop().add_reader(self.fd, self._pump)

    def _pump(self):
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            data = b""
        if not data:
            return self.close()
        for ws in list(self.clients):
            asyncio.ensure_future(self._send(ws, data))

    async def _send(self, ws: WebSocket, data: bytes):
        try:
            await ws.send_bytes(data)
        except Exception:
            self.clients.discard(ws)

    def write(self, data: str):
        os.write(self.fd, data.encode())

    def resize(self, cols: int, rows: int):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def close(self):
        try:
            asyncio.get_event_loop().remove_reader(self.fd)
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.kill(self.pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        sessions.pop(self.name, None)


def _origin_host(origin: str) -> str:
    return origin.split("//")[-1].split(":")[0].split("/")[0]


def _local_host(host: str) -> bool:
    # Only loopback-local origins may reach the pty. NOT *.fish: a public .fish
    # page must never instruct the local shell — trusted remote pages run via
    # the *viewer's own* localhost origin (arming happens client-side), so the
    # service only ever legitimately sees a localhost/*.localhost Origin.
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def origin_allowed(ws: WebSocket) -> bool:
    return _local_host(_origin_host(ws.headers.get("origin", "")))


def http_origin_allowed(request: Request) -> bool:
    # A missing Origin is a non-browser local caller or a same-origin request —
    # the 127.0.0.1 bind already contains those. A *present* cross-origin header
    # from a page we don't serve is the drive-by-RCE risk: reject it.
    origin = request.headers.get("origin")
    return origin is None or _local_host(_origin_host(origin))


@router.get("/health")
def health():
    return {"status": "ok", "sessions": sorted(sessions)}


class RunRequest(BaseModel):
    text: str
    cwd: str | None = None
    host: str | None = None
    timeout: int = 30


@router.post("/run")
def run(req: RunRequest, request: Request):
    """Ward's shell-plugin model: run, capture, return structured output."""
    if not http_origin_allowed(request):
        return JSONResponse(
            {"stdout": "", "stderr": "forbidden origin", "exit": -1}, status_code=403
        )
    cwd = os.path.expanduser(req.cwd) if req.cwd else None
    if req.host:
        # A HOST directive ssh's out with the service user's key, to an
        # allowlisted host only. The remote shell reads the script on stdin's -c.
        target = resolve_ssh_target(req.host)
        if target is None:
            return {"stdout": "", "stderr": f"host not allowed: {req.host}", "exit": -1}
        # Pass the script as one remote command; ssh runs it through the remote
        # user's own login shell (the Pi runs bash, not zsh — don't assume zsh).
        cmd = ["ssh", "-o", "BatchMode=yes", target, req.text]
    else:
        cmd = ["zsh", "-c", req.text]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=req.timeout, cwd=cwd,
        )
        return {"stdout": proc.stdout, "stderr": proc.stderr, "exit": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"timed out after {req.timeout}s", "exit": -1}


class Guard(BaseModel):
    id: str
    test: str


class CheckRequest(BaseModel):
    guards: list[Guard]
    timeout: int = 10


@router.post("/check")
def check(req: CheckRequest, request: Request):
    """Evaluate workflow guards: a step is unlocked iff its test exits 0.

    Used on page load to decide which terminal items to lock. Output is
    discarded — only the exit status matters.
    """
    if not http_origin_allowed(request):
        return JSONResponse({"results": {}}, status_code=403)
    results: dict[str, bool] = {}
    for g in req.guards:
        try:
            proc = subprocess.run(
                ["zsh", "-c", g.test],
                capture_output=True, timeout=req.timeout,
            )
            results[g.id] = proc.returncode == 0
        except subprocess.TimeoutExpired:
            results[g.id] = False
    return {"results": results}


@router.websocket("/pty/{session}")
async def attach(ws: WebSocket, session: str, host: str | None = Query(None)):
    target = resolve_ssh_target(host) if host else None
    if (
        not SESSION_NAME.match(session)
        or not origin_allowed(ws)
        or (host and target is None)  # a HOST was asked for but isn't allowed
    ):
        await ws.close(code=4403)
        return
    await ws.accept()
    live = sessions.get(session)
    if live is None:
        live = sessions[session] = Session(session, target)
    live.clients.add(ws)
    try:
        while True:
            message = json.loads(await ws.receive_text())
            if message["type"] == "input":
                live.write(message["data"])
            elif message["type"] == "resize":
                live.resize(int(message["cols"]), int(message["rows"]))
    except (WebSocketDisconnect, OSError):
        pass
    finally:
        live.clients.discard(ws)
        # session stays alive for re-attach; close explicitly via shell `exit`


PAGE_HTML = """<!doctype html>
<html><head><title>terminal — {session}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css">
<style>html,body{{margin:0;height:100%;background:#1e1e1e}}#term{{height:100%;padding:8px;box-sizing:border-box}}</style>
</head><body><div id="term"></div>
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js"></script>
<script>
  const term = new Terminal({{fontSize: 14, cursorBlink: true,
    theme: {{background:'#1e1e1e', foreground:'#d4d4d4', cursor:'#ffffff',
             selectionBackground:'#264f78'}}}})
  const fit = new FitAddon.FitAddon()
  term.loadAddon(fit)
  term.open(document.getElementById('term'))
  fit.fit()
  const ws = new WebSocket(`ws://${{location.host}}/terminal/pty/{session}{hostq}`)
  ws.binaryType = 'arraybuffer'
  ws.onmessage = e => term.write(new Uint8Array(e.data))
  ws.onopen = () => ws.send(JSON.stringify({{type:'resize', cols:term.cols, rows:term.rows}}))
  term.onData(d => ws.send(JSON.stringify({{type:'input', data:d}})))
  term.onResize(({{cols, rows}}) => ws.send(JSON.stringify({{type:'resize', cols, rows}})))
  addEventListener('resize', () => fit.fit())
</script></body></html>"""


@router.get("/page")
def page(session: str = Query("default"), host: str | None = Query(None)):
    if not SESSION_NAME.match(session):
        return HTMLResponse("bad session name", status_code=400)
    target = resolve_ssh_target(host) if host else None
    if host and target is None:
        return HTMLResponse("host not allowed", status_code=403)
    hostq = f"?host={target}" if target else ""
    return HTMLResponse(PAGE_HTML.format(session=session, hostq=hostq))


# standalone: uvicorn terminal_service:app --port 4248
app = FastAPI()
# Browser clients probe /terminal/health cross-origin (the wiki page and the
# service live on different local origins); without CORS the plugin silently
# degrades to display-only. Restrict CORS to local origins (localhost /
# *.localhost / loopback) so a public page can't drive the pty cross-origin —
# the loopback bind plus the per-request Origin checks are the real backstop.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(([a-z0-9-]+\.)*localhost|127\.0\.0\.1|\[::1\])(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)
