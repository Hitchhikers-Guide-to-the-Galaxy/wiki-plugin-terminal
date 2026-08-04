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
import shlex
import shutil
import signal
import struct
import subprocess
import termios
from datetime import datetime

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
# The trailing source line applies any resolved NEEDS for this session: it runs
# before the first prompt, so nothing is ever echoed into the scrollback.
ZSHRC_HOOKS = r"""
[ -f ~/.zshrc ] && source ~/.zshrc
precmd()  { print -n "\e]133;D;$?\a\e]133;A\a" }
preexec() { print -n "\e]133;C\a" }
[ -f "$ZDOTDIR/.needs" ] && source "$ZDOTDIR/.needs"
"""

# ── NEEDS resolution ──────────────────────────────────────────────────────────
#
# A wiki page may NAME a credential; it may never describe how to fetch one.
# The mapping from an abstract name to an actual Keychain query lives here, on
# the viewer's own machine, in a file the service owns:
#
#   ~/.config/wiki-plugin-terminal/vault.json
#   {
#     "Nextcloud": {
#       "service": "Nextcloud",
#       "account": "david_app-password:https://nextcloud.example/:0",
#       "login":   "david",
#       "machine": "nextcloud.example"
#     }
#   }
#
# A page naming an entry that is not in this file resolves to nothing — it is
# reported back as unknown so the reader can fill the value in by hand. That is
# what keeps a forked page from minting arbitrary `security` reads.
VAULT_PATH = os.path.expanduser(
    os.environ.get("WIKI_TERMINAL_VAULT", "~/.config/wiki-plugin-terminal/vault.json")
)

SESSION_HOME = os.path.expanduser("~/.cache/wiki-plugin-terminal/sessions")

# Fields whose value must never travel back to the browser.
SECRET_FIELDS = {"password", "passwd", "pass", "netrc", "token", "secret",
                 "key", "apikey", "api-key"}
# Fields that name a person rather than a secret: safe to return for display.
LOGIN_FIELDS = {"account", "user", "login", "username"}


def load_vault() -> dict:
    try:
        with open(VAULT_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


KEYCHAIN_TIMEOUT = int(os.environ.get("WIKI_TERMINAL_KEYCHAIN_TIMEOUT", "20"))


class Blocked(Exception):
    """The Keychain did not answer — locked, or waiting on an approval dialog."""


def keychain_password(service: str, account: str | None) -> str | None:
    """Read one secret. Raises Blocked when macOS is waiting on the human.

    `security` blocks indefinitely when the login keychain is locked or when the
    item's ACL has not yet been granted to it — macOS puts up a dialog and waits.
    That is a different failure from "no such entry", and the reader needs to be
    told which one it is, so it surfaces as Blocked rather than as a missing key.
    """
    cmd = ["security", "find-generic-password", "-s", service]
    if account:
        cmd += ["-a", account]
    cmd += ["-w"]
    try:
        done = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=KEYCHAIN_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Blocked(service)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.rstrip("\n") if done.returncode == 0 else None


def session_dir(session: str) -> str:
    path = os.path.join(SESSION_HOME, session)
    os.makedirs(path, mode=0o700, exist_ok=True)
    with open(os.path.join(path, ".zshrc"), "w") as f:
        f.write(ZSHRC_HOOKS)
    return path


def _write_private(path: str, text: str) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


def resolve_needs(session: str, needs: list) -> dict:
    """Resolve declared needs for one session.

    Secrets are written into the session's private `.needs` file as exports —
    for a netrc field, only the *path* of a 0600 credentials file is exported,
    so the secret itself never lands in a variable. Non-secret values (a login
    name) are returned for the client to substitute into the displayed command.
    """
    vault = load_vault()
    values: dict[str, str] = {}
    unknown: list[str] = []
    blocked: list[str] = []
    exports: list[str] = []
    path = session_dir(session)

    for need in needs:
        name = need.get("name") or ""
        if not re.match(r"^[A-Z][A-Z0-9_]*$", name):
            continue
        entry = vault.get(need.get("service") or "")
        if not entry:
            unknown.append(name)
            continue
        field = str(need.get("field") or "password").lower()

        if field in LOGIN_FIELDS:
            login = entry.get("login") or entry.get("account")
            if login:
                values[name] = login
            else:
                unknown.append(name)
            continue

        try:
            secret = keychain_password(entry.get("service", ""), entry.get("account"))
        except Blocked:
            blocked.append(name)
            continue
        if secret is None:
            unknown.append(name)
            continue

        if field == "netrc":
            machine = entry.get("machine")
            login = entry.get("login") or entry.get("account")
            if not machine or not login:
                # Without an explicit machine a netrc would have to say
                # `default`, handing the credential to every host the script
                # touches. Refuse rather than leak.
                unknown.append(name)
                continue
            netrc = _write_private(
                os.path.join(path, f"netrc-{name}"),
                f"machine {machine} login {login} password {secret}\n",
            )
            exports.append(f"export {name}={shlex.quote(netrc)}")
        elif field in SECRET_FIELDS:
            exports.append(f"export {name}={shlex.quote(secret)}")
        else:
            unknown.append(name)

    _write_private(os.path.join(path, ".needs"), "\n".join(exports) + "\n")
    return {
        "values": values,
        "unknown": unknown,
        "blocked": blocked,
        "secrets": [e.split("=", 1)[0].removeprefix("export ") for e in exports],
        "live": session in sessions,
    }

sessions: dict[str, "Session"] = {}

# The service may itself have been launched from an agent session or an IDE,
# whose ANTHROPIC_* / CLAUDE* variables (base-URL auth proxies, API keys,
# session markers) would otherwise leak into every shell it hosts — a nested
# `claude` would then authenticate as the launcher instead of the user's own
# login. Spawned shells get a clean slate so they behave exactly like a fresh
# Terminal window.
_LAUNCHER_ENV = ("ANTHROPIC", "CLAUDE")


def scrub_launcher_env() -> dict:
    return {k: v for k, v in os.environ.items() if not k.startswith(_LAUNCHER_ENV)}


class Session:
    """One forked zsh on a pty; many websocket clients may attach."""

    def __init__(self, name: str, ssh_target: str | None = None):
        # Per-session ZDOTDIR: resolved secrets belong to one session and must
        # not be readable by the next one. session_dir writes the hooks, and any
        # .needs already resolved for this session is picked up at shell start.
        zdotdir = session_dir(name)

        pid, fd = pty_module.fork()
        if pid == 0:  # child
            for key in [k for k in os.environ if k.startswith(_LAUNCHER_ENV)]:
                del os.environ[key]
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
            # The pty fork made the shell a session leader, so its pgid is its
            # pid — HUP the whole group so a foreground REPL (claude, python)
            # dies with its shell instead of lingering orphaned.
            os.killpg(self.pid, signal.SIGHUP)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(self.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
        # Tell every window the session is gone — otherwise their websockets
        # dangle open against a dead pty and the client shows a frozen frame
        # that still looks live (the original "jammed terminal").
        for ws in list(self.clients):
            asyncio.ensure_future(self._close_ws(ws))
        self.clients.clear()
        # Resolved secrets die with the session they were minted for.
        shutil.rmtree(os.path.join(SESSION_HOME, self.name), ignore_errors=True)
        sessions.pop(self.name, None)

    @staticmethod
    async def _close_ws(ws: WebSocket):
        try:
            await ws.close()
        except Exception:
            pass


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


# ── Claude Code conversations ────────────────────────────────────────────────
#
# Claude Code (CLI and app alike) keeps every conversation as a .jsonl
# transcript under ~/.claude/projects/<encoded-cwd>/<session-id>.jsonl. Listing
# them read-only lets a wiki page offer a `claudesession` picker whose pick is
# a session id for `claude --resume`. Nothing here ever writes or deletes a
# transcript — ending a wiki pty never touches this folder.
CLAUDE_PROJECTS = os.path.expanduser("~/.claude/projects")


def _first_prompt(path: str) -> str | None:
    """The first user message's opening words — the human name of a session."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for _ in range(40):
                line = fh.readline(200_000)
                if not line:
                    break
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("type") != "user":
                    continue
                content = (rec.get("message") or {}).get("content")
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    text = next((c.get("text", "") for c in content
                                 if isinstance(c, dict) and c.get("type") == "text"), "")
                else:
                    text = ""
                text = " ".join(text.split())
                # Skip machine-generated records (<local-command-caveat> and
                # kin) — keep reading for the first human words.
                if text and not text.startswith("<"):
                    return text[:57] + "…" if len(text) > 58 else text
    except OSError:
        pass
    return None


def list_claude_sessions(limit: int = 25) -> list[dict]:
    found = []
    try:
        for proj in os.scandir(CLAUDE_PROJECTS):
            if not proj.is_dir():
                continue
            for f in os.scandir(proj.path):
                if f.name.endswith(".jsonl") and f.is_file():
                    found.append((f.stat().st_mtime, f.path, f.name[:-6]))
    except OSError:
        return []
    found.sort(reverse=True)
    sessions = []
    for mtime, path, sid in found[:limit]:
        label = _first_prompt(path) or sid[:8]
        when = datetime.fromtimestamp(mtime).strftime("%b %d %H:%M")
        sessions.append({"id": sid, "label": f"{label} · {when}"})
    return sessions


@router.get("/options")
def options(request: Request):
    """Names only, never values: the ssh-host allowlist and the vault's entry
    names, feeding the client's `sshhost` / `vault` pulldown chips. Listing a
    vault name reveals nothing the vault file's purpose doesn't imply — the
    secret itself only ever moves into a session's private .needs file."""
    if not http_origin_allowed(request):
        return JSONResponse({"error": "forbidden origin"}, status_code=403)
    return {"hosts": sorted(SSH_HOSTS), "vault": sorted(load_vault().keys()),
            "claude_sessions": list_claude_sessions()}


class RunRequest(BaseModel):
    text: str
    cwd: str | None = None
    host: str | None = None
    timeout: int = 30
    session: str | None = None


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
        # A one-shot run has no login shell, so it never reads ZDOTDIR. Source
        # the session's resolved needs explicitly so `$AUTH` means the same
        # here as it does in the live terminal. Secrets stay in the file.
        text = req.text
        if req.session and SESSION_NAME.match(req.session):
            needs_file = os.path.join(SESSION_HOME, req.session, ".needs")
            if os.path.exists(needs_file):
                text = f"source {shlex.quote(needs_file)}\n{text}"
        cmd = ["zsh", "-c", text]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=req.timeout, cwd=cwd,
            env=scrub_launcher_env(),
        )
        return {"stdout": proc.stdout, "stderr": proc.stderr, "exit": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"timed out after {req.timeout}s", "exit": -1}


class KillRequest(BaseModel):
    session: str


@router.post("/kill")
async def kill(req: KillRequest, request: Request):
    """End a named session outright — the reset gesture for a wedged or
    stale shell (and whatever REPL it runs). Idempotent: killing a session
    that is not there is already the desired state. Async on purpose:
    close() touches the event loop (remove_reader), which must happen on
    the loop thread, not a threadpool worker."""
    if not http_origin_allowed(request):
        return JSONResponse({"ok": False, "error": "forbidden origin"}, status_code=403)
    if not SESSION_NAME.match(req.session or ""):
        return {"ok": False, "error": "bad session name"}
    live = sessions.get(req.session)
    if live is None:
        return {"ok": True, "gone": True}
    live.close()
    return {"ok": True, "killed": req.session}


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


class NeedSpec(BaseModel):
    name: str
    kind: str = "keychain"
    service: str | None = None
    field: str | None = None


class NeedsRequest(BaseModel):
    session: str
    needs: list[NeedSpec] = []


@router.post("/needs")
def needs(req: NeedsRequest, request: Request):
    """Resolve a session's declared NEEDS against the local vault map.

    Returns non-secret values (a login name) for the client to substitute into
    the command it displays and pastes. Secret values are never in the response:
    they are written to the session's private .needs file, which its shell
    sources before the first prompt. Names the vault does not know come back as
    `unknown` so the reader can supply them by hand.
    """
    if not http_origin_allowed(request):
        return JSONResponse({"values": {}, "unknown": [], "secrets": []}, status_code=403)
    if not SESSION_NAME.match(req.session):
        return JSONResponse({"values": {}, "unknown": [], "secrets": []}, status_code=400)
    return resolve_needs(req.session, [n.model_dump() for n in req.needs])


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
