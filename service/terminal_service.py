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
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import termios
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    import bip340
except ImportError:  # the service copy travels with bip340.py beside it
    bip340 = None

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

# A session shell is a LOGIN shell, like a Terminal.app window, so the user's
# login files run too. ZDOTDIR points zsh at the session folder, so each of
# those files there just hands on to the user's own.
ZSH_HANDOFFS = {
    ".zshenv": '[ -f ~/.zshenv ] && source ~/.zshenv\n',
    ".zprofile": '[ -f ~/.zprofile ] && source ~/.zprofile\n',
    ".zlogin": '[ -f ~/.zlogin ] && source ~/.zlogin\n',
}

# Every shell starts from the system PATH, as a fresh Terminal window does,
# and builds the rest from /etc/zprofile and the user's own files. It never
# inherits this service's PATH. That PATH depends on who restarted the
# service: on 21 October 2026 a restart from an agent's stripped PATH put
# Node 18 and an old nvm `claude` first, so every BUTTON's BOOT crashed
# ("Object not disposable") and its brief fell into zsh.
FRESH_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def fresh_env() -> dict:
    """The environment a fresh Terminal window starts from: this service's
    variables without launcher ones (see scrub_launcher_env), PATH reset."""
    env = scrub_launcher_env()
    env["PATH"] = FRESH_PATH
    env.pop("ZDOTDIR", None)
    return env

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
    for name, text in ZSH_HANDOFFS.items():
        with open(os.path.join(path, name), "w") as f:
            f.write(text)
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
REPLAY_BYTES = 256 * 1024  # how much of a session's recent output a new window is shown

# Terminal queries: a program asks the terminal something (its colours, the
# cursor position, what it is) and the terminal answers on the program's input.
# A replay must not ask again. The program that asked is long gone, so the
# window's answer lands at the shell prompt as typed text: "zsh: command not
# found: 11" from `\e]11;rgb:…` (0.9.17, 2026-10-21 — `claude-squad version`
# asks for colours and exits without reading, and every later window on that
# session answered it again). Live output still carries its queries untouched.
_QUERIES = re.compile(
    rb"\x1b\][0-9]+(?:;[0-9]+)*;\?(?:\x07|\x1b\\)"   # OSC colour queries: 10/11/12 ;?  and 4;n;?
    rb"|\x1b\[\??[56]n"                               # DSR: status, cursor position
    rb"|\x1b\[[>=]?[0-9;]*c"                          # DA1, DA2, DA3: what terminal is this
    rb"|\x1b\[>[0-9]*q"                               # XTVERSION
    rb"|\x1b\[\?[0-9;]*\$p"                           # DECRQM: is this mode set
    rb"|\x1b\[\?u"                                    # kitty keyboard protocol query
    rb"|\x1b\[(?:1[134689]|2[01])t"                   # window size and title reports
    rb"|\x1bP\+q[0-9A-Fa-f;]*\x1b\\")                 # XTGETTCAP


def without_queries(data: bytes) -> bytes:
    """A session's recent output fit to replay: everything it drew, minus the
    questions it asked the terminal."""
    return _QUERIES.sub(b"", data)

# The service may itself have been launched from an agent session or an IDE,
# whose ANTHROPIC_* / CLAUDE* variables (base-URL auth proxies, API keys,
# session markers) would otherwise leak into every shell it hosts — a nested
# `claude` would then authenticate as the launcher instead of the user's own
# login. Spawned shells get a clean slate so they behave exactly like a fresh
# Terminal window.
_LAUNCHER_ENV = ("ANTHROPIC", "CLAUDE")


def scrub_launcher_env() -> dict:
    return {k: v for k, v in os.environ.items() if not k.startswith(_LAUNCHER_ENV)}


# A one-shot run is `zsh -c`, which reads no rc file, so its PATH is whatever
# this service was launched with — and a service started by launchd or an IDE
# has never seen ~/.zshrc, where the user's own directories join the PATH.
# The live pane is an interactive zsh and has them, so the same command line
# worked there and failed on the RUN button ("command not found: wiki-plugman",
# 3 September 2026). Ask a login, interactive zsh, started from a fresh PATH
# like a Terminal window, once what PATH it would have and give every run
# that; it is cached, because starting one costs about a second.
_interactive_path: str | None = None


def interactive_env() -> dict:
    global _interactive_path
    env = fresh_env()
    if _interactive_path is None:
        try:
            out = subprocess.run(
                ["zsh", "-lic", "print -r -- $PATH"],
                capture_output=True, text=True, timeout=15, env=env,
            ).stdout.strip().splitlines()
            _interactive_path = out[-1].strip() if out else ""
        except (OSError, subprocess.SubprocessError):
            _interactive_path = ""
    if _interactive_path:
        env["PATH"] = _interactive_path
    return env


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
            # A login shell from the system PATH, as a Terminal window starts.
            os.environ["PATH"] = FRESH_PATH
            os.execv("/bin/zsh", ["zsh", "-l"])

        self.name, self.pid, self.fd = name, pid, fd
        self.clients: set[WebSocket] = set()
        self.last_output = time.monotonic()  # for a paste that waits for a REPL to settle
        # Ready once the line editor has drawn its first prompt and switched
        # bracketed paste on (\e[?2004h) — the client's own test. Before that a
        # heavy ~/.zshrc may still be running, and anything typed is lost or
        # mistaken for a booted REPL.
        self.ready = False
        self._probe = b""
        # The last of the session's output, for whoever attaches next: a window
        # opened on a live session showed nothing until something new was drawn,
        # and a REPL waiting at a prompt draws nothing (2026-10-21).
        self.recent = bytearray()
        asyncio.get_event_loop().add_reader(self.fd, self._pump)

    def _pump(self):
        try:
            data = os.read(self.fd, 65536)
        except OSError:
            data = b""
        if not data:
            return self.close()
        self.last_output = time.monotonic()
        self.recent += data
        if len(self.recent) > REPLAY_BYTES:
            del self.recent[: len(self.recent) - REPLAY_BYTES]
        if not self.ready:
            self._probe = (self._probe + data)[-4096:]
            if b"\x1b[?2004h" in self._probe:
                self.ready, self._probe = True, b""
        for ws in list(self.clients):
            asyncio.ensure_future(self._send(ws, data))

    async def _send(self, ws: WebSocket, data: bytes):
        try:
            await ws.send_bytes(data)
        except Exception:
            self.clients.discard(ws)

    def shell_idle(self) -> bool:
        """True when the shell itself holds the terminal: nothing (no REPL)
        runs in the foreground, so a BUTTON's prompt pasted now would be parsed
        by zsh, not read by claude. The pty fork made the shell a session
        leader, so its pgid is its pid."""
        try:
            return os.tcgetpgrp(self.fd) == self.pid
        except OSError:
            return False

    def write(self, data: str):
        os.write(self.fd, data.encode())

    def resize(self, cols: int, rows: int):
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def size(self) -> tuple[int, int]:
        rows, cols, _, _ = struct.unpack("HHHH", fcntl.ioctl(self.fd, termios.TIOCGWINSZ, b"\0" * 8))
        return cols, rows

    async def redraw(self):
        """Make a full-screen program (claude, vim, top) paint its whole screen
        again: change the size by a row and back, which it hears as SIGWINCH."""
        try:
            cols, rows = self.size()
            if rows > 2:
                self.resize(cols, rows - 1)
                await asyncio.sleep(0.15)
                self.resize(cols, rows)
        except OSError:
            pass

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
    return host in ("localhost", "127.0.0.1", "::1", "[::1]") or host.endswith(".localhost")


# ── Trust: whose text may run ──────────────────────────────────────────────────
#
# A page the viewer merely browses is display-only. A page from a site the
# viewer TRUSTS may run — but the browser's word for "this page came from
# plan.ide.earth" is a DOM attribute any script on the origin can write. So
# the service does not take the browser's word: for a page that is not local
# it fetches the page from its home site itself and requires the item text to
# be byte-equal to what the browser sent. Publication is the signature — only
# the site's owner can publish there. The trusted sites live in a file beside
# the vault, never in the browser (a co-resident script could set a window
# global; it cannot write ~/.config).
#
#   ~/.config/wiki-plugin-terminal/trust.json
#   { "sites": ["plan.ide.earth"], "farms": [{"anchor": "https://fab.fish", "owner": "david"}],
#     "except": [], "keys": {}, "verify_local": false }
#
# A farm entry with an `owner` trusts only the sites that login owns on the
# farm (the farm's sites.json, Farm plugin >= 0.10.2); a plain URL trusts them all.
# `farms` is the farm default: every site a listed farm ANCHOR publishes under
# x-fedwiki-farm.sites at /system/api.json is trusted as if it were in `sites`.
# The anchor is a site of your own farm, so the list is your box's word, not
# the page's — a stranger's site cannot talk its way in by claiming a farm id.
# `except` names farm sites you do not trust (other people's sites on your
# farm). The farm list is refreshed every ten minutes; an unreachable anchor
# contributes nothing until it answers.
#
# `keys` is reserved for signed items (BIP-340, the Terminal Trust Plan's
# Phase 3): a signature by a listed key passes offline on any site.
TRUST_PATH = os.path.expanduser(
    os.environ.get("WIKI_TERMINAL_TRUST", "~/.config/wiki-plugin-terminal/trust.json")
)
SITE_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
OWNER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.I)
SLUG_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
ITEM_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PAGE_FETCH_TIMEOUT = 5.0
PAGE_FETCH_CAP = 2_000_000
PAGE_CACHE_TTL = 30.0


class TrustStore:
    """trust.json, reloaded when its mtime changes — edits need no restart.
    A missing or broken file means no trusted sites: the door closes."""

    def __init__(self, path: str = TRUST_PATH):
        self.path = path
        self._mtime: float | None = None
        self._data: dict = {}

    def load(self) -> dict:
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            self._mtime, self._data = None, {}
            return self._data
        if mtime != self._mtime:
            try:
                with open(self.path) as f:
                    data = json.load(f)
                self._data = data if isinstance(data, dict) else {}
            except (OSError, ValueError) as e:
                print(f"caution: {self.path}: {e}")
                self._data = {}
            self._mtime = mtime
        return self._data

    def sites(self) -> set[str]:
        raw = self.load().get("sites", [])
        return {str(x).lower() for x in raw if isinstance(x, str) and SITE_NAME.match(str(x).lower())}

    def farms(self) -> list[dict]:
        """Farm anchors: each {anchor, owner}. An entry is an https URL (a bare
        host is taken as https://host) for the whole farm, or an object
        {"anchor": url, "owner": id} for the sites that id owns on it.
        An owner entry may add "standing": true — a standing Unlock for those
        sites (see standing_sites); a whole-farm entry never stands."""
        out = []
        for x in self.load().get("farms", []):
            owner = None
            standing = False
            if isinstance(x, dict):
                owner = str(x.get("owner") or "").strip() or None
                standing = x.get("standing") is True
                x = x.get("anchor")
            if not isinstance(x, str):
                continue
            x = x.strip().rstrip("/")
            if not x.startswith("https://"):
                x = "https://" + x
            host = x[len("https://"):].split("/")[0].lower()
            if owner is not None and not OWNER_ID.match(owner):
                continue
            if SITE_NAME.match(host) and not _private_address(host):
                out.append({"anchor": "https://" + host, "owner": owner,
                            "standing": bool(standing and owner)})
        return out

    def excepted(self) -> set[str]:
        raw = self.load().get("except", [])
        return {str(x).lower() for x in raw if isinstance(x, str)}

    def keys(self) -> dict:
        keys = self.load().get("keys", {})
        return keys if isinstance(keys, dict) else {}

    def verify_local(self) -> bool:
        return bool(self.load().get("verify_local", False))

    def public(self) -> dict:
        """What a client may know: names, never secrets."""
        # `sites` is everything the service trusts, listed and farm alike: the
        # client's originTrust() reads this one field, so a farm site must be in it.
        return {
            "sites": sorted(trusted_sites()),
            "listed": sorted(self.sites()),
            "farms": self.farms(),
            "farm_sites": len(trusted_sites() - self.sites()),
            "standing_sites": len(standing_sites()),
            "standing_paused": _standing_paused,
            "except": sorted(self.excepted()),
            "keys": {k: (v.get("id") if isinstance(v, dict) else None) for k, v in self.keys().items()},
            "verify_local": self.verify_local(),
        }


trust = TrustStore()


def _private_address(host: str) -> bool:
    """A trusted site is fetched over the network; never let that fetch be
    steered at loopback, link-local or RFC1918 space (the SSRF door)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


FARM_CACHE_TTL = 600.0
_farm_cache: dict[str, tuple[float, set[str]]] = {}
_farm_lock = threading.Lock()


def farm_sites(anchor: str, owner: str | None = None) -> set[str]:
    """The sites a farm anchor publishes — all of them from x-fedwiki-farm.sites,
    or, with an owner, only that login's sites from the farm's sites.json
    (Farm plugin >= 0.10.2). Cached; an anchor that cannot be read (or answers
    without the block) contributes nothing."""
    key = f"{anchor}|{owner or ''}"
    now = time.monotonic()
    with _farm_lock:
        hit = _farm_cache.get(key)
        if hit and now - hit[0] < FARM_CACHE_TTL:
            return hit[1]
    sites: set[str] = set()
    try:
        if owner:
            api = fetch_json(anchor + "/system/api/farm/sites.json?owner=" + urllib.parse.quote(owner))
            raw = api.get("sites") or []
        else:
            api = fetch_json(anchor + "/system/api.json")
            raw = (api.get("x-fedwiki-farm") or {}).get("sites") or []
        sites = {str(x).lower() for x in raw if isinstance(x, str) and SITE_NAME.match(str(x).lower())}
    except (urllib.error.URLError, ValueError, OSError, TimeoutError, AttributeError) as e:
        print(f"caution: farm anchor {anchor}: {e}")
    with _farm_lock:
        _farm_cache[key] = (now, sites)
    return sites


def trusted_sites() -> set[str]:
    """Listed sites plus every site of every trusted farm (or of its named owner), minus the exceptions."""
    sites = set(trust.sites())
    for farm in trust.farms():
        sites |= farm_sites(farm["anchor"], farm["owner"])
    return {s for s in sites - trust.excepted() if not _private_address(s)}


def site_trusted(site: str | None) -> bool:
    if not site:
        return False
    return site.lower() in trusted_sites()


# A standing Unlock (Standing Unlock Plan, 2026-10-25): the sites David owns on
# his own farms — a farm entry with an owner and "standing": true — need no
# grant. The list comes from his farm, never from the page; publication is still
# checked; `except` still removes a site; Lock everything pauses it until the
# service restarts or the Unlock page resumes it.
_standing_paused = False


def standing_sites() -> set[str]:
    """Sites whose https origin passes the Unlock without a grant."""
    sites: set[str] = set()
    for farm in trust.farms():
        if farm.get("standing") and farm.get("owner"):
            sites |= farm_sites(farm["anchor"], farm["owner"])
    return {s for s in sites - trust.excepted() if not _private_address(s)}


def origin_standing(origin: str | None) -> bool:
    if _standing_paused or not origin or not origin.lower().startswith("https://"):
        return False
    return _origin_host(origin) in standing_sites()


def allowed_origin(origin: str | None) -> bool:
    """The one predicate every door asks: a local origin, or the https origin
    of a trusted site. Used by the HTTP gate, the websocket gate and the CORS
    layer, so there is one answer and not three."""
    if not origin:
        return False
    host = _origin_host(origin)
    if _local_host(host):
        return True
    return origin.lower().startswith("https://") and site_trusted(host)


class PageRef(BaseModel):
    site: str
    slug: str
    itemId: str


_page_cache: dict[tuple[str, str], tuple[float, dict]] = {}
_page_lock = threading.Lock()


def _fetch_page_raw(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "wiki-plugin-terminal/verify"})
    with urllib.request.urlopen(req, timeout=PAGE_FETCH_TIMEOUT) as resp:
        body = resp.read(PAGE_FETCH_CAP + 1)
    if len(body) > PAGE_FETCH_CAP:
        raise ValueError("page too large")
    return json.loads(body.decode("utf-8"))


# Test seams: a test replaces fetch_page (pages) and fetch_json (farm anchors) with stubs.
fetch_page = _fetch_page_raw
fetch_json = _fetch_page_raw


def _cached_page(site: str, slug: str, scheme: str) -> dict:
    key = (site, slug)
    now = time.monotonic()
    with _page_lock:
        hit = _page_cache.get(key)
        if hit and now - hit[0] < PAGE_CACHE_TTL:
            return hit[1]
    page = fetch_page(f"{scheme}://{site}/{slug}.json")
    with _page_lock:
        _page_cache[key] = (now, page)
    return page


class Verdict(BaseModel):
    ok: bool
    why: str = ""
    site: str | None = None
    signed_by: str | None = None
    at: str | None = None
    status: int = 403
    locked: bool = False


def verify_publication(text: str, ref: PageRef | None) -> Verdict:
    """Does the site the page claims as home publish this exact text?

    The text must be byte-equal to the terminal item on the page as the site
    serves it. No trimming and no normalisation: one changed byte is a
    different script, and a different script is not what was published."""
    if ref is None:
        return Verdict(ok=False, why="no page reference: a script from a non-local page must say where it lives")
    site, slug, item_id = ref.site.lower(), ref.slug, ref.itemId
    if not SITE_NAME.match(site) or not SLUG_NAME.match(slug) or not ITEM_ID.match(item_id):
        return Verdict(ok=False, why="malformed page reference")
    local = _local_host(site)
    if not local and not site_trusted(site):
        return Verdict(ok=False, why=f"{site} is not a trusted site — add it to trust.json to accept its scripts")
    try:
        page = _cached_page(site, slug, "http" if local else "https")
    except (urllib.error.URLError, ValueError, OSError, TimeoutError) as e:
        return Verdict(ok=False, why=f"could not read {site}/{slug} to verify the script: {e}")
    for item in page.get("story") or []:
        if not isinstance(item, dict) or item.get("id") != item_id:
            continue
        if item.get("type") != "terminal":
            return Verdict(ok=False, why="the referenced item is not a terminal item")
        if item.get("text") != text:
            return Verdict(ok=False, why=f"the script differs from what {site} publishes — edited, or not yet saved")
        return Verdict(ok=True, site=site, at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return Verdict(ok=False, why=f"{site}/{slug} has no item {item_id}")


# ── Signed items: trust that follows the author ─────────────────────────────
#
# A site vouches for what it publishes; a signature vouches for who wrote it.
# The author signs the item TEXT — directives included, since they carry
# authority — as a nostr event, so any nostr tool can check it, and the
# signature travels with the item through every fork. A key listed in
# trust.json's `keys` passes offline, on any site, with no page fetch:
#
#   "keys": { "npub1…": { "id": "david" } }
#
# The event is NIP-01: [0, pubkey, created_at, kind, tags, content], kind
# 30078 (application-specific data), tags [["d","fedwiki-item"],["type",<item
# type>]]. Serialised the JSON.stringify way — no spaces, raw unicode — and
# sha256'd; that digest is what BIP-340 signs. test/fixtures/sign-vectors.json
# holds texts that JavaScript and Python must serialise byte-identically.
SIGN_KIND = 30078
SIGN_TAG = "fedwiki-item"


def canonical_event(pubkey_hex: str, created_at: int, item_type: str, text: str) -> str:
    event = [0, pubkey_hex, int(created_at), SIGN_KIND, [["d", SIGN_TAG], ["type", item_type]], text]
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False)


def event_id(pubkey_hex: str, created_at: int, item_type: str, text: str) -> bytes:
    return hashlib.sha256(canonical_event(pubkey_hex, created_at, item_type, text).encode("utf-8")).digest()


class Signature(BaseModel):
    alg: str = "bip340"
    pubkey: str
    created_at: int
    sig: str


def trusted_keys() -> dict[str, str]:
    """pubkey hex → holder id, from trust.json's keys (npub or hex accepted)."""
    out = {}
    for key, holder in trust.keys().items():
        pub = bip340.pubkey_from(str(key)) if bip340 else None
        if pub:
            out[pub.hex()] = (holder.get("id") if isinstance(holder, dict) else None) or "unnamed"
    return out


def verify_signature(source: str, signature: Signature | None, item_type: str = "terminal") -> Verdict:
    """Is this text signed by a key this machine trusts? Offline, no fetch."""
    if signature is None:
        return Verdict(ok=False, why="unsigned")
    if bip340 is None:
        return Verdict(ok=False, why="bip340 module not deployed beside the service")
    if signature.alg != "bip340":
        return Verdict(ok=False, why=f"unknown signature algorithm {signature.alg}")
    pub = bip340.pubkey_from(signature.pubkey)
    try:
        sig = bytes.fromhex(signature.sig)
    except ValueError:
        sig = b""
    if pub is None or len(sig) != 64:
        return Verdict(ok=False, why="malformed signature")
    holder = trusted_keys().get(pub.hex())
    if holder is None:
        return Verdict(ok=False, why=f"signed by a key this machine does not trust ({bip340.npub(pub)[:16]}…)")
    if not bip340.verify(event_id(pub.hex(), signature.created_at, item_type, source), pub, sig):
        return Verdict(ok=False, why=f"signature stale — the text changed since {holder} signed it")
    return Verdict(ok=True, signed_by=holder, site=None,
                   at=datetime.fromtimestamp(signature.created_at, timezone.utc).isoformat(timespec="seconds"))


def page_is_local(ref: PageRef | None) -> bool:
    return ref is not None and _local_host(ref.site.lower())


def must_verify(request: Request, ref: PageRef | None) -> bool:
    """Which runs go through publication verification: any from a non-local
    Origin, any whose page reference names a non-local site, and — when the
    operator asks for it — local pages too (verify_local closes the
    foreign-page-in-the-lineup hole for the private farm at one GET per run)."""
    origin = request.headers.get("origin")
    if origin and not _local_host(_origin_host(origin)):
        return True
    if ref is not None and not page_is_local(ref):
        return True
    return trust.verify_local() and ref is not None


DIRECTIVE_LINE = re.compile(r"^[A-Z][A-Z0-9_]+(?::.*|\s.*)?$")  # two letters or more: "I have…" is prose


def script_of(source: str) -> str:
    """The runnable part of an item's text, the way the client strips it:
    UPPERCASE directive lines (and blank lines among them) lead; the script is
    everything after. Kept here so a verified SOURCE decides what may run,
    rather than trusting the client's stripped copy."""
    lines = (source or "").split("\n")
    i = 0
    while i < len(lines) and (not lines[i].strip() or DIRECTIVE_LINE.match(lines[i].strip())):
        i += 1
    return "\n".join(lines[i:])


def boot_of(source: str) -> str | None:
    """The BOOT directive of a (verified) item source: the command that starts
    the session's REPL. Read from the source, never from the asking page."""
    for line in (source or "").split("\n"):
        if line.startswith("BOOT:"):
            return line[len("BOOT:"):].strip() or None
    return None


_HOST_LINE = re.compile(r"^(?:HOST|SSH)[:\s]\s*(\S.*)$")
_BUTTON_LINE = re.compile(r"^BUTTON(?::\s*\S+)?\s*$")


def host_of(source: str | None) -> str | None:
    """The HOST (or SSH) directive of a verified item source: where its session
    runs. Read from the source, never from the asking page."""
    for line in (source or "").split("\n"):
        m = _HOST_LINE.match(line)
        if m:
            return m.group(1).strip()
    return None


def is_button(source: str | None) -> bool:
    """True when a verified item source is a BUTTON item."""
    return any(_BUTTON_LINE.match(line) for line in (source or "").split("\n"))


def guard_of(source: str) -> str | None:
    for line in (source or "").split("\n"):
        if line.startswith("GUARD:"):
            return line[len("GUARD:"):].strip()
    return None


# ── Unlock: the person at this machine consents ──────────────────────────────
#
# Page trust says whose text may run. It says nothing about whether the person
# at this keyboard wants a public page to drive their shell right now. So a
# request from a non-local origin also needs a GRANT: a token the person minted
# by clicking Unlock on a page served by this service, bound to the asking
# origin, short-lived, revocable, and born of a secret that dies with the
# process — a restart locks everything. No cookie: a cookie on this origin sent
# from another site is a third-party cookie, which browsers block or
# partition; the token goes back to the page by postMessage and lives in that
# tab's sessionStorage.
GRANT_DEFAULT = 30 * 60
GRANT_MAX = 8 * 60 * 60
_grant_secret = os.urandom(32)
_grants: dict[str, tuple[str, int]] = {}  # nonce -> (origin, exp)
_revoked: set[str] = set()


def _b64u(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(t: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def mint_grant(origin: str, ttl: int | None = None) -> tuple[str, int]:
    ttl = max(60, min(int(ttl or GRANT_DEFAULT), GRANT_MAX))
    exp = int(time.time()) + ttl
    nonce = _b64u(os.urandom(12))
    payload = json.dumps({"o": origin, "exp": exp, "n": nonce}, separators=(",", ":")).encode()
    sig = hmac.new(_grant_secret, payload, hashlib.sha256).hexdigest()
    _grants[nonce] = (origin, exp)
    return f"{_b64u(payload)}.{sig}", exp


def check_grant(token: str | None, origin: str | None) -> bool:
    if not token or not origin or "." not in token:
        return False
    body, _, sig = token.rpartition(".")
    try:
        payload = _unb64u(body)
        want = hmac.new(_grant_secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig):
            return False
        claims = json.loads(payload)
    except (ValueError, TypeError):
        return False
    if claims.get("n") in _revoked or claims.get("o") != origin:
        return False
    return int(claims.get("exp", 0)) > time.time()


def live_grants() -> list[dict]:
    now = time.time()
    for n, (o, exp) in list(_grants.items()):
        if exp <= now or n in _revoked:
            _grants.pop(n, None)
    return [{"origin": o, "exp": exp, "nonce": n} for n, (o, exp) in _grants.items()]


def lock_all() -> None:
    global _grant_secret, _standing_paused
    _grant_secret = os.urandom(32)
    _grants.clear()
    _revoked.clear()
    _standing_paused = True


def resume_standing() -> None:
    global _standing_paused
    _standing_paused = False


def bearer_of(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return None


def origin_is_local(origin: str | None) -> bool:
    return bool(origin) and _local_host(_origin_host(origin))


def consented(origin: str | None, token: str | None) -> bool:
    """The Unlock question, asked one way by every door: a local origin, one of
    David's own sites under a standing Unlock, or a live grant for this origin."""
    if not origin or origin_is_local(origin):
        return True
    return origin_standing(origin) or check_grant(token, origin)


def gate(request: Request, text: str, ref: PageRef | None, source: str | None = None,
         signature: Signature | None = None) -> Verdict:
    """The whole decision for a run, a check or a paste.

    1. Origin: local, or the https origin of a trusted site.
    2. Consent: a non-local origin needs a live grant for that origin.
    3. Page: a non-local page (or any page when verify_local is on) must be
       published byte-for-byte by its home site, and the text to run must be
       the script of that published source."""
    origin = request.headers.get("origin")
    if not http_origin_allowed(request):
        return Verdict(ok=False, why="forbidden origin", status=403)
    if origin and not origin_is_local(origin):
        if not consented(origin, bearer_of(request)):
            return Verdict(ok=False, why=f"locked: {origin} has no live grant on this machine — click Unlock",
                           status=401, locked=True)
    if must_verify(request, ref) or signature is not None:
        body = source if source is not None else text
        # A signature by a trusted key settles page trust on its own, on any
        # site, offline. Otherwise the page's home site must publish the text.
        signed = verify_signature(body, signature)
        if signed.ok:
            trusted = signed
        elif must_verify(request, ref):
            published = verify_publication(body, ref)
            if not published.ok:
                if signature is not None:
                    published.why = f"{signed.why}; {published.why}"
                return published
            trusted = published
        else:
            return Verdict(ok=True)
        if source is not None and text != script_of(source):
            return Verdict(ok=False, why="the text to run is not the script of the published item", status=403)
        return trusted
    return Verdict(ok=True)




def origin_allowed(ws: WebSocket) -> bool:
    return allowed_origin(ws.headers.get("origin", ""))


def http_origin_allowed(request: Request) -> bool:
    # A missing Origin is a non-browser local caller or a same-origin request —
    # the 127.0.0.1 bind already contains those. A *present* cross-origin header
    # from a page we don't serve is the drive-by-RCE risk: reject it.
    origin = request.headers.get("origin")
    return origin is None or allowed_origin(origin)


@router.get("/health")
def health(request: Request):
    origin = request.headers.get("origin")
    locked = not consented(origin, bearer_of(request))
    idle = sorted(n for n, s in sessions.items() if s.shell_idle())
    return {"status": "ok", "sessions": sorted(sessions), "idle": idle, "locked": locked, "trust": bool(trust.sites())}


# ── Claude Sessions: a read-only door (Standing Unlock Plan, 2026-10-25) ─────
#
# The Plan Tool's Claude Sessions face lists every Claude session on this
# laptop. It used to post `claude agents --json` and `ps -E` to /terminal/run:
# bare text with no page behind it, so a remote page could never pass the
# publication check, and `ps -E` handed the page each process's whole
# environment, tokens and all. Here the service runs both itself and returns
# only the sessions and, per pid, the wiki terminal session its ZDOTDIR names.
AGENTS_TIMEOUT = 20
_ZDOTDIR_SESSION = re.compile(r"(?:^|\s)ZDOTDIR=\S*/wiki-plugin-terminal/sessions/([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\s|$)")


def _shell_out(cmd: list[str], check: bool = True) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=AGENTS_TIMEOUT, env=interactive_env())
    if check and proc.returncode != 0:
        last = (proc.stderr or "").strip().splitlines()
        raise ValueError(last[-1] if last else f"exit {proc.returncode}")
    return proc.stdout


# Test seam: a test replaces shell_out with a stub.
shell_out = _shell_out


def terminals_of(ps_text: str) -> dict[int, str]:
    """pid -> wiki terminal session, read from `ps -E` lines; nothing else kept."""
    out: dict[int, str] = {}
    for line in (ps_text or "").split("\n"):
        pid = re.match(r"^\s*(\d+)\s", line)
        z = _ZDOTDIR_SESSION.search(line)
        if pid and z:
            out[int(pid.group(1))] = z.group(1)
    return out


@router.get("/agents")
def agents_view(request: Request):
    """Every Claude session on this machine (`claude agents --json`), with the
    wiki terminal session of each pid the wiki started. Read-only; no text from
    the page runs, so it needs the Unlock (or a standing one) and no page."""
    origin = request.headers.get("origin")
    if not http_origin_allowed(request):
        return JSONResponse({"error": "forbidden origin"}, status_code=403)
    if not consented(origin, bearer_of(request)):
        return JSONResponse({"error": f"locked: {origin} has no live grant on this machine — click Unlock",
                             "locked": True}, status_code=401)
    try:
        agents = json.loads(shell_out(["zsh", "-c", "claude agents --json"]))
        if not isinstance(agents, list):
            raise ValueError("claude agents --json did not print a list")
    except (subprocess.TimeoutExpired, ValueError, OSError) as e:
        return JSONResponse({"error": f"could not run claude agents --json: {e}"}, status_code=502)
    agents = [a for a in agents if isinstance(a, dict)]
    pids = sorted({a["pid"] for a in agents if isinstance(a.get("pid"), int) and a["pid"] > 0})
    terminals: dict[int, str] = {}
    if pids:
        try:
            # ps exits 1 when one pid has gone, and still prints the rest
            terminals = terminals_of(shell_out(["ps", "-E", "-o", "pid=,command=", "-p", ",".join(map(str, pids))], check=False))
        except (subprocess.TimeoutExpired, OSError):
            terminals = {}
    return {"agents": agents, "terminals": {str(k): v for k, v in terminals.items()}}


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


# A one-shot run's time limit. An item may ask for more with TIMEOUT:, up to a
# ceiling the service owns: a page can ask, not grant. Work longer than the
# ceiling belongs in a live session (BUTTON/SESSION), which has no limit.
RUN_TIMEOUT_DEFAULT = 30
RUN_TIMEOUT_MAX = int(os.environ.get("WIKI_TERMINAL_RUN_TIMEOUT_MAX", "600"))


def run_timeout(asked) -> tuple[int, bool]:
    """(seconds to allow, whether the ask was cut down to the ceiling)."""
    try:
        n = int(asked)
    except (TypeError, ValueError):
        return RUN_TIMEOUT_DEFAULT, False
    if n < 1:
        return RUN_TIMEOUT_DEFAULT, False
    return (RUN_TIMEOUT_MAX, True) if n > RUN_TIMEOUT_MAX else (n, False)


class RunRequest(BaseModel):
    text: str
    cwd: str | None = None
    host: str | None = None
    timeout: int | None = None
    session: str | None = None
    # Where the item lives and what its home site publishes — required for a
    # page that is not local; `source` is the whole item text, `text` its script.
    page: PageRef | None = None
    source: str | None = None
    signature: Signature | None = None


@router.post("/run")
def run(req: RunRequest, request: Request):
    """Ward's shell-plugin model: run, capture, return structured output."""
    verdict = gate(request, req.text, req.page, req.source, req.signature)
    if not verdict.ok:
        return JSONResponse(
            {"stdout": "", "stderr": verdict.why, "exit": -1, "locked": verdict.locked},
            status_code=verdict.status,
        )
    # A verified page names its own working directory only through its script;
    # a page-supplied cwd is honoured on local pages alone.
    cwd = os.path.expanduser(req.cwd) if (req.cwd and not must_verify(request, req.page)) else None
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
    limit, clamped = run_timeout(req.timeout)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=limit, cwd=cwd,
            env=interactive_env(),
        )
        reply = {"stdout": proc.stdout, "stderr": proc.stderr, "exit": proc.returncode, "timeout": limit}
        if clamped:
            reply["timeout_clamped"] = f"asked {req.timeout}s; the ceiling is {RUN_TIMEOUT_MAX}s"
        if verdict.site or verdict.signed_by:
            reply["verified"] = {"site": verdict.site, "at": verdict.at, "signed_by": verdict.signed_by}
        return reply
    except subprocess.TimeoutExpired:
        hint = (" — ask for more with a TIMEOUT: line (up to %ds), or run it in a live session" % RUN_TIMEOUT_MAX) if limit < RUN_TIMEOUT_MAX \
            else " — longer than any one-shot run may take; run it in a live session (BUTTON/SESSION)"
        return {"stdout": "", "stderr": f"timed out after {limit}s{hint}", "exit": -1, "timeout": limit}


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
    page: PageRef | None = None
    source: str | None = None
    signature: Signature | None = None


@router.post("/check")
def check(req: CheckRequest, request: Request):
    """Evaluate workflow guards: a step is unlocked iff its test exits 0.

    Used on page load to decide which terminal items to lock. Output is
    discarded — only the exit status matters. For a page that is not local the
    guard must be the GUARD line of the published item, verified like a run.
    """
    verified = must_verify(request, req.page)
    # The gate verifies the published SOURCE; the guard is checked against its
    # GUARD line below, so the text handed to the gate is the source's script.
    verified = verified or req.signature is not None
    verdict = gate(request, script_of(req.source or ""), req.page, req.source, req.signature) if verified \
        else gate(request, "", None)
    if not verdict.ok:
        return JSONResponse({"results": {}, "error": verdict.why, "locked": verdict.locked},
                            status_code=verdict.status)
    if verified:
        allowed = guard_of(req.source or "")
        for g in req.guards:
            if g.test.strip() != (allowed or "").strip():
                return JSONResponse({"results": {}, "error": "a guard must be the GUARD line of the published item"},
                                    status_code=403)
    results: dict[str, bool] = {}
    for g in req.guards:
        try:
            proc = subprocess.run(
                ["zsh", "-c", g.test],
                capture_output=True, timeout=req.timeout,
                env=interactive_env(),
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


class VerifyRequest(BaseModel):
    source: str
    page: PageRef | None = None
    signature: Signature | None = None


@router.post("/verify")
def verify(req: VerifyRequest, request: Request):
    """Say whether this item, as sent, is what its home site publishes — so a
    toolbar can wear the verdict before anyone clicks. Runs nothing."""
    if not http_origin_allowed(request):
        return JSONResponse({"ok": False, "why": "forbidden origin"}, status_code=403)
    signed = verify_signature(req.source, req.signature) if req.signature is not None else None
    if not must_verify(request, req.page):
        return {"ok": True, "site": None, "local": True,
                "signed_by": signed.signed_by if signed and signed.ok else None,
                "signature": None if signed is None else ("ok" if signed.ok else signed.why)}
    origin = request.headers.get("origin")
    locked = not consented(origin, bearer_of(request))
    if signed and signed.ok:
        return {"ok": True, "why": "", "site": None, "signed_by": signed.signed_by, "at": signed.at,
                "signature": "ok", "locked": locked}
    v = verify_publication(req.source, req.page)
    return {"ok": v.ok, "why": v.why, "site": v.site, "signed_by": None, "at": v.at, "locked": locked,
            "signature": None if signed is None else signed.why}


class PasteRequest(BaseModel):
    session: str
    text: str
    page: PageRef | None = None
    source: str | None = None
    signature: Signature | None = None
    enter: bool = True
    boot: bool = False


async def _until(test, seconds: float, step: float = 0.3) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if test():
            return True
        await asyncio.sleep(step)
    return test()


async def _quiet(live: "Session", still: float, most: float) -> None:
    """Wait until the session has drawn nothing for `still` seconds (at most `most`)."""
    end = time.monotonic() + most
    while time.monotonic() < end and time.monotonic() - live.last_output < still:
        await asyncio.sleep(0.1)


@router.post("/paste")
async def paste(req: PasteRequest, request: Request):
    """Write a verified script into a named live session — the BUTTON of a page
    that is not local, without handing that page the raw socket.

    With boot (2026-10-20), the BUTTON's BOOT, read from the VERIFIED source,
    starts the session's REPL first: the session is created when there is none,
    and BOOT runs when its shell holds the terminal with nothing running. The
    prompt is pasted only once the REPL has taken the terminal and settled —
    pasted into a bare zsh, a brief is parsed as a command line ("parse error
    near `then'"). The text goes as one bracketed paste, so a REPL reads a
    multi-line brief whole instead of submitting it at the first newline."""
    verdict = gate(request, req.text, req.page, req.source, req.signature)
    if not verdict.ok:
        return JSONResponse({"ok": False, "error": verdict.why, "locked": verdict.locked},
                            status_code=verdict.status)
    if not SESSION_NAME.match(req.session):
        return JSONResponse({"ok": False, "error": "bad session name"}, status_code=400)
    boot = boot_of(req.source) if req.boot and req.source is not None else None
    live = sessions.get(req.session)
    booted = fresh = False
    if live is None:
        # A verified BUTTON makes its own session (0.9.16, David 2026-10-21:
        # "the button should run the code" — before, a BUTTON with no BOOT
        # raced the panel's websocket, found no session, and only a second
        # click ran). The session is the one the item names, on the host its
        # verified HOST line names, exactly as the panel would have made it.
        if not (boot or is_button(req.source)):
            return JSONResponse({"ok": False, "error": "no such live session — open the terminal first"},
                                status_code=409)
        host = host_of(req.source)
        target = resolve_ssh_target(host) if host else None
        if host and target is None:
            return JSONResponse({"ok": False, "error": f"host {host} is not allowed"}, status_code=403)
        live = sessions[req.session] = Session(req.session, target)
        fresh = True
    if boot or fresh or not live.ready:
        # the shell's first prompt (bracketed paste switched on), or a REPL
        # already running; ssh to a Pi takes longer than a local zsh
        await _until(lambda: live.ready, 20)
        if fresh and not live.ready:
            return JSONResponse({"ok": False, "session": req.session,
                                 "error": "the shell did not draw a prompt — open the session and look"},
                                status_code=409)
        if fresh and not boot:
            await _quiet(live, 0.3, 3)  # the prompt fully drawn before the paste lands
    if boot and live.shell_idle():
        live.write(boot + "\r")
        if not await _until(lambda: not live.shell_idle(), 20):
            return JSONResponse({"ok": False, "booted": False, "session": req.session,
                                 "error": f"{boot} did not take the terminal — open the session and look"},
                                status_code=409)
        await _quiet(live, 1.0, 25)  # its first screen drawn
        booted = True
    live.write(f"\x1b[200~{req.text}\x1b[201~")
    if req.enter:
        await _quiet(live, 0.35, 2.5)  # a TUI digests a paste before Return means submit
        live.write("\r")
    return {"ok": True, "session": req.session, "booted": booted,
            "verified": {"site": verdict.site, "at": verdict.at}}


@router.get("/trust")
def trust_view(request: Request):
    """What this machine trusts — site names and key holders, never secrets —
    and whether the asking origin currently holds a grant."""
    origin = request.headers.get("origin")
    if origin and not allowed_origin(origin):
        return JSONResponse({"error": "forbidden origin"}, status_code=403)
    data = trust.public()
    data["locked"] = not consented(origin, bearer_of(request))
    data["standing"] = origin_standing(origin)
    data["unlock"] = "/terminal/unlock"
    return data


def _same_origin(request: Request) -> bool:
    """Only a page this service served itself may mint or revoke grants: the
    browser's own Sec-Fetch-Site says so, and the Origin, when present, must be
    this host. A cross-site page cannot forge either from a browser."""
    if request.headers.get("sec-fetch-site", "same-origin") != "same-origin":
        return False
    origin = request.headers.get("origin")
    return origin is None or _origin_host(origin) == (request.url.hostname or "")


UNLOCK_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>terminal — unlock</title>
<style>body{font:15px/1.5 -apple-system,system-ui,sans-serif;max-width:34em;margin:3em auto;padding:0 1em;color:#222}
button{font:inherit;padding:.5em 1.2em;margin:.3em .4em .3em 0;border-radius:6px;border:1px solid #888;background:#fff;cursor:pointer}
button.primary{background:#2a6;color:#fff;border-color:#2a6}code{background:#eee;padding:.1em .3em;border-radius:3px}
ul{padding-left:1.2em}small{color:#666}</style></head><body>
<h2>Allow <code>__ORIGIN__</code> to run verified scripts on this Mac?</h2>
<p>A button on a page of <code>__ORIGIN__</code> wants to run on this Mac. Only scripts that <code>__ORIGIN__</code> itself publishes will run, checked against the page as it publishes it, and only when you click them. The grant is for that origin, in the tab that asked. Restarting this service, or Lock everything, ends every grant.</p>
<p><button class="primary" id="unlock8">Unlock for 8 hours</button>
<button id="unlock">Unlock for 30 minutes</button>
<button id="lock">Lock everything</button></p>
<p><small id="status"></small></p>
<h3>Live grants</h3><ul id="grants"><li><small>none</small></li></ul>
<h3>Standing Unlock</h3><p id="standing"><small>…</small></p>
<p><button id="resume" hidden>Resume the standing Unlock</button></p>
<script>
const origin = __ORIGIN_JSON__
const $ = s => document.querySelector(s)
const refresh = async () => {
  const r = await fetch('/terminal/grants?origin=' + encodeURIComponent(origin)); const j = await r.json()
  $('#grants').innerHTML = (j.grants||[]).map(g => `<li><code>${g.origin}</code> until ${new Date(g.exp*1000).toLocaleTimeString()}</li>`).join('') || '<li><small>none</small></li>'
  const st = j.standing || {}
  $('#standing').innerHTML = st.paused
    ? `<b>Paused</b> by Lock everything: your own ${st.sites} sites ask for Unlock like any other until you resume it or the service restarts.`
    : st.sites
      ? `On for ${st.sites} sites you own (trust.json farms with <code>"standing": true</code>)${st.here ? `, <code>${origin}</code> among them: it needs no Unlock` : ''}. Lock everything pauses it.`
      : '<small>Off: no trust.json farm entry has <code>"standing": true</code>.</small>'
  $('#resume').hidden = !st.paused
}
$('#resume').onclick = async () => { await fetch('/terminal/unlock/resume', {method:'POST'}); $('#status').textContent = 'standing Unlock resumed'; if (window.opener) window.opener.postMessage({type:'wiki-terminal-standing'}, origin); await refresh() }
const grant = async ttl => {
  const r = await fetch('/terminal/unlock/grant', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({origin, ttl})})
  const j = await r.json()
  if (!r.ok) { $('#status').textContent = j.error || 'refused'; return }
  if (window.opener) { window.opener.postMessage({type:'wiki-terminal-unlock', token:j.token, exp:j.exp, origin}, origin) }
  $('#status').textContent = 'unlocked — you can close this window'
  await refresh()
  if (window.opener) setTimeout(() => window.close(), 600)
}
$('#unlock').onclick = () => grant(1800)
$('#unlock8').onclick = () => grant(8*3600)
$('#lock').onclick = async () => { await fetch('/terminal/lock', {method:'POST'}); $('#status').textContent = 'everything locked'; if (window.opener) window.opener.postMessage({type:'wiki-terminal-lock'}, origin); await refresh() }
refresh()
</script></body></html>"""


@router.get("/unlock")
def unlock_page(origin: str = Query("")):
    """The consent page. Only an origin this service would accept can be asked
    for — a local origin or the https origin of a trusted site."""
    origin = origin.strip().rstrip("/")
    if not allowed_origin(origin):
        return HTMLResponse("<p>That origin is not local and not a trusted site. Add it to trust.json first.</p>",
                            status_code=403)
    html = UNLOCK_HTML.replace("__ORIGIN_JSON__", json.dumps(origin)).replace("__ORIGIN__", origin.replace("<", "&lt;"))
    return HTMLResponse(html)


class GrantRequest(BaseModel):
    origin: str
    ttl: int | None = None


@router.post("/unlock/grant")
def unlock_grant(req: GrantRequest, request: Request):
    if not _same_origin(request):
        return JSONResponse({"error": "grants are minted only from the unlock page"}, status_code=403)
    origin = req.origin.strip().rstrip("/")
    if not allowed_origin(origin):
        return JSONResponse({"error": "origin is not local and not a trusted site"}, status_code=403)
    token, exp = mint_grant(origin, req.ttl)
    print(f"terminal unlock: {origin} until {datetime.fromtimestamp(exp).isoformat(timespec='minutes')}")
    return {"token": token, "exp": exp, "origin": origin}


@router.get("/grants")
def grants(request: Request):
    if not _same_origin(request):
        return JSONResponse({"error": "same-origin only"}, status_code=403)
    origin = (request.query_params.get("origin") or "").strip().rstrip("/")
    return {"grants": live_grants(),
            "standing": {"sites": len(standing_sites()), "paused": _standing_paused,
                         "here": bool(origin) and not _standing_paused and origin_standing(origin)}}


@router.post("/unlock/resume")
def unlock_resume(request: Request):
    """Lift the pause Lock everything put on the standing Unlock."""
    if not _same_origin(request):
        return JSONResponse({"error": "same-origin only"}, status_code=403)
    resume_standing()
    print("terminal unlock: standing Unlock resumed")
    return {"ok": True}


@router.post("/lock")
def lock(request: Request):
    if not _same_origin(request):
        return JSONResponse({"error": "same-origin only"}, status_code=403)
    lock_all()
    print("terminal lock: every grant revoked")
    return {"ok": True}


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
    origin = ws.headers.get("origin", "")
    if not origin_is_local(origin):
        # A public page reaches the pty only with the person's grant, sent as
        # the first frame — websockets carry no Authorization header.
        try:
            first = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=5))
        except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
            await ws.close(code=4401)
            return
        if first.get("type") != "auth" or not consented(origin, first.get("token")):
            await ws.close(code=4401)
            return
    live = sessions.get(session)
    existing = live is not None
    if live is None:
        live = sessions[session] = Session(session, target)
    if existing and live.recent:
        # Joining a live session: show what it last drew, then ask it to draw
        # its screen again, so a REPL waiting at a prompt is not a blank window.
        try:
            await ws.send_bytes(without_queries(bytes(live.recent)))
        except Exception:
            pass
    live.clients.add(ws)
    if existing:
        asyncio.ensure_future(live.redraw())
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
class TrustCORS(CORSMiddleware):
    """CORS decided per request by allowed_origin(), so a site added to
    trust.json or published by a trusted farm is accepted without a restart
    (the regex form was fixed at import time)."""

    def is_allowed_origin(self, origin: str) -> bool:
        return allowed_origin(origin)


async def private_network_headers(request, call_next):
    """Chrome's Private/Local Network Access asks a loopback service, on the
    preflight, whether a public page may talk to it. Answer yes: the real
    gates are the Origin check, the grant and the page verification."""
    response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


app.add_middleware(
    TrustCORS,
    allow_origin_regex=r"^$",
    allow_methods=["*"],
    allow_headers=["*"],
    # Starlette >= 0.46 answers the Private/Local Network Access preflight
    # itself, with 400 unless allowed here (2026-10-20).
    allow_private_network=True,
)
app.middleware("http")(private_network_headers)
app.include_router(router)
