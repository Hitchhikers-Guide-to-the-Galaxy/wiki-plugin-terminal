# Federated Wiki - Terminal Plugin

A live shell terminal in a wiki page — the successor to
[wiki-plugin-shell](https://github.com/WardCunningham/wiki-plugin-shell),
keeping its item `text` semantics and run-and-capture model, adding an
interactive xterm attached to named pty sessions.

Design: [Terminal Plugin](https://plugin.fedwiki.club/terminal-plugin.html)

## How it works

- **Client** (`src/client/terminal.js`): bundles [@xterm/xterm](https://github.com/xtermjs/xterm.js)
  with the fit addon, styled for the 400px wiki column. Probes the local
  pty service; unreachable → code-style display only (public servers),
  reachable → run / terminal / send / zoom / tab toolbar.
- **Service** (`service/terminal_service.py`): FastAPI router owning ptys
  keyed by session name. Sessions survive detach (tmux semantics) so the
  column view, the zoom overlay, and the fullscreen tab share one shell.
  Spawned zsh emits OSC 133 shell-integration markers; the client scanner
  turns them into per-command `{output, exit}` results fired as the
  `terminal-result` event on the item.
- **Wiki server** (`server/server.js`): intentionally a no-op — live
  capabilities are local-first only.

## Build

    npm install
    npm run build        # clean + test + esbuild → client/terminal.{js,css}
    npm run dev          # watch mode

## Install into a local wiki farm

    ln -s $(pwd) <wiki>/node_modules/wiki-plugin-terminal
    # add "wiki-plugin-terminal": "^0.1.0" to <wiki>/package.json dependencies
    # restart the wiki server

## Wire the pty service into the local FastAPI app

    cp service/terminal_service.py <fastapi-app-dir>/
    # in main.py:
    #   from terminal_service import router as terminal_router
    #   app.include_router(terminal_router)

Or standalone: `uvicorn terminal_service:app --port 4248` (bind 127.0.0.1).

The client reaches the service as `http://terminal.localhost` — a Caddy route to port 4248, per the hitchhiker 42xx port policy. Port 8000 was abandoned: Bitfocus Companion owns it.

## Succession

Legacy `shell` items can be redirected to this plugin via wiki-client's
`window.pluginSuccessor` table (`shell: 'terminal'` — one line, precedent
`mathjax: 'math'`). `factory.json` carries a forward-looking
`"supersedes": ["shell"]` field proposing that the server aggregate
succession declarations from plugins into `/system/factories.json`.

## Security

The pty service is remote code execution by design. It binds to
`127.0.0.1`; Caddy proxies `terminal.localhost` to it from loopback only,
and it is simply absent on public servers, where the plugin renders
display-only. Two trusts decide whether a script runs, and they are kept
apart.

**Page trust — whose text may run.** A page of a local site (`localhost`,
`*.localhost`, or the local mirror farm, where the `wiki-security-author`
client sets `window.isLocalMirror`) runs as before. A page from any other
site runs only if that site is listed in
`~/.config/wiki-plugin-terminal/trust.json` (`{"sites": ["plan.ide.earth"]}`,
mode 600, reloaded on change) AND the service, fetching the page from that
site itself, finds the item text byte-equal to what the browser sent.
Publication is the signature: only the site's owner can publish there. A
trusted page's toolbar wears `verified · <site>`; a stale or edited copy is
refused. Directives travel with the text, so a page cannot strip or alter a
`GUARD`, and `service:` is honoured on local pages only.

**Keyboard trust — the person consents.** A request from a non-local
origin (the public page itself, opened in a browser on this machine) also
needs a grant: the person clicks **unlock**, a popup on `terminal.localhost`
asks whether that origin may run verified scripts for 30 minutes, and hands
the page an origin-bound HMAC token by `postMessage`. The token lives in
that tab's `sessionStorage`, is sent as a bearer and as the first websocket
frame, and dies with the service (the secret is minted at start). Never a
cookie. Nothing runs on view: a `GUARD` on a non-local page is a button, not
a poll.

The health probe remains the backstop — no service, no toolbar — and the
browser adds its own consent when a public https page first reaches a
loopback address (Chrome's Local Network Access prompt). The Terminal
Trust Plan on the private security wiki records the audit this answers.

## License

MIT
