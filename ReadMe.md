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
`127.0.0.1`, checks websocket `Origin` against local wiki hosts
(`localhost`, `*.localhost`, `*.fish`), and is simply absent on public
servers, where the plugin renders display-only.

## License

MIT
