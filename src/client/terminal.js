// wiki-plugin-terminal
//
// One item type: terminal — successor to the shell plugin.
//
// item: {
//   type: "terminal",
//   text: "the script",                  // same semantics as a shell item
//   session: "localhost-admin",          // optional named pty; shared when named
//   service: "http://localhost:8000"     // optional FastAPI service override
// }
//
// Degradation: when the pty service is unreachable (public servers), the item
// renders as a code-style display only. When reachable (local-first), a
// toolbar offers:
//   run      — POST /terminal/run, capture {stdout, stderr, exit} inline
//   terminal — attach an interactive xterm to the pty session, in the item
//   send     — send the script to the attached terminal
//   zoom     — expand the item to a full-window overlay (esc restores)
//   tab      — open the session full-bleed in a new browser tab
//
// Output capture: the pty service starts zsh with OSC 133 shell-integration
// hooks; makeCaptureScanner watches the stream and fires a jQuery event
// 'terminal-result' with {output, exit} after each command completes.

import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import { expand, sessionName, serviceBase, wsUrl, makeCaptureScanner } from './helpers.js'

hljs.registerLanguage('bash', bash)

// The script is always shell — highlight as bash to match the code plugin.
// (A future `language` field could route LiveCode/wasm here instead.)
const highlightScript = text => hljs.highlight(text || '', { language: 'bash' }).value

// Dark terminal palette (VS Code "Dark+" flavour). The host and xterm share
// the same background so the column reads as one dark surface.
const THEME = {
  background: '#1e1e1e',
  foreground: '#d4d4d4',
  cursor: '#ffffff',
  cursorAccent: '#1e1e1e',
  selectionBackground: '#264f78',
  black: '#000000', red: '#cd3131', green: '#0dbc79', yellow: '#e5e510',
  blue: '#2472c8', magenta: '#bc3fbc', cyan: '#11a8cd', white: '#e5e5e5',
  brightBlack: '#666666', brightRed: '#f14c4c', brightGreen: '#23d18b',
  brightYellow: '#f5f543', brightBlue: '#3b8eea', brightMagenta: '#d670d6',
  brightCyan: '#29b8db', brightWhite: '#ffffff',
}

const STYLE = `
  .terminal-item .terminal-tools { margin-top:4px }
  .terminal-item .terminal-tools button { margin-right:4px; font-size:11px }
  .terminal-item.term-open .terminal-tools .t-term { background:#333; color:#fff }
  .terminal-item .terminal-reply { margin-top:4px }
  .terminal-item .terminal-reply pre.hljs { margin:0 }
  .terminal-item .terminal-reply pre.stderr code { color:#f14c4c }
  .terminal-item .terminal-reply .exit { font-size:10px; color:#888 }
  .terminal-item .terminal-panel { display:none; margin-top:6px; border-radius:4px;
    overflow:hidden; background:${THEME.background} }
  .terminal-item.term-open .terminal-panel { display:block }
  .terminal-item .terminal-bar { display:flex; align-items:center;
    justify-content:space-between; padding:3px 6px; background:#2d2d2d;
    color:#bbb; font-size:11px; font-family:monospace }
  .terminal-item .terminal-bar .terminal-name { opacity:.8 }
  .terminal-item .terminal-bar button { background:none; border:none;
    color:#bbb; cursor:pointer; font-size:12px; padding:1px 5px; margin-left:2px }
  .terminal-item .terminal-bar button:hover { color:#fff; background:#444;
    border-radius:3px }
  .terminal-item .terminal-host { height:240px; padding:6px;
    background:${THEME.background} }
  .terminal-item .terminal-panel.zoomed { position:fixed; inset:0; z-index:9999;
    margin:0; border-radius:0; display:flex; flex-direction:column }
  .terminal-item .terminal-panel.zoomed .terminal-host { flex:1; height:auto }
`

// Stylesheets to load: the plugin's own bundle (xterm.css — without it the
// hidden helper textarea renders as a visible box) and the code plugin's
// highlight.css theme so the script and captured output match a code item.
const LINK_CSS = ['/plugins/terminal/terminal.css', '/plugins/code/highlight.css']

const ensureAssets = () => {
  if (!document.getElementById('terminal-plugin-style')) {
    const style = document.createElement('style')
    style.id = 'terminal-plugin-style'
    style.textContent = STYLE
    document.head.appendChild(style)
  }
  for (const href of LINK_CSS) {
    if (!document.querySelector(`link[href='${href}']`)) {
      const link = document.createElement('link')
      link.rel = 'stylesheet'
      link.href = href
      document.head.appendChild(link)
    }
  }
}

const healthy = async base => {
  try {
    const res = await fetch(`${base}/terminal/health`, { signal: AbortSignal.timeout(1500) })
    return res.ok
  } catch {
    return false
  }
}

const emit = ($item, item) => {
  ensureAssets()
  $item.append(`
    <div class="terminal-item">
      <pre class="terminal-script hljs"><code class="hljs language-bash">${highlightScript(item.text)}</code></pre>
      <div class="terminal-tools"></div>
      <div class="terminal-reply"></div>
      <div class="terminal-panel">
        <div class="terminal-bar">
          <span class="terminal-name"></span>
          <span class="terminal-acts">
            <button class="t-paste" title="paste the script at the prompt">paste</button>
            <button class="t-enter" title="press Return to run">⏎</button>
            <button class="t-zoom" title="zoom fullscreen">⤢</button>
            <button class="t-close" title="close terminal">✕</button>
          </span>
        </div>
        <div class="terminal-host"></div>
      </div>
    </div>
  `)
}

const renderReply = ($item, { stdout, stderr, exit }) => {
  $item.find('.terminal-reply').html(`
    ${stderr ? `<pre class="stderr hljs"><code class="hljs">${expand(stderr)}</code></pre>` : ''}
    <pre class="hljs"><code class="hljs">${expand(stdout || '')}</code></pre>
    <span class="exit">exit ${exit}</span>
  `)
}

const run = async ($item, item, base) => {
  $item.find('.terminal-reply').html('<span class="exit">running…</span>')
  try {
    const res = await fetch(`${base}/terminal/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: item.text || '' }),
    })
    renderReply($item, await res.json())
  } catch (err) {
    renderReply($item, { stdout: '', stderr: String(err), exit: -1 })
  }
}

const attach = ($item, item, base) => {
  const cached = $item.data('terminal')
  if (cached) return cached

  // The panel is shown before attach is called, so the host already has a real
  // layout — no .show() here (panel visibility is the toggle).
  const host = $item.find('.terminal-host').get(0)
  const term = new Terminal({ fontSize: 12, cursorBlink: true, theme: THEME })
  const fit = new FitAddon()
  term.loadAddon(fit)
  term.open(host)

  const socket = new WebSocket(wsUrl(base, `/terminal/pty/${sessionName(item)}`))
  socket.binaryType = 'arraybuffer'
  const decoder = new TextDecoder()
  const scan = makeCaptureScanner(result => $item.trigger('terminal-result', result))

  // Send pty input, buffering until the socket is open so paste/enter issued
  // immediately after attach are not dropped.
  const send = data => {
    const frame = JSON.stringify({ type: 'input', data })
    if (socket.readyState === WebSocket.OPEN) socket.send(frame)
    else socket.addEventListener('open', () => socket.send(frame), { once: true })
  }

  // Fit once the host has a settled layout — fitting against a zero-height box
  // mis-sizes the cell grid (cursor renders as a tall bar). Defer a frame, then
  // sync the pty to the settled dimensions.
  const refit = () => {
    fit.fit()
    if (socket.readyState === WebSocket.OPEN)
      socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
  }
  requestAnimationFrame(() => { refit(); term.focus() })

  // The shell isn't ready for bracketed paste until its line editor draws the
  // first prompt and enables paste mode (\e[?2004h). Pasting before then leaks
  // the raw \e[200~…\e[201~ markers into the buffer. Resolve `ready` when that
  // sequence arrives, with a fallback so a shell that never sends it (or a
  // re-attach to an already-primed session) still unblocks.
  let markReady
  const ready = new Promise(resolve => { markReady = resolve })
  setTimeout(markReady, 1500)

  socket.onmessage = event => {
    const bytes = new Uint8Array(event.data)
    term.write(bytes)
    const text = decoder.decode(bytes, { stream: true })
    if (text.includes('\x1b[?2004h')) markReady()
    scan(text)
  }
  socket.onopen = () => refit()
  socket.onclose = () => term.write('\r\n\x1b[2m[disconnected]\x1b[0m\r\n')

  term.onData(data => socket.send(JSON.stringify({ type: 'input', data })))
  term.onResize(({ cols, rows }) => {
    if (socket.readyState === WebSocket.OPEN)
      socket.send(JSON.stringify({ type: 'resize', cols, rows }))
  })
  new ResizeObserver(() => fit.fit()).observe(host)

  const handle = { term, fit, socket, refit, send, ready }
  $item.data('terminal', handle)
  return handle
}

// Bracketed paste: zsh inserts the text as one editable block at the prompt
// (multi-line scripts land intact, cursor ready) without executing it. Gated on
// `ready` so the markers are never sent before the shell enables paste mode.
const pasteScript = (handle, item) =>
  handle.ready.then(() => handle.send(`\x1b[200~${item.text || ''}\x1b[201~`))

const bind = async ($item, item) => {
  $item.find('.terminal-script').on('dblclick', () => wiki.textEditor($item, item))

  const base = serviceBase(item)
  if (!(await healthy(base))) return // public server or service down: display only

  // Guard against fedwiki binding the *same* rendered item twice (the async
  // health check above can let two binds interleave). Key the flag on the
  // .terminal-item wrapper, which emit recreates on every render — so an edit,
  // which re-emits a fresh wrapper, correctly rebuilds the toolbar instead of
  // being skipped (keying on the outer .item, which persists, would suppress it).
  const $box = $item.find('.terminal-item')
  if ($box.data('bound')) return
  $box.data('bound', true)

  const $tools = $item.find('.terminal-tools')
  $tools.html(`
    <button class="t-run" title="run once, capture the output">run</button>
    <button class="t-term" title="toggle a live terminal with the script pasted">terminal</button>
    <button class="t-tab" title="open the session in a new tab">tab ↗</button>
  `)

  const $panel = $item.find('.terminal-panel')

  // run — one-shot capture, no terminal UI
  $tools.find('.t-run').on('click', () => run($item, item, base))

  // terminal — toggle the live area. Opening attaches (once) and pastes the
  // script ready to run; closing hides the area but keeps the session alive.
  //
  // Open state lives as a single `term-open` class on the item, and CSS derives
  // both the panel's visibility and the button's active style from it. The item
  // element survives fedwiki re-binding the plugin (which rebuilds the toolbar
  // buttons), so the state can't be wiped out from under us.
  const setOpen = open => {
    $box.toggleClass('term-open', open)
    if (!open) return $panel.removeClass('zoomed')
    const handle = attach($item, item, base)
    $item.find('.terminal-name').text(sessionName(item))
    if (!$item.data('pasted')) {
      pasteScript(handle, item)
      $item.data('pasted', true)
    }
    requestAnimationFrame(() => { handle.refit(); handle.term.focus() })
  }
  $tools.find('.t-term').on('click', () => setOpen(!$box.hasClass('term-open')))
  $item.find('.t-close').on('click', () => setOpen(false))

  // paste — re-paste the (possibly edited) script at the prompt
  $item.find('.t-paste').on('click', () => pasteScript(attach($item, item, base), item))

  // ⏎ — press Return to run whatever is at the prompt
  $item.find('.t-enter').on('click', () => attach($item, item, base).send('\r'))

  // ⤢ — zoom the panel fullscreen
  $item.find('.t-zoom').on('click', () => {
    $panel.toggleClass('zoomed')
    requestAnimationFrame(() => attach($item, item, base).refit())
  })
  $(document).on('keydown.terminal', event => {
    if (event.key === 'Escape' && $panel.hasClass('zoomed')) {
      $panel.removeClass('zoomed')
      requestAnimationFrame(() => attach($item, item, base).refit())
    }
  })

  $tools.find('.t-tab').on('click', () =>
    window.open(`${base}/terminal/page?session=${sessionName(item)}`, '_blank')
  )
}

if (typeof window !== 'undefined') window.plugins.terminal = { emit, bind }
