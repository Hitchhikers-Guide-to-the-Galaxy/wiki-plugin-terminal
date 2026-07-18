// wiki-plugin-terminal
//
// One item type: terminal — successor to the shell plugin.
//
// item: {
//   type: "terminal",
//   text: "the script",                  // same semantics as a shell item
//   session: "localhost-admin",          // optional named pty; shared when named
//   service: "http://terminal.localhost" // optional FastAPI service override
// }
//
// Leading ALL-CAPS lines of the text are formatting directives (see
// parseDirectives in helpers.js), stripped from the displayed/pasted/run
// script:
//
//   COLOR: green     named scheme — dark, paper, green, amber, solarized,
//                    solarized-light, dracula, nord (COLOUR:/THEME: accepted)
//   HEIGHT: 320      terminal area height in px
//   FONT: 14         font size
//   SESSION: build   pty session name
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
import { expand, sessionName, serviceBase, wsUrl, makeCaptureScanner, originTrust,
  parseDirectives, schemeFor, attachResult } from './helpers.js'

hljs.registerLanguage('bash', bash)

// The script is always shell — highlight as bash to match the code plugin.
// (A future `language` field could route LiveCode/wasm here instead.)
const highlightScript = text => hljs.highlight(text || '', { language: 'bash' }).value

// Default palette for the baked CSS; per-item schemes from a COLOR: directive
// override with inline styles at open time.
const THEME = schemeFor('dark')

const STYLE = `
  .terminal-item .terminal-script { background:#fff8e6; border-left:3px solid #ffb000 }
  .terminal-item .terminal-script code.hljs { background:transparent;
    white-space:pre-wrap; padding:6px }
  .terminal-item .terminal-tools { margin-top:4px }
  .terminal-item .terminal-tools button { margin-right:4px; font-size:11px }
  .terminal-item.term-open .terminal-tools .t-term { background:#333; color:#fff }
  .terminal-item .terminal-reply { margin-top:4px }
  .terminal-item .terminal-reply pre.hljs { margin:0; padding:6px }
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

  /* workflow-gated step (wiki-plugin-termflow locked this item via a
     'workflow-lock' event): no toolbar. A red left bar and faint red tint
     mark it clearly as a *blocked* terminal step — distinct from a runnable
     step's amber bar — until its guard passes and it unlocks. */
  .terminal-item .wf-lock-hint { display:none; margin-top:3px; font-size:11px; color:#b03a3a }
  .terminal-item .wf-lock-hint::before { content:'🔒 ' }
  .terminal-item.wf-locked .terminal-script { background:#fdecec;
    border-left:3px solid #d64545; opacity:.9 }
  .terminal-item.wf-locked .terminal-tools { display:none }
  .terminal-item.wf-locked .wf-lock-hint { display:block }

  /* bash token palette, scoped to terminal items. Self-contained on purpose:
     the code plugin only ships highlight.css from 0.6.0, so borrowing it
     404s on farms with an older wiki core. Scoping keeps a newer code
     plugin's own theme untouched. */
  .terminal-item .hljs-comment { color:#6a737d }
  .terminal-item .hljs-keyword { color:#d73a49 }
  .terminal-item .hljs-string { color:#032f62 }
  .terminal-item .hljs-built_in { color:#005cc5 }
  .terminal-item .hljs-variable, .terminal-item .hljs-template-variable { color:#e36209 }
  .terminal-item .hljs-number, .terminal-item .hljs-literal { color:#005cc5 }
  .terminal-item .hljs-meta { color:#032f62 }
  .terminal-item .hljs-title, .terminal-item .hljs-function { color:#6f42c1 }
`

// Stylesheets to load: only the plugin's own bundle (xterm.css — without it
// the hidden helper textarea renders as a visible box). Script and captured
// output styling is fully self-contained in STYLE above.
const LINK_CSS = ['/plugins/terminal/terminal.css']

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
  const { script } = parseDirectives(item.text)
  $item.append(`
    <div class="terminal-item">
      <pre class="terminal-script hljs"><code class="hljs language-bash">${highlightScript(script)}</code></pre>
      <div class="terminal-tools"></div>
      <div class="wf-lock-hint"></div>
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
  // A workflow may have stored this step's last result on the item; render it so
  // a reload or a history rewind shows what the step produced (lab notebook).
  if (item.result) renderReply($item, item.result)
}

const renderReply = ($item, { stdout, stderr, exit }) => {
  $item.find('.terminal-reply').html(`
    ${stderr ? `<pre class="stderr hljs"><code class="hljs">${expand(stderr)}</code></pre>` : ''}
    <pre class="hljs"><code class="hljs">${expand(stdout || '')}</code></pre>
    <span class="exit">exit ${exit}</span>
  `)
}

// A HOST directive routes the run through ssh on the named host (the service
// allowlists it and uses the viewer's own key); without it, the local shell.
const run = async ($item, script, base, host) => {
  $item.trigger('terminal-run', { script })
  $item.find('.terminal-reply').html('<span class="exit">running…</span>')
  try {
    const res = await fetch(`${base}/terminal/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: script || '', host: host || null }),
    })
    renderReply($item, await res.json())
  } catch (err) {
    renderReply($item, { stdout: '', stderr: String(err), exit: -1 })
  }
}

// Workflow runner: how wiki-plugin-termflow runs a `terminal` step. It executes
// the step body (already the stripped script) via /terminal/run and renders the
// captured output inline, returning the outcome to the step-through.
const runStep = async ({ item, $item, body }) => {
  const base = serviceBase(item, window.location.protocol)
  const { host } = parseDirectives(item.text)
  $item.trigger('terminal-run', { script: body })
  $item.find('.terminal-reply').html('<span class="exit">running…</span>')
  try {
    const res = await fetch(`${base}/terminal/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: body || '', host: host || null }),
    })
    const data = await res.json()
    renderReply($item, data)
    // Return the item carrying its result so the workflow can journal a native
    // edit — that's what records the step in the page history for rewind.
    const result = { stdout: data.stdout, stderr: data.stderr, exit: data.exit, date: Date.now() }
    return { ok: data.exit === 0, exit: data.exit, output: data.stdout, item: attachResult(item, result) }
  } catch (err) {
    renderReply($item, { stdout: '', stderr: String(err), exit: -1 })
    return { ok: false, exit: -1, output: String(err) }
  }
}

const attach = ($item, item, base, opts = {}) => {
  // The panel is shown before attach is called, so the host already has a real
  // layout — no .show() here (panel visibility is the toggle).
  const host = $item.find('.terminal-host').get(0)

  // Reuse the live terminal — but only while its host is still in the
  // document. An edit re-emits a fresh wrapper, orphaning the old xterm; in
  // that case dispose it and attach anew (the pty session itself persists
  // server-side, so the shell survives — only local scrollback is lost).
  const cached = $item.data('terminal')
  if (cached) {
    if (cached.host === host) return cached
    cached.socket.close()
    cached.term.dispose()
    $item.removeData('terminal')
  }

  const theme = schemeFor(opts.scheme)
  if (opts.height) host.style.height = `${opts.height}px`
  host.style.background = theme.background
  const term = new Terminal({ fontSize: opts.fontSize || 12, cursorBlink: true, theme })
  const fit = new FitAddon()
  term.loadAddon(fit)
  term.open(host)

  // A HOST directive makes the pty an ssh session to that host (viewer's key);
  // the service allowlists it. Passed as a query param at session-create time.
  const hostQuery = opts.host ? `?host=${encodeURIComponent(opts.host)}` : ''
  const socket = new WebSocket(wsUrl(base, `/terminal/pty/${sessionName(item, opts.session)}${hostQuery}`))
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
  // sequence arrives — accumulating across frames, since the marker can split —
  // with a generous fallback only for shells that never send it (a slow login
  // shell sourcing a heavy ~/.zshrc can take seconds to reach its first prompt).
  let markReady
  const ready = new Promise(resolve => { markReady = resolve })
  setTimeout(markReady, 8000)
  let probe = ''

  socket.onmessage = event => {
    const bytes = new Uint8Array(event.data)
    term.write(bytes)
    const text = decoder.decode(bytes, { stream: true })
    if (probe !== null) {
      probe = (probe + text).slice(-4096)
      if (probe.includes('\x1b[?2004h')) {
        markReady()
        probe = null
      }
    }
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

  const handle = { term, fit, socket, refit, send, ready, host, theme }
  $item.data('terminal', handle)
  return handle
}

// Bracketed paste: zsh inserts the text as one editable block at the prompt
// (multi-line scripts land intact, cursor ready) without executing it. Gated on
// `ready` so the markers are never sent before the shell enables paste mode.
const pasteScript = (handle, script) =>
  handle.ready.then(() => handle.send(`\x1b[200~${script || ''}\x1b[201~`))

const bind = async ($item, item) => {
  $item.find('.terminal-script').on('dblclick', () => wiki.textEditor($item, item))

  // Gate on the ORIGIN of the page this item lives on — not the browser's
  // address bar. Federated wiki carries each lineup page's home site on the
  // enclosing .page ($page data-site); a page that belongs to the site being
  // viewed has none, so fall back to the view host. A public page a viewer is
  // merely browsing stays inert (display only, like the code plugin); the
  // viewer's own local page runs live; a trusted remote page is *offered*.
  const originSite = $item.parents('.page').data('site') || window.location.hostname
  const trust = originTrust(originSite, window.isLocalMirror, window.trustedAuthors)
  if (trust === 'inert') return

  const base = serviceBase(item, window.location.protocol)
  if (!(await healthy(base))) return // no local pty reachable: display only

  // Guard against fedwiki binding the *same* rendered item twice (the async
  // health check above can let two binds interleave). Key the flag on the
  // .terminal-item wrapper, which emit recreates on every render — so an edit,
  // which re-emits a fresh wrapper, correctly rebuilds the toolbar instead of
  // being skipped (keying on the outer .item, which persists, would suppress it).
  const $box = $item.find('.terminal-item')
  if ($box.data('bound')) return
  $box.data('bound', true)

  // Formatting directives from the leading lines of the item text; the script
  // is what remains. Everything below runs against the stripped script.
  const opts = parseDirectives(item.text)
  const { script } = opts

  // A trusted REMOTE page (from a site in window.trustedAuthors) is never
  // auto-run: one explicit button runs its script on the viewer's OWN local pty
  // (base is terminal.localhost = the viewer's loopback). A HOST directive can
  // still ssh onward with the viewer's key. No live terminal, no auto-attach —
  // deliberate consent is the whole point of instructing a local shell from a
  // page you did not write.
  if (trust === 'trusted') {
    const $tools = $item.find('.terminal-tools')
    $tools.html(`<button class="t-run-remote" title="run this script from ${expand(originSite)} on your own machine">▶ run · from ${expand(originSite)}</button>`)
    $tools.find('.t-run-remote').on('click', () => run($item, script, base, opts.host))
    return
  }

  // trust === 'local' — the viewer's own page: the full live toolbar, as before.
  // run is opt-in (RUN directive): one-shot capture has no pty, so anything
  // that prompts — sudo above all — would hang. The live terminal always works.
  const $tools = $item.find('.terminal-tools')
  $tools.html(`
    ${opts.run ? '<button class="t-run" title="run once, capture the output">run</button>' : ''}
    <button class="t-term" title="toggle a live terminal with the script pasted">terminal</button>
    <button class="t-tab" title="open the session in a new tab">tab ↗</button>
  `)

  const $panel = $item.find('.terminal-panel')
  $panel.css('background', schemeFor(opts.scheme).background)

  // Workflow gating (wiki-plugin-termflow). A workflow item on the page may lock
  // this step until its guard passes; we render the lock and otherwise stay a
  // normal terminal item. Listen for the dispatched event, and apply any verdict
  // already standing (the workflow may have bound and evaluated before us).
  const applyLock = st => {
    $box.toggleClass('wf-locked', !!(st && st.locked))
    $item.find('.wf-lock-hint').text(st && st.guard ? `needs: ${st.guard}` : 'locked')
  }
  $item.on('workflow-lock', (_e, st) => applyLock(st))
  const standing = window.workflow?.getLock?.($item.parents('.page').data('key') || 'page', item.id)
  if (standing) applyLock(standing)

  // run — one-shot capture, no terminal UI (HOST directive ssh's out)
  $tools.find('.t-run').on('click', () => run($item, script, base, opts.host))

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
    const handle = attach($item, item, base, opts)
    $item.find('.terminal-name').text(sessionName(item, opts.session) + (opts.host ? ` @${opts.host}` : ''))
    if (!$item.data('pasted')) {
      pasteScript(handle, script)
      $item.data('pasted', true)
    }
    requestAnimationFrame(() => { handle.refit(); handle.term.focus() })
  }
  $tools.find('.t-term').on('click', () => setOpen(!$box.hasClass('term-open')))
  $item.find('.t-close').on('click', () => setOpen(false))

  // paste — re-paste the (possibly edited) script at the prompt
  $item.find('.t-paste').on('click', () => pasteScript(attach($item, item, base, opts), script))

  // ⏎ — press Return to run whatever is at the prompt
  $item.find('.t-enter').on('click', () => attach($item, item, base, opts).send('\r'))

  // ⤢ — zoom the panel fullscreen
  $item.find('.t-zoom').on('click', () => {
    $panel.toggleClass('zoomed')
    requestAnimationFrame(() => attach($item, item, base, opts).refit())
  })
  $(document).on('keydown.terminal', event => {
    if (event.key === 'Escape' && $panel.hasClass('zoomed')) {
      $panel.removeClass('zoomed')
      requestAnimationFrame(() => attach($item, item, base, opts).refit())
    }
  })

  $tools.find('.t-tab').on('click', () =>
    window.open(`${base}/terminal/page?session=${sessionName(item, opts.session)}` +
      (opts.host ? `&host=${encodeURIComponent(opts.host)}` : ''), '_blank')
  )
}

// Register the terminal adapter on the shared workflow registry (idempotent;
// wiki-plugin-termflow may or may not be present). This lets a workflow item
// run terminal steps and read their scripts.
const registerWorkflowAdapter = () => {
  const w = (window.workflow = window.workflow || {})
  w.runners = w.runners || {}
  w.scriptOf = w.scriptOf || {}
  w.runners.terminal = w.runners.terminal || runStep
  w.scriptOf.terminal = w.scriptOf.terminal || (item => parseDirectives(item.text).script)
}

if (typeof window !== 'undefined') {
  window.plugins.terminal = { emit, bind }
  registerWorkflowAdapter()
}
