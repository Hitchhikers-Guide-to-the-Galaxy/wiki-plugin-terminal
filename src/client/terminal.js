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
  parseDirectives, schemeFor, attachResult, applyNeeds, resolveScript, needsPayload,
  needWarnings, buttonLabel, STYLE, serviceOrigin, pageRef, isLocalHost } from './helpers.js'

hljs.registerLanguage('bash', bash)

// The script is always shell — highlight as bash to match the code plugin.
// (A future `language` field could route LiveCode/wasm here instead.)
const highlightScript = text => hljs.highlight(text || '', { language: 'bash' }).value

// Default palette for the baked CSS; per-item schemes from a COLOR: directive
// override with inline styles at open time.
const THEME = schemeFor('dark')

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

// ── Where the page lives, and what this machine trusts ──────────────────────
//
// The lineup carries each page's home site; a page of the site being viewed
// has none, so the view host stands in. The browser's own origin decides
// whether a run needs the person's grant (Unlock): a public page driving the
// local shell must hold one; a *.localhost page never does.
const pageContext = ($item, item) => {
  const $page = $item.parents('.page')
  const site = $page.data('site') || window.location.hostname
  const ref = pageRef(site, $page.attr('id') || '', item.id)
  const isLocalPage = isLocalHost(String(site)) || Boolean(window.isLocalMirror)
  const isLocalOrigin = isLocalHost(window.location.hostname) || Boolean(window.isLocalMirror)
  return { ref, isLocalPage, isLocalOrigin, site: String(site) }
}

// The trust list lives with the service (~/.config/wiki-plugin-terminal/
// trust.json), not in the browser: fetched once per page load. While the
// fetch is in flight emit sees no list and chips stay plain; bind waits.
const trustList = base => {
  if (!window.wikiTerminalTrust) {
    window.wikiTerminalTrust = fetch(`${base}/terminal/trust`, {
      headers: authHeaders(base), signal: AbortSignal.timeout(2500) })
      .then(r => (r.ok ? r.json() : { sites: [] }))
      .then(t => { window.wikiTerminalTrustSites = t.sites || []; return t })
      .catch(() => ({ sites: [] }))
  }
  return window.wikiTerminalTrust
}

// Unlock: a grant the person minted on the service's own page, handed back
// by postMessage and kept per tab. Sent as a bearer; websockets send it as
// their first frame. Never a cookie (third-party cookies are blocked).
const grantKey = base => `wiki-terminal-unlock:${serviceOrigin(base)}`
const grantOf = base => {
  try {
    const raw = sessionStorage.getItem(grantKey(base))
    if (!raw) return null
    const g = JSON.parse(raw)
    if (g.exp * 1000 < Date.now()) { sessionStorage.removeItem(grantKey(base)); return null }
    return g.token
  } catch { return null }
}
const authHeaders = base => {
  const token = grantOf(base)
  return token ? { Authorization: `Bearer ${token}` } : {}
}
const unlock = base => new Promise(resolve => {
  const origin = serviceOrigin(base)
  const onMessage = event => {
    if (event.origin !== origin || !event.data) return
    if (event.data.type === 'wiki-terminal-unlock') {
      try { sessionStorage.setItem(grantKey(base), JSON.stringify({ token: event.data.token, exp: event.data.exp })) } catch {}
      window.removeEventListener('message', onMessage)
      resolve(true)
    } else if (event.data.type === 'wiki-terminal-lock') {
      try { sessionStorage.removeItem(grantKey(base)) } catch {}
    }
  }
  window.addEventListener('message', onMessage)
  const popup = window.open(`${base}/terminal/unlock?origin=${encodeURIComponent(window.location.origin)}`,
    'wiki-terminal-unlock', 'popup,width=520,height=520')
  if (!popup) { window.removeEventListener('message', onMessage); resolve(false) }
  const poll = setInterval(() => {
    if (popup && popup.closed) { clearInterval(poll); window.removeEventListener('message', onMessage); resolve(Boolean(grantOf(base))) }
  }, 500)
})

// One POST to the service with the page's provenance and the person's grant;
// a 401 means locked — offer the unlock once and retry.
const post = async (base, path, body, ctx) => {
  const send = () => fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders(base) },
    body: JSON.stringify(body),
  })
  let res = await send()
  if (res.status === 401 && ctx && !ctx.isLocalOrigin) {
    if (await unlock(base)) res = await send()
  }
  return res
}

const emit = ($item, item) => {
  ensureAssets()
  const opts = parseDirectives(item.text)
  const { script, needs } = opts
  // Chips are gated on the same origin trust the toolbar uses: on a page the
  // viewer is merely browsing, declared names stay plain text. Computed here
  // (not in bind) because emit renders the script pane.
  const originSite = $item.parents('.page').data('site') || window.location.hostname
  const trust = originTrust(originSite, window.isLocalMirror, window.wikiTerminalTrustSites)
  // BUTTON mode renders as a button on the viewer's own page and on a trusted
  // page (where the click goes through the service's verified paste).
  const buttonMode = opts.button && trust !== 'inert'
  $item.append(`
    <div class="terminal-item${buttonMode ? ' term-button-mode' : ''}">
      <pre class="terminal-script hljs"><code class="hljs language-bash">${applyNeeds(highlightScript(script), needs, trust)}</code></pre>
      ${buttonMode ? `<div class="terminal-go"><button class="t-go" disabled
        title="terminal service unreachable — display only">${expand(buttonLabel(opts))}</button></div>` : ''}
      <div class="terminal-tools"></div>
      <div class="terminal-needs-hint"></div>
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
  bindNeeds($item, item)
  // A workflow may have stored this step's last result on the item; render it so
  // a reload or a history rewind shows what the step produced (lab notebook).
  if (item.result) renderReply($item, item.result)
}

// Chip interactions. Bound in emit (not bind) so they work even where no local
// pty answers — explaining a command is useful with or without a shell.
//
// Values the reader types into an `ask` chip are held on the .terminal-item
// wrapper, which emit recreates per render; substitution into paste/run is
// Phase 2's job, this only records intent.
const bindNeeds = ($item, item) => {
  const $box = $item.find('.terminal-item')
  const follow = (e, name) => {
    e.preventDefault()
    e.stopPropagation()
    if (window.wiki && window.wiki.doInternalLink) {
      window.wiki.doInternalLink(name, e.shiftKey ? null : $item.parents('.page'))
    }
  }
  // Pulldown chips: fill options from the local service (names only) and record
  // selections — sshhost picks substitute into the pasted text like ask values;
  // vault picks steer which Keychain entry resolves at attach time.
  const $picks = $box.find('select.term-need')
  if ($picks.length && item) {
    const base = serviceBase(item, window.location.protocol)
    fetch(`${base}/terminal/options`, { signal: AbortSignal.timeout(2500) })
      .then(r => (r.ok ? r.json() : null))
      .then(opts => {
        if (!opts) return
        $picks.each(function () {
          const kind = $(this).data('kind')
          const names = (kind === 'vault' ? opts.vault
            : kind === 'claudesession' ? opts.claude_sessions
            : opts.hosts) || []
          const current = $(this).val()
          for (const n of names) {
            // claude_sessions entries are {id, label}; the others plain names
            const value = typeof n === 'object' ? n.id : n
            const text = typeof n === 'object' ? n.label : n
            if (value !== current)
              $(this).append($('<option>').attr('value', value).text(text))
          }
        })
      })
      .catch(() => {})
    $picks.on('click', e => e.stopPropagation()).on('change', function () {
      const name = $(this).data('need')
      const value = $(this).val()
      if ($(this).data('kind') === 'vault') {
        const picks = $box.data('needPicks') || {}
        picks[name] = value
        $box.data('needPicks', picks)
      } else {
        const values = $box.data('needValues') || {}
        values[name] = value
        $box.data('needValues', values)
      }
    })
  }
  // A keychain or plain-value chip is not editable, so a click follows its page.
  $box.find('.term-need-linked:not(.term-need-ask)').on('click', function (e) {
    follow(e, $(this).data('link'))
  })
  // An `ask` chip belongs to the reader: a plain click edits it, so following
  // its explainer needs a modifier (the title says so).
  $box.find('.term-need-ask').on('click', function (e) {
    const link = $(this).data('link')
    if (link && (e.metaKey || e.ctrlKey)) follow(e, link)
  }).on('input', function () {
    const values = $box.data('needValues') || {}
    values[$(this).data('need')] = $(this).text().trim()
    $box.data('needValues', values)
  }).on('keydown', function (e) {
    // Newlines would break the one-line shape of the command.
    if (e.key === 'Enter') { e.preventDefault(); $(this).blur() }
  })
}

const renderReply = ($item, { stdout, stderr, exit, verified }) => {
  $item.find('.terminal-reply').html(`
    ${stderr ? `<pre class="stderr hljs"><code class="hljs">${expand(stderr)}</code></pre>` : ''}
    <pre class="hljs"><code class="hljs">${expand(stdout || '')}</code></pre>
    <span class="exit">exit ${expand(exit)}${verified && verified.site ? ` · verified · ${expand(verified.site)}` : ''}</span>
  `)
}

// A HOST directive routes the run through ssh on the named host (the service
// allowlists it and uses the viewer's own key); without it, the local shell.
const run = async ($item, script, base, host, session, ctx, item) => {
  $item.trigger('terminal-run', { script })
  $item.find('.terminal-reply').html('<span class="exit">running…</span>')
  try {
    const body = { text: script || '', host: host || null, session: session || null }
    // A page that is not local says where it lives and what it publishes; the
    // service checks that against the site itself before anything runs.
    if (ctx && (!ctx.isLocalPage || !ctx.isLocalOrigin)) { body.page = ctx.ref; body.source = item ? item.text : undefined }
    const res = await post(base, '/terminal/run', body, ctx)
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
  // document AND its socket still breathes. An edit re-emits a fresh wrapper,
  // orphaning the old xterm; a session that ended (exit, a kill, a service
  // restart) leaves a dead socket behind — a frozen window wearing the old
  // REPL's last frame, eating keystrokes. Either way: dispose and attach
  // anew, which also recreates the session server-side on first input.
  const cached = $item.data('terminal')
  if (cached) {
    if (cached.host === host && cached.socket.readyState <= WebSocket.OPEN) return cached
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
  // From a public origin the pty asks for the person's grant as its first frame.
  if (!(isLocalHost(window.location.hostname) || window.isLocalMirror)) {
    const token = grantOf(base)
    socket.addEventListener('open', () => socket.send(JSON.stringify({ type: 'auth', token })), { once: true })
  }
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
  let lastData = Date.now()

  socket.onmessage = event => {
    lastData = Date.now()
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
  socket.onclose = () => term.write(
    '\r\n\x1b[2m[session ended — close and reopen the terminal for a fresh shell]\x1b[0m\r\n')

  term.onData(data => socket.send(JSON.stringify({ type: 'input', data })))
  term.onResize(({ cols, rows }) => {
    if (socket.readyState === WebSocket.OPEN)
      socket.send(JSON.stringify({ type: 'resize', cols, rows }))
  })
  new ResizeObserver(() => fit.fit()).observe(host)

  const handle = { term, fit, socket, refit, send, ready, host, theme,
    lastOutput: () => lastData }
  $item.data('terminal', handle)
  return handle
}

// Wait until the pty has been silent for quietMs — a REPL that was just booted
// has finished drawing its first screen. Hard-capped, since some TUIs animate
// even at rest; on cap we proceed rather than strand the click.
const awaitQuiet = (handle, quietMs = 900, maxMs = 15000) => new Promise(resolve => {
  const started = Date.now()
  const tick = () => {
    if (Date.now() - handle.lastOutput() >= quietMs ||
        Date.now() - started >= maxMs) return resolve()
    setTimeout(tick, 150)
  }
  setTimeout(tick, quietMs)
})

// Bracketed paste: zsh inserts the text as one editable block at the prompt
// (multi-line scripts land intact, cursor ready) without executing it. Gated on
// `ready` so the markers are never sent before the shell enables paste mode.
const pasteScript = (handle, script) =>
  handle.ready.then(() => handle.send(`\x1b[200~${script || ''}\x1b[201~`))

// Ask the service to resolve this session's declared needs. Secrets go into the
// session's private .needs file (sourced by its shell); only non-secret values —
// a login name — come back here, for substitution into what we display and
// paste. Failure is not fatal: the script simply pastes with its placeholders.
const resolveNeeds = async (base, session, needs, $box) => {
  const payload = needsPayload(needs, $box.data('needPicks') || {})
  if (!payload.length) return {}
  try {
    const res = await fetch(`${base}/terminal/needs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session, needs: payload }),
    })
    if (!res.ok) return {}
    const out = await res.json()
    $box.data('needsResolved', out)
    const notes = []
    if (out.blocked && out.blocked.length) {
      notes.push(`your Keychain is waiting on you for ${out.blocked.join(', ')} `
        + '— approve the access prompt (or unlock the login keychain), then click again')
    }
    if (out.unknown && out.unknown.length) {
      notes.push(`not in your vault: ${out.unknown.join(', ')} `
        + '— fill it in by hand, or add the entry to vault.json')
    }
    if (notes.length) $box.find('.terminal-needs-hint').text(notes.join('. '))
    return out
  } catch {
    return {}
  }
}

// The text actually pasted: ask-chip edits and service-resolved logins folded
// in, secrets left as $NAME for the shell to expand.
const scriptFor = ($box, script, needs) => resolveScript(script, needs, {
  ...(($box.data('needsResolved') || {}).values || {}),
  ...($box.data('needValues') || {}),
})

const bind = async ($item, item) => {
  $item.find('.terminal-script').on('dblclick', () => wiki.textEditor($item, item))

  // Gate on the ORIGIN of the page this item lives on — not the browser's
  // address bar. Federated wiki carries each lineup page's home site on the
  // enclosing .page ($page data-site); a page that belongs to the site being
  // viewed has none, so fall back to the view host. A public page a viewer is
  // merely browsing stays inert (display only, like the code plugin); the
  // viewer's own local page runs live; a trusted remote page is *offered*.
  const ctx = pageContext($item, item)
  // The service's own base first (it holds the trust list); a page-named
  // service is honoured only on the viewer's own page.
  let base = serviceBase(item, window.location.protocol, ctx.isLocalPage)
  // From a public https page a loopback name is reachable over plain http
  // (a potentially trustworthy origin, exempt from mixed content) and needs
  // no locally trusted certificate; try the page's scheme, then the other.
  if (!(await healthy(base))) {
    const other = base.startsWith('https:') ? base.replace(/^https:/, 'http:') : base.replace(/^http:/, 'https:')
    if (item.service && ctx.isLocalPage) return
    if (!(await healthy(other))) return // no local pty reachable: display only
    base = other
  }
  const trusted = await trustList(base)
  const trust = originTrust(ctx.site, window.isLocalMirror, trusted.sites)
  if (trust === 'inert') return

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
    // A trusted REMOTE page: the service verifies the script against the
    // page as its home site publishes it before anything runs, and a public
    // origin also needs the person's grant. Everything is a click; nothing
    // runs on view — a GUARD is a button here, never a poll.
    const $tools = $item.find('.terminal-tools')
    const site = expand(ctx.site)
    $tools.html(`
      <span class="t-verify" title="checking with ${site}…">verifying…</span>
      <button class="t-run-remote" title="run this script, as ${site} publishes it, on your own machine">▶ run · ${site}</button>
      ${opts.guard ? `<button class="t-check" title="run the GUARD test: ${expand(opts.guard)}">check</button>` : ''}
      ${!ctx.isLocalOrigin ? `<button class="t-unlock" title="allow ${expand(window.location.origin)} to run verified scripts on this machine">unlock</button>` : ''}
    `)
    const $verify = $tools.find('.t-verify')
    const showVerdict = v => {
      if (v.ok) $verify.text(`verified · ${v.site || ctx.site}${v.locked ? ' · locked' : ''}`).attr('title', v.at || '')
      else $verify.text('not verified').attr('title', v.why || '')
      $tools.find('.t-run-remote, .t-check').prop('disabled', !v.ok)
      $tools.find('.t-unlock').toggle(Boolean(v.locked))
    }
    const verify = async () => {
      try {
        const res = await post(base, '/terminal/verify', { source: item.text, page: ctx.ref })
        showVerdict(await res.json())
      } catch (err) { showVerdict({ ok: false, why: String(err) }) }
    }
    verify()
    $tools.find('.t-run-remote').on('click', () => run($item, script, base, opts.host, null, ctx, item))
    $tools.find('.t-unlock').on('click', async () => { await unlock(base); verify() })
    $tools.find('.t-check').on('click', async () => {
      try {
        const res = await post(base, '/terminal/check',
          { guards: [{ id: item.id, test: opts.guard }], page: ctx.ref, source: item.text, timeout: 20 }, ctx)
        const j = await res.json()
        const ok = j.results && j.results[item.id]
        $item.find('.terminal-reply').html(`<span class="exit">${ok ? 'guard passes' : `guard fails${j.error ? ` — ${expand(j.error)}` : ''}`}</span>`)
      } catch (err) { renderReply($item, { stdout: '', stderr: String(err), exit: -1 }) }
    })
    // BUTTON on a trusted page: the click sends the verified script into a
    // live session on this machine through the service, never the raw socket.
    if (opts.button) {
      const $go = $box.find('.t-go')
      $go.prop('disabled', false).attr('title', `send to session ${sessionName(item, opts.session)} on this machine`)
      $go.on('click', async () => {
        $go.prop('disabled', true)
        try {
          const res = await post(base, '/terminal/paste',
            { session: sessionName(item, opts.session), text: script, page: ctx.ref, source: item.text }, ctx)
          const j = await res.json()
          $go.text(j.ok ? 'sent ✓' : (j.error || 'refused')).toggleClass('t-go-sent', Boolean(j.ok))
        } catch (err) { $go.text(String(err)) }
        setTimeout(() => $go.prop('disabled', false).removeClass('t-go-sent').text(buttonLabel(opts)), 2500)
      })
    }
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

  // Authoring mistakes worth saying out loud rather than debugging at a prompt:
  // a name the shell already owns, or a secret the script forgot to write as
  // $NAME (which would paste as a bare word and never be substituted).
  const warnings = needWarnings(opts.needs, script)
  if (warnings.length) $item.find('.terminal-needs-hint').text(warnings.join(' '))

  // Arm the session before anything attaches: the service must write the
  // resolved .needs file *before* the shell starts, because that shell sources
  // it at login. If the shell is already running, source it now — the line
  // names a path, never a secret.
  const armed = async () => {
    const session = sessionName(item, opts.session)
    const out = await resolveNeeds(base, session, opts.needs, $box)
    const handle = attach($item, item, base, opts)
    if (out.live && out.secrets && out.secrets.length) {
      await handle.ready
      handle.send('source "$ZDOTDIR/.needs"\r')
    }
    return handle
  }

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

  // run — one-shot capture, no terminal UI (HOST directive ssh's out).
  // Resolve first so the run can source the same secrets the terminal would.
  $tools.find('.t-run').on('click', async () => {
    const session = sessionName(item, opts.session)
    await resolveNeeds(base, session, opts.needs, $box)
    run($item, scriptFor($box, script, opts.needs), base, opts.host, session)
  })

  // terminal — toggle the live area. Opening attaches (once) and pastes the
  // script ready to run; closing hides the area but keeps the session alive.
  //
  // Open state lives as a single `term-open` class on the item, and CSS derives
  // both the panel's visibility and the button's active style from it. The item
  // element survives fedwiki re-binding the plugin (which rebuilds the toolbar
  // buttons), so the state can't be wiped out from under us.
  const setOpen = async open => {
    $box.toggleClass('term-open', open)
    if (!open) return $panel.removeClass('zoomed')
    const handle = await armed()
    $item.find('.terminal-name').text(sessionName(item, opts.session) + (opts.host ? ` @${opts.host}` : ''))
    if (!$item.data('pasted')) {
      pasteScript(handle, scriptFor($box, script, opts.needs))
      $item.data('pasted', true)
    }
    requestAnimationFrame(() => { handle.refit(); handle.term.focus() })
  }
  $tools.find('.t-term').on('click', () => setOpen(!$box.hasClass('term-open')))
  $item.find('.t-close').on('click', () => setOpen(false))

  // paste — re-paste the (possibly edited) script at the prompt
  $item.find('.t-paste').on('click', async () =>
    pasteScript(await armed(), scriptFor($box, script, opts.needs)))

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

  // BUTTON mode — one click sends the script into the live session and presses
  // Return, without opening the panel: the way to drive a long-lived REPL
  // (e.g. Claude Code) waiting at the shared session's prompt. The button was
  // emitted disabled; only a healthy local service reaches this line, so arm it
  // now. paste-then-Enter ordering is safe: pasteScript resolves on the
  // shell's ready handshake, by which time the socket is open, and send()
  // preserves order on one socket.
  if (opts.button) {
    const $go = $box.find('.t-go')
    const label = $go.text()
    // A button's script belongs to the CLICK: opening the terminal view is
    // just a window onto the session, never a paste (a REPL mid-boot must not
    // be fed the prompt early, and a watcher expects to watch, not to type).
    $item.data('pasted', true)

    // GUARD — a readiness test run one-shot on the service (exit 0 = ready).
    // While it fails, the button is a fix-it affordance: it opens the live
    // terminal (booting the REPL if BOOT says so) so the reader settles the
    // precondition — a /login, a missing tool — and it sends nothing.
    const guardOk = async () => {
      if (!opts.guard) return true
      try {
        const res = await fetch(`${base}/terminal/run`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: opts.guard, timeout: 20 }),
        })
        return (await res.json()).exit === 0
      } catch { return false }
    }
    const showGuard = ok => {
      $go.toggleClass('t-go-guard', !ok)
      $go.text(ok ? label : (opts.guardLabel || 'setup needed'))
      $go.attr('title', ok
        ? `send to session ${sessionName(item, opts.session)}`
        : `${opts.guard} — failing; click to open the terminal and put it right`)
    }
    const freshSession = async () => {
      try {
        const res = await fetch(`${base}/terminal/health`, { signal: AbortSignal.timeout(1500) })
        const j = await res.json()
        return !(j.sessions || []).includes(sessionName(item, opts.session))
      } catch { return false } // health raced away — treat as live, paste plainly
    }

    // After a send, the agent on the other end may rewrite THIS page (tick a
    // phase, walk the button). The stored page changes but the rendered one
    // doesn't — so watch the page's own json and, once its journal grows and
    // settles, reload so the reader sees the work land. Pulsing border while
    // watching; gives up quietly after ten minutes.
    const slug = ($item.parents('.page').attr('id') || '').replace(/_rev\d+$/, '')
    const journalLen = async () => {
      try {
        const res = await fetch(`/${slug}.json`, {
          cache: 'no-store', signal: AbortSignal.timeout(3000) })
        return ((await res.json()).journal || []).length
      } catch { return null }
    }
    const watchPage = async () => {
      if (!slug || $go.data('watching')) return
      $go.data('watching', true).addClass('t-go-watch')
      const start = await journalLen()
      const t0 = Date.now()
      let grown = null
      while (Date.now() - t0 < 10 * 60 * 1000) {
        await new Promise(resolve => setTimeout(resolve, 4000))
        if (!document.contains($go.get(0))) return
        const len = await journalLen()
        if (len == null || start == null) continue
        if (grown != null && len === grown) return window.location.reload()
        if (len > start) grown = len
      }
      $go.removeClass('t-go-watch').data('watching', false)
    }

    // The guard state changes outside the page — a /login in the open
    // terminal, a logout in another window — so a guarded button watches
    // both ways and wears the truth on its face: briskly (5s) while failing,
    // gently (15s) while passing. The watch dies with the wrapper (an edit
    // re-emits a fresh one).
    let guardWatching = false
    const watchGuard = () => {
      if (guardWatching) return
      guardWatching = true
      const tick = async () => {
        if (!document.contains($go.get(0))) { guardWatching = false; return }
        if (!$go.data('busy')) showGuard(await guardOk())
        setTimeout(tick, $go.hasClass('t-go-guard') ? 5000 : 15000)
      }
      setTimeout(tick, 5000)
    }

    // No actionable face until the first guard verdict: a wrong face for the
    // first second reads as a bug (and invites a wrong click).
    if (opts.guard) {
      $go.prop('disabled', true).text('checking…')
      guardOk().then(ok => {
        $go.prop('disabled', false)
        showGuard(ok)
        watchGuard()
      })
    } else {
      $go.prop('disabled', false)
        .attr('title', `send to session ${sessionName(item, opts.session)}`)
    }

    $go.on('click', async () => {
      if ($go.data('busy')) return
      $go.data('busy', true).prop('disabled', true)
      try {
        const ok = await guardOk()
        // BOOT: when this click is what creates the session, run the boot
        // command first (start the REPL) and wait for its first screen to
        // finish drawing. An already-live session is assumed booted.
        const fresh = (opts.boot || !ok) ? await freshSession() : false
        const handle = await armed()
        if (opts.boot && fresh) {
          $go.text('starting…')
          await handle.ready
          handle.send(opts.boot + '\r')
          await awaitQuiet(handle)
        }
        if (!ok) {
          // Precondition unmet: present the terminal, not the prompt — the
          // REPL is sitting exactly where the fix happens (e.g. /login).
          // Zoomed, because a full-screen TUI is unreadable in the small
          // in-column box; Escape drops back to the page.
          showGuard(false)
          await setOpen(true)
          $panel.addClass('zoomed')
          requestAnimationFrame(() => { handle.refit(); handle.term.focus() })
          return
        }
        // BUTTON: show — do the sending in the open, so a closed panel never
        // leaves the reader wondering whether anything happened.
        if (opts.buttonShow && !$box.hasClass('term-open')) await setOpen(true)
        await pasteScript(handle, scriptFor($box, script, opts.needs))
        // A TUI needs a beat to digest a paste before Return registers as
        // "submit" — wait for its echo to settle instead of racing it.
        await awaitQuiet(handle, 350, 2500)
        handle.send('\r')
        $go.text('sent ✓').addClass('t-go-sent')
        watchPage()
      } finally {
        setTimeout(() => {
          $go.removeClass('t-go-sent').prop('disabled', false).data('busy', false)
          if (opts.guard) guardOk().then(showGuard) // the standing watch carries on
          else $go.text(label)
        }, 2000)
      }
    })
    // The script pane is hidden, so its dblclick-to-edit is out of reach:
    // dblclick on the row (not the button itself) opens the editor instead.
    $box.find('.terminal-go').on('dblclick', event => {
      if (!event.target.closest('button')) wiki.textEditor($item, item)
    })
  }
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
  // Trust used to be a browser list set here; it now lives with the service.
  if (!window.trustAuthor) {
    window.trustAuthor = site => console.log(`trust now lives in ~/.config/wiki-plugin-terminal/trust.json — add "${site}" to its sites list`)
  }
}
