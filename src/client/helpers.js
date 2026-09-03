// wiki-plugin-terminal — pure helpers, kept import-free so node --test can
// exercise them without touching xterm or the DOM.

export const expand = text =>
  String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

// pty sessions are named; items sharing a session share one shell.
// Default: a session private to the item. A SESSION: directive overrides
// the item field.
export const sessionName = (item, override) =>
  (override || item.session || `item-${item.id}`).replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 64)

// Default service is reached by name through Caddy (hitchhiker port policy:
// services live on 42xx behind a .localhost name, never a hardcoded port).
// The scheme follows the PAGE's protocol: an https page (the local mirror
// serves real domain names over Caddy's internal TLS) must not call an http
// service — the browser blocks that as mixed content. Caddy answers
// terminal.localhost on both http and https, so mirroring the page protocol
// works either way. An explicit item.service (full URL) always wins.
export const serviceBase = (item, protocol = 'http:', isLocalPage = true) => {
  // A page-controlled service URL is honoured only on the viewer's own page:
  // a forked public page could otherwise repoint run, needs and the pty at a
  // stranger's host (Terminal Plugin Audit, finding 4.1).
  if (item.service && isLocalPage) return item.service.replace(/\/$/, '')
  const scheme = protocol === 'https:' ? 'https' : 'http'
  return `${scheme}://terminal.localhost`
}

// The service's own origin, for postMessage checks and the trust fetch.
export const serviceOrigin = base => {
  try { return new URL(base).origin } catch { return base }
}

// Where a page lives, as the lineup carries it: a remote page's home site sits
// on the enclosing .page as data('site'); a page of the site being viewed has
// none, so the view host stands in. Pure given the two strings and the id.
export const pageRef = (site, slug, itemId) => ({
  site: String(site || '').toLowerCase(),
  slug: String(slug || '').replace(/_rev\d+$/, ''),
  itemId: String(itemId || ''),
})

// The live terminal is local-first only. Anywhere else — a public server —
// the plugin must behave exactly like the code plugin: display the script and
// nothing more (no toolbar, no network probe). Gate on the wiki's own origin.
export const isLocalHost = hostname =>
  hostname === 'localhost' ||
  hostname === '127.0.0.1' ||
  hostname === '::1' ||
  hostname === '[::1]' ||
  hostname.endsWith('.localhost')

// Two contexts count as local. Either the wiki's own origin is local
// (localhost / *.localhost), OR the page was served by the local mirror farm,
// which sets window.isLocalMirror via the wiki-security-author client. The
// mirror serves real public domain names, so the hostname can't reveal it —
// the flag carries the fact, and live sites never load that client, so it is
// absent there. Kept import-free (isMirror passed in) so node --test can run it.
export const isLocalContext = (hostname, isMirror) =>
  isLocalHost(hostname) || Boolean(isMirror)

// Is the page's ORIGIN site one the viewer has vouched for? Federated wiki
// carries each lineup page's home site; a page from a *remote* site the viewer
// trusts may be OFFERED to run on the viewer's own local pty (never auto-run).
// trustedAuthors is a plain list (or Set) of origin-site hostnames — e.g.
// ['plan.ide.earth'] — read from the service (GET /terminal/trust, which
// reads ~/.config/wiki-plugin-terminal/trust.json). It used to be a browser
// localStorage list set by window.trustAuthor; a co-resident script could set
// that, so trust moved off the browser (Terminal Plugin Audit, 2.2). Pure.
export const isTrustedAuthor = (originSite, trustedAuthors) => {
  if (!originSite) return false
  const list = trustedAuthors instanceof Set ? [...trustedAuthors]
    : Array.isArray(trustedAuthors) ? trustedAuthors : []
  return list.map(String).includes(String(originSite))
}

// Classify a terminal item by the ORIGIN of the page it lives on — NOT the
// browser's address bar. In a federated lineup a bot.pi5 page and a
// one.localhost page sit side by side; each remembers its own home site (the
// caller passes it in as originSite: $page data-site, or the view host for a
// page that belongs to the site being viewed).
//   'local'   — the viewer's own page (localhost/*.localhost, or the local
//               mirror): full live toolbar, runs on the local pty, as before.
//   'trusted' — a remote page whose origin the viewer trusts: may be OFFERED to
//               run on the viewer's local pty behind one explicit click.
//   'inert'   — any other remote/public page: display only, like the code plugin.
export const originTrust = (originSite, isMirror, trustedAuthors) => {
  if (isLocalContext(originSite, isMirror)) return 'local'
  if (isTrustedAuthor(originSite, trustedAuthors)) return 'trusted'
  return 'inert'
}

// ── Formatting directives ────────────────────────────────────────────────────
//
// Ward's ALL-CAPS convention (cf. the frame plugin's HEIGHT, the similarity
// plugin's SIMILAR:/LIMIT:): leading lines of the item text may carry
// directives, which are stripped from the script before display, paste or run.
//
//   COLOR: green        named colour scheme (COLOUR:/THEME:/SCHEME: accepted)
//   HEIGHT: 320         terminal area height in px
//   FONT: 14            font size (SIZE: accepted)
//   SESSION: build      pty session name (overrides the item's session field)
//   HOST: pi5.local     run through ssh on this host instead of the local shell
//                       (SSH: user@host accepted) — the local pty ssh's out with
//                       the viewer's own key; the service allowlists the host
//   RUN                 show the one-shot run button (off by default — scripts
//                       that prompt, e.g. sudo, need the live terminal's pty)
//   BUTTON              render the item as a text button: the script pane is
//                       hidden and one click pastes the script into the live
//                       session and presses Return — for driving a long-lived
//                       REPL (e.g. Claude Code) in a shared SESSION from a page
//   BUTTON: show        same, but the click opens the terminal panel first so
//                       the paste and run happen where the reader can see them
//   LABEL: Do Phase 1   the button's face text (defaults to the script's first
//                       line, truncated)
//   BOOT: claude        command a BUTTON click runs first when its click just
//                       created the session — start the REPL, wait for it to
//                       draw, then paste. An already-live session skips boot.
//   GUARD: <command>    readiness test for a BUTTON, run one-shot server-side.
//                       Exit 0 = ready. Otherwise the button turns into a
//                       fix-it affordance (see GUARDLABEL): clicking it opens
//                       the terminal — booting the session if BOOT says so —
//                       instead of sending the prompt, so the reader settles
//                       the precondition (e.g. /login) first. Re-checked on
//                       every click.
//   GUARDLABEL: Sign in the fix-it face text while the guard fails
//
// A valued directive requires a value, introduced by a colon or whitespace — so
// shell lines like `SIZE=10` are never mistaken for directives. Keywords are
// case-sensitive uppercase, per the convention.
const DIRECTIVE = /^(COLOR|COLOUR|THEME|SCHEME|HEIGHT|FONT|SIZE|SESSION|HOST|SSH|LABEL|BOOT|GUARD|GUARDLABEL)[:\s]\s*(\S.*)$/
const FLAG = /^RUN:?\s*$/
const BUTTON_FLAG = /^BUTTON(?::\s*(\S+))?\s*$/

// ── NEEDS — declared context variables ───────────────────────────────────────
//
// A shell example should read as the command you actually run, not as the
// plumbing that fetches its secrets. NEEDS declares where a placeholder's value
// comes from, so the script line stays clean and the placeholder renders as a
// chip the reader can hover or follow.
//
//   NEEDS USER: keychain Nextcloud account — [[Nextcloud App Password]]
//   NEEDS AUTH: keychain Nextcloud netrc
//   NEEDS SERVER: ask "Your Nextcloud host" = nextcloud.hitchhikers.earth
//   NEEDS ROOT: /var/www
//
// Three source kinds:
//   keychain <service> [field]  resolved on the viewer's machine via `security`;
//                               never typed, never echoed. field 'netrc' asks for
//                               a temporary credentials file rather than a value.
//   ask "prompt" [= default]    an inline editable chip — local context the
//                               reader fills in.
//   <anything else>             a plain value, substituted and shown as-is.
//
// A trailing `[[Page Name]]` (anywhere in the spec) names the page that explains
// the variable; the chip links to it.
//
// Resolution happens on the viewer's machine, never from page text — see the
// vault map in Phase 2. Parsing here is pure and does no lookups.
const NEEDS = /^NEEDS\s+([A-Z][A-Z0-9_]*)\s*:?\s+(\S.*)$/

export const parseNeed = (name, spec) => {
  let rest = String(spec).trim()
  let link = null
  const lm = rest.match(/\[\[([^\]]+)\]\]/)
  if (lm) {
    link = lm[1].trim()
    rest = (rest.slice(0, lm.index) + rest.slice(lm.index + lm[0].length))
      .replace(/[\s—–-]+$/, '').trim()
  }

  const kc = rest.match(/^keychain\s+(\S+)(?:\s+(\S+))?\s*$/i)
  if (kc) return { name, kind: 'keychain', service: kc[1], field: kc[2] || 'password', link }

  // Pulldown kinds — options come from the local service, names only:
  //   NEEDS HOST: sshhost = pi5.local      the pty's ssh allowlist
  //   NEEDS SECRET: vault = Dynadot API Key  the vault's entry names
  //   NEEDS SID: claudesession             Claude Code conversations, newest
  //                                        first — the pick is a session id,
  //                                        for `claude --resume $SID`
  const sh = rest.match(/^sshhost\b\s*(?:=\s*(\S.*))?$/i)
  if (sh) return { name, kind: 'sshhost', value: (sh[1] || '').trim(), link }
  const vp = rest.match(/^vault\b\s*(?:=\s*(\S.*))?$/i)
  if (vp) return { name, kind: 'vault', entry: (vp[1] || '').trim(), link }
  const cs = rest.match(/^claudesession\b\s*(?:=\s*(\S.*))?$/i)
  if (cs) return { name, kind: 'claudesession', value: (cs[1] || '').trim(), link }

  if (/^ask\b/i.test(rest)) {
    let tail = rest.replace(/^ask\b\s*/i, '')
    let prompt = ''
    // A quoted prompt is consumed first so an `=` inside it is not read as the
    // default-value separator.
    const q = tail.match(/^"([^"]*)"|^'([^']*)'/)
    if (q) { prompt = q[1] ?? q[2]; tail = tail.slice(q[0].length) }
    let value = ''
    const eq = tail.indexOf('=')
    if (eq !== -1) {
      value = tail.slice(eq + 1).trim()
      if (!q) prompt = tail.slice(0, eq).trim()
    } else if (!q) prompt = tail.trim()
    return { name, kind: 'ask', prompt: prompt || name, value, link }
  }

  return { name, kind: 'value', value: rest, link }
}

export const parseDirectives = text => {
  const lines = String(text || '').split('\n')
  const opts = {}
  const needs = []
  let i = 0
  for (; i < lines.length; i++) {
    if (lines[i].match(FLAG)) { opts.run = true; continue }
    const b = lines[i].match(BUTTON_FLAG)
    if (b) {
      opts.button = true
      if ((b[1] || '').toLowerCase() === 'show') opts.buttonShow = true
      continue
    }
    const n = lines[i].match(NEEDS)
    if (n) { needs.push(parseNeed(n[1], n[2])); continue }
    const m = lines[i].match(DIRECTIVE)
    if (!m) break
    const [, key, raw] = m
    const value = raw.trim()
    if (key === 'HEIGHT') opts.height = parseInt(value, 10) || undefined
    else if (key === 'FONT' || key === 'SIZE') opts.fontSize = parseInt(value, 10) || undefined
    else if (key === 'SESSION') opts.session = value
    else if (key === 'HOST' || key === 'SSH') opts.host = value
    else if (key === 'LABEL') opts.label = value
    else if (key === 'BOOT') opts.boot = value
    else if (key === 'GUARD') opts.guard = value
    else if (key === 'GUARDLABEL') opts.guardLabel = value
    else opts.scheme = value.toLowerCase()
  }
  while (i < lines.length && lines[i].trim() === '') i++
  return { script: lines.slice(i).join('\n'), needs, ...opts }
}

// The face text of a BUTTON-mode item: LABEL wins; otherwise the script's
// first line stands in, truncated so a verbose prompt still reads as a button.
export const buttonLabel = (opts = {}) => {
  if (opts.label) return opts.label
  const first = String(opts.script || '').split('\n')[0].trim()
  return first.length > 48 ? first.slice(0, 47) + '…' : first || 'run'
}

// ── Secret / non-secret ──────────────────────────────────────────────────────
//
// The split that makes a pasted command both correct and safe:
//
//   non-secret — an ask value, a plain value, or a keychain *account* — is
//     substituted into the pasted text. The prompt shows the real command, and
//     the scrollback stays re-runnable.
//   secret — a keychain password, token or netrc — never appears in the pasted
//     text. The script keeps `$NAME` and the shell expands it from the session
//     environment, which the service fills in before the first prompt.
//
// A netrc field is the strongest form: the service writes a 0600 file and
// exports its path, so the secret itself is in no variable, no argv, no
// scrollback — only a path is.
const SECRET_FIELDS = new Set(['password', 'passwd', 'pass', 'netrc', 'token',
  'secret', 'key', 'apikey', 'api-key'])

export const isSecret = need =>
  need.kind === 'vault' ||
  (need.kind === 'keychain' && SECRET_FIELDS.has(String(need.field).toLowerCase()))

// Names the shell already owns. Exporting one would clobber it for the session,
// and — worse — a script writing `$USER` would silently get the login name
// instead of the declared value, working by accident for whoever wrote the page
// and failing for everyone else.
export const RESERVED_NAMES = new Set(['USER', 'HOME', 'PATH', 'SHELL', 'PWD',
  'OLDPWD', 'LANG', 'LC_ALL', 'TERM', 'IFS', 'PS1', 'ZDOTDIR', 'LOGNAME',
  'TMPDIR', 'EDITOR', 'HOSTNAME', 'UID', 'SHLVL', 'PPID', 'RANDOM'])

export const needWarnings = (needs = [], script = '') => {
  const out = []
  for (const need of needs) {
    if (RESERVED_NAMES.has(need.name)) {
      out.push(`${need.name} is already a shell variable — rename it, or the shell's own value wins.`)
    }
    if (isSecret(need) && !new RegExp(`\\$${escRe(need.name)}\\b`).test(script)) {
      out.push(`${need.name} holds a secret, so the script must use $${need.name} — a bare ${need.name} is never substituted.`)
    }
  }
  return out
}

// Build the text actually pasted at the prompt. Non-secret values (supplied by
// the reader via ask chips, or resolved from the Keychain by the service and
// handed back) are substituted; secrets are left as `$NAME` for the shell.
export const resolveScript = (script, needs = [], values = {}) => {
  let out = String(script)
  for (const need of needs) {
    if (isSecret(need)) continue
    const value = values[need.name] ?? need.value ?? ''
    if (!value) continue
    out = out.replace(new RegExp(`(\\$?)\\b${escRe(need.name)}\\b`, 'g'), value)
  }
  return out
}

// What the service is asked to resolve: names and where to look, never values.
// picks: the reader's pulldown selections ({name: vault entry}) — a vault chip
// resolves as a keychain need against the CHOSEN entry name, which the service
// looks up in vault.json (the allowlist), same as a literal keychain chip.
export const needsPayload = (needs = [], picks = {}) => needs
  .filter(n => n.kind === 'keychain' || n.kind === 'vault')
  .map(n => n.kind === 'vault'
    ? { name: n.name, kind: 'keychain', service: picks[n.name] || n.entry || '', field: 'password' }
    : { name: n.name, kind: n.kind, service: n.service, field: n.field })
  .filter(n => n.service)

// ── Chips ────────────────────────────────────────────────────────────────────
//
// Rendering carries the convention "you do not type this": a declared variable
// appears as a coloured chip, not as bare text a newcomer would copy literally.

const attr = s => expand(s).replace(/"/g, '&quot;')
const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export const needTitle = need => {
  const explains = need.link ? ` Click to read ${need.link}.` : ''
  if (need.kind === 'keychain') {
    // The second word may name a field (account, password) or an account value
    // (hitchhiker); quoting the entry keeps the sentence true either way.
    const what = need.field === 'netrc'
      ? `a temporary credentials file built from your Keychain entry “${need.service}”`
      : `read from your Keychain entry “${need.service}” (${need.field})`
    return `${need.name} — ${what}, when the script runs. `
      + `You never type it and it never appears on screen.${explains}`
  }
  if (need.kind === 'ask') {
    return `${need.name} — ${need.prompt}. Click to edit`
      + `${need.value ? `; default ${need.value}` : ''}. Filled in on your machine.${explains}`
  }
  if (need.kind === 'sshhost') {
    return `${need.name} — pick a host from the terminal service's ssh allowlist. `
      + `The pty ssh's out with this machine's own key.${explains}`
  }
  if (need.kind === 'vault') {
    return `${need.name} — pick a secret by name from your vault `
      + `(~/.config/wiki-plugin-terminal/vault.json). Resolved from the Keychain when `
      + `the terminal attaches; you never type it and it never appears on screen.${explains}`
  }
  if (need.kind === 'claudesession') {
    return `${need.name} — pick a Claude Code conversation (newest first, from `
      + `~/.claude/projects). The pick is its session id, for claude --resume.${explains}`
  }
  return `${need.name} — filled in as ${need.value}. You do not type it.${explains}`
}

export const chipHtml = (need, label = need.name) => {
  const link = need.link ? ` data-link="${attr(need.link)}"` : ''
  const cls = `term-need term-need-${need.kind}${need.link ? ' term-need-linked' : ''}`
  const common = `class="${cls}" data-need="${attr(need.name)}" title="${attr(needTitle(need))}"${link}`
  if (need.kind === 'ask') {
    return `<span ${common} contenteditable="true" spellcheck="false"`
      + ` data-default="${attr(need.value)}">${attr(need.value || need.prompt)}</span>`
  }
  // Pulldown chips: rendered with just their default; bind fills the options
  // from the service's /terminal/options (names only) once a pty is reachable.
  if (need.kind === 'sshhost' || need.kind === 'vault' || need.kind === 'claudesession') {
    const def = need.kind === 'vault' ? need.entry : need.value
    const opt = def ? `<option value="${attr(def)}" selected>${attr(def)}</option>`
                    : `<option value="">choose…</option>`
    return `<select ${common} data-kind="${need.kind}">${opt}</select>`
  }
  return `<span ${common} tabindex="0">${attr(label)}</span>`
}

// Rewrite declared names in already-highlighted script HTML as chips. Splitting
// on tags keeps the substitution inside text nodes, so a name can never land in
// an attribute of highlight.js's own markup. A leading `$` is folded into the
// chip so `$AUTH` reads as one thing.
//
// On an 'inert' page (public, not the viewer's own) chips are not rendered at
// all: the script degrades to plain uppercase placeholders, which is exactly
// what a reader on someone else's site should see and copy.
export const applyNeeds = (html, needs = [], trust = 'local') => {
  if (!needs.length || trust === 'inert') return html
  const byName = new Map(needs.map(n => [n.name, n]))
  const alt = [...byName.keys()].sort((a, b) => b.length - a.length).map(escRe).join('|')
  if (!alt) return html
  const re = new RegExp(`(\\$?)\\b(${alt})\\b`, 'g')
  return String(html).split(/(<[^>]*>)/).map((seg, i) =>
    i % 2 ? seg : seg.replace(re, (m, sigil, name) => {
      const need = byName.get(name)
      return need ? chipHtml(need, `${sigil}${name}`) : m
    })
  ).join('')
}

// Named colour schemes — well-known, eye-tested text/background combinations.
const ANSI_DARK = {
  black: '#000000', red: '#cd3131', green: '#0dbc79', yellow: '#e5e510',
  blue: '#2472c8', magenta: '#bc3fbc', cyan: '#11a8cd', white: '#e5e5e5',
  brightBlack: '#666666', brightRed: '#f14c4c', brightGreen: '#23d18b',
  brightYellow: '#f5f543', brightBlue: '#3b8eea', brightMagenta: '#d670d6',
  brightCyan: '#29b8db', brightWhite: '#ffffff',
}

export const SCHEMES = {
  // VS Code Dark+ — the default
  dark: { background: '#1e1e1e', foreground: '#d4d4d4', cursor: '#ffffff',
    cursorAccent: '#1e1e1e', selectionBackground: '#264f78', ...ANSI_DARK },
  // light, wiki-friendly
  paper: { background: '#fafafa', foreground: '#222222', cursor: '#222222',
    cursorAccent: '#fafafa', selectionBackground: '#bbdfff' },
  // classic phosphor monitors
  green: { background: '#0c100c', foreground: '#33ff33', cursor: '#33ff33',
    cursorAccent: '#0c100c', selectionBackground: '#145214' },
  amber: { background: '#100c00', foreground: '#ffb000', cursor: '#ffb000',
    cursorAccent: '#100c00', selectionBackground: '#5a3d00' },
  // Ethan Schoonover's contrast-engineered palette
  solarized: { background: '#002b36', foreground: '#839496', cursor: '#93a1a1',
    cursorAccent: '#002b36', selectionBackground: '#073642',
    black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900',
    blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#eee8d5' },
  'solarized-light': { background: '#fdf6e3', foreground: '#657b83', cursor: '#586e75',
    cursorAccent: '#fdf6e3', selectionBackground: '#eee8d5',
    black: '#073642', red: '#dc322f', green: '#859900', yellow: '#b58900',
    blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#eee8d5' },
  dracula: { background: '#282a36', foreground: '#f8f8f2', cursor: '#f8f8f2',
    cursorAccent: '#282a36', selectionBackground: '#44475a',
    black: '#21222c', red: '#ff5555', green: '#50fa7b', yellow: '#f1fa8c',
    blue: '#bd93f9', magenta: '#ff79c6', cyan: '#8be9fd', white: '#f8f8f2' },
  nord: { background: '#2e3440', foreground: '#d8dee9', cursor: '#d8dee9',
    cursorAccent: '#2e3440', selectionBackground: '#434c5e',
    black: '#3b4252', red: '#bf616a', green: '#a3be8c', yellow: '#ebcb8b',
    blue: '#81a1c1', magenta: '#b48ead', cyan: '#88c0d0', white: '#e5e9f0' },
}

const SCHEME_ALIASES = {
  light: 'paper', white: 'paper', matrix: 'green',
  'solarized-dark': 'solarized',
}

export const schemeFor = name => {
  const key = String(name || 'dark').toLowerCase()
  return SCHEMES[SCHEME_ALIASES[key] || key] || SCHEMES.dark
}

export const wsUrl = (base, path) => base.replace(/^http/, 'ws') + path

// A workflow records each step's outcome on the source item so it can be
// journaled (a native wiki edit) and re-rendered after a reload or a history
// rewind. Pure: the caller supplies the result (incl. its date).
export const attachResult = (item, result) => ({ ...item, result })

// OSC 133 (FinalTerm / shell integration) stream scanner.
//
// The spawned zsh emits \e]133;C\a when command output starts and
// \e]133;D;<exit>\a when it ends. Feeding the decoded pty stream through this
// scanner yields {output, exit} per command — exact capture, no buffer
// scraping. Output still contains ANSI colour codes; strip downstream if
// plain text is wanted.
export const makeCaptureScanner = onResult => {
  let buf = ''
  let capturing = false
  let output = ''
  const marker = /\x1b\]133;([A-D])(?:;([^\x07\x1b]*))?(?:\x07|\x1b\\)/
  return chunk => {
    buf += chunk
    let m
    while ((m = buf.match(marker))) {
      if (capturing) output += buf.slice(0, m.index)
      const [, code, arg] = m
      if (code === 'C') {
        capturing = true
        output = ''
      } else if (code === 'D' && capturing) {
        capturing = false
        onResult({ output, exit: arg === undefined || arg === '' ? null : Number(arg) })
      }
      buf = buf.slice(m.index + m[0].length)
    }
    if (capturing) {
      // hold back a partial trailing escape sequence, if any
      const tail = buf.lastIndexOf('\x1b')
      const safe = tail === -1 ? buf.length : tail
      output += buf.slice(0, safe)
      buf = buf.slice(safe)
    } else if (buf.length > 64) {
      buf = buf.slice(-64)
    }
  }
}

// Display CSS, shared by both faces (moved from terminal.js).
const THEME = schemeFor('dark')
export const STYLE = `
  .terminal-item .terminal-script { background:#fff8e6; border-left:3px solid #ffb000 }
  .terminal-item .terminal-script code.hljs { background:transparent;
    white-space:pre-wrap; padding:6px }
  .terminal-item .term-need { border-radius:3px; padding:0 3px; cursor:pointer;
    border-bottom:1px dotted currentColor; font-weight:600 }
  .terminal-item .term-need-keychain { color:#6f42c1; background:#f3eeff }
  .terminal-item .term-need-value { color:#0a7d5a; background:#e7f6f0 }
  .terminal-item .term-need-ask { color:#1c5fa8; background:#e8f1fc;
    border-bottom:1px dashed currentColor; cursor:text; outline:none }
  .terminal-item .term-need-ask:focus { background:#d7e8fb }
  .terminal-item select.term-need { appearance:auto; font:inherit; font-weight:600;
    border:1px solid currentColor; border-radius:3px; padding:0 2px; max-width:16em }
  .terminal-item select.term-need-sshhost { color:#0a7d5a; background:#e7f6f0 }
  .terminal-item select.term-need-vault { color:#6f42c1; background:#f3eeff }
  .terminal-item select.term-need-claudesession { color:#1c5fa8; background:#e8f1fc;
    max-width:24em }
  .terminal-item .terminal-needs-hint:not(:empty) { font-size:11px; color:#8a6d00;
    background:#fff8e6; border-left:3px solid #ffb000; padding:2px 6px; margin-top:4px }
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

  /* BUTTON mode: the script pane gives way to one text button. Amber matches
     the runnable script accent; the transient sent state borrows the green of
     a resolved need. The expand affordance stays the usual t-term toggle. */
  .terminal-item .terminal-go { display:none }
  .terminal-item.term-button-mode .terminal-script { display:none }
  .terminal-item.term-button-mode .terminal-go { display:block; margin:2px 0;
    text-align:right }
  .terminal-item.term-button-mode .terminal-tools { text-align:right }
  .terminal-item .t-go { font:600 13px/1.4 sans-serif; padding:6px 16px;
    border-radius:6px; border:1px solid #ffb000; background:#fff8e6;
    color:#7a5800; cursor:pointer }
  .terminal-item .t-go:hover:not(:disabled) { background:#ffefc2 }
  .terminal-item .t-go:disabled { opacity:.45; cursor:default }
  .terminal-item .t-go.t-go-sent { background:#e7f6f0; border-color:#0a7d5a;
    color:#0a7d5a }
  .terminal-item .t-go.t-go-guard { background:#e8f1fc; border-color:#1c5fa8;
    color:#1c5fa8 }
  .terminal-item .t-go.t-go-watch { animation: t-go-pulse 2s ease-in-out infinite }
  @keyframes t-go-pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(255,176,0,0) }
    50% { box-shadow: 0 0 0 4px rgba(255,176,0,.35) }
  }
  .terminal-item.term-button-mode.wf-locked .terminal-go { display:none }

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
