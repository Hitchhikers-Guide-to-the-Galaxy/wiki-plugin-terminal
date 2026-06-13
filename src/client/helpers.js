// wiki-plugin-terminal — pure helpers, kept import-free so node --test can
// exercise them without touching xterm or the DOM.

export const expand = text =>
  String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

// pty sessions are named; items sharing a session share one shell.
// Default: a session private to the item. A SESSION: directive overrides
// the item field.
export const sessionName = (item, override) =>
  (override || item.session || `item-${item.id}`).replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 64)

export const serviceBase = item =>
  (item.service || 'http://localhost:8000').replace(/\/$/, '')

// The live terminal is local-first only. Anywhere else — a public server —
// the plugin must behave exactly like the code plugin: display the script and
// nothing more (no toolbar, no network probe). Gate on the wiki's own origin.
export const isLocalHost = hostname =>
  hostname === 'localhost' ||
  hostname === '127.0.0.1' ||
  hostname === '::1' ||
  hostname === '[::1]' ||
  hostname.endsWith('.localhost') ||
  hostname.endsWith('.fish')

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
//   RUN                 show the one-shot run button (off by default — scripts
//                       that prompt, e.g. sudo, need the live terminal's pty)
//
// A valued directive requires a value, introduced by a colon or whitespace — so
// shell lines like `SIZE=10` are never mistaken for directives. Keywords are
// case-sensitive uppercase, per the convention.
const DIRECTIVE = /^(COLOR|COLOUR|THEME|SCHEME|HEIGHT|FONT|SIZE|SESSION)[:\s]\s*(\S.*)$/
const FLAG = /^RUN:?\s*$/

export const parseDirectives = text => {
  const lines = String(text || '').split('\n')
  const opts = {}
  let i = 0
  for (; i < lines.length; i++) {
    if (lines[i].match(FLAG)) { opts.run = true; continue }
    const m = lines[i].match(DIRECTIVE)
    if (!m) break
    const [, key, raw] = m
    const value = raw.trim()
    if (key === 'HEIGHT') opts.height = parseInt(value, 10) || undefined
    else if (key === 'FONT' || key === 'SIZE') opts.fontSize = parseInt(value, 10) || undefined
    else if (key === 'SESSION') opts.session = value
    else opts.scheme = value.toLowerCase()
  }
  while (i < lines.length && lines[i].trim() === '') i++
  return { script: lines.slice(i).join('\n'), ...opts }
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
