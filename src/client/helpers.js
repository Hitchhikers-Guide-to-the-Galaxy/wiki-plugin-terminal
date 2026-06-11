// wiki-plugin-terminal — pure helpers, kept import-free so node --test can
// exercise them without touching xterm or the DOM.

export const expand = text =>
  String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

// pty sessions are named; items sharing a session share one shell.
// Default: a session private to the item.
export const sessionName = item =>
  (item.session || `item-${item.id}`).replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 64)

export const serviceBase = item =>
  (item.service || 'http://localhost:8000').replace(/\/$/, '')

export const wsUrl = (base, path) => base.replace(/^http/, 'ws') + path

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
