// wiki-plugin-terminal — MODERN face: the display slice only. A Sweet Client
// column is never the trusted local mirror, so this face renders exactly what
// the classic plugin renders on any page the viewer is merely browsing: the
// bash-highlighted script pane, chips as plain text, no run button, no pty.
// Sessions, BUTTON mode and workflows stay with the official client.
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import { expand, parseDirectives, applyNeeds, STYLE } from './helpers.js'

hljs.registerLanguage('bash', bash)
const highlightScript = (text) => hljs.highlight(text || '', { language: 'bash' }).value

const ensureCSS = () => {
  if (!document.getElementById('wiki-terminal-modern-styles')) {
    const style = document.createElement('style')
    style.id = 'wiki-terminal-modern-styles'
    style.textContent = STYLE.replace(/<\/?style[^>]*>/g, '')
    document.head.appendChild(style)
  }
}

export function emit(el, item, _context) {
  ensureCSS()
  const { script, needs } = parseDirectives(item.text)
  el.innerHTML = `
    <div class="terminal-item">
      <pre class="terminal-script hljs"><code class="hljs language-bash">${applyNeeds(highlightScript(script), needs, 'remote')}</code></pre>
    </div>`
}

export function bind(el, item, context) {
  el.addEventListener('dblclick', (e) => {
    e.stopPropagation()
    context.textEditor(item)
  })
}
