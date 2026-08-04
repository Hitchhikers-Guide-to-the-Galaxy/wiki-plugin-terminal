import { test } from 'node:test'
import assert from 'node:assert/strict'
import { expand, sessionName, wsUrl, makeCaptureScanner, isLocalHost, isLocalContext,
  isTrustedAuthor, originTrust, serviceBase, parseDirectives, schemeFor, SCHEMES,
  attachResult, parseNeed, chipHtml, applyNeeds, needTitle, isSecret, needWarnings,
  resolveScript, needsPayload, RESERVED_NAMES, buttonLabel } from '../src/client/helpers.js'

test('expand escapes html', () => {
  assert.equal(expand('a < b & c > d'), 'a &lt; b &amp; c &gt; d')
})

test('isLocalHost recognises local origins, rejects servers', () => {
  for (const h of ['localhost', '127.0.0.1', '::1', 'wiki.localhost'])
    assert.equal(isLocalHost(h), true, h)
  // .fish is an ordinary public TLD — not local (superseded old spec)
  for (const h of ['plugin.fedwiki.club', 'hitchhikers.earth', 'example.com', 'private.fish'])
    assert.equal(isLocalHost(h), false, h)
})

test('isLocalContext: local hostname OR mirror flag opens live behaviour', () => {
  // local origin, no flag → live
  assert.equal(isLocalContext('wiki.localhost', undefined), true)
  // public domain served by the mirror (window.isLocalMirror set) → live
  assert.equal(isLocalContext('media.anarchive.earth', true), true)
  // public domain, no flag → inert (real live site)
  assert.equal(isLocalContext('media.anarchive.earth', undefined), false)
  assert.equal(isLocalContext('example.com', false), false)
})

test('isTrustedAuthor matches an origin against the vouched list (array or Set)', () => {
  assert.equal(isTrustedAuthor('bot.pi5', ['bot.pi5']), true)
  assert.equal(isTrustedAuthor('bot.pi5', new Set(['bot.pi5', 'other'])), true)
  assert.equal(isTrustedAuthor('evil.example', ['bot.pi5']), false)
  // no origin, or no/empty list → never trusted
  assert.equal(isTrustedAuthor('', ['bot.pi5']), false)
  assert.equal(isTrustedAuthor(undefined, ['bot.pi5']), false)
  assert.equal(isTrustedAuthor('bot.pi5', undefined), false)
  assert.equal(isTrustedAuthor('bot.pi5', []), false)
})

test('originTrust classifies a page by its origin site', () => {
  // the viewer's own page (local origin, no flag) → full live behaviour
  assert.equal(originTrust('one.localhost', undefined, []), 'local')
  assert.equal(originTrust('localhost', undefined, undefined), 'local')
  // public domain served by the local mirror → local
  assert.equal(originTrust('media.anarchive.earth', true, []), 'local')
  // a remote page whose origin the viewer trusts → offered (armed)
  assert.equal(originTrust('bot.pi5', undefined, ['bot.pi5']), 'trusted')
  // any other remote/public page → inert (display only)
  assert.equal(originTrust('bot.pi5', undefined, []), 'inert')
  assert.equal(originTrust('example.com', false, ['bot.pi5']), 'inert')
})

test('serviceBase follows page protocol, honours explicit service', () => {
  assert.equal(serviceBase({}, 'http:'), 'http://terminal.localhost')
  assert.equal(serviceBase({}, 'https:'), 'https://terminal.localhost')
  assert.equal(serviceBase({}), 'http://terminal.localhost') // default protocol
  // an explicit item.service (full URL) always wins, trailing slash trimmed
  assert.equal(serviceBase({ service: 'http://box.localhost/' }, 'https:'), 'http://box.localhost')
})

test('sessionName defaults to item id and sanitizes', () => {
  assert.equal(sessionName({ id: 'abc123' }), 'item-abc123')
  assert.equal(sessionName({ id: 'x', session: 'my session!' }), 'my-session-')
})

test('wsUrl converts http(s) to ws(s)', () => {
  assert.equal(wsUrl('http://localhost:8000', '/terminal/pty/x'), 'ws://localhost:8000/terminal/pty/x')
  assert.equal(wsUrl('https://h', '/p'), 'wss://h/p')
})

test('capture scanner extracts output between OSC 133 C and D markers', () => {
  const results = []
  const scan = makeCaptureScanner(r => results.push(r))
  scan('\x1b]133;A\x07prompt% ls\r\n')
  scan('\x1b]133;C\x07file-one\r\nfile-two\r\n')
  scan('\x1b]133;D;0\x07\x1b]133;A\x07prompt% ')
  assert.equal(results.length, 1)
  assert.equal(results[0].output, 'file-one\r\nfile-two\r\n')
  assert.equal(results[0].exit, 0)
})

test('capture scanner survives markers split across chunks', () => {
  const results = []
  const scan = makeCaptureScanner(r => results.push(r))
  scan('\x1b]133;C\x07out')
  scan('put\r\n\x1b]133')
  scan(';D;1\x07')
  assert.equal(results.length, 1)
  assert.equal(results[0].output, 'output\r\n')
  assert.equal(results[0].exit, 1)
})

test('parseDirectives strips leading directives, keeps the script intact', () => {
  const r = parseDirectives('COLOR: green\nHEIGHT: 320\nFONT: 14\nSESSION: build\n\necho hi\nSIZE=10 make')
  assert.equal(r.scheme, 'green')
  assert.equal(r.height, 320)
  assert.equal(r.fontSize, 14)
  assert.equal(r.session, 'build')
  assert.equal(r.script, 'echo hi\nSIZE=10 make')
})

test('parseDirectives reads a HOST directive (SSH: user@host accepted)', () => {
  assert.equal(parseDirectives('HOST: pi5.local\nhostname').host, 'pi5.local')
  assert.equal(parseDirectives('HOST pi5\nuname -a').host, 'pi5')
  const r = parseDirectives('SSH: david@pi5.local\nwhoami')
  assert.equal(r.host, 'david@pi5.local')
  assert.equal(r.script, 'whoami')
  // a lowercase host= assignment in the script is not a directive
  assert.equal(parseDirectives('host=pi5\necho hi').host, undefined)
})

test('parseDirectives leaves plain scripts untouched', () => {
  const text = 'echo hello\nuname -a'
  // needs is always present (a collection callers can map over); every other
  // option stays absent unless its directive appears
  assert.deepEqual(parseDirectives(text), { script: text, needs: [] })
  // shell assignments and lowercase words are never directives
  assert.equal(parseDirectives('SIZE=10\necho hi').script, 'SIZE=10\necho hi')
  assert.equal(parseDirectives('color: green\nls').script, 'color: green\nls')
})

test('parseDirectives accepts COLOUR and bare-word form', () => {
  assert.equal(parseDirectives('COLOUR: amber\nls').scheme, 'amber')
  assert.equal(parseDirectives('THEME nord\nls').scheme, 'nord')
})

test('schemeFor resolves names, aliases, and falls back to dark', () => {
  assert.equal(schemeFor('green').foreground, '#33ff33')
  assert.equal(schemeFor('light'), SCHEMES.paper)
  assert.equal(schemeFor('solarized-dark'), SCHEMES.solarized)
  assert.equal(schemeFor('no-such-scheme'), SCHEMES.dark)
  assert.equal(schemeFor(undefined), SCHEMES.dark)
})

test('sessionName override wins over item field', () => {
  assert.equal(sessionName({ id: 'x', session: 'a' }, 'b'), 'b')
})

test('RUN flag sets run=true and is stripped', () => {
  const r = parseDirectives('RUN\nsudo ls')
  assert.equal(r.run, true)
  assert.equal(r.script, 'sudo ls')
})

test('run defaults to undefined without RUN', () => {
  const r = parseDirectives('echo hi')
  assert.equal(r.run, undefined)
  assert.equal(r.script, 'echo hi')
})

test('RUN mixes with other directives in any order', () => {
  const r = parseDirectives('COLOR: green\nRUN\nHEIGHT: 200\n\necho hi')
  assert.equal(r.run, true)
  assert.equal(r.scheme, 'green')
  assert.equal(r.height, 200)
  assert.equal(r.script, 'echo hi')
})

test('a script line starting RUNNER is not the RUN flag', () => {
  const r = parseDirectives('RUNNER=x ./go')
  assert.equal(r.run, undefined)
  assert.equal(r.script, 'RUNNER=x ./go')
})

test('BUTTON flag sets button=true and is stripped', () => {
  const r = parseDirectives('BUTTON\nDo Phase 1')
  assert.equal(r.button, true)
  assert.equal(r.script, 'Do Phase 1')
})

test('LABEL directive is parsed and mixes with BUTTON and SESSION in any order', () => {
  const r = parseDirectives('SESSION: plan-agent\nBUTTON\nLABEL: Do Phase 1\n\nDo Phase 1 of the plan.')
  assert.equal(r.button, true)
  assert.equal(r.label, 'Do Phase 1')
  assert.equal(r.session, 'plan-agent')
  assert.equal(r.script, 'Do Phase 1 of the plan.')
})

test('BUTTON: show sets button and buttonShow', () => {
  const r = parseDirectives('BUTTON: show\nLABEL: Go\nDo it')
  assert.equal(r.button, true)
  assert.equal(r.buttonShow, true)
  assert.equal(r.script, 'Do it')
})

test('bare BUTTON leaves buttonShow unset', () => {
  const r = parseDirectives('BUTTON\nDo it')
  assert.equal(r.button, true)
  assert.equal(r.buttonShow, undefined)
})

test('a script line starting BUTTONS= is not the BUTTON flag', () => {
  const r = parseDirectives('BUTTONS=3 ./go')
  assert.equal(r.button, undefined)
  assert.equal(r.script, 'BUTTONS=3 ./go')
})

test('buttonLabel prefers LABEL, else truncates the first script line', () => {
  assert.equal(buttonLabel({ label: 'Do Phase 1', script: 'long prompt' }), 'Do Phase 1')
  assert.equal(buttonLabel({ script: 'short line\nmore' }), 'short line')
  const long = 'x'.repeat(60)
  const cut = buttonLabel({ script: long })
  assert.equal(cut.length, 48)
  assert.ok(cut.endsWith('…'))
})

test('BOOT directive is parsed and stripped, with the command intact', () => {
  const r = parseDirectives('BUTTON\nBOOT: cd ~/work && claude\nSESSION: plan-agent\nDo Phase 1')
  assert.equal(r.button, true)
  assert.equal(r.boot, 'cd ~/work && claude')
  assert.equal(r.session, 'plan-agent')
  assert.equal(r.script, 'Do Phase 1')
})

test('a script line starting BOOTSTRAP= is not the BOOT directive', () => {
  const r = parseDirectives('BOOTSTRAP=1 ./go')
  assert.equal(r.boot, undefined)
  assert.equal(r.script, 'BOOTSTRAP=1 ./go')
})

test('GUARD and GUARDLABEL directives are parsed and stripped', () => {
  const r = parseDirectives('BUTTON\nGUARD: claude auth status\nGUARDLABEL: Sign in to Claude first\nDo Phase 1')
  assert.equal(r.guard, 'claude auth status')
  assert.equal(r.guardLabel, 'Sign in to Claude first')
  assert.equal(r.script, 'Do Phase 1')
})

test('a script line starting GUARDIAN= is not the GUARD directive', () => {
  const r = parseDirectives('GUARDIAN=x ./go')
  assert.equal(r.guard, undefined)
  assert.equal(r.script, 'GUARDIAN=x ./go')
})

test('parseNeed reads a claudesession pulldown with optional default', () => {
  const n = parseNeed('SID', 'claudesession')
  assert.deepEqual(n, { name: 'SID', kind: 'claudesession', value: '', link: null })
  const d = parseNeed('SID', 'claudesession = abc-123')
  assert.equal(d.value, 'abc-123')
})

test('a claudesession pick is not a secret and substitutes into the script', () => {
  const need = parseNeed('SID', 'claudesession')
  assert.equal(isSecret(need), false)
  assert.equal(resolveScript('claude --resume $SID', [need], { SID: 'aaaa-bbbb' }),
    'claude --resume aaaa-bbbb')
})

test('buttonLabel falls back to run for an empty script', () => {
  assert.equal(buttonLabel({}), 'run')
  assert.equal(buttonLabel({ script: '' }), 'run')
})

test('attachResult embeds a run result for journaling + later rendering', () => {
  const item = { type: 'terminal', id: 'abc', text: 'echo hi' }
  const result = { stdout: 'hi\n', stderr: '', exit: 0, date: 1781000000000 }
  const withResult = attachResult(item, result)
  // original untouched; result carried so emit() can re-render it after a rewind
  assert.deepEqual(item, { type: 'terminal', id: 'abc', text: 'echo hi' })
  assert.deepEqual(withResult, { type: 'terminal', id: 'abc', text: 'echo hi', result })
})

// ── NEEDS directive ──────────────────────────────────────────────────────────

test('parseNeed reads a keychain source with an explainer link', () => {
  const n = parseNeed('USER', 'keychain Nextcloud account — [[Nextcloud App Password]]')
  assert.deepEqual(n, { name: 'USER', kind: 'keychain', service: 'Nextcloud',
    field: 'account', link: 'Nextcloud App Password' })
})

test('parseNeed defaults the keychain field to password', () => {
  assert.equal(parseNeed('PW', 'keychain Nextcloud').field, 'password')
})

test('parseNeed reads an ask source with prompt and default', () => {
  const n = parseNeed('SERVER', 'ask "Your Nextcloud host" = nextcloud.hitchhikers.earth')
  assert.deepEqual(n, { name: 'SERVER', kind: 'ask', prompt: 'Your Nextcloud host',
    value: 'nextcloud.hitchhikers.earth', link: null })
})

test('parseNeed keeps an = inside a quoted ask prompt out of the default', () => {
  const n = parseNeed('X', 'ask "set a = b?" = yes')
  assert.equal(n.prompt, 'set a = b?')
  assert.equal(n.value, 'yes')
})

test('parseNeed falls back to a plain value', () => {
  const n = parseNeed('ROOT', '/var/www')
  assert.deepEqual(n, { name: 'ROOT', kind: 'value', value: '/var/www', link: null })
})

test('parseDirectives collects NEEDS alongside other directives', () => {
  const r = parseDirectives([
    'COLOR: green',
    'NEEDS USER: keychain Nextcloud account',
    'NEEDS SERVER: ask "Host" = example.com',
    'RUN',
    '',
    'curl https://SERVER/dav/files/USER/x',
  ].join('\n'))
  assert.equal(r.scheme, 'green')
  assert.equal(r.run, true)
  assert.equal(r.needs.length, 2)
  assert.deepEqual(r.needs.map(n => n.name), ['USER', 'SERVER'])
  // the script keeps the raw names — substitution is the runner's job
  assert.equal(r.script, 'curl https://SERVER/dav/files/USER/x')
})

test('parseDirectives leaves needs empty and script intact when none declared', () => {
  const r = parseDirectives('echo hi')
  assert.deepEqual(r.needs, [])
  assert.equal(r.script, 'echo hi')
})

test('a NEEDS-shaped shell line below the block is not a directive', () => {
  const r = parseDirectives('echo hi\nNEEDS FOO: bar')
  assert.deepEqual(r.needs, [])
  assert.equal(r.script, 'echo hi\nNEEDS FOO: bar')
})

test('applyNeeds wraps declared names as chips and folds in a leading $', () => {
  const needs = [parseNeed('AUTH', 'keychain Nextcloud netrc')]
  const html = applyNeeds('curl --netrc-file "$AUTH" https://x', needs, 'local')
  assert.match(html, /<span class="term-need term-need-keychain"[^>]*>\$AUTH<\/span>/)
  assert.doesNotMatch(html, /"\$AUTH"[^<]*$/)
})

test('applyNeeds leaves the script plain on an inert page', () => {
  const needs = [parseNeed('USER', 'keychain Nextcloud account')]
  const src = 'curl https://host/files/USER/x'
  assert.equal(applyNeeds(src, needs, 'inert'), src)
})

test('applyNeeds never substitutes inside highlight markup attributes', () => {
  const needs = [parseNeed('USER', 'keychain Nextcloud account')]
  // a tag whose attribute text contains the name must survive untouched
  const html = applyNeeds('<span class="USER-ish">USER</span>', needs, 'local')
  assert.match(html, /^<span class="USER-ish">/)
  assert.match(html, /term-need-keychain/)
})

test('applyNeeds matches whole words only', () => {
  const needs = [parseNeed('USER', 'keychain Nextcloud account')]
  assert.equal(applyNeeds('echo USERNAME', needs, 'local'), 'echo USERNAME')
})

test('an ask chip is editable and carries its default', () => {
  const html = chipHtml(parseNeed('SERVER', 'ask "Host" = example.com'))
  assert.match(html, /contenteditable="true"/)
  assert.match(html, /data-default="example\.com"/)
  assert.match(html, />example\.com</)
})

test('a keychain chip title promises the secret is never shown', () => {
  assert.match(needTitle(parseNeed('AUTH', 'keychain Nextcloud netrc')),
    /never type it and it never appears on screen/)
})

test('chip markup escapes quotes and angle brackets in values', () => {
  const html = chipHtml(parseNeed('MSG', 'he said "hi" <now>'))
  // no raw quote may close the title attribute early, no raw tag may be injected
  assert.match(html, /&quot;hi&quot;/)
  assert.match(html, /&lt;now&gt;/)
  assert.doesNotMatch(html, /<now>/)
  assert.equal(html.match(/"/g).length % 2, 0)
})

// ── Phase 2: secret split, warnings, substitution ────────────────────────────

test('isSecret splits credential fields from identifiers', () => {
  assert.equal(isSecret(parseNeed('A', 'keychain X netrc')), true)
  assert.equal(isSecret(parseNeed('A', 'keychain X password')), true)
  assert.equal(isSecret(parseNeed('A', 'keychain X')), true)     // default field
  assert.equal(isSecret(parseNeed('A', 'keychain X token')), true)
  // an account name is an identifier, not a secret — safe to show
  assert.equal(isSecret(parseNeed('A', 'keychain X account')), false)
  assert.equal(isSecret(parseNeed('A', 'ask "Host" = h')), false)
  assert.equal(isSecret(parseNeed('A', '/var/www')), false)
})

test('resolveScript substitutes non-secrets and leaves secrets to the shell', () => {
  const needs = [
    parseNeed('AUTH', 'keychain Nextcloud netrc'),
    parseNeed('NCUSER', 'keychain Nextcloud account'),
    parseNeed('SERVER', 'ask "Host" = nextcloud.example'),
  ]
  const script = 'curl --netrc-file "$AUTH" https://SERVER/dav/files/NCUSER/x'
  const out = resolveScript(script, needs, { NCUSER: 'david' })
  assert.equal(out, 'curl --netrc-file "$AUTH" https://nextcloud.example/dav/files/david/x')
  // the secret is never written into the pasted text
  assert.match(out, /\$AUTH/)
})

test('an edited ask value wins over the declared default', () => {
  const needs = [parseNeed('SERVER', 'ask "Host" = nextcloud.example')]
  assert.equal(resolveScript('ping SERVER', needs, { SERVER: 'cloud.other' }), 'ping cloud.other')
})

test('needsPayload sends names and lookups only — never values', () => {
  const needs = [parseNeed('AUTH', 'keychain Nextcloud netrc'),
                 parseNeed('SERVER', 'ask "Host" = secret-looking-default')]
  const payload = needsPayload(needs)
  assert.deepEqual(payload, [{ name: 'AUTH', kind: 'keychain', service: 'Nextcloud', field: 'netrc' }])
  assert.doesNotMatch(JSON.stringify(payload), /secret-looking-default/)
})

test('needWarnings catches a name the shell already owns', () => {
  const w = needWarnings([parseNeed('USER', 'keychain Nextcloud account')], 'echo USER')
  assert.equal(w.length, 1)
  assert.match(w[0], /already a shell variable/)
  assert.ok(RESERVED_NAMES.has('HOME') && RESERVED_NAMES.has('PATH'))
})

test('needWarnings catches a secret referenced without its $', () => {
  const needs = [parseNeed('AUTH', 'keychain Nextcloud netrc')]
  assert.match(needWarnings(needs, 'curl --netrc-file AUTH x')[0], /must use \$AUTH/)
  // correctly written, no warning
  assert.deepEqual(needWarnings(needs, 'curl --netrc-file "$AUTH" x'), [])
})
