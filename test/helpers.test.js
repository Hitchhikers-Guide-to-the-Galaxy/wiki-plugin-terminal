import { test } from 'node:test'
import assert from 'node:assert/strict'
import { expand, sessionName, wsUrl, makeCaptureScanner, isLocalHost, isLocalContext,
  serviceBase, parseDirectives, schemeFor, SCHEMES, attachResult } from '../src/client/helpers.js'

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

test('parseDirectives leaves plain scripts untouched', () => {
  const text = 'echo hello\nuname -a'
  assert.deepEqual(parseDirectives(text), { script: text })
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

test('attachResult embeds a run result for journaling + later rendering', () => {
  const item = { type: 'terminal', id: 'abc', text: 'echo hi' }
  const result = { stdout: 'hi\n', stderr: '', exit: 0, date: 1781000000000 }
  const withResult = attachResult(item, result)
  // original untouched; result carried so emit() can re-render it after a rewind
  assert.deepEqual(item, { type: 'terminal', id: 'abc', text: 'echo hi' })
  assert.deepEqual(withResult, { type: 'terminal', id: 'abc', text: 'echo hi', result })
})
