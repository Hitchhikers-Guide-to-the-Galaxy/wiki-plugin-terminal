import { test } from 'node:test'
import assert from 'node:assert/strict'
import { expand, sessionName, wsUrl, makeCaptureScanner } from '../src/client/helpers.js'

test('expand escapes html', () => {
  assert.equal(expand('a < b & c > d'), 'a &lt; b &amp; c &gt; d')
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
