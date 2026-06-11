import * as esbuild from 'esbuild'
import fs from 'node:fs/promises'
import packJSON from '../package.json' with { type: 'json' }

const watch = process.argv.includes('--watch')
const version = packJSON.version
const now = new Date()

// Bundles src/client/terminal.js (including @xterm/xterm and its css import)
// into client/terminal.js + client/terminal.css — the files wiki serves at
// /plugins/terminal/terminal.{js,css}

const ctx = await esbuild.context({
  entryPoints: ['src/client/terminal.js'],
  bundle: true,
  banner: { js: `/* wiki-plugin-terminal - ${version} - ${now.toUTCString()} */` },
  minify: !watch,
  sourcemap: true,
  logLevel: 'info',
  metafile: true,
  outfile: 'client/terminal.js',
})

if (watch) {
  await ctx.watch()
  console.log('Watching for changes...')
} else {
  const results = await ctx.rebuild()
  await ctx.dispose()
  await fs.writeFile('meta-client.json', JSON.stringify(results.metafile))
  console.log("\n  esbuild metadata written to 'meta-client.json'.")
}
