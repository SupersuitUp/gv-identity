#!/usr/bin/env node
// Properties of the BUILT package the tests (which run the sources) cannot see:
// the entry exists, and it imports no node: module, so it stays safe in Edge middleware.
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const DIST = fileURLToPath(new URL('../dist', import.meta.url))
const walk = (d) => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p] })
const bad = []
for (const e of ['index.js', 'index.d.ts']) if (!existsSync(join(DIST, e))) bad.push(`dist/${e} is missing`)
for (const f of walk(DIST).filter((p) => p.endsWith('.js'))) {
  if (/(from|import)\s*\(?\s*['"]node:/.test(readFileSync(f, 'utf8'))) bad.push(`${f} imports a node: module`)
}
for (const b of bad) console.error(b)
if (bad.length) process.exit(1)
console.log('dist: entry present, no node: imports (Edge-safe)')
