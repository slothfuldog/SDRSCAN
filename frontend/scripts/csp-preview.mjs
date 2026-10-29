// Serves the generated site (.output/public) like the backend will: same origin, SPA fallback to index.html,
// the TRD content security policy (hash of the inline Nuxt config script computed at start), and /api proxied
// to the mock (or to SDRSCAN_API_URL). Use it to check that the build runs under the policy:
//   npm run build && npm run mock &  node scripts/csp-preview.mjs   ->  http://127.0.0.1:4173
// Override the policy for experiments with CSP="...".
import { createHash } from 'node:crypto'
import { createServer, request as httpRequest } from 'node:http'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { extname, join, normalize } from 'node:path'

const root = join(process.cwd(), '.output/public')
const port = Number(process.env.PORT ?? 4173)
const api = new URL(process.env.SDRSCAN_API_URL ?? `http://127.0.0.1:${process.env.MOCK_PORT ?? 8787}`)
const index = readFileSync(join(root, 'index.html'), 'utf8')
const hashes = [...index.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => `'sha256-${createHash('sha256').update(m[1]).digest('base64')}'`)

const csp = process.env.CSP ?? [
  "default-src 'none'",
  `script-src 'self' ${hashes.join(' ')}`.trim(),
  "style-src 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ')

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.json': 'application/json' }

createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost')
  if (url.pathname.startsWith('/api/')) {
    const proxied = httpRequest({ host: api.hostname, port: api.port, path: req.url, method: req.method, headers: { ...req.headers, host: req.headers.host } }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers)
      r.pipe(res)
    })
    proxied.on('error', () => { res.writeHead(502); res.end() })
    req.pipe(proxied)
    return
  }
  let file = normalize(join(root, decodeURIComponent(url.pathname)))
  if (!file.startsWith(root) || !existsSync(file) || statSync(file).isDirectory()) file = join(root, 'index.html')
  res.writeHead(200, {
    'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream',
    'Content-Security-Policy': csp,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  })
  res.end(readFileSync(file))
}).listen(port, '127.0.0.1', () => {
  console.log(`Serving ${root} on http://127.0.0.1:${port}`)
  console.log(`CSP: ${csp}`)
})
