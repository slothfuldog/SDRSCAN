// Standalone development server for the mock API: `npm run mock` (default http://127.0.0.1:8787).
// Run through `npm run dev:mock`, which also starts Nuxt with its /api proxy pointed here.
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { SEED_CREDENTIALS, createMockBackend } from './core.ts'
import type { MockRequest } from './core.ts'

const PORT = Number(process.env.MOCK_PORT ?? 8787)
const backend = createMockBackend()

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

function toMockRequest(req: IncomingMessage, url: URL, body: unknown): MockRequest {
  const headers: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v
  return { method: req.method ?? 'GET', path: url.pathname, query: url.searchParams, headers, body }
}

function sendJson(res: ServerResponse, status: number, headers: Record<string, string>, body?: unknown) {
  const payload = body === undefined ? '' : JSON.stringify(body)
  res.writeHead(status, { ...headers, ...(payload ? { 'Content-Type': 'application/json; charset=utf-8' } : {}) })
  res.end(payload)
}

function serveEvents(req: IncomingMessage, res: ServerResponse, url: URL, id: number) {
  const mockReq = toMockRequest(req, url, undefined)
  const first = backend.peekScan(mockReq, id)
  if (first.status !== 200) {
    sendJson(res, first.status, { 'Cache-Control': 'no-store' }, { error: { code: first.status === 401 ? 'not_authenticated' : 'not_found', message: first.status === 401 ? 'You are not signed in.' : 'Scan not found.' } })
    return
  }
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' })
  let sentLines = 0
  let lastStatus = ''
  const send = (event: string, data: unknown) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
  const tick = () => {
    const snap = backend.peekScan(mockReq, id)
    if (snap.status !== 200 || !snap.scan) { clearInterval(timer); res.end(); return }
    const lines = snap.log ?? []
    while (sentLines < lines.length) send('log', { line: lines[sentLines++] })
    const s = snap.scan
    if (s.status !== lastStatus) {
      lastStatus = s.status
      send('status', { status: s.status, started_at: s.started_at, finished_at: s.finished_at, ...(s.summary ? { summary: s.summary } : {}) })
    }
    if (s.status === 'succeeded' || s.status === 'failed' || s.status === 'cancelled') { clearInterval(timer); res.end() }
  }
  const timer = setInterval(tick, 1000)
  req.on('close', () => clearInterval(timer))
  tick()
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const m = /^\/api\/v1\/scans\/(\d+)\/events$/.exec(url.pathname)
    if (m && req.method === 'GET') { serveEvents(req, res, url, Number(m[1])); return }

    const raw = await readBody(req)
    let body: unknown
    if (raw) {
      try { body = JSON.parse(raw) } catch {
        sendJson(res, 400, { 'Cache-Control': 'no-store' }, { error: { code: 'bad_request', message: 'The request body is not valid JSON.' } })
        return
      }
    }
    const out = backend.handle(toMockRequest(req, url, body))
    sendJson(res, out.status, out.headers, out.body)
  } catch {
    sendJson(res, 500, {}, { error: { code: 'internal', message: 'Internal error.' } })
  }
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`SDRScan mock API listening on http://127.0.0.1:${PORT}/api/v1`)
  console.log('Sample accounts (mock only):')
  for (const [k, v] of Object.entries(SEED_CREDENTIALS)) console.log(`  ${k.padEnd(10)} ${v.username} / ${v.password}`)
})
