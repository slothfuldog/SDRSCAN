// In-memory mock of the SDRScan REST API (TRD "API REST backend"), for development and tests only.
// It enforces the parts of the contract the UI depends on: session cookie, CSRF, roles, DAST rules,
// error format, pagination, filters, facets, scan lifecycle and comparison.
import type {
  AuditEntry, Codebase, CodebaseRow, DastAuth, DastAuthBody, DastAuthType, DastCrawl, Finding, FindingSummary, FileRow, IngestToken, Project, ProjectListItem, Role, Scan, ScanRef,
  ScanStatus, Severity, SeveritySummary, VulnDbInfo, VulnDbSource, VulnDbStatus, VulnDbUpdate,
} from '../types/api'
import {
  API_TEMPLATES, BILLING_TEMPLATES, DAST_ACTIVE_TEMPLATES, DAST_TEMPLATES, DAST_VULN_TEMPLATES, SCA_TEMPLATES, STOREFRONT_TEMPLATES, fingerprintOf,
} from './seed.ts'
import type { FindingTemplate } from './seed.ts'
import { PRIVATE_NETWORK_MESSAGE, isPrivateHost } from '../utils/validators.ts'
import { minIntervalMinutes, nextRuns, parseCron } from '../utils/cron.ts'

export interface MockRequest {
  method: string
  /** Path including the /api/v1 prefix. */
  path: string
  query: URLSearchParams
  headers: Record<string, string | undefined>
  body?: unknown
}

export interface MockResponse {
  status: number
  headers: Record<string, string>
  body?: unknown
}

export interface MockOptions {
  /** Multiplier for scan lifecycle timings (tests use a small value). */
  scanSpeed?: number
  now?: () => number
  /** Vulnerability database scenario (defaults: configured, installed, data 2 days old, tool available). */
  /** False: the server has no SDRSCAN_SECRET_KEY, so credentials are refused with 503 secret_key_required. Default true. */
  secretKey?: boolean
  vulndb?: { configured?: boolean, installed?: boolean, toolAvailable?: boolean, scaEnabled?: boolean, dataAgeDays?: number, cron?: string | null }
}

interface MockUser {
  id: number
  username: string
  password: string
  role: Role
  can_run_dast: boolean
  is_active: boolean
  must_change_password: boolean
  last_login_at: string | null
  failed: number
  lockedUntil: number
}

interface MockSchedule {
  cron: string
  owner_id: number
  status: 'active' | 'suspended'
  suspended_reason: 'owner_deactivated' | 'owner_lost_permission' | null
  suspended_at: string | null
  last_enqueued_at: string | null
}

interface MockCodebase {
  id: number
  project_id: number
  name: string
  target_type: 'repo' | 'url'
  language: string
  repo_url: string | null
  branch: string | null
  subdirectory: string
  git_auth_kind: 'none' | 'https_token' | 'ssh_key'
  git_username: string | null
  has_credential: boolean
  base_url: string | null
  dast_status: 'pending_confirmation' | 'confirmed' | null
  dast_registered_by: number | null
  dast_confirmed_by: number | null
  dast_confirmed_at: string | null
  dast_max_rps: number
  schedule: MockSchedule | null
  auth: MockAuth | null
  crawl: DastCrawl
  // Active (payload-sending) scanning: a separate, stricter authorization on top of dast_status === 'confirmed'.
  active_authorized_at: string | null
  active_authorized_by: number | null
  active_statement: string | null
  openapi_spec_url: string | null
  created_at: string
  updated_at: string
  templates: FindingTemplate[]
}

/** What the mock keeps for DAST authentication. `secrets` never leaves the backend (write-only, like the real API). */
interface MockAuth {
  type: DastAuthType
  meta: Omit<DastAuth, 'type' | 'has_secret'>
  secrets: { password: string, extra: Record<string, string>, headers: Record<string, string>, cookies: Record<string, string> }
}

interface MockScan {
  id: number
  codebase_id: number
  type: 'sast' | 'dast'
  coverage: 'full' | 'partial'
  trigger: 'manual' | 'schedule' | 'ci'
  status: ScanStatus
  queued_at: string
  started_at: string | null
  finished_at: string | null
  ref: string
  engine: string
  engine_version: string
  scanned_files: string[] | null
  error_code: string | null
  log: Array<{ t: number, line: string }>
  /** Active (payload-sending) scanning and its time-based SQLi extra; always false for sast. */
  active: boolean
  active_timing: boolean
  /** Simulated run (web-triggered scans only). */
  sim: { queuedAtMs: number, plan: Array<{ at: number, line?: string, status?: ScanStatus }>, outcome: 'succeeded' | 'failed', cancelled: boolean } | null
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

class HttpError extends Error {
  status: number
  code: string
  details?: unknown
  headers?: Record<string, string>
  constructor(status: number, code: string, message: string, details?: unknown, headers?: Record<string, string>) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
    this.headers = headers
  }
}

function fail(status: number, code: string, message: string, details?: unknown, headers?: Record<string, string>): never {
  throw new HttpError(status, code, message, details, headers)
}

export const SEED_CREDENTIALS = {
  admin: { username: 'admin', password: 'admin-password-1234' },
  member: { username: 'member', password: 'member-password-1234' },
  dastMember: { username: 'dast-member', password: 'dast-member-pass-1234' },
  newHire: { username: 'newhire', password: 'temporary-pass-1234' },
}

export function createMockBackend(options: MockOptions = {}) {
  const speed = options.scanSpeed ?? 1
  const nowMs = options.now ?? (() => Date.now())
  const iso = (ms = nowMs()) => new Date(ms).toISOString()

  const seq = { user: 1, project: 1, codebase: 1, scan: 100, finding: 1000, token: 1, audit: 1 }

  const users: MockUser[] = []
  /** The caller of the request being handled (set by handle()); drives URL-Codebase visibility. */
  let viewer: MockUser | null = null
  const visible = (cb: MockCodebase) => cb.target_type === 'repo' || (!!viewer && (viewer.role === 'admin' || viewer.can_run_dast))
  const sessions = new Map<string, { userId: number, csrf: string }>()
  const projects: Array<Project & { created_at: string, updated_at: string }> = []
  const codebases: MockCodebase[] = []
  const scans: MockScan[] = []
  const findings: Finding[] = []
  const tokens: Array<{ id: number, name: string, token_prefix: string, project_id: number | null, created_by: number, created_at: string, last_used_at: string | null, revoked_at: string | null, hash: string }> = []
  const audit: AuditEntry[] = []

  // ---- seeding ---------------------------------------------------------------

  const addUser = (username: string, password: string, role: Role, can_run_dast = false, must_change_password = false) => {
    const u: MockUser = { id: seq.user++, username, password, role, can_run_dast, is_active: true, must_change_password, last_login_at: null, failed: 0, lockedUntil: 0 }
    users.push(u)
    return u
  }

  function makeFinding(scan: MockScan, t: FindingTemplate): Finding {
    const location = t.url
      ? { kind: 'url' as const, url: t.url }
      : { kind: 'file' as const, path: t.path!, start_line: t.start_line ?? null, start_column: t.start_column ?? null, end_line: t.end_line ?? null, end_column: t.end_column ?? null }
    const f: Finding = {
      id: seq.finding++, scan_id: scan.id, codebase_id: scan.codebase_id, is_current: false, rule_id: t.rule_id, severity: t.severity,
      // A vulnerability finding is never low confidence at finding level (vulnerability.confidence carries the detail).
      confidence: t.vulnerability ? 'normal' : (t.confidence ?? 'normal'), message: t.message, location, snippet: t.snippet, redacted: !!t.redacted, cwe: t.cwe, fingerprint: fingerprintOf(t.key),
      kind: t.vulnerability ? 'vulnerability' : 'code', vulnerability: t.vulnerability ?? null,
    }
    findings.push(f)
    return f
  }

  function addScan(cb: MockCodebase, init: Partial<MockScan> & { templates: FindingTemplate[], startedAgoMin: number }): MockScan {
    const started = nowMs() - init.startedAgoMin * 60_000
    const s: MockScan = {
      id: init.id ?? seq.scan++, codebase_id: cb.id, type: cb.target_type === 'url' ? 'dast' : 'sast', coverage: init.coverage ?? 'full',
      trigger: init.trigger ?? 'manual', status: init.status ?? 'succeeded', queued_at: iso(started - 2000), started_at: iso(started), finished_at: iso(started + 37_000),
      ref: init.ref ?? 'a1b2c3d', engine: cb.target_type === 'url' ? 'sdrscan-dast' : 'sdrscan-sast', engine_version: '0.1.0',
      active: init.active ?? false, active_timing: init.active_timing ?? false,
      scanned_files: init.scanned_files ?? null, error_code: null, log: [{ t: started, line: 'cloned (depth 1)' }, { t: started + 30_000, line: 'ingested results' }], sim: null,
    }
    scans.push(s)
    for (const t of init.templates) makeFinding(s, t)
    return s
  }

  function seed() {
    addUser('admin', SEED_CREDENTIALS.admin.password, 'admin')
    addUser('member', SEED_CREDENTIALS.member.password, 'member')
    addUser('dast-member', SEED_CREDENTIALS.dastMember.password, 'member', true)
    addUser('newhire', SEED_CREDENTIALS.newHire.password, 'member', false, true)

    const ts = iso(nowMs() - 20 * 86_400_000)
    projects.push({ id: seq.project++, name: 'Online Shop', description: 'Web and API', created_at: ts, updated_at: ts })
    projects.push({ id: seq.project++, name: 'Internal Tools', description: 'Back-office services', created_at: ts, updated_at: ts })
    projects.push({ id: seq.project++, name: 'Playground', description: '', created_at: ts, updated_at: ts })

    const base = (over: Partial<MockCodebase>): MockCodebase => ({
      id: seq.codebase++, project_id: 1, name: '', target_type: 'repo', language: 'php', repo_url: 'https://git.example.com/shop/app.git', branch: 'main', subdirectory: '',
      git_auth_kind: 'none', git_username: null, has_credential: false, base_url: null, dast_status: null, dast_registered_by: null, dast_confirmed_by: null,
      dast_confirmed_at: null, dast_max_rps: 5, schedule: null, auth: null, crawl: { enabled: false, max_depth: 3, max_pages: 50, exclude: [] },
      active_authorized_at: null, active_authorized_by: null, active_statement: null, openapi_spec_url: null,
      created_at: ts, updated_at: ts, templates: [], ...over,
    })

    // 1: storefront: two full scans and one partial scan from CI.
    const sf = base({ name: 'storefront', subdirectory: 'apps/storefront', git_auth_kind: 'https_token', git_username: 'x-access-token', has_credential: true, templates: STOREFRONT_TEMPLATES })
    codebases.push(sf)
    const t = STOREFRONT_TEMPLATES
    const nonNew = t.filter(x => x.key !== 'sf:partial-new')
    addScan(sf, { id: 39, startedAgoMin: 60 * 24 * 7, ref: '91fe0aa', templates: nonNew.slice(2) })
    addScan(sf, { id: 45, startedAgoMin: 60 * 24 * 2, ref: 'c0ffee1', templates: nonNew.filter((_, i) => i !== 5 && i !== 9) })
    const partialFiles = ['src/Controller/CartController.php', 'src/Auth/Login.php']
    const base45 = nonNew.filter((_, i) => i !== 5 && i !== 9)
    const inPartial = base45.filter(x => x.path && partialFiles.includes(x.path))
    addScan(sf, {
      id: 58, coverage: 'partial', trigger: 'ci', startedAgoMin: 90, ref: 'a1b2c3d', scanned_files: partialFiles,
      templates: [...inPartial.slice(1), t.find(x => x.key === 'sf:partial-new')!],
    })

    // 2: DAST target waiting for confirmation (registered by dast-member).
    codebases.push(base({ name: 'storefront (live)', target_type: 'url', language: '', repo_url: null, branch: null, base_url: 'https://shop.example.com', dast_status: 'pending_confirmation', dast_registered_by: 3 }))

    // 3: confirmed DAST target with a result, active scanning already authorized (demo of the full flow).
    const admin = base({
      name: 'admin-portal (live)', target_type: 'url', language: '', repo_url: null, branch: null, base_url: 'https://admin.example.com',
      dast_status: 'confirmed', dast_registered_by: 3, dast_confirmed_by: 1, dast_confirmed_at: iso(nowMs() - 5 * 86_400_000), templates: DAST_TEMPLATES,
      active_authorized_at: iso(nowMs() - 2 * 86_400_000), active_authorized_by: 1,
      active_statement: 'I confirm that I am authorized to run ACTIVE security scans against admin-portal (live).',
    })
    codebases.push(admin)
    addScan(admin, { id: 61, startedAgoMin: 300, ref: '', templates: DAST_TEMPLATES })
    // A later active scan, kept out of the "current state" (partial, no scanned_files) so it only shows
    // up in the scan's own history/detail — demonstrating the "Active scan" badge and active findings
    // without shifting the codebase's/project's severity totals used elsewhere.
    addScan(admin, { id: 62, coverage: 'partial', startedAgoMin: 120, ref: '', active: true, active_timing: true, templates: DAST_ACTIVE_TEMPLATES })

    // 4: never scanned.
    codebases.push(base({ name: 'legacy-cms', repo_url: 'git@git.example.com:shop/legacy-cms.git', branch: 'master' }))

    // 5: other project.
    const api = base({ name: 'api', project_id: 2, repo_url: 'https://git.example.com/tools/api.git', templates: API_TEMPLATES })
    codebases.push(api)
    addScan(api, { id: 70, startedAgoMin: 60 * 5, ref: '5e5e5e5', templates: API_TEMPLATES })
    const billing = base({ name: 'billing-service', project_id: 2, repo_url: 'https://git.example.com/tools/billing.git', templates: BILLING_TEMPLATES })
    codebases.push(billing)
    addScan(billing, { id: 71, startedAgoMin: 60 * 30, ref: '7a7a7a7', templates: BILLING_TEMPLATES })
    addScan(codebases[0]!, { id: 72, status: 'failed', startedAgoMin: 20, templates: [], ref: '' })
    scans.find(s => s.id === 72)!.error_code = 'clone_failed'
    scans.find(s => s.id === 72)!.log = [{ t: nowMs(), line: 'cloning https://git.example.com/shop/app.git' }, { t: nowMs(), line: 'fatal: Authentication failed' }]

    // 6 and 7: vulnerability findings (SCA lockfile CVEs, and a DAST product CVE with low confidence), both in "Internal Tools".
    const deps = base({ name: 'shop-deps', project_id: 2, repo_url: 'https://git.example.com/tools/shop-deps.git', templates: SCA_TEMPLATES })
    codebases.push(deps)
    addScan(deps, { id: 73, startedAgoMin: 60 * 3, ref: '3d3d3d3', templates: SCA_TEMPLATES })
    const status = base({ name: 'status-page (live)', project_id: 2, target_type: 'url', language: '', repo_url: null, branch: null, base_url: 'https://status.example.com', dast_status: 'confirmed', dast_registered_by: 3, dast_confirmed_by: 1, dast_confirmed_at: iso(nowMs() - 3 * 86_400_000), templates: DAST_VULN_TEMPLATES })
    codebases.push(status)
    addScan(status, { id: 74, startedAgoMin: 200, ref: '', templates: DAST_VULN_TEMPLATES })

    addUser('former-dev', 'former-password-1234', 'member').is_active = false
    sf.schedule = { cron: '0 2 * * *', owner_id: 1, status: 'active', suspended_reason: null, suspended_at: null, last_enqueued_at: iso(nowMs() - 20 * 3_600_000) }
    admin.schedule = { cron: '0 2 * * 1', owner_id: 3, status: 'active', suspended_reason: null, suspended_at: null, last_enqueued_at: iso(nowMs() - 2 * 86_400_000) }
    const legacy = codebases.find(c => c.name === 'legacy-cms')!
    legacy.schedule = { cron: '*/30 * * * *', owner_id: 5, status: 'suspended', suspended_reason: 'owner_deactivated', suspended_at: iso(nowMs() - 3_600_000), last_enqueued_at: iso(nowMs() - 4_000_000) }
    for (const cb of codebases) recomputeCurrent(cb.id)
    tokens.push({ id: seq.token++, name: 'storefront pipeline', token_prefix: 'sdrscan_', project_id: 1, created_by: 1, created_at: ts, last_used_at: iso(nowMs() - 3 * 3_600_000), revoked_at: null, hash: 'x' })
    tokens.push({ id: seq.token++, name: 'old runner', token_prefix: 'sdrscan_', project_id: null, created_by: 1, created_at: ts, last_used_at: null, revoked_at: iso(nowMs() - 86_400_000), hash: 'y' })
    audit.push({ id: seq.audit++, at: iso(nowMs() - 3_600_000), actor_name: 'admin', action: 'user_created', target: 'dast-member' })
    audit.push({ id: seq.audit++, at: iso(nowMs() - 1_800_000), actor_name: 'admin', action: 'dast_target_confirmed', target: 'admin-portal (live)' })
    audit.push({ id: seq.audit++, at: iso(nowMs() - 600_000), actor_name: 'unknown', action: 'login_failed', target: 'root' })
  }

  // ---- derived state -------------------------------------------------------------

  const succeeded = (cbId: number) => scans.filter(s => s.codebase_id === cbId && s.status === 'succeeded')
  const byStart = (a: MockScan, b: MockScan) => (a.started_at ?? '').localeCompare(b.started_at ?? '') || a.id - b.id
  const locKey = (f: Finding) => (f.location.kind === 'url' ? f.location.url : f.location.path)

  function baseScanOf(cbId: number): MockScan | undefined {
    return succeeded(cbId).filter(s => s.coverage === 'full').sort(byStart).pop()
  }
  function partialsSince(cbId: number, base: MockScan): MockScan[] {
    return succeeded(cbId).filter(s => s.coverage === 'partial' && byStart(s, base) > 0).sort(byStart)
  }

  /** Latest state: base full scan, overridden per file by later partial scans. */
  function currentFindings(cbId: number): Finding[] {
    const base = baseScanOf(cbId)
    if (!base) return []
    const owner = new Map<string, number>()
    for (const p of partialsSince(cbId, base)) for (const path of p.scanned_files ?? []) owner.set(path, p.id)
    return findings.filter((f) => {
      if (f.codebase_id !== cbId) return false
      const o = owner.get(locKey(f))
      return o === undefined ? f.scan_id === base.id : f.scan_id === o
    })
  }

  function recomputeCurrent(cbId: number) {
    const cur = new Set(currentFindings(cbId).map(f => f.id))
    for (const f of findings) if (f.codebase_id === cbId) f.is_current = cur.has(f.id)
  }

  function summarize(list: Finding[]): SeveritySummary {
    const out: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, highest_severity: null }
    for (const f of list) if (f.confidence === 'normal') out[f.severity]++
    out.highest_severity = SEVERITIES.find(s => out[s] > 0) ?? null
    return out
  }

  const codebaseSummary = (cbId: number): SeveritySummary | null => (baseScanOf(cbId) ? summarize(currentFindings(cbId)) : null)

  function scanRef(s: MockScan | undefined): ScanRef | null {
    return s ? { id: s.id, coverage: s.coverage, status: s.status, started_at: s.started_at, ref: s.ref, type: s.type } : null
  }
  const latestScanOf = (cbId: number) => succeeded(cbId).sort(byStart).pop()

  // ---- scan simulation ---------------------------------------------------------------

  const ms = (n: number) => n * speed

  function startSim(cb: MockCodebase, user: MockUser, opts: { active?: boolean, activeTiming?: boolean } = {}): MockScan {
    const willFail = cb.name.toLowerCase().includes('fail')
    const crawl = cb.target_type === 'url' && cb.crawl.enabled
    const active = !!opts.active && cb.target_type === 'url'
    const activeTiming = active && !!opts.activeTiming
    const activeKind = `boolean/error-based/XSS/open-redirect/header-injection${activeTiming ? '/time-based' : ''}`
    const plan = [
      { at: ms(1500), status: 'running' as ScanStatus, line: cb.target_type === 'url' ? `resolving ${cb.base_url}` : `cloning ${cb.repo_url} (branch ${cb.branch})` },
      { at: ms(2000), line: cb.auth && cb.target_type === 'url' ? `authenticated scan (${cb.auth.type})` : undefined },
      { at: ms(2200), line: crawl ? `crawl enabled (max depth ${cb.crawl.max_depth}, max pages ${cb.crawl.max_pages}, ${cb.crawl.exclude.length} excluded patterns)` : undefined },
      { at: ms(2350), line: active ? `active scanning authorized by ${user.username} on ${iso().slice(0, 10)}, type: ${activeKind}` : undefined },
      { at: ms(2400), line: active && cb.openapi_spec_url ? `OpenAPI/Swagger spec: ${cb.openapi_spec_url}` : undefined },
      { at: ms(2500), line: cb.target_type === 'url' ? 'passive checks started (max 100 requests)' : 'cloned 9d8c7b6 (depth 1)' },
      { at: ms(3500), line: cb.target_type === 'url' ? `scan summary: ${crawl ? Math.min(cb.crawl.max_pages, 12) : (cb.auth ? 2 : 1)} pages scanned` : `running sdrscan-sast on ${cb.subdirectory || '.'}` },
      { at: ms(3600), line: active ? `${activeTiming ? 23 : 11} active requests sent` : undefined },
      { at: ms(5000), line: willFail ? 'fatal: engine exited with code 2' : 'ingesting results' },
      { at: ms(6000), status: (willFail ? 'failed' : 'succeeded') as ScanStatus, line: willFail ? undefined : 'done' },
    ]
    const s: MockScan = {
      id: seq.scan++, codebase_id: cb.id, type: cb.target_type === 'url' ? 'dast' : 'sast', coverage: 'full', trigger: 'manual', status: 'queued', queued_at: iso(),
      started_at: null, finished_at: null, ref: '', engine: cb.target_type === 'url' ? 'sdrscan-dast' : 'sdrscan-sast', engine_version: '0.1.0', scanned_files: null,
      active, active_timing: activeTiming, error_code: null, log: [], sim: { queuedAtMs: nowMs(), plan, outcome: willFail ? 'failed' : 'succeeded', cancelled: false },
    }
    scans.push(s)
    return s
  }

  function finishSucceeded(s: MockScan) {
    const cb = codebases.find(c => c.id === s.codebase_id)!
    const cur = currentFindings(cb.id)
    // New full result: previous state, minus one finding (fixed), plus one new finding.
    const keep = cur.filter((_, i) => i !== 0)
    const templates = cb.templates
    const keepKeys = new Set(keep.map(f => f.fingerprint))
    const carry = templates.filter(t => keepKeys.has(fingerprintOf(t.key)))
    const fresh: FindingTemplate = s.active
      ? { key: `new:${s.id}`, rule_id: 'dast-active-sqli-error-based', severity: 'critical', message: 'A database error was disclosed after injecting a test payload into a request parameter.', url: `${cb.base_url}/report?id=1'`, snippet: "GET /report?id=1' HTTP/1.1\n\nHTTP/1.1 500 Internal Server Error\nSQL syntax error", cwe: ['CWE-89'] }
      : cb.target_type === 'url'
        ? { key: `new:${s.id}`, rule_id: 'http-missing-referrer-policy', severity: 'low', message: 'Referrer-Policy header is missing.', url: `${cb.base_url}/account`, snippet: 'GET /account HTTP/1.1\n\nHTTP/1.1 200 OK', cwe: ['CWE-200'] }
        : { key: `new:${s.id}`, rule_id: 'php-weak-hash-md5', severity: 'medium', message: 'MD5 is not suitable for password hashing. Use password_hash().', path: 'src/Util/Hash.php', start_line: 3, end_line: 3, start_column: 5, end_column: 30, snippet: '$h = md5($pw);', cwe: ['CWE-328'] }
    for (const t of [...carry, fresh]) makeFinding(s, t)
    cb.templates = [...carry, fresh]
    s.ref = s.ref || '9d8c7b6'
    recomputeCurrent(cb.id)
  }

  /** Advance simulated scans according to elapsed time. */
  function tick(s: MockScan) {
    const sim = s.sim
    if (!sim || s.status === 'succeeded' || s.status === 'failed' || s.status === 'cancelled') return
    if (sim.cancelled) return
    const elapsed = nowMs() - sim.queuedAtMs
    for (const step of sim.plan) {
      if (elapsed < step.at) break
      const at = sim.queuedAtMs + step.at
      if (step.line && !s.log.some(l => l.t === at && l.line === step.line)) s.log.push({ t: at, line: step.line })
      if (step.status === 'running' && s.status === 'queued') { s.status = 'running'; s.started_at = iso(at) }
      if (step.status === 'succeeded' || step.status === 'failed') {
        s.status = step.status
        s.finished_at = iso(at)
        if (step.status === 'failed') {
          s.error_code = 'engine_failed'
        } else {
          finishSucceeded(s)
        }
      }
    }
  }

  const tickAll = () => scans.forEach(tick)

  function scanDto(s: MockScan, withLog = false): Scan {
    tick(s)
    const own = findings.filter(f => f.scan_id === s.id)
    const dto: Scan = {
      id: s.id, codebase_id: s.codebase_id, type: s.type, coverage: s.coverage, trigger: s.trigger, status: s.status, queued_at: s.queued_at, started_at: s.started_at,
      finished_at: s.finished_at, ref: s.ref, engine: s.engine, engine_version: s.engine_version, scanned_file_count: s.scanned_files?.length ?? null,
      summary: s.status === 'succeeded' ? summarize(own) : null, error_code: s.error_code, active: s.active, active_timing: s.active_timing,
    }
    if (withLog) dto.log_tail = s.log.map(l => l.line).join('\n')
    return dto
  }

  // ---- helpers ---------------------------------------------------------------------------

  const asObj = (b: unknown): Record<string, unknown> => (b && typeof b === 'object' && !Array.isArray(b) ? (b as Record<string, unknown>) : {})
  const str = (v: unknown) => (typeof v === 'string' ? v : undefined)

  function paged<T>(list: T[], q: URLSearchParams) {
    const page = Math.max(1, Number(q.get('page')) || 1)
    const size = Math.min(200, Math.max(1, Number(q.get('page_size')) || 50))
    return { items: list.slice((page - 1) * size, page * size), total: list.length, page, page_size: size }
  }

  function validationFailed(message: string, details?: unknown): never {
    return fail(422, 'validation_failed', message, details)
  }

  /** The error contract of the real backend: details.field names the first failing field, details.fields lists all of them when there are several. */
  interface FieldIssue { field: string, message: string, code?: string }
  class Issues {
    readonly list: FieldIssue[] = []
    add(field: string, message: string, code?: string) { this.list.push({ field, message, ...(code ? { code } : {}) }) }
    get any() { return this.list.length > 0 }
    /** Throws 422 when something was recorded. A single failure keeps its own code (address_not_allowed, invalid_cron, ...). */
    throwIf(): void {
      const [first] = this.list
      if (!first) return
      if (this.list.length === 1) fail(422, first.code ?? 'validation_failed', first.message, { field: first.field })
      fail(422, 'validation_failed', first.message, { field: first.field, fields: this.list })
    }
  }
  function invalidField(field: string, message: string, code?: string): never {
    return fail(422, code ?? 'validation_failed', message, { field })
  }

  /** null when the name is fine; otherwise the message the backend gives. */
  function nameIssue(v: unknown, field = 'name'): string | null {
    const raw = str(v) ?? ''
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(raw)) return `${field} must not contain control characters.`
    const n = raw.trim()
    if (n.length < 1) return `${field} is required.`
    if (n.length > 100) return `${field} must be at most 100 characters.`
    return null
  }
  const passwordIssue = (pw: string, who: string, username: string): string | null => {
    if (!pw) return `${who} is required.`
    if (pw.length < 12) return `${who === 'New password' ? 'Password' : who} must be at least 12 characters.`
    if (pw.length > 128) return `${who === 'New password' ? 'Password' : who} must be at most 128 characters.`
    if (pw.toLowerCase() === username.toLowerCase()) return 'Password must not be the same as the username.'
    return null
  }

  function addAudit(actor: MockUser | null, action: string, target?: string) {
    audit.unshift({ id: seq.audit++, at: iso(), actor_name: actor?.username ?? 'unknown', action, target: target ?? null })
  }

  const hasDast = (u: MockUser) => u.role === 'admin' || u.can_run_dast
  const userDto = (u: MockUser) => ({ id: u.id, username: u.username, role: u.role, can_run_dast: u.can_run_dast, is_active: u.is_active, last_login_at: u.last_login_at, must_change_password: u.must_change_password })

  /** Schedule object of GET /codebases/{id} and rows of GET /schedules. URL targets only run once confirmed. */
  function scheduleDto(cb: MockCodebase) {
    const sc = cb.schedule
    if (!sc) return null
    const owner = users.find(u => u.id === sc.owner_id)
    const runs = sc.status === 'active' && (cb.target_type === 'repo' || cb.dast_status === 'confirmed') ? nextRuns(sc.cron, new Date(nowMs()), 1) : []
    return {
      cron: sc.cron, status: sc.status, owner: owner ? { id: owner.id, username: owner.username } : null, suspended_reason: sc.suspended_reason, suspended_at: sc.suspended_at,
      last_enqueued_at: sc.last_enqueued_at, next_run_at: runs[0]?.toISOString() ?? null,
    }
  }

  /** Owner changes suspend schedules immediately (deactivated, or lost DAST access for URL targets). SAST schedules survive a lost can_run_dast. */
  function suspendSchedulesOf(u: MockUser, actor: MockUser) {
    for (const cb of codebases) {
      const sc = cb.schedule
      if (!sc || sc.owner_id !== u.id || sc.status !== 'active') continue
      const reason = !u.is_active ? 'owner_deactivated' : (cb.target_type === 'url' && !hasDast(u) ? 'owner_lost_permission' : null)
      if (!reason) continue
      sc.status = 'suspended'
      sc.suspended_reason = reason
      sc.suspended_at = iso()
      addAudit(actor, 'schedule_suspended', cb.name)
    }
  }

  function codebaseDto(cb: MockCodebase): Codebase {
    const base = baseScanOf(cb.id)
    const proj = projects.find(p => p.id === cb.project_id)!
    const active = scans.filter(s => s.codebase_id === cb.id && (tick(s), s.status === 'queued' || s.status === 'running')).sort((a, b) => b.id - a.id)[0]
    const ref = (id: number | null) => {
      const u = users.find(x => x.id === id)
      return u ? { id: u.id, username: u.username } : null
    }
    const isUrl = cb.target_type === 'url'
    const dastActiveDto = isUrl
      ? { authorized: cb.active_authorized_at !== null, authorized_at: cb.active_authorized_at, authorized_by: ref(cb.active_authorized_by), openapi_spec_url: cb.openapi_spec_url }
      : null
    return {
      id: cb.id, project: { id: proj.id, name: proj.name }, name: cb.name, target_type: cb.target_type, language: cb.language,
      repo_url: cb.repo_url, branch: cb.branch, subdirectory: isUrl ? null : cb.subdirectory, git_auth_kind: isUrl ? null : cb.git_auth_kind,
      git_username: cb.git_username, has_credential: isUrl ? null : cb.has_credential, base_url: cb.base_url, dast_max_rps: isUrl ? cb.dast_max_rps : null,
      dast: isUrl ? { status: cb.dast_status!, registered_by: ref(cb.dast_registered_by), confirmed_by: ref(cb.dast_confirmed_by), confirmed_at: cb.dast_confirmed_at } : null,
      dast_active: dastActiveDto,
      confirmation_statement: isUrl && cb.dast_status === 'pending_confirmation' ? `I confirm that I am authorized to run security scans against ${cb.base_url}.` : null,
      summary: codebaseSummary(cb.id), latest_scan: scanRef(latestScanOf(cb.id)), base_scan: scanRef(base),
      state: base ? { base_scan_id: base.id, partial_scans_since_base: partialsSince(cb.id, base).length } : null,
      active_scan: active ? { id: active.id, type: active.type, status: active.status as ScanStatus, trigger: active.trigger, queued_at: active.queued_at, started_at: active.started_at } : null,
      schedule: scheduleDto(cb), dast_auth: isUrl ? authDto(cb) : null, dast_crawl: isUrl ? { ...cb.crawl, exclude: [...cb.crawl.exclude] } : null,
      created_at: cb.created_at, updated_at: cb.updated_at,
    }
  }

  /** The non-secret description (type, has_secret, names): the only thing the API ever returns about credentials. */
  function authDto(cb: MockCodebase): DastAuth {
    const a = cb.auth
    if (!a) {
      return { type: 'none', has_secret: false, login_url: null, method: null, body_format: null, username_field: null, password_field: null, username: null,
        extra_field_names: [], csrf: null, token: null, success: null, header_names: [], cookie_names: [], updated_at: null, updated_by: null }
    }
    return { type: a.type, has_secret: true, ...a.meta }
  }

  function codebaseRow(cb: MockCodebase): CodebaseRow {
    const base = baseScanOf(cb.id)
    return {
      id: cb.id, name: cb.name, target_type: cb.target_type, subdirectory: cb.subdirectory, language: cb.language, ...(cb.target_type === 'url' ? { dast_status: cb.dast_status } : {}),
      latest_scan: scanRef(latestScanOf(cb.id)), state: base ? { base_scan_id: base.id, partial_scans_since_base: partialsSince(cb.id, base).length } : null, summary: codebaseSummary(cb.id),
    }
  }

  function sumOf(list: Array<SeveritySummary | null>): SeveritySummary {
    const out: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, highest_severity: null }
    for (const s of list) if (s) for (const k of SEVERITIES) out[k] += s[k]
    out.highest_severity = SEVERITIES.find(s => out[s] > 0) ?? null
    return out
  }

  type FindingFacetKey = 'severity' | 'rule' | 'kind' | 'cve' | 'confidence' | 'scope'
  const ADVISORY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/

  function filterFindings(list: Finding[], q: URLSearchParams, skip: FindingFacetKey[] = []) {
    const sev = (q.get('severity') ?? '').split(',').filter(Boolean)
    const rule = q.get('rule')
    const path = q.get('path')
    const text = q.get('q')?.toLowerCase()
    const low = q.get('include_low_confidence') === 'true'
    const kind = q.get('kind')
    if (kind && kind !== 'code' && kind !== 'vulnerability') fail(400, 'bad_request', 'kind must be code or vulnerability.')
    const cve = q.get('cve')
    if (cve && !ADVISORY_ID.test(cve)) fail(400, 'bad_request', 'cve must be an advisory id such as CVE-2024-12345.')
    const cveLower = cve?.toLowerCase()
    const vconf = q.get('confidence')
    if (vconf && vconf !== 'high' && vconf !== 'low') fail(400, 'bad_request', 'confidence must be high or low.')
    const vscope = q.get('scope')
    if (vscope && vscope !== 'runtime' && vscope !== 'dev') fail(400, 'bad_request', 'scope must be runtime or dev.')
    return list.filter((f) => {
      if (!low && f.confidence === 'low') return false
      if (!skip.includes('severity') && sev.length && !sev.includes(f.severity)) return false
      if (!skip.includes('rule') && rule && f.rule_id !== rule) return false
      if (!skip.includes('kind') && kind && f.kind !== kind) return false
      if (!skip.includes('cve') && cveLower && !(f.vulnerability?.ids ?? []).some(id => id.toLowerCase() === cveLower)) return false
      if (!skip.includes('confidence') && vconf && f.vulnerability?.confidence !== vconf) return false
      if (!skip.includes('scope') && vscope && f.vulnerability?.scope !== vscope) return false
      if (path && !locKey(f).startsWith(path)) return false
      if (text) {
        const v = f.vulnerability
        const hay = `${locKey(f)}\n${f.message}\n${(v?.ids ?? []).join(' ')}\n${v?.package?.name ?? ''} ${v?.package?.product ?? ''}`.toLowerCase()
        if (!hay.includes(text)) return false
      }
      return true
    })
  }

  const summaryOfFinding = (f: Finding): FindingSummary => ({ id: f.id, rule_id: f.rule_id, severity: f.severity, confidence: f.confidence, message: f.message, location: f.location, redacted: f.redacted, kind: f.kind, vulnerability: f.vulnerability })

  function findingsPage(list: Finding[], q: URLSearchParams) {
    const filtered = filterFindings(list, q)
    const sorted = [...filtered].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || locKey(a).localeCompare(locKey(b)) || ((a.location.kind === 'file' ? a.location.start_line ?? 0 : 0) - (b.location.kind === 'file' ? b.location.start_line ?? 0 : 0)))
    const sevFacet: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of filterFindings(list, q, ['severity'])) sevFacet[f.severity]++
    const ruleCount = new Map<string, number>()
    for (const f of filterFindings(list, q, ['rule'])) ruleCount.set(f.rule_id, (ruleCount.get(f.rule_id) ?? 0) + 1)
    const kindFacet = { code: 0, vulnerability: 0 }
    for (const f of filterFindings(list, q, ['kind'])) kindFacet[f.kind]++
    const confFacet = { high: 0, low: 0 }
    for (const f of filterFindings(list, q, ['confidence'])) if (f.vulnerability?.confidence) confFacet[f.vulnerability.confidence]++
    const scopeFacet = { runtime: 0, dev: 0 }
    for (const f of filterFindings(list, q, ['scope'])) if (f.vulnerability?.scope) scopeFacet[f.vulnerability.scope]++
    const cveCount = new Map<string, number>()
    for (const f of filterFindings(list, q, ['cve'])) for (const id of (f.vulnerability?.ids ?? []).filter(i => /^CVE-/.test(i))) cveCount.set(id, (cveCount.get(id) ?? 0) + 1)
    const cve = [...cveCount.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)).slice(0, 100)
    const packages = new Set<string>()
    for (const f of filterFindings(list, q, ['kind', 'cve'])) {
      const p = f.vulnerability?.package
      if (f.vulnerability) packages.add(`${p?.ecosystem ?? ''}|${p?.name ?? p?.product ?? f.rule_id}@${p?.version ?? ''}`)
    }
    const selected = q.get('rule')
    if (selected && !ruleCount.has(selected)) ruleCount.set(selected, 0)
    const rule = [...ruleCount.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
    const page = paged(sorted, q)
    return { ...page, items: page.items.map(summaryOfFinding), facets: { severity: sevFacet, rule, kind: kindFacet, cve, confidence: confFacet, scope: scopeFacet, vulnerable_packages: packages.size } }
  }

  function filesRows(list: Finding[], q: URLSearchParams) {
    const map = new Map<string, FileRow & { rank: number }>()
    for (const f of list) {
      if (f.confidence !== 'normal') continue
      const key = locKey(f)
      const row = map.get(key) ?? { location: key, kind: f.location.kind, total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, rank: -1 }
      row.total++
      row[f.severity] = (row[f.severity] ?? 0) + 1
      row.rank = Math.max(row.rank, SEV_RANK[f.severity])
      map.set(key, row)
    }
    const rows = [...map.values()].sort((a, b) => b.rank - a.rank || b.total - a.total || a.location.localeCompare(b.location)).map(({ rank: _r, ...r }) => r)
    return paged(rows, q)
  }

  const cmpScan = (s: MockScan) => ({ id: s.id, started_at: s.started_at, coverage: s.coverage })

  function compare(cb: MockCodebase, q: URLSearchParams) {
    const ok = succeeded(cb.id).sort(byStart)
    const baseId = Number(q.get('base')) || undefined
    const headId = Number(q.get('head')) || undefined
    let head = headId ? ok.find(s => s.id === headId) : ok[ok.length - 1]
    let base = baseId ? ok.find(s => s.id === baseId) : (headId ? undefined : ok[ok.length - 2])
    if ((baseId && !base) || (headId && !head)) fail(400, 'bad_request', 'Both scans must be successful scans of this codebase.')
    if (!head) fail(404, 'not_found', 'There is no successful scan to compare yet.')
    head = head!
    if (!baseId && headId) base = ok.filter(s => byStart(s, head!) < 0).pop()
    // Scope: partial scans limit the comparison to the files they scanned.
    let scope: { kind: 'all' | 'partial', file_count?: number } = { kind: 'all' }
    let allowed: Set<string> | null = null
    const partials = [base, head].filter((s): s is MockScan => !!s && s.coverage === 'partial')
    if (partials.length) {
      const sets = partials.map(p => new Set(p.scanned_files ?? []))
      allowed = sets.length === 2 ? new Set([...sets[0]!].filter(x => sets[1]!.has(x))) : sets[0]!
      scope = { kind: 'partial', file_count: allowed.size }
    }
    const pick = (s: MockScan | undefined) => (s ? findings.filter(f => f.scan_id === s.id && f.confidence === 'normal' && (!allowed || allowed.has(locKey(f)))) : [])
    const b = pick(base)
    const h = pick(head)
    const idOf = (f: Finding) => `${f.fingerprint}#1`
    const bIds = new Set(b.map(idOf))
    const hIds = new Set(h.map(idOf))
    const groups = {
      new: h.filter(f => !bIds.has(idOf(f))),
      unchanged: h.filter(f => bIds.has(idOf(f))),
      fixed: b.filter(f => !hIds.has(idOf(f))),
    }
    const status = (q.get('status') ?? 'new') as 'new' | 'unchanged' | 'fixed'
    if (!(status in groups)) fail(400, 'bad_request', 'status must be new, unchanged or fixed.')
    const sorted = [...groups[status]].sort((a, c) => SEV_RANK[c.severity] - SEV_RANK[a.severity] || locKey(a).localeCompare(locKey(c)))
    return {
      base: base ? cmpScan(base) : null, head: cmpScan(head), counts: { new: groups.new.length, unchanged: groups.unchanged.length, fixed: groups.fixed.length }, scope,
      warning: scope.kind === 'partial' && scope.file_count === 0 ? { code: 'empty_scope', message: 'The two partial scans share no scanned files, so there is nothing to compare.' } : null,
      status, ...(({ items, ...rest }) => ({ ...rest, items: items.map(f => ({ status, finding: summaryOfFinding(f) })) }))(paged(sorted, q)),
    }
  }

  /** Messages of the backend's netguard; null when the URL is acceptable. */
  function repoUrlIssue(v: string): FieldIssue | null {
    const u = v.trim()
    if (!u) return { field: 'repo_url', message: 'repo_url is required.' }
    if (u.startsWith('-')) return { field: 'repo_url', message: "repo_url must not start with '-'." }
    if (!/^(https:\/\/[^\s/@]+\/\S+|ssh:\/\/[^\s/@]+\/\S+|git@[\w.-]+:\S+)$/.test(u)) return { field: 'repo_url', message: 'repo_url must be https://host/path, ssh://host/path or git@host:path.' }
    const host = /^git@([\w.-]+):/.exec(u)?.[1] ?? new URL(u).hostname
    if (isPrivateHost(host)) return { field: 'repo_url', message: PRIVATE_NETWORK_MESSAGE, code: 'address_not_allowed' }
    return null
  }
  function baseUrlIssue(v: string): FieldIssue | null {
    if (!v.trim()) return { field: 'base_url', message: 'base_url is required.' }
    let u: URL
    try { u = new URL(v) } catch { return { field: 'base_url', message: 'base_url is not a valid URL.' } }
    if (!['http:', 'https:'].includes(u.protocol)) return { field: 'base_url', message: 'base_url must use http or https.' }
    if (u.username || u.password) return { field: 'base_url', message: 'base_url must not contain credentials.' }
    if (u.search || v.includes('?')) return { field: 'base_url', message: 'base_url must not contain a query or fragment.' }
    if (isPrivateHost(u.hostname)) return { field: 'base_url', message: PRIVATE_NETWORK_MESSAGE, code: 'address_not_allowed' }
    return null
  }
  const BRANCH_RE = /^[A-Za-z0-9._/-]{1,200}$/
  const branchIssue = (v: string) => (BRANCH_RE.test(v) && !v.startsWith('-') && !v.includes('..') ? null : 'branch must match ^[A-Za-z0-9._/-]{1,200}$ and must not start with \'-\' or contain \'..\'.')
  const subdirIssue = (v: string) => {
    if (!v) return null
    if (v.startsWith('/') || v.includes('\\') || v.length > 500) return "subdirectory must be a relative path with '/' separators (at most 500 characters)."
    if (v.split('/').includes('..')) return "subdirectory must not contain '..'."
    return null
  }

  // ---- routing ----------------------------------------------------------------------------

  type Ctx = { user: MockUser, csrf: string, q: URLSearchParams, body: Record<string, unknown>, params: string[], req: MockRequest }
  type Handler = (c: Ctx) => { status?: number, body?: unknown, headers?: Record<string, string> } | undefined
  interface Route { method: string, re: RegExp, auth: 'none' | 'session', csrf: boolean, admin?: boolean, h: Handler }
  const routes: Route[] = []
  const route = (method: string, pattern: string, opts: { auth?: 'none' | 'session', admin?: boolean }, h: Handler) => {
    const re = new RegExp(`^${pattern.replace(/:id/g, '(\\d+)')}$`)
    routes.push({ method, re, auth: opts.auth ?? 'session', csrf: method !== 'GET' && (opts.auth ?? 'session') !== 'none', admin: opts.admin, h })
  }
  const findProject = (id: string) => projects.find(p => p.id === Number(id)) ?? fail(404, 'not_found', 'Project not found.')
  const findCodebase = (id: string) => codebases.find(c => c.id === Number(id) && visible(c)) ?? fail(404, 'not_found', 'Codebase not found.')
  const findScan = (id: string) => scans.find(s => s.id === Number(id) && visible(codebases.find(c => c.id === s.codebase_id)!)) ?? fail(404, 'not_found', 'Scan not found.')

  const throttle = new Map<string, number>()

  // auth
  route('GET', '/healthz', { auth: 'none' }, () => ({ body: { status: 'ok' } }))
  route('POST', '/auth/login', { auth: 'none' }, ({ body, req }) => {
    const username = str(body.username)?.trim() ?? ''
    const password = str(body.password) ?? ''
    const missing = new Issues()
    if (!username) missing.add('username', 'Username is required.')
    if (!password) missing.add('password', 'Password is required.')
    missing.throwIf()
    const u = users.find(x => x.username.toLowerCase() === username.toLowerCase())
    const key = username.toLowerCase()
    const lockedUntil = u?.lockedUntil ?? throttle.get(key) ?? 0
    if (lockedUntil > nowMs()) fail(429, 'login_throttled', 'Too many attempts. Try again later.', undefined, { 'Retry-After': String(Math.ceil((lockedUntil - nowMs()) / 1000)) })
    if (!u || !u.is_active || u.password !== password) {
      if (u) {
        u.failed++
        if (u.failed >= 5) { u.lockedUntil = nowMs() + 15 * 60_000; u.failed = 0 }
      }
      addAudit(null, 'login_failed', username)
      fail(401, 'invalid_credentials', 'Invalid username or password.')
    }
    u.failed = 0
    u.last_login_at = iso()
    const token = `s_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`
    const csrf = `c_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`
    sessions.set(token, { userId: u.id, csrf })
    void req
    return { body: { user: userDto(u), csrf_token: csrf, must_change_password: u.must_change_password }, headers: { 'Set-Cookie': `sdrscan_session=${token}; HttpOnly; SameSite=Strict; Path=/` } }
  })
  route('POST', '/auth/logout', {}, ({ req }) => {
    const token = cookieToken(req)
    if (token) sessions.delete(token)
    return { status: 204, headers: { 'Set-Cookie': 'sdrscan_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' } }
  })
  route('GET', '/auth/me', {}, ({ user, csrf }) => ({ body: { user: userDto(user), csrf_token: csrf, must_change_password: user.must_change_password } }))
  route('POST', '/auth/password', {}, ({ user, body, req }) => {
    const issues = new Issues()
    const cur = str(body.current_password) ?? ''
    const next = str(body.new_password) ?? ''
    if (!cur) issues.add('current_password', 'Current password is required.')
    else if (cur !== user.password) issues.add('current_password', 'Current password is incorrect.')
    if (!next) issues.add('new_password', 'New password is required.')
    else {
      const m = passwordIssue(next, 'New password', user.username)
      if (m) issues.add('new_password', m)
      else if (cur === user.password && next === user.password) issues.add('new_password', 'New password must be different from the current password.')
    }
    issues.throwIf()
    user.password = next
    user.must_change_password = false
    const keep = cookieToken(req)
    for (const [t, s] of sessions) if (s.userId === user.id && t !== keep) sessions.delete(t)
    return { status: 204 }
  })

  // users
  route('GET', '/users', { admin: true }, ({ q }) => ({ body: paged(users.map(userDto), q) }))
  route('POST', '/users', { admin: true }, ({ user, body }) => {
    const username = str(body.username)?.trim() ?? ''
    const pw = str(body.password) ?? ''
    const issues = new Issues()
    if (!username) issues.add('username', 'Username is required.')
    else if (!/^[A-Za-z0-9._-]{3,64}$/.test(username)) issues.add('username', "Username must be 3 to 64 characters from A-Z, a-z, 0-9, '.', '_' and '-'.")
    if (body.role !== undefined && body.role !== '' && body.role !== 'admin' && body.role !== 'member') issues.add('role', "role must be 'admin' or 'member'.")
    const pwMsg = passwordIssue(pw, 'Password', username)
    if (pwMsg) issues.add('password', pwMsg)
    issues.throwIf()
    if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) fail(409, 'username_taken', 'That username is already taken.', { field: 'username' })
    const role = body.role === 'admin' ? 'admin' : 'member'
    const u = addUser(username, pw, role, body.can_run_dast === true, true)
    addAudit(user, 'user_created', username)
    return { status: 201, body: userDto(u) }
  })
  route('PATCH', '/users/:id', { admin: true }, ({ user, body, params }) => {
    const target = users.find(u => u.id === Number(params[0])) ?? fail(404, 'not_found', 'User not found.')
    const activeAdmins = () => users.filter(u => u.role === 'admin' && u.is_active)
    if ((body.role === 'member' && target.role === 'admin') || (body.is_active === false && target.role === 'admin' && target.is_active)) {
      if (activeAdmins().length <= 1 && activeAdmins()[0]?.id === target.id) fail(409, 'last_admin', 'There must be at least one active Admin.')
    }
    if (body.role === 'admin' || body.role === 'member') { target.role = body.role as Role; addAudit(user, 'user_role_changed', target.username) }
    if (typeof body.can_run_dast === 'boolean') { target.can_run_dast = body.can_run_dast; addAudit(user, 'user_dast_access_changed', target.username) }
    if (typeof body.is_active === 'boolean') {
      target.is_active = body.is_active
      if (!body.is_active) { for (const [t, s] of sessions) if (s.userId === target.id) sessions.delete(t); addAudit(user, 'user_disabled', target.username) }
    }
    suspendSchedulesOf(target, user)
    return { body: userDto(target) }
  })
  route('POST', '/users/:id/reset-password', { admin: true }, ({ user, body, params }) => {
    const target = users.find(u => u.id === Number(params[0])) ?? fail(404, 'not_found', 'User not found.')
    const pw = str(body.new_password) ?? ''
    const pwMsg = passwordIssue(pw, 'New password', target.username)
    if (pwMsg) invalidField('new_password', pwMsg)
    target.password = pw
    target.must_change_password = true
    for (const [t, s] of sessions) if (s.userId === target.id) sessions.delete(t)
    addAudit(user, 'password_reset', target.username)
    return { status: 204 }
  })
  route('GET', '/audit-log', { admin: true }, ({ q }) => ({ body: paged(audit, q) }))

  // projects
  route('GET', '/projects', {}, ({ q }) => {
    tickAll()
    const items: ProjectListItem[] = [...projects].sort((a, b) => a.name.localeCompare(b.name)).map((p) => {
      const cbs = codebases.filter(c => c.project_id === p.id && visible(c))
      const { highest_severity, ...totals } = sumOf(cbs.map(c => codebaseSummary(c.id)))
      return { id: p.id, name: p.name, description: p.description, codebase_count: cbs.length, totals, highest_severity: highest_severity ?? null, created_at: p.created_at }
    })
    return { body: paged(items, q) }
  })
  route('POST', '/projects', {}, ({ body }) => {
    const issues = new Issues()
    const nm = nameIssue(body.name)
    if (nm) issues.add('name', nm)
    const description = str(body.description)?.trim() ?? ''
    if (description.length > 1000) issues.add('description', 'description must be at most 1000 characters.')
    issues.throwIf()
    const name = str(body.name)!.trim()
    if (projects.some(p => p.name.toLowerCase() === name.toLowerCase())) fail(409, 'name_taken', 'Project name is already in use.', { field: 'name' })
    const p = { id: seq.project++, name, description, created_at: iso(), updated_at: iso() }
    projects.push(p)
    return { status: 201, body: p }
  })
  route('GET', '/projects/:id', {}, ({ params }) => {
    tickAll()
    const p = findProject(params[0]!)
    const cbs = codebases.filter(c => c.project_id === p.id && visible(c)).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
    const rows = cbs.map(codebaseRow)
    return { body: { project: { id: p.id, name: p.name, description: p.description }, totals: sumOf(rows.map(r => r.summary)), codebases: rows } }
  })
  route('PATCH', '/projects/:id', {}, ({ body, params }) => {
    const p = findProject(params[0]!)
    const issues = new Issues()
    if (body.name !== undefined) { const m = nameIssue(body.name); if (m) issues.add('name', m) }
    if (body.description !== undefined && (str(body.description)?.trim().length ?? 0) > 1000) issues.add('description', 'description must be at most 1000 characters.')
    issues.throwIf()
    if (body.name !== undefined) {
      const name = str(body.name)!.trim()
      if (projects.some(x => x.id !== p.id && x.name.toLowerCase() === name.toLowerCase())) fail(409, 'name_taken', 'Project name is already in use.', { field: 'name' })
      p.name = name
    }
    if (body.description !== undefined) p.description = str(body.description)?.trim() ?? ''
    p.updated_at = iso()
    return { body: p }
  })
  route('DELETE', '/projects/:id', { admin: true }, ({ user, q, params }) => {
    const p = findProject(params[0]!)
    confirmName(q, p.name)
    const cbs = codebases.filter(c => c.project_id === p.id)
    const result = { codebases: cbs.length, scans: 0, findings: 0 }
    for (const cb of cbs) { const d = removeCodebase(cb); result.scans += d.scans; result.findings += d.findings }
    projects.splice(projects.indexOf(p), 1)
    addAudit(user, 'project_deleted', p.name)
    return { body: { deleted: result } }
  })

  function confirmName(q: URLSearchParams, name: string) {
    const c = q.get('confirm')
    if (c === null || c === '') fail(422, 'confirmation_required', `Type the exact name "${name}" to confirm.`, { field: 'confirm' })
    if (c !== name) fail(422, 'confirmation_mismatch', 'The confirmation does not match the name.', { field: 'confirm' })
  }
  function removeCodebase(cb: MockCodebase) {
    const own = scans.filter(s => s.codebase_id === cb.id)
    const fs = findings.filter(f => f.codebase_id === cb.id)
    for (const s of own) scans.splice(scans.indexOf(s), 1)
    for (const f of fs) findings.splice(findings.indexOf(f), 1)
    codebases.splice(codebases.indexOf(cb), 1)
    return { scans: own.length, findings: fs.length }
  }

  // codebases
  route('POST', '/projects/:id/codebases', {}, ({ user, body, params }) => {
    const p = findProject(params[0]!)
    if (body.target_type === 'url' && !hasDast(user)) fail(403, 'dast_forbidden', 'You need DAST access to register URL targets.')
    // Every field is checked before answering, so the client learns about all of them at once.
    const issues = new Issues()
    const nm = nameIssue(body.name)
    if (nm) issues.add('name', nm)
    if ((str(body.language) ?? '').length > 50) issues.add('language', 'language must be at most 50 characters without control characters.')
    const type = body.target_type
    if (type === undefined || type === '') issues.add('target_type', "target_type is required: choose 'repo' or 'url'.")
    else if (type !== 'repo' && type !== 'url') issues.add('target_type', "target_type must be 'repo' or 'url'.")
    const kind = str(body.git_auth_kind) || 'none'
    if (type === 'repo') {
      const ri = repoUrlIssue(str(body.repo_url) ?? '')
      if (ri) issues.add(ri.field, ri.message, ri.code)
      const branch = str(body.branch)?.trim() || 'main'
      const bi = branchIssue(branch)
      if (bi) issues.add('branch', bi)
      const si = subdirIssue(str(body.subdirectory)?.trim() ?? '')
      if (si) issues.add('subdirectory', si)
      if (!['none', 'https_token', 'ssh_key'].includes(kind)) issues.add('git_auth_kind', 'git_auth_kind must be none, https_token or ssh_key.')
      else if (kind !== 'none' && !str(body.git_secret)) issues.add('git_secret', `git_secret is required when git_auth_kind is ${kind}.`)
    } else if (type === 'url') {
      const bi = baseUrlIssue(str(body.base_url) ?? '')
      if (bi) issues.add(bi.field, bi.message, bi.code)
      if (body.dast_max_rps !== undefined && body.dast_max_rps !== 0 && (typeof body.dast_max_rps !== 'number' || body.dast_max_rps < 1 || body.dast_max_rps > 100)) issues.add('dast_max_rps', 'dast_max_rps must be between 1 and 100.')
    }
    issues.throwIf()
    const name = str(body.name)!.trim()
    if (codebases.some(c => c.project_id === p.id && c.name.toLowerCase() === name.toLowerCase())) fail(409, 'name_taken', 'Codebase name is already in use.', { field: 'name' })
    const cb: MockCodebase = {
      id: seq.codebase++, project_id: p.id, name, target_type: type as 'repo' | 'url', language: str(body.language) ?? '', repo_url: null, branch: null, subdirectory: '', git_auth_kind: 'none',
      git_username: null, has_credential: false, base_url: null, dast_status: null, dast_registered_by: null, dast_confirmed_by: null, dast_confirmed_at: null, dast_max_rps: 5,
      schedule: null, auth: null, crawl: { enabled: false, max_depth: 3, max_pages: 50, exclude: [] },
      active_authorized_at: null, active_authorized_by: null, active_statement: null, openapi_spec_url: null,
      created_at: iso(), updated_at: iso(), templates: [],
    }
    if (type === 'repo') {
      cb.repo_url = str(body.repo_url)!.trim()
      cb.branch = str(body.branch)?.trim() || 'main'
      cb.subdirectory = str(body.subdirectory)?.trim() ?? ''
      cb.git_auth_kind = kind as MockCodebase['git_auth_kind']
      cb.git_username = str(body.git_username) || null
      cb.has_credential = kind !== 'none' && !!str(body.git_secret)
    } else {
      cb.base_url = str(body.base_url)!.trim()
      cb.dast_status = 'pending_confirmation'
      cb.dast_registered_by = user.id
      addAudit(user, 'dast_target_registered', name)
    }
    codebases.push(cb)
    return { status: 201, body: codebaseDto(cb) }
  })
  route('GET', '/codebases/:id', {}, ({ params }) => ({ body: codebaseDto(findCodebase(params[0]!)) }))
  route('PATCH', '/codebases/:id', {}, ({ user, body, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type === 'url' && (body.base_url !== undefined || body.dast_max_rps !== undefined) && !hasDast(user)) fail(403, 'dast_forbidden', 'You need DAST access to change a URL target.')
    const issues = new Issues()
    if (body.name !== undefined) { const m = nameIssue(body.name); if (m) issues.add('name', m) }
    if (body.language !== undefined && (typeof body.language !== 'string' || body.language.length > 50)) issues.add('language', 'language must be at most 50 characters without control characters.')
    if (body.project_id !== undefined) {
      const pid = body.project_id
      if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0) issues.add('project_id', 'project_id must be a positive integer.')
      else if (!projects.some(x => x.id === pid)) issues.add('project_id', 'project_id does not exist.')
    }
    if (cb.target_type === 'repo') {
      for (const k of ['base_url', 'dast_max_rps', 'dast_crawl_enabled', 'dast_crawl_max_depth', 'dast_crawl_max_pages', 'dast_crawl_exclude']) if (body[k] !== undefined) issues.add(k, `${k} applies only to URL targets.`)
      if (body.repo_url !== undefined) { const ri = repoUrlIssue(str(body.repo_url) ?? ''); if (ri) issues.add(ri.field, ri.message, ri.code) }
      if (body.branch !== undefined) { const bi = branchIssue(str(body.branch)?.trim() || 'main'); if (bi) issues.add('branch', bi) }
      if (body.subdirectory !== undefined) { const si = subdirIssue(str(body.subdirectory)?.trim() ?? ''); if (si) issues.add('subdirectory', si) }
      const kind = body.git_auth_kind !== undefined ? String(body.git_auth_kind) : cb.git_auth_kind
      if (!['none', 'https_token', 'ssh_key'].includes(kind)) issues.add('git_auth_kind', 'git_auth_kind must be none, https_token or ssh_key.')
      else if (kind !== 'none' && !cb.has_credential && !str(body.git_secret)) issues.add('git_secret', `git_secret is required when git_auth_kind is ${kind}.`)
    } else {
      for (const k of ['repo_url', 'branch', 'subdirectory', 'git_auth_kind', 'git_username', 'git_secret']) if (body[k] !== undefined) issues.add(k, `${k} applies only to repository targets.`)
      if (body.base_url !== undefined) { const bi = baseUrlIssue(str(body.base_url) ?? ''); if (bi) issues.add(bi.field, bi.message, bi.code) }
      if (body.dast_max_rps !== undefined && (typeof body.dast_max_rps !== 'number' || !Number.isInteger(body.dast_max_rps) || body.dast_max_rps < 1 || body.dast_max_rps > 100)) issues.add('dast_max_rps', 'dast_max_rps must be between 1 and 100.')
      for (const i of crawlIssues(body)) issues.add(i.field, i.message)
      if (body.dast_openapi_spec_url !== undefined && body.dast_openapi_spec_url !== null) {
        const v = str(body.dast_openapi_spec_url)?.trim() ?? ''
        if (v) {
          const bi = baseUrlIssue(v)
          const effectiveBase = typeof body.base_url === 'string' ? body.base_url : cb.base_url
          if (bi) issues.add('dast_openapi_spec_url', bi.message, bi.code)
          else if (!effectiveBase || new URL(v).origin !== new URL(effectiveBase).origin) issues.add('dast_openapi_spec_url', 'dast_openapi_spec_url must be on the same origin as base_url.')
        }
      }
    }
    issues.throwIf()
    if (body.name !== undefined) {
      const name = str(body.name)!.trim()
      const target = Number(body.project_id ?? cb.project_id)
      if (codebases.some(c => c.id !== cb.id && c.project_id === target && c.name.toLowerCase() === name.toLowerCase())) fail(409, 'name_taken', 'Codebase name is already in use.', { field: 'name' })
      cb.name = name
    }
    if (body.project_id !== undefined) {
      const target = Number(body.project_id)
      if (codebases.some(c => c.id !== cb.id && c.project_id === target && c.name.toLowerCase() === cb.name.toLowerCase())) fail(409, 'name_taken', 'Codebase name is already in use.', { field: 'name' })
      cb.project_id = target
    }
    if (body.language !== undefined) cb.language = str(body.language) ?? ''
    if (cb.target_type === 'repo') {
      if (body.repo_url !== undefined) cb.repo_url = str(body.repo_url)!.trim()
      if (body.branch !== undefined) cb.branch = str(body.branch)?.trim() || 'main'
      if (body.subdirectory !== undefined) cb.subdirectory = str(body.subdirectory)?.trim() ?? ''
      if (body.git_auth_kind !== undefined) { cb.git_auth_kind = body.git_auth_kind as MockCodebase['git_auth_kind']; if (cb.git_auth_kind === 'none') cb.has_credential = false }
      if (body.git_username !== undefined) cb.git_username = str(body.git_username) || null
      if (body.git_secret !== undefined && str(body.git_secret)) cb.has_credential = true
    } else {
      if (body.base_url !== undefined && body.base_url !== cb.base_url) {
        const oldOrigin = new URL(cb.base_url!).origin
        cb.base_url = str(body.base_url)!.trim()
        cb.dast_status = 'pending_confirmation'
        cb.dast_confirmed_by = null
        cb.dast_confirmed_at = null
        addAudit(user, 'dast_target_reset', cb.name)
        // Active-scanning authorization is a separate, stricter layer on top of the confirmation above:
        // any base_url change revokes it too.
        if (cb.active_authorized_at !== null) {
          cb.active_authorized_at = null
          cb.active_authorized_by = null
          cb.active_statement = null
          addAudit(user, 'dast_active_revoked', `${cb.name} (target origin changed)`)
        }
        // Credentials and the OpenAPI spec URL never follow a target to another origin.
        if (new URL(cb.base_url).origin !== oldOrigin) {
          if (cb.auth) {
            cb.auth = null
            addAudit(user, 'dast_auth_deleted', `${cb.name} (target origin changed)`)
          }
          cb.openapi_spec_url = null
        }
      }
      if (typeof body.dast_max_rps === 'number') cb.dast_max_rps = body.dast_max_rps
      if (body.dast_openapi_spec_url !== undefined) {
        const v = body.dast_openapi_spec_url === null ? '' : (str(body.dast_openapi_spec_url)?.trim() ?? '')
        cb.openapi_spec_url = v || null
      }
      applyCrawl(cb, body, user)
    }
    cb.updated_at = iso()
    return { body: codebaseDto(cb) }
  })
  route('POST', '/codebases/:id/confirm-authorization', { admin: true }, ({ user, body, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'Only URL targets need authorization confirmation.')
    if (body.statement_accepted !== true) invalidField('statement_accepted', 'statement_accepted must be true: confirm that you are authorized to scan this target.')
    if (cb.dast_status !== 'confirmed') {
      cb.dast_status = 'confirmed'
      cb.dast_confirmed_by = user.id
      cb.dast_confirmed_at = iso()
      addAudit(user, 'dast_target_confirmed', cb.name)
    }
    return { body: codebaseDto(cb) }
  })
  // Active (payload-sending) scanning: a separate, stricter authorization layer on top of confirm-authorization.
  // Not admin-only: Admin or Member with can_run_dast, like dast-auth (URL targets already require that to be visible at all).
  route('POST', '/codebases/:id/authorize-active-scanning', {}, ({ user, body, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'Active scanning applies only to URL targets.')
    if (cb.dast_status !== 'confirmed') fail(409, 'target_not_confirmed', 'An Admin must confirm authorization for this target before active scanning can be authorized.')
    if (body.statement_accepted !== true) invalidField('statement_accepted', 'statement_accepted must be true: confirm that you understand the risks of active scanning.')
    const typedName = str(body.codebase_name) ?? ''
    if (typedName !== cb.name) invalidField('codebase_name', 'codebase_name must exactly match the codebase name.')
    cb.active_authorized_at = iso()
    cb.active_authorized_by = user.id
    cb.active_statement = `I confirm that I am authorized to run ACTIVE security scans (SQL injection, XSS, open redirect and header `
      + `injection test payloads) against ${cb.name}, and that I understand this may affect the target application.`
    cb.updated_at = iso()
    addAudit(user, 'dast_active_authorized', `${cb.name} ${cb.base_url}`)
    return { body: codebaseDto(cb) }
  })
  route('DELETE', '/codebases/:id/authorize-active-scanning', {}, ({ user, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'Active scanning applies only to URL targets.')
    if (cb.active_authorized_at !== null) {
      cb.active_authorized_at = null
      cb.active_authorized_by = null
      cb.active_statement = null
      cb.updated_at = iso()
      addAudit(user, 'dast_active_revoked', cb.name)
    }
    return { status: 204 }
  })
  route('DELETE', '/codebases/:id', { admin: true }, ({ user, q, params }) => {
    const cb = findCodebase(params[0]!)
    confirmName(q, cb.name)
    const d = removeCodebase(cb)
    addAudit(user, 'codebase_deleted', cb.name)
    return { body: { deleted: d } }
  })

  // ---- DAST authentication and crawl ---------------------------------------------------------------

  const HEADER_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/
  const FIELD_NAME = /^[A-Za-z0-9_.:[\]-]{1,100}$/
  const FORBIDDEN_HEADERS = ['host', 'content-length', 'transfer-encoding', 'connection', 'cookie', 'upgrade', 'te', 'trailer', 'keep-alive', 'expect', 'proxy-authorization', 'proxy-connection', 'x-forwarded-host']
  // eslint-disable-next-line no-control-regex
  const hasCtlChar = (v: string): boolean => /[\u0000-\u001f\u007f]/.test(v)
  const JSON_PATH_MESSAGE = (field: string) => `${field} must be a dotted JSON path such as data.access_token or items[0].token (at most 200 characters).`
  /** Same syntax as the engine and the backend: keys separated by dots, each optionally followed by [n]; a path may start with [n]. */
  const validJsonPath = (p: string): boolean => {
    if (!p || p.length > 200) return false
    let n = 0
    const parts = p.split('.')
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]!
      const b = part.indexOf('[')
      const name = b >= 0 ? part.slice(0, b) : part
      let rest = b >= 0 ? part.slice(b) : ''
      if (name.includes(']') || hasCtlChar(name)) return false
      if (!name) { if (i !== 0 || !rest) return false } else n++
      while (rest) {
        const m = /^\[(\d{1,6})\]/.exec(rest)
        if (!m) return false
        n++
        rest = rest.slice(m[0].length)
      }
    }
    return n > 0 && n <= 32
  }
  const invalid = (field: string, message: string): never => fail(422, 'validation_failed', message, { field })
  /** Object of strings; anything else is reported on `field` (and the object is treated as empty). */
  const textMap = (v: unknown, field: string, issues: Issues): Record<string, string> => {
    if (v === undefined || v === null) return {}
    if (typeof v !== 'object' || Array.isArray(v)) { issues.add(field, `${field} must be an object of strings.`); return {} }
    const out: Record<string, string> = {}
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (typeof val !== 'string') { issues.add(`${field}.${k}`, `${field} values must be strings.`); continue }
      out[k] = val
    }
    return out
  }

  /** Same rules and field paths as the backend (dastauth.Validate), with "blank keeps the stored value". Every failing field is reported. */
  function putAuth(cb: MockCodebase, user: MockUser, body: Record<string, unknown>): DastAuth {
    if (options.secretKey === false) fail(503, 'secret_key_required', 'DAST credentials cannot be stored: SDRSCAN_SECRET_KEY is not configured on the server.')
    const type = body.type as DastAuthType
    if (!['form', 'header', 'form+header'].includes(type)) invalid('type', 'type must be form, header or form+header.')
    const issues = new Issues()
    const wantLogin = type === 'form' || type === 'form+header'
    const wantHeaders = type === 'header' || type === 'form+header'
    const prev = cb.auth?.secrets
    const headers = textMap(body.headers, 'headers', issues)
    const cookies = textMap(body.cookies, 'cookies', issues)
    if (!wantHeaders && (Object.keys(headers).length || Object.keys(cookies).length)) issues.add('headers', `headers and cookies are not allowed for type ${type}.`)
    if (wantHeaders) {
      if (!Object.keys(headers).length && !Object.keys(cookies).length) issues.add('headers', 'At least one header or cookie is required for this type.')
      if (Object.keys(headers).length > 10) issues.add('headers', 'At most 10 headers are allowed.')
      const seen = new Set<string>()
      for (const [k, v0] of Object.entries(headers).sort(([x], [y]) => x.localeCompare(y))) {
        const lk = k.toLowerCase()
        const path = `headers.${k}`
        if (!HEADER_TOKEN.test(k)) { issues.add('headers', `Header name "${k.slice(0, 40)}" is not a valid HTTP token.`); continue }
        if (FORBIDDEN_HEADERS.includes(lk) || lk.startsWith('proxy-') || lk.startsWith('sec-')) { issues.add(path, `The header ${k} cannot be configured.`); continue }
        if (seen.has(lk)) { issues.add(path, 'Header names must be unique (case-insensitive).'); continue }
        seen.add(lk)
        const keep = Object.entries(prev?.headers ?? {}).find(([pk]) => pk.toLowerCase() === lk)?.[1]
        const v = v0 === '' ? (keep ?? '') : v0
        if (!v) issues.add(path, `The header ${k} needs a value.`)
        else if (/[\r\n\0]/.test(v)) issues.add(path, 'Header values must not contain CR, LF or control characters.')
        else if (v.length > 4096) issues.add(path, 'A header value must be at most 4 KiB.')
        else if (v.length < 4) issues.add(path, 'A header value must be at least 4 characters.')
        headers[k] = v
      }
      for (const [k, v0] of Object.entries(cookies).sort(([x], [y]) => x.localeCompare(y))) {
        const path = `cookies.${k}`
        if (!HEADER_TOKEN.test(k)) { issues.add('cookies', `Cookie name "${k.slice(0, 40)}" is not a valid token.`); continue }
        const v = v0 === '' ? (prev?.cookies[k] ?? '') : v0
        if (v.length < 4) issues.add(path, `The cookie ${k} needs a value of at least 4 characters.`)
        else if (/[;,\s]/.test(v)) issues.add(path, 'Cookie values must be at most 4 KiB without spaces, \';\', \',\' or control characters.')
        cookies[k] = v
      }
    }
    let meta: MockAuth['meta'] = { login_url: null, method: null, body_format: null, username_field: null, password_field: null, username: null, extra_field_names: [], csrf: null, token: null, success: null, header_names: [], cookie_names: [], updated_at: null, updated_by: null }
    let password = ''
    const extra: Record<string, string> = {}
    if (wantLogin) {
      const l = asObj(body.login)
      if (!Object.keys(l).length) issues.add('login', 'login is required for this type.')
      else {
        const url = str(l.url) ?? ''
        const u = ((): URL | null => { try { return new URL(url) } catch { return null } })()
        if (!url.trim()) issues.add('login.url', 'login.url is required.')
        else if (!u || !['http:', 'https:'].includes(u.protocol)) issues.add('login.url', 'login.url must be an absolute http(s) URL.')
        else if (u.username || u.hash) issues.add('login.url', 'login.url must be an absolute http(s) URL without credentials or fragment.')
        else if (u.origin !== new URL(cb.base_url!).origin) issues.add('login.url', 'login.url must have the same origin (scheme, host and port) as the target base URL.')
        else if (isPrivateHost(u.hostname) && !isPrivateHost(new URL(cb.base_url!).hostname)) issues.add('login.url', PRIVATE_NETWORK_MESSAGE, 'address_not_allowed')
        const method = (str(l.method) ?? 'POST').toUpperCase()
        if (!['POST', 'PUT', 'PATCH'].includes(method)) issues.add('login.method', 'login.method must be POST, PUT or PATCH.')
        const fmt = str(l.body_format) ?? 'form'
        if (!['form', 'json'].includes(fmt)) issues.add('login.body_format', 'login.body_format must be form or json.')
        const uf = str(l.username_field) ?? ''
        const pf = str(l.password_field) ?? ''
        if (!FIELD_NAME.test(uf)) issues.add('login.username_field', 'login.username_field is required (letters, digits and _ . : [ ] -, at most 100).')
        if (!FIELD_NAME.test(pf)) issues.add('login.password_field', 'login.password_field is required (letters, digits and _ . : [ ] -, at most 100).')
        else if (pf === uf) issues.add('login.password_field', 'login.username_field and login.password_field must differ.')
        const username = str(l.username) ?? ''
        if (!username) issues.add('login.username', 'login.username is required.')
        else if (username.length > 256) issues.add('login.username', 'login.username must be at most 256 characters without control characters.')
        password = str(l.password) || (cb.auth && (cb.auth.type === 'form' || cb.auth.type === 'form+header') ? cb.auth.secrets.password : '')
        if (!password) issues.add('login.password', 'login.password is required.')
        else if (password.length < 4 || password.length > 1024) issues.add('login.password', 'login.password must be 4 to 1024 characters without control characters.')
        const ef = textMap(l.extra_fields, 'login.extra_fields', issues)
        if (Object.keys(ef).length > 20) issues.add('login.extra_fields', 'At most 20 extra fields are allowed.')
        for (const [k, v] of Object.entries(ef).sort(([x], [y]) => x.localeCompare(y))) {
          if (!FIELD_NAME.test(k)) issues.add('login.extra_fields', `Extra field name "${k.slice(0, 40)}" may contain only letters, digits and _ . : [ ] - (at most 100).`)
          else if (k === uf || k === pf) issues.add(`login.extra_fields.${k}`, 'An extra field must not repeat the username or password field.')
          else extra[k] = v === '' ? (prev?.extra[k] ?? '') : v
        }
        const cs = l.csrf === undefined ? null : asObj(l.csrf)
        if (cs) {
          if (!['html_input', 'cookie', 'header'].includes(String(cs.source))) issues.add('login.csrf.source', 'login.csrf.source must be html_input, cookie or header.')
          if (!str(cs.name)) issues.add('login.csrf.name', 'login.csrf.name is required (at most 100 characters).')
          const sendAs = str(cs.send_as) ?? 'field'
          if (!['field', 'header'].includes(sendAs)) issues.add('login.csrf.send_as', 'login.csrf.send_as must be field or header.')
          else if (sendAs === 'header' && str(cs.header_name) && !HEADER_TOKEN.test(str(cs.header_name)!)) issues.add('login.csrf.header_name', 'login.csrf.header_name must be a valid header name when send_as is header.')
        }
        const tk = l.token === undefined || l.token === null ? null : asObj(l.token)
        let tokenMeta: NonNullable<DastAuth['token']> | null = null
        if (tk) {
          const from = str(tk.from) || 'json'
          const tpath = (str(tk.path) ?? '').trim()
          if (!['json', 'header'].includes(from)) issues.add('login.token.from', 'login.token.from must be json or header.')
          else if (from === 'json' && !validJsonPath(tpath)) issues.add('login.token.path', JSON_PATH_MESSAGE('login.token.path'))
          else if (from === 'header' && !HEADER_TOKEN.test(tpath)) issues.add('login.token.path', 'login.token.path must be a valid response header name when from is header.')
          const tsend = str(tk.send_as) || 'header'
          let tHeader: string | null = null
          let tPrefix: string | null = null
          let tCookie: string | null = null
          if (tsend === 'header') {
            tHeader = str(tk.header_name) || 'Authorization'
            const lower = tHeader.toLowerCase()
            if (!HEADER_TOKEN.test(tHeader) || FORBIDDEN_HEADERS.includes(lower) || lower.startsWith('proxy-') || lower.startsWith('sec-')) issues.add('login.token.header_name', 'login.token.header_name must be a valid header name that can be configured (not Host, Cookie, Content-Length and similar).')
            tPrefix = typeof tk.prefix === 'string' ? tk.prefix : (lower === 'authorization' ? 'Bearer ' : null)
            if (tPrefix !== null && (tPrefix.length > 32 || hasCtlChar(tPrefix) || [...tPrefix].some(c => c.charCodeAt(0) > 0x7f))) issues.add('login.token.prefix', 'login.token.prefix must be at most 32 ASCII characters without control characters (CR/LF).')
          } else if (tsend === 'cookie') {
            tCookie = str(tk.cookie_name) ?? ''
            if (!HEADER_TOKEN.test(tCookie)) issues.add('login.token.cookie_name', 'login.token.cookie_name is required (a valid cookie name) when send_as is cookie.')
          } else issues.add('login.token.send_as', 'login.token.send_as must be header or cookie.')
          tokenMeta = { from: from as 'json', path: tpath, send_as: tsend as 'header', header_name: tHeader, prefix: tPrefix, cookie_name: tCookie }
        }
        const su = l.success === undefined ? null : asObj(l.success)
        const jsonExists = su ? (str(su.json_path_exists) ?? '').trim() : ''
        if (jsonExists && !validJsonPath(jsonExists)) issues.add('login.success.json_path_exists', JSON_PATH_MESSAGE('login.success.json_path_exists'))
        const jeq = su && su.json_path_equals ? asObj(su.json_path_equals) : null
        if (jeq) {
          if (!validJsonPath((str(jeq.path) ?? '').trim())) issues.add('login.success.json_path_equals.path', JSON_PATH_MESSAGE('login.success.json_path_equals.path'))
          if (!['string', 'number', 'boolean'].includes(typeof jeq.value)) issues.add('login.success.json_path_equals.value', 'login.success.json_path_equals.value must be a string, number or boolean.')
        }
        if (su && Array.isArray(su.statuses)) {
          (su.statuses as unknown[]).forEach((c, i) => { if (typeof c !== 'number' || !Number.isInteger(c) || c < 100 || c > 599) issues.add(`login.success.statuses[${i}]`, 'Status codes must be between 100 and 599.') })
        }
        meta = {
          ...meta, login_url: url, method: method as 'POST', body_format: fmt as 'form', username_field: uf, password_field: pf, username, extra_field_names: Object.keys(extra).sort(),
          csrf: cs ? { source: cs.source as 'cookie', name: String(cs.name), send_as: (str(cs.send_as) ?? 'field') as 'field', header_name: str(cs.header_name) || null } : null,
          token: tokenMeta,
          success: su ? {
            statuses: Array.isArray(su.statuses) ? [...new Set(su.statuses as number[])].sort() : [], cookie_set: str(su.cookie_set) || null, body_contains: str(su.body_contains) || null,
            body_not_contains: str(su.body_not_contains) || null, redirect_not_to: str(su.redirect_not_to) || null,
            json_path_exists: jsonExists || null,
            json_path_equals: jeq ? { path: (str(jeq.path) ?? '').trim(), value: jeq.value as string } : null,
          } : null,
        }
      }
    }
    // The backend validates the login form first, then headers, then cookies.
    const rank = (f: string) => (f.startsWith('login') ? 0 : f.startsWith('headers') ? 1 : 2)
    issues.list.sort((a, b) => rank(a.field) - rank(b.field))
    issues.throwIf()
    if (JSON.stringify(body).length > 16 * 1024) invalid('type', 'The authentication configuration is too large (maximum 16 KiB).')
    meta.header_names = Object.keys(headers).sort()
    meta.cookie_names = Object.keys(cookies).sort()
    meta.updated_at = iso()
    meta.updated_by = { id: user.id, username: user.username }
    cb.auth = { type, meta, secrets: { password, extra, headers, cookies } }
    cb.updated_at = iso()
    addAudit(user, 'dast_auth_set', `${cb.name} type=${type}`)
    return authDto(cb)
  }

  /** Field problems of the dast_crawl_* keys of a PATCH body (the backend reports every one). */
  function crawlIssues(body: Record<string, unknown>): FieldIssue[] {
    const out: FieldIssue[] = []
    if (body.dast_crawl_enabled !== undefined && typeof body.dast_crawl_enabled !== 'boolean') out.push({ field: 'dast_crawl_enabled', message: 'dast_crawl_enabled must be true or false.' })
    for (const [k, lo, hi] of [['dast_crawl_max_depth', 1, 10], ['dast_crawl_max_pages', 1, 500]] as const) {
      const n = body[k]
      if (n !== undefined && (typeof n !== 'number' || !Number.isInteger(n) || n < lo || n > hi)) out.push({ field: k, message: `${k} must be a whole number between ${lo} and ${hi}.` })
    }
    if (body.dast_crawl_exclude !== undefined) {
      const list = body.dast_crawl_exclude === null ? [] : body.dast_crawl_exclude
      if (!Array.isArray(list) || list.some(x => typeof x !== 'string')) out.push({ field: 'dast_crawl_exclude', message: 'dast_crawl_exclude must be a list of strings.' })
      else {
        if (list.length > 20) out.push({ field: 'dast_crawl_exclude', message: 'At most 20 exclusion patterns are allowed.' })
        ;(list as string[]).forEach((raw, i) => {
          const p = raw.trim()
          const f = `dast_crawl_exclude[${i}]`
          if (!p) { out.push({ field: f, message: `Pattern ${i + 1} is empty; enter a regular expression or remove the row.` }); return }
          if (p.length > 200) { out.push({ field: f, message: `Pattern ${i + 1} must be 1 to 200 characters without control characters.` }); return }
          let ok = !/\(\?[=!<]/.test(p) && !/\\[1-9]/.test(p)
          if (ok) { try { new RegExp(p) } catch { ok = false } }
          if (!ok) out.push({ field: f, message: `Pattern ${i + 1} is not a valid regular expression: "${p}".` })
        })
      }
    }
    return out
  }

  function applyCrawl(cb: MockCodebase, body: Record<string, unknown>, user: MockUser) {
    const keys = ['dast_crawl_enabled', 'dast_crawl_max_depth', 'dast_crawl_max_pages', 'dast_crawl_exclude']
    if (!keys.some(k => body[k] !== undefined)) return
    const next = { ...cb.crawl }
    if (typeof body.dast_crawl_enabled === 'boolean') next.enabled = body.dast_crawl_enabled
    if (typeof body.dast_crawl_max_depth === 'number') next.max_depth = body.dast_crawl_max_depth
    if (typeof body.dast_crawl_max_pages === 'number') next.max_pages = body.dast_crawl_max_pages
    if (body.dast_crawl_exclude !== undefined) next.exclude = ((body.dast_crawl_exclude ?? []) as string[]).map(x => x.trim())
    cb.crawl = next
    addAudit(user, 'dast_crawl_updated', `${cb.name} enabled=${next.enabled} depth=${next.max_depth} pages=${next.max_pages} exclude=${next.exclude.length}`)
  }

  route('GET', '/codebases/:id/dast-auth', {}, ({ params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'DAST authentication applies only to URL targets.')
    return { body: authDto(cb) }
  })
  route('PUT', '/codebases/:id/dast-auth', {}, ({ user, body, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'DAST authentication applies only to URL targets.')
    return { body: putAuth(cb, user, body as Record<string, unknown> & Partial<DastAuthBody>) }
  })
  route('DELETE', '/codebases/:id/dast-auth', {}, ({ user, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'DAST authentication applies only to URL targets.')
    if (cb.auth) {
      cb.auth = null
      cb.updated_at = iso()
      addAudit(user, 'dast_auth_deleted', cb.name)
    }
    return { status: 204 }
  })
  route('POST', '/codebases/:id/dast-auth/test', {}, ({ user, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type !== 'url') fail(409, 'not_a_url_target', 'DAST authentication applies only to URL targets.')
    if (cb.dast_status !== 'confirmed') fail(409, 'target_not_confirmed', 'The target must be confirmed by an Admin before the login can be tested.')
    if (!cb.auth) fail(409, 'no_auth_configured', 'No authentication is configured for this target.')
    if (cb.auth.type === 'header') fail(409, 'no_login_configured', 'Only a login form can be tested. Fixed headers and cookies have no login step.')
    // A password containing "wrong" simulates rejected credentials. The message never repeats a secret.
    const rejected = cb.auth.secrets.password.toLowerCase().includes('wrong')
    addAudit(user, 'dast_auth_tested', `${cb.name} ${rejected ? 'failed' : 'ok'}`)
    return {
      body: rejected
        ? { ok: false, message: 'Login failed: the server answered HTTP 401 (invalid credentials).' }
        : cb.auth.meta.token
          ? { ok: true, message: `login berhasil: token diterima (${cb.auth.meta.token.send_as === 'cookie' ? `cookie ${cb.auth.meta.token.cookie_name}` : `header ${cb.auth.meta.token.header_name}`}), halaman awal /app` }
          : { ok: true, message: `Login succeeded: HTTP 302 -> /app, cookie sid set as ${cb.auth.meta.username ?? 'the test account'}.` },
    }
  })

  // scans
  route('POST', '/scans', {}, ({ user, body }) => {
    if (!body.codebase_id || Number(body.codebase_id) <= 0) invalidField('codebase_id', 'codebase_id is required.')
    const wantActive = body.active === true
    const wantActiveTiming = body.active_timing === true
    if (wantActiveTiming && !wantActive) invalidField('active_timing', 'active_timing requires active to be true.')
    const cb = findCodebase(String(body.codebase_id ?? ''))
    if (cb.target_type === 'url') {
      if (!hasDast(user)) fail(403, 'dast_forbidden', 'You need DAST access to run DAST scans.')
      if (cb.dast_status !== 'confirmed') fail(409, 'target_not_confirmed', 'An Admin must confirm authorization for this target first.')
      if (wantActive && cb.active_authorized_at === null) {
        fail(409, 'active_scanning_not_authorized', "Active scanning has not been authorized for this target. Authorize it in the codebase's settings first.")
      }
    }
    const running = scans.find(s => s.codebase_id === cb.id && (tick(s), s.status === 'queued' || s.status === 'running'))
    if (running) fail(409, 'scan_in_progress', 'A scan is already queued or running for this codebase.', { scan_id: running.id })
    const active = cb.target_type === 'url' && wantActive
    const activeTiming = active && wantActiveTiming
    if (cb.target_type === 'url') {
      addAudit(user, 'dast_scan_started', active ? `${cb.name} active:true${activeTiming ? '+timing' : ''}` : cb.name)
    }
    return { status: 202, body: scanDto(startSim(cb, user, { active, activeTiming })) }
  })
  route('GET', '/scans/:id', {}, ({ params }) => ({ body: scanDto(findScan(params[0]!), true) }))
  route('POST', '/scans/:id/cancel', {}, ({ params }) => {
    const s = findScan(params[0]!)
    tick(s)
    if (s.status !== 'queued' && s.status !== 'running') fail(409, 'scan_finished', 'This scan has already ended.')
    s.status = 'cancelled'
    s.finished_at = iso()
    s.log.push({ t: nowMs(), line: 'scan cancelled by user' })
    if (s.sim) s.sim.cancelled = true
    return { status: 202, body: scanDto(s) }
  })
  route('GET', '/codebases/:id/scans', {}, ({ q, params }) => {
    const cb = findCodebase(params[0]!)
    tickAll()
    let list = scans.filter(s => s.codebase_id === cb.id)
    const st = q.get('status')
    if (st) list = list.filter(s => s.status === st)
    list.sort((a, b) => (b.started_at ?? b.queued_at).localeCompare(a.started_at ?? a.queued_at) || b.id - a.id)
    return { body: paged(list.map(s => scanDto(s)), q) }
  })
  route('GET', '/codebases/:id/compare', {}, ({ q, params }) => ({ body: compare(findCodebase(params[0]!), q) }))

  // schedules
  const SCHEDULE_MIN = { repo: 15, url: 60 }
  const scheduleRow = (cb: MockCodebase) => {
    const proj = projects.find(p => p.id === cb.project_id)!
    return { ...scheduleDto(cb)!, codebase: { id: cb.id, name: cb.name, target_type: cb.target_type }, project: { id: proj.id, name: proj.name } }
  }
  route('GET', '/schedules', {}, ({ q }) => {
    const st = q.get('status')
    if (st && st !== 'active' && st !== 'suspended') fail(400, 'bad_request', 'status must be active or suspended.')
    const rows = codebases.filter(c => c.schedule && visible(c) && (!st || c.schedule.status === st)).sort((a, b) => a.name.localeCompare(b.name)).map(scheduleRow)
    return { body: paged(rows, q) }
  })
  route('PUT', '/codebases/:id/schedule', {}, ({ user, body, params }) => {
    const cb = findCodebase(params[0]!)
    if (cb.target_type === 'url' && !hasDast(user)) fail(403, 'dast_forbidden', 'You need DAST access to set the schedule of a URL target.')
    // Scheduled scans are always passive in this version: active scanning is rejected, not silently ignored.
    if (body.active !== undefined) invalidField('active', 'Scheduled scans are always passive; active is not supported here.')
    if (body.active_timing !== undefined) invalidField('active_timing', 'Scheduled scans are always passive; active_timing is not supported here.')
    const cron = str(body.cron)?.trim() ?? ''
    const parsed = parseCron(cron)
    if (!cron) return fail(422, 'invalid_cron', "cron is required: enter a 5-field cron expression (UTC), for example '0 3 * * *'.", { field: 'cron' })
    if (!parsed.ok) return fail(422, 'invalid_cron', `Invalid cron expression: ${parsed.error}`, { field: 'cron' })
    const gap = minIntervalMinutes(cron)
    if (gap !== null && gap < SCHEDULE_MIN[cb.target_type]) fail(422, 'schedule_too_frequent', `The schedule runs too often. The minimum interval is ${SCHEDULE_MIN[cb.target_type]} minutes.`, { field: 'cron' })
    cb.schedule = { cron, owner_id: user.id, status: 'active', suspended_reason: null, suspended_at: null, last_enqueued_at: cb.schedule?.last_enqueued_at ?? null }
    addAudit(user, 'schedule_set', cb.name)
    return { body: { schedule: scheduleDto(cb) } }
  })
  route('POST', '/codebases/:id/schedule/resume', {}, ({ user, params }) => {
    const cb = findCodebase(params[0]!)
    if (!cb.schedule || cb.schedule.status !== 'suspended') fail(409, 'schedule_not_suspended', 'The schedule is not suspended.')
    if (cb.target_type === 'url' && !hasDast(user)) fail(403, 'dast_forbidden', 'You need DAST access to resume the schedule of a URL target.')
    cb.schedule = { ...cb.schedule, owner_id: user.id, status: 'active', suspended_reason: null, suspended_at: null }
    addAudit(user, 'schedule_resumed', cb.name)
    return { body: { schedule: scheduleDto(cb) } }
  })
  route('DELETE', '/codebases/:id/schedule', {}, ({ user, params }) => {
    const cb = findCodebase(params[0]!)
    cb.schedule = null
    addAudit(user, 'schedule_deleted', cb.name)
    return { status: 204 }
  })

  // findings and files
  route('GET', '/codebases/:id/findings', {}, ({ q, params }) => {
    const cb = findCodebase(params[0]!)
    tickAll()
    return { body: findingsPage(currentFindings(cb.id), q) }
  })
  route('GET', '/scans/:id/findings', {}, ({ q, params }) => ({ body: findingsPage(findings.filter(f => f.scan_id === findScan(params[0]!).id), q) }))
  route('GET', '/findings/:id', {}, ({ params }) => ({ body: findings.find(f => f.id === Number(params[0]) && visible(codebases.find(c => c.id === f.codebase_id)!)) ?? fail(404, 'not_found', 'Finding not found.') }))
  route('GET', '/codebases/:id/files', {}, ({ q, params }) => ({ body: filesRows(currentFindings(findCodebase(params[0]!).id), q) }))
  route('GET', '/scans/:id/files', {}, ({ q, params }) => ({ body: filesRows(findings.filter(f => f.scan_id === findScan(params[0]!).id), q) }))

  // tokens and system
  const tokenDto = (t: (typeof tokens)[number]): IngestToken => {
    const proj = projects.find(p => p.id === t.project_id)
    const by = users.find(u => u.id === t.created_by)
    return {
      id: t.id, name: t.name, token_prefix: t.token_prefix, project: proj ? { id: proj.id, name: proj.name } : null, created_by: by ? { id: by.id, username: by.username } : null,
      created_at: t.created_at, last_used_at: t.last_used_at, revoked_at: t.revoked_at, status: t.revoked_at ? 'revoked' : 'active',
    }
  }
  route('GET', '/ingest-tokens', { admin: true }, ({ q }) => ({ body: paged([...tokens].sort((a, b) => b.id - a.id).map(tokenDto), q) }))
  route('POST', '/ingest-tokens', { admin: true }, ({ user, body }) => {
    const issues = new Issues()
    const nm = nameIssue(body.name)
    if (nm) issues.add('name', nm)
    const pid = body.project_id ? Number(body.project_id) : null
    if (body.project_id !== undefined && body.project_id !== null && (typeof body.project_id !== 'number' || body.project_id <= 0)) issues.add('project_id', 'project_id must be a positive integer.')
    else if (pid && !projects.some(x => x.id === pid)) issues.add('project_id', 'project_id does not exist.')
    issues.throwIf()
    const name = str(body.name)!.trim()
    const raw = `sdrscan_${Array.from({ length: 43 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'[Math.floor(Math.random() * 64)]).join('')}`
    const t = { id: seq.token++, name, token_prefix: raw.slice(0, 9), project_id: pid, created_by: user.id, created_at: iso(), last_used_at: null, revoked_at: null, hash: raw }
    tokens.push(t)
    addAudit(user, 'token_created', name)
    return { status: 201, body: { token: tokenDto(t), secret: raw } }
  })
  route('DELETE', '/ingest-tokens/:id', { admin: true }, ({ user, params }) => {
    const t = tokens.find(x => x.id === Number(params[0])) ?? fail(404, 'not_found', 'Token not found.')
    t.revoked_at = iso()
    addAudit(user, 'token_revoked', t.name)
    return { status: 204 }
  })
  route('GET', '/system/info', {}, () => ({ body: { backend_version: '0.1.0-mock', sast_version: '0.1.0', dast_version: '0.1.0', jobs_queued: 0, jobs_running: 0 } }))

  // vulnerability database (Admin only): status plus one background update job at a time.
  // An update that asks for npm only fails (to show the failure state); anything else succeeds after 3 s (x scanSpeed).
  const VULN_ECOSYSTEMS = ['Packagist', 'npm', 'Go', 'crates.io']
  const VULN_STALE_DAYS = 7
  const vopt = { configured: true, installed: true, toolAvailable: true, scaEnabled: true, dataAgeDays: 2, cron: null as string | null, ...options.vulndb }
  const vdbCounts: Record<string, number> = { Packagist: 18432, npm: 51233, Go: 4120, 'crates.io': 1890 }
  type RawSource = Pick<VulnDbSource, 'name' | 'ecosystem' | 'advisories' | 'updated_at'>
  const NVD_PRODUCTS = ['cpe:2.3:a:apache:http_server', 'cpe:2.3:a:nginx:nginx', 'cpe:2.3:a:php:php']
  let vdbSources: RawSource[] = vopt.configured && vopt.installed
    ? [
        ...VULN_ECOSYSTEMS.map(e => ({ name: 'osv', ecosystem: e, advisories: vdbCounts[e]!, updated_at: iso(nowMs() - vopt.dataAgeDays * 86_400_000) })),
        { name: 'nvd', ecosystem: null, advisories: 215_000, updated_at: iso(nowMs() - vopt.dataAgeDays * 86_400_000) },
      ]
    : []
  interface MockVulnJob { id: number, requested_by: string, ecosystems: string[], nvd: boolean, startedMs: number, willFail: boolean, cancelled: boolean, cancelledMs?: number, applied: boolean }
  let vdbJob: MockVulnJob | null = null
  let vdbSeq = 1

  function vdbJobDto(j: MockVulnJob): VulnDbUpdate {
    const elapsed = nowMs() - j.startedMs
    const total = ms(3000)
    const finished = !j.cancelled && elapsed >= total
    const state: VulnDbUpdate['state'] = j.cancelled ? 'cancelled' : finished ? (j.willFail ? 'failed' : 'succeeded') : 'running'
    if (state === 'succeeded' && !j.applied) {
      j.applied = true
      const at = iso(j.startedMs + total)
      const names = new Set(j.ecosystems)
      const known = new Set(vdbSources.map(x => `${x.name}/${x.ecosystem}`))
      for (const e of j.ecosystems) if (!known.has(`osv/${e}`)) vdbSources.push({ name: 'osv', ecosystem: e, advisories: 0, updated_at: at })
      if (j.nvd && !known.has('nvd/null')) vdbSources.push({ name: 'nvd', ecosystem: null, advisories: 0, updated_at: at })
      vdbSources = vdbSources.map(x => ((x.name === 'osv' && x.ecosystem && names.has(x.ecosystem)) || (x.name === 'nvd' && j.nvd) ? { ...x, advisories: x.advisories + 17, updated_at: at } : x))
    }
    const lines: Array<{ at: number, line: string }> = [{ at: 0, line: `sdrscan-vuln update --ecosystems ${j.ecosystems.join(',')}${j.nvd ? ' --nvd' : ''}` }]
    j.ecosystems.forEach((e, i) => lines.push({ at: ms(500 + (i * 2000) / Math.max(1, j.ecosystems.length)), line: `osv: downloading ${e} advisories` }))
    if (j.nvd) lines.push({ at: ms(2000), line: 'nvd: downloading CVE feed' })
    lines.push(j.willFail ? { at: total, line: 'error: could not download the npm advisory archive (HTTP 503)' } : { at: total, line: 'done' })
    const log = lines.filter(l => elapsed >= l.at).map(l => l.line).join('\n')
    const stoppedAt = j.cancelled ? (j.cancelledMs ?? nowMs()) : j.startedMs + total
    return {
      id: j.id, state, trigger: 'manual', requested_by: j.requested_by, ecosystems: j.ecosystems, nvd: j.nvd, started_at: iso(j.startedMs),
      finished_at: state === 'running' ? null : iso(stoppedAt), exit_code: state === 'failed' ? 1 : state === 'succeeded' ? 0 : null,
      error_code: state === 'failed' ? 'update_failed' : state === 'cancelled' ? 'cancelled' : null, log_tail: j.cancelled ? `${log}\ncancelled` : log,
    }
  }

  function vdbInfo(): VulnDbInfo {
    const update = vdbJob ? vdbJobDto(vdbJob) : null // may apply a finished update first
    const times = vdbSources.map(x => x.updated_at).filter((t): t is string => !!t).sort()
    const oldest = times[0] ?? null
    const installed = vopt.configured && vdbSources.length > 0
    const ageOf = (t: string | null) => (t ? Math.max(0, Math.floor((nowMs() - new Date(t).getTime()) / 86_400_000)) : null)
    const sources: VulnDbSource[] = vdbSources.map(x => ({ ...x, age_days: ageOf(x.updated_at), products: x.name === 'nvd' ? NVD_PRODUCTS : [] }))
    // Like `sdrscan-vuln status --json`: never null while the tool works (installed: false when nothing is there yet).
    const status: VulnDbStatus | null = !vopt.toolAvailable
      ? null
      : { installed, advisory_count: vdbSources.reduce((n, x) => n + x.advisories, 0), updated_at: oldest, age_days: ageOf(oldest), max_age_days: VULN_STALE_DAYS, format_version: installed ? 1 : null, sources }
    return {
      configured: vopt.configured, sca_enabled: vopt.scaEnabled, db_path: vopt.configured ? '/var/lib/sdrscan/vulndb' : null, db_present: vopt.configured && installed,
      tool: { available: vopt.toolAvailable, path: 'sdrscan-vuln' },
      status, status_error: status ? null : 'sdrscan-vuln was not found or could not be started.',
      stale: installed && !!oldest && nowMs() - new Date(oldest).getTime() > VULN_STALE_DAYS * 86_400_000,
      stale_after_days: VULN_STALE_DAYS, ecosystems: VULN_ECOSYSTEMS, update_timeout_seconds: 3600, update_cron: vopt.cron, update,
    }
  }

  route('GET', '/system/vulndb', { admin: true }, () => ({ body: vdbInfo() }))
  route('POST', '/system/vulndb/update', { admin: true }, ({ user, body }) => {
    let ecosystems = VULN_ECOSYSTEMS
    if (body.ecosystems !== undefined) {
      if (!Array.isArray(body.ecosystems) || body.ecosystems.some(e => typeof e !== 'string')) invalidField('ecosystems', 'ecosystems must be a list of names.')
      const list = body.ecosystems as string[]
      const eco = new Issues()
      list.forEach((e, i) => { if (!VULN_ECOSYSTEMS.includes(e)) eco.add(`ecosystems[${i}]`, `Unknown ecosystem "${e.slice(0, 40)}". Allowed: ${VULN_ECOSYSTEMS.join(', ')}.`) })
      eco.throwIf()
      if (list.length) ecosystems = VULN_ECOSYSTEMS.filter(e => list.includes(e))
    }
    if (body.nvd !== undefined && typeof body.nvd !== 'boolean') validationFailed('nvd must be true or false.')
    if (!vopt.configured) fail(409, 'vulndb_not_configured', 'The vulnerability database is not configured (SDRSCAN_VULN_DB is empty).')
    if (!vopt.toolAvailable) fail(409, 'vuln_tool_unavailable', 'The sdrscan-vuln tool is not available on this server.')
    if (vdbJob && vdbJobDto(vdbJob).state === 'running') fail(409, 'update_in_progress', 'A vulnerability database update is already running.')
    vdbJob = { id: vdbSeq++, requested_by: user.username, ecosystems, nvd: body.nvd === true, startedMs: nowMs(), willFail: ecosystems.length === 1 && ecosystems[0] === 'npm', cancelled: false, applied: false }
    addAudit(user, 'vulndb_update_started', ecosystems.join(','))
    return { status: 202, body: { update: vdbJobDto(vdbJob) } }
  })
  route('POST', '/system/vulndb/update/cancel', { admin: true }, ({ user }) => {
    if (!vdbJob || vdbJobDto(vdbJob).state !== 'running') fail(409, 'no_update_running', 'No vulnerability database update is running.')
    vdbJob!.cancelled = true
    vdbJob!.cancelledMs = nowMs()
    addAudit(user, 'vulndb_update_cancelled', '')
    return { status: 202, body: { update: vdbJobDto(vdbJob!) } }
  })

  function cookieToken(req: MockRequest): string | undefined {
    const raw = req.headers.cookie ?? ''
    const m = /(?:^|;\s*)sdrscan_session=([^;]+)/.exec(raw)
    return m?.[1]
  }

  const NO_STORE = { 'Cache-Control': 'no-store' }

  function handle(req: MockRequest): MockResponse {
    try {
      const prefix = '/api/v1'
      if (!req.path.startsWith(prefix)) return fail(404, 'not_found', 'Unknown endpoint.')
      const path = req.path.slice(prefix.length).replace(/\/+$/, '') || '/'
      let matchedPath = false
      for (const r of routes) {
        const m = r.re.exec(path)
        if (!m) continue
        matchedPath = true
        if (r.method !== req.method.toUpperCase()) continue
        viewer = null
        let user: MockUser = undefined as unknown as MockUser
        let csrf = ''
        if (r.auth === 'session') {
          const token = cookieToken(req)
          const sess = token ? sessions.get(token) : undefined
          const u = sess ? users.find(x => x.id === sess.userId) : undefined
          if (!sess || !u || !u.is_active) fail(401, 'not_authenticated', 'You are not signed in.')
          user = u!
          csrf = sess!.csrf
          viewer = user
          if (r.csrf) {
            if (req.headers['x-csrf-token'] !== sess!.csrf) fail(403, 'csrf_invalid', 'The CSRF token is missing or invalid.')
          }
          if (r.admin && user.role !== 'admin') fail(403, 'forbidden_role', 'You do not have permission to do this.')
        }
        if (req.method.toUpperCase() !== 'GET' && !(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
          fail(415, 'unsupported_media_type', 'Content-Type must be application/json.')
        }
        const out = r.h({ user, csrf, q: req.query, body: asObj(req.body), params: m.slice(1), req })
        return { status: out?.status ?? 200, headers: { ...NO_STORE, ...(out?.headers ?? {}) }, body: out?.body }
      }
      return fail(matchedPath ? 405 : 404, matchedPath ? 'method_not_allowed' : 'not_found', matchedPath ? 'Method not allowed.' : 'Unknown endpoint.')
    } catch (e) {
      if (e instanceof HttpError) {
        return { status: e.status, headers: { ...NO_STORE, ...(e.headers ?? {}) }, body: { error: { code: e.code, message: e.message, ...(e.details !== undefined ? { details: e.details } : {}) } } }
      }
      return { status: 500, headers: NO_STORE, body: { error: { code: 'internal', message: 'Internal error.' } } }
    }
  }

  /** For the SSE endpoint of the dev server: session check plus scan snapshot. */
  function peekScan(req: MockRequest, id: number): { status: number, scan?: Scan, log?: string[] } {
    const token = cookieToken(req)
    const sess = token ? sessions.get(token) : undefined
    if (!sess) return { status: 401 }
    viewer = users.find(u => u.id === sess.userId) ?? null
    const s = scans.find(x => x.id === id && visible(codebases.find(c => c.id === x.codebase_id)!))
    if (!s) return { status: 404 }
    const dto = scanDto(s, true)
    return { status: 200, scan: dto, log: s.log.map(l => l.line) }
  }

  seed()
  return { handle, peekScan, _state: { users, projects, codebases, scans, findings } }
}

export type MockBackend = ReturnType<typeof createMockBackend>
