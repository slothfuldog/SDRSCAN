// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { createMockBackend } from '../../mock/core.ts'
import { createSession } from '../helpers/mockClient'
import type { ApiError } from '~/utils/errors'

const fails = async (p: Promise<unknown>): Promise<ApiError> => {
  try { await p } catch (e) { return e as ApiError }
  throw new Error('expected the request to fail')
}

describe('API contract (mock backend, same rules the real one enforces)', () => {
  it('rejects bad logins with 401 and throttles after repeated failures with Retry-After', async () => {
    const s = createSession()
    const e1 = await fails(s.api.auth.login('admin', 'wrong'))
    expect(e1).toMatchObject({ status: 401, code: 'invalid_credentials' })
    for (let i = 0; i < 4; i++) await fails(s.api.auth.login('admin', 'wrong'))
    const e2 = await fails(s.api.auth.login('admin', 'admin-password-1234'))
    expect(e2).toMatchObject({ status: 429, code: 'login_throttled' })
    expect(e2.retryAfter).toBeGreaterThan(0)
  })

  it('requires a session (401) and the CSRF header on writes (403 csrf_invalid)', async () => {
    const backend = createMockBackend()
    const anon = createSession({}, backend)
    expect(await fails(anon.api.projects.list())).toMatchObject({ status: 401, code: 'not_authenticated' })

    const s = createSession({}, backend)
    await s.login('admin')
    const raw = backend.handle({ method: 'POST', path: '/api/v1/projects', query: new URLSearchParams(), headers: { cookie: '', 'content-type': 'application/json' }, body: { name: 'x' } })
    expect(raw.status).toBe(401)
    // valid session but no CSRF header
    const loginRes = backend.handle({ method: 'POST', path: '/api/v1/auth/login', query: new URLSearchParams(), headers: { 'content-type': 'application/json' }, body: { username: 'admin', password: 'admin-password-1234' } })
    const cookie = loginRes.headers['Set-Cookie']!.split(';')[0]!
    const noCsrf = backend.handle({ method: 'POST', path: '/api/v1/projects', query: new URLSearchParams(), headers: { cookie, 'content-type': 'application/json' }, body: { name: 'x' } })
    expect(noCsrf).toMatchObject({ status: 403, body: { error: { code: 'csrf_invalid' } } })
  })

  it('Members get 403 forbidden_role on Admin endpoints; Admins do not', async () => {
    const backend = createMockBackend()
    const m = createSession({}, backend)
    await m.login('member')
    expect(await fails(m.api.users.list())).toMatchObject({ status: 403, code: 'forbidden_role' })
    expect(await fails(m.api.tokens.list())).toMatchObject({ status: 403, code: 'forbidden_role' })
    expect(await fails(m.api.projects.remove(3, 'Playground'))).toMatchObject({ status: 403, code: 'forbidden_role' })
    const a = createSession({}, backend)
    await a.login('admin')
    expect((await a.api.users.list()).items.length).toBeGreaterThan(2)
  })

  it('permanent deletes need ?confirm=<exact name>', async () => {
    const s = createSession()
    await s.login('admin')
    const missing = await fails(s.api.projects.remove(3, ''))
    expect(missing).toMatchObject({ status: 422, code: 'confirmation_required' })
    expect(await fails(s.api.projects.remove(3, 'playground'))).toMatchObject({ status: 422, code: 'confirmation_mismatch' })
    const ok = await s.api.projects.remove(3, 'Playground')
    expect(ok.deleted).toBeDefined()
    expect(await fails(s.api.projects.get(3))).toMatchObject({ status: 404 })
  })

  it('DAST rules: registration needs DAST access, new targets are pending, only Admin confirms, scans need confirmed', async () => {
    const backend = createMockBackend()
    const member = createSession({}, backend)
    await member.login('member')
    const body = { name: 'blog (live)', target_type: 'url' as const, base_url: 'https://blog.example.com' }
    expect(await fails(member.api.codebases.create(1, body))).toMatchObject({ status: 403, code: 'dast_forbidden' })

    const dast = createSession({}, backend)
    await dast.login('dastMember')
    const cb = await dast.api.codebases.create(1, body)
    expect(cb.dast).toMatchObject({ status: 'pending_confirmation', registered_by: { username: 'dast-member' }, confirmed_by: null, confirmed_at: null })
    expect(cb.confirmation_statement).toMatch(/authorized to run security scans against https:\/\/blog\.example\.com/)
    expect(await fails(dast.api.scans.create(cb.id))).toMatchObject({ status: 409, code: 'target_not_confirmed' })
    expect(await fails(dast.api.codebases.confirmAuthorization(cb.id))).toMatchObject({ status: 403, code: 'forbidden_role' })
    // a Member without DAST access cannot even see the URL target: 404, not 403
    expect(await fails(member.api.scans.create(cb.id))).toMatchObject({ status: 404, code: 'not_found' })

    const admin = createSession({}, backend)
    await admin.login('admin')
    const confirmed = await admin.api.codebases.confirmAuthorization(cb.id)
    expect(confirmed.dast).toMatchObject({ status: 'confirmed', confirmed_by: { username: 'admin' } })
    expect(confirmed.confirmation_statement).toBeNull()
    const scan = await dast.api.scans.create(cb.id)
    expect(scan.status).toBe('queued')
    expect(scan.type).toBe('dast')
    expect(await fails(dast.api.scans.create(cb.id))).toMatchObject({ status: 409, code: 'scan_in_progress' })
    // Changing the base URL returns the target to pending.
    const changed = await dast.api.codebases.patch(cb.id, { base_url: 'https://blog2.example.com' })
    expect(changed.dast).toMatchObject({ status: 'pending_confirmation', confirmed_by: null, confirmed_at: null })
    expect(changed.confirmation_statement).not.toBeNull()
  })

  it('refuses private network addresses for clone and DAST targets', async () => {
    const s = createSession()
    await s.login('admin')
    for (const host of ['10.1.2.3', '192.168.0.4', '127.0.0.1', '169.254.169.254', '100.64.0.9', 'localhost']) {
      const e1 = await fails(s.api.codebases.create(1, { name: `r-${host}`, target_type: 'repo', repo_url: `https://${host}/a/b.git` }))
      expect(e1).toMatchObject({ status: 422 })
      expect(e1.message).toBe('Private network addresses are not allowed.')
      const e2 = await fails(s.api.codebases.create(1, { name: `u-${host}`, target_type: 'url', base_url: `https://${host}` }))
      expect(e2.message).toBe('Private network addresses are not allowed.')
    }
  })

  it('scan lifecycle: queued -> running -> succeeded updates the latest state; cancel ends a run', async () => {
    let clock = Date.parse('2026-10-27T08:00:00Z')
    const s = createSession({ now: () => clock })
    await s.login('admin')
    const before = await s.api.codebases.get(4)
    expect(before.summary).toBeNull()
    const scan = await s.api.scans.create(4)
    expect((await s.api.scans.get(scan.id)).status).toBe('queued')
    clock += 2000
    const running = await s.api.scans.get(scan.id)
    expect(running.status).toBe('running')
    expect(running.log_tail).toContain('cloning')
    clock += 6000
    const done = await s.api.scans.get(scan.id)
    expect(done.status).toBe('succeeded')
    expect((await s.api.codebases.get(4)).summary).not.toBeNull()
    expect(await fails(s.api.scans.cancel(scan.id))).toMatchObject({ status: 409 })

    const second = await s.api.scans.create(4)
    clock += 500
    await s.api.scans.cancel(second.id)
    expect((await s.api.scans.get(second.id)).status).toBe('cancelled')
  })

  it('latest state = base full scan + later partial scans; summary matches the finding list', async () => {
    const s = createSession()
    await s.login('admin')
    const cb = await s.api.codebases.get(1)
    expect(cb.state).toEqual({ base_scan_id: 45, partial_scans_since_base: 1 })
    const list = await s.api.codebases.findings(1, { page_size: 200 })
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of list.items) if (f.confidence === 'normal') counts[f.severity]++
    expect(cb.summary).toMatchObject(counts)
    expect(cb.summary?.highest_severity).toBe('critical')
    expect(list.facets.severity).toEqual({ critical: counts.critical, high: expect.any(Number), medium: expect.any(Number), low: expect.any(Number), info: expect.any(Number) })
  })

  it('findings filters: severity, rule, path prefix, text, and low confidence', async () => {
    const s = createSession()
    await s.login('admin')
    const high = await s.api.codebases.findings(1, { severity: ['critical', 'high'], page_size: 200 })
    expect(high.items.every(f => f.severity === 'critical' || f.severity === 'high')).toBe(true)
    const sorted = high.items.map(f => (f.severity === 'critical' ? 4 : 3))
    expect(sorted).toEqual([...sorted].sort((a, b) => b - a))
    const rule = await s.api.codebases.findings(1, { rule: 'php-hardcoded-secret' })
    expect(rule.items).toHaveLength(1)
    expect(rule.items[0]!.redacted).toBe(true)
    const path = await s.api.codebases.findings(1, { path: 'src/Controller/', page_size: 200 })
    expect(path.items.every(f => f.location.kind === 'file' && f.location.path.startsWith('src/Controller/'))).toBe(true)
    const hidden = await s.api.codebases.findings(1, { rule: 'php-possible-ssrf' })
    expect(hidden.items).toHaveLength(0)
    const shown = await s.api.codebases.findings(1, { rule: 'php-possible-ssrf', include_low_confidence: true })
    expect(shown.items).toHaveLength(1)
  })

  it('compare: full vs full covers all files; partial scans limit the scope', async () => {
    const s = createSession()
    await s.login('admin')
    const full = await s.api.codebases.compare(1, { base: 39, head: 45 })
    expect(full.scope.kind).toBe('all')
    expect(full.counts.new).toBeGreaterThan(0)
    expect(full.counts.fixed).toBeGreaterThan(0)
    expect(full.counts.unchanged).toBeGreaterThan(0)
    const latest = await s.api.codebases.compare(1)
    expect(latest.scope).toEqual({ kind: 'partial', file_count: 2 })
    expect(latest.counts.new).toBe(1)
    expect(latest.items).toHaveLength(1)
    const fixed = await s.api.codebases.compare(1, { status: 'fixed' })
    expect(fixed.items).toHaveLength(latest.counts.fixed)
  })

  it('last Admin cannot be demoted or deactivated (409 last_admin)', async () => {
    const s = createSession()
    await s.login('admin')
    expect(await fails(s.api.users.patch(1, { role: 'member' }))).toMatchObject({ status: 409, code: 'last_admin' })
    expect(await fails(s.api.users.patch(1, { is_active: false }))).toMatchObject({ status: 409, code: 'last_admin' })
  })

  it('schedule object: cron, status, owner, next run; DAST schedules suspend when the owner loses DAST access', async () => {
    const s = createSession()
    await s.login('admin')
    const before = (await s.api.codebases.get(3)).schedule!
    expect(before).toMatchObject({ cron: '0 2 * * 1', status: 'active', owner: { id: 3, username: 'dast-member' }, suspended_reason: null })
    expect(before.next_run_at).toMatch(/T02:00:00/)
    expect(before.last_enqueued_at).not.toBeNull()
    await s.api.users.patch(3, { can_run_dast: false })
    const cb = (await s.api.codebases.get(3)).schedule!
    expect(cb.status).toBe('suspended')
    expect(cb.suspended_reason).toBe('owner_lost_permission')
    expect(cb.suspended_at).not.toBeNull()
    expect(cb.next_run_at).toBeNull()
    const suspended = await s.api.schedules.list({ status: 'suspended' })
    expect(suspended.items.map(i => i.codebase.id).sort()).toEqual([3, 4])
    expect((await s.api.schedules.list({ status: 'active' })).items.map(i => i.codebase.name)).toEqual(['storefront'])
  })

  it('a SAST schedule survives losing DAST access but not deactivation of its owner', async () => {
    const backend = createMockBackend()
    const dast = createSession({}, backend)
    await dast.login('dastMember')
    await dast.api.schedules.put(1, '0 4 * * *')
    const admin = createSession({}, backend)
    await admin.login('admin')
    await admin.api.users.patch(3, { can_run_dast: false })
    expect((await admin.api.codebases.get(1)).schedule).toMatchObject({ status: 'active', owner: { username: 'dast-member' } })
    await admin.api.users.patch(3, { is_active: false })
    expect((await admin.api.codebases.get(1)).schedule).toMatchObject({ status: 'suspended', suspended_reason: 'owner_deactivated' })
  })

  it('PUT schedule: owner becomes the caller; invalid cron and too-frequent schedules are 422; DAST needs access', async () => {
    const backend = createMockBackend()
    const member = createSession({}, backend)
    await member.login('member')
    const sched = (await member.api.schedules.put(1, '0 * * * *')).schedule
    expect(sched).toMatchObject({ cron: '0 * * * *', status: 'active', owner: { username: 'member' } })
    expect(await fails(member.api.schedules.put(1, 'not a cron'))).toMatchObject({ status: 422, code: 'invalid_cron' })
    expect(await fails(member.api.schedules.put(1, '*/5 * * * *'))).toMatchObject({ status: 422, code: 'schedule_too_frequent' })
    await member.api.schedules.put(1, '*/15 * * * *')
    expect(await fails(member.api.schedules.put(3, '0 5 * * *'))).toMatchObject({ status: 404, code: 'not_found' })
    const dast = createSession({}, backend)
    await dast.login('dastMember')
    expect(await fails(dast.api.schedules.put(3, '*/30 * * * *'))).toMatchObject({ status: 422, code: 'schedule_too_frequent' })
    await dast.api.schedules.put(3, '0 * * * *')
  })

  it('resume: 409 when not suspended, 404 for an invisible URL target, new owner otherwise; delete clears the schedule', async () => {
    const backend = createMockBackend()
    const member = createSession({}, backend)
    await member.login('member')
    expect(await fails(member.api.schedules.resume(1))).toMatchObject({ status: 409, code: 'schedule_not_suspended' })
    // legacy-cms (#4) has a suspended SAST schedule
    expect((await member.api.codebases.get(4)).schedule).toMatchObject({ status: 'suspended', suspended_reason: 'owner_deactivated' })
    await member.api.schedules.resume(4)
    expect((await member.api.codebases.get(4)).schedule).toMatchObject({ status: 'active', owner: { username: 'member' } })
    const admin = createSession({}, backend)
    await admin.login('admin')
    await admin.api.users.patch(3, { can_run_dast: false })
    expect(await fails(member.api.schedules.resume(3))).toMatchObject({ status: 404, code: 'not_found' })
    await admin.api.schedules.resume(3)
    expect((await admin.api.codebases.get(3)).schedule?.owner?.username).toBe('admin')
    await member.api.schedules.remove(4)
    expect((await member.api.codebases.get(4)).schedule).toBeNull()
  })

  it('must-change-password users are flagged and the flag clears after changing the password', async () => {
    const s = createSession()
    await s.login('newHire')
    const me = await s.api.auth.me()
    expect(me.must_change_password).toBe(true)
    expect(await fails(s.api.auth.changePassword('temporary-pass-1234', 'short'))).toMatchObject({ status: 422 })
    await s.api.auth.changePassword('temporary-pass-1234', 'a-brand-new-password')
    expect((await s.api.auth.me()).must_change_password).toBe(false)
  })

  it('DTO shapes: project list, codebase, facets, compare, tokens and schedule rows follow the TRD examples', async () => {
    const s = createSession()
    await s.login('admin')
    const projects = await s.api.projects.list()
    expect(Object.keys(projects).sort()).toEqual(['items', 'page', 'page_size', 'total'])
    const shop = projects.items.find(p => p.name === 'Online Shop')!
    expect(Object.keys(shop).sort()).toEqual(['codebase_count', 'created_at', 'description', 'highest_severity', 'id', 'name', 'totals'])
    expect(shop.totals).toEqual({ critical: expect.any(Number), high: expect.any(Number), medium: expect.any(Number), low: expect.any(Number), info: expect.any(Number) })
    expect(projects.items.find(p => p.name === 'Playground')).toMatchObject({ codebase_count: 0, highest_severity: null, totals: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } })

    const repo = await s.api.codebases.get(1)
    expect(repo).toMatchObject({ dast: null, confirmation_statement: null, base_url: null, project: { id: 1, name: 'Online Shop' }, active_scan: null })
    expect(repo.schedule).toMatchObject({ cron: '0 2 * * *', status: 'active', owner: { username: 'admin' } })
    const url = await s.api.codebases.get(2)
    expect(url).toMatchObject({ target_type: 'url', repo_url: null, has_credential: null, dast: { status: 'pending_confirmation' }, schedule: null })

    const page = await s.api.codebases.findings(1, { rule: 'php-xss-echo', page_size: 5 })
    expect(Object.keys(page.items[0]!).sort()).toEqual(['confidence', 'id', 'kind', 'location', 'message', 'redacted', 'rule_id', 'severity', 'vulnerability'])
    expect(page.facets.rule[0]).toEqual({ id: expect.any(String), count: expect.any(Number) })
    const counts = page.facets.rule.map(r => r.count)
    expect(counts).toEqual([...counts].sort((a, b) => b - a))
    // the selected rule stays listed even when other filters leave it with 0
    const none = await s.api.codebases.findings(1, { rule: 'php-hardcoded-secret', severity: ['info'] })
    expect(none.facets.rule.find(r => r.id === 'php-hardcoded-secret')).toEqual({ id: 'php-hardcoded-secret', count: 0 })

    const cmp = await s.api.codebases.compare(1)
    expect(cmp.base).toEqual({ id: 45, started_at: expect.any(String), coverage: 'full' })
    expect(cmp.head).toMatchObject({ id: 58, coverage: 'partial' })
    expect(cmp.warning).toBeNull()
    expect(Object.keys(cmp.items[0]!).sort()).toEqual(['finding', 'status'])
    const only = await s.api.codebases.compare(5)
    expect(only.base).toBeNull()

    const tokens = await s.api.tokens.list()
    expect(Object.keys(tokens).sort()).toEqual(['items', 'page', 'page_size', 'total'])
    expect(tokens.items[0]).toMatchObject({ status: expect.stringMatching(/active|revoked/), created_by: { username: 'admin' } })
    const created = await s.api.tokens.create({ name: 'ci', project_id: 1 })
    expect(created.secret).toMatch(/^sdrscan_/)
    expect(created.token).toMatchObject({ name: 'ci', project: { id: 1, name: 'Online Shop' }, status: 'active' })
    expect(JSON.stringify(created.token)).not.toContain(created.secret)

    const rows = (await s.api.schedules.list()).items
    expect(rows[0]).toMatchObject({ codebase: { id: expect.any(Number), name: expect.any(String), target_type: expect.any(String) }, project: { id: expect.any(Number) }, cron: expect.any(String) })
  })

  it('URL codebases do not exist for a Member without DAST access (404 identical to a missing id) and are excluded from every total', async () => {
    const backend = createMockBackend()
    const admin = createSession({}, backend)
    await admin.login('admin')
    const member = createSession({}, backend)
    await member.login('member')
    const dast = createSession({}, backend)
    await dast.login('dastMember')

    const missing = await fails(member.api.codebases.get(9999))
    for (const call of [
      () => member.api.codebases.get(3), () => member.api.codebases.findings(3), () => member.api.codebases.files(3), () => member.api.codebases.scans(3),
      () => member.api.codebases.compare(3), () => member.api.scans.get(61), () => member.api.scans.findings(61), () => member.api.scans.files(61),
      () => member.api.scans.cancel(61), () => member.api.scans.create(3), () => member.api.schedules.put(3, '0 2 * * *'), () => member.api.schedules.resume(3),
      () => member.api.schedules.remove(3),
    ]) {
      const e = await fails(call())
      expect(e.status).toBe(404)
      expect(e.code).toBe('not_found')
    }
    expect(missing.status).toBe(404)
    const finding = (await admin.api.codebases.findings(3)).items[0]!
    expect(await fails(member.api.findings.get(finding.id))).toMatchObject({ status: 404 })
    expect((await dast.api.findings.get(finding.id)).id).toBe(finding.id)

    // lists and totals
    const dash = await member.api.projects.get(1)
    expect(dash.codebases.map(c => c.target_type)).toEqual(['repo', 'repo'])
    const full = await admin.api.projects.get(1)
    expect(full.codebases.some(c => c.target_type === 'url')).toBe(true)
    expect(full.totals.medium).toBeGreaterThan(dash.totals.medium)
    const listed = (await member.api.projects.list()).items.find(p => p.id === 1)!
    const listedAdmin = (await admin.api.projects.list()).items.find(p => p.id === 1)!
    expect(listed.codebase_count).toBe(2)
    expect(listedAdmin.codebase_count).toBe(4)
    expect((await member.api.schedules.list()).items.every(r => r.codebase.target_type === 'repo')).toBe(true)
    expect((await admin.api.schedules.list()).items.some(r => r.codebase.target_type === 'url')).toBe(true)

    // revoking DAST access hides the target on the next request with the same session; granting shows it again
    expect((await dast.api.codebases.get(3)).id).toBe(3)
    await admin.api.users.patch(3, { can_run_dast: false })
    expect(await fails(dast.api.codebases.get(3))).toMatchObject({ status: 404 })
    expect((await dast.api.projects.get(1)).codebases.some(c => c.target_type === 'url')).toBe(false)
    await admin.api.users.patch(3, { can_run_dast: true })
    expect((await dast.api.codebases.get(3)).id).toBe(3)
  })
})

describe('vulnerability findings (CVE) in the mock', () => {
  it('SCA and DAST findings carry kind and the full vulnerability object; code findings carry null', async () => {
    const s = createSession()
    await s.login('admin')
    const sca = await s.api.codebases.findings(7)
    expect(sca.items.every(f => f.kind === 'vulnerability')).toBe(true)
    const symfony = sca.items.find(f => f.rule_id === 'CVE-2023-46734')!
    expect(symfony.location).toMatchObject({ kind: 'file', path: 'composer.lock' })
    expect(Object.keys(symfony.vulnerability!).sort()).toEqual(['confidence', 'cvss', 'fixed_versions', 'ids', 'package', 'references', 'scope', 'source'])
    expect(symfony.vulnerability).toMatchObject({ ids: ['CVE-2023-46734', 'GHSA-q847-2q57-wmr3', 'PKSA-2099-FRAM-0001'], package: { ecosystem: 'Packagist', name: 'symfony/twig-bridge', version: '5.4.30' }, source: 'osv', scope: 'runtime' })
    expect(symfony.vulnerability!.references.length).toBeLessThanOrEqual(5)

    const dast = await s.api.codebases.findings(8)
    const nginx = dast.items.find(f => f.rule_id === 'CVE-2021-23017')!
    expect(nginx.location.kind).toBe('url')
    expect(nginx.vulnerability).toMatchObject({ package: { product: 'cpe:2.3:a:nginx:nginx', version: '1.18.0' }, confidence: 'low', source: 'nvd', scope: null })
    expect(dast.items.find(f => f.rule_id === 'http-missing-csp')).toMatchObject({ kind: 'code', vulnerability: null })

    const detail = await s.api.findings.get(symfony.id)
    expect(detail).toMatchObject({ kind: 'vulnerability', vulnerability: { ids: ['CVE-2023-46734', 'GHSA-q847-2q57-wmr3', 'PKSA-2099-FRAM-0001'] } })
  })

  it('kind and cve filters, text search over ids and package names, and the new facets', async () => {
    const s = createSession()
    await s.login('admin')
    const all = await s.api.codebases.findings(7)
    expect(all.facets.kind).toEqual({ code: 0, vulnerability: 3 })
    expect(all.facets.vulnerable_packages).toBe(3)
    expect(all.facets.cve.map(c => c.id)).toEqual(['CVE-2021-23337', 'CVE-2023-46734', 'CVE-2024-99999'])
    expect(all.facets.cve[0]).toEqual({ id: 'CVE-2021-23337', count: 1 })

    const byCve = await s.api.codebases.findings(7, { cve: 'cve-2023-46734' })
    expect(byCve.items.map(f => f.rule_id)).toEqual(['CVE-2023-46734'])
    // an alias matches too, and the cve facet ignores the cve filter itself
    expect((await s.api.codebases.findings(7, { cve: 'GHSA-35jh-r3h4-6jhm' })).items.map(f => f.rule_id)).toEqual(['CVE-2021-23337'])
    expect(byCve.facets.cve).toHaveLength(3)
    expect(byCve.facets.vulnerable_packages).toBe(3)

    expect((await s.api.codebases.findings(7, { kind: 'code' })).items).toHaveLength(0)
    expect((await s.api.codebases.findings(7, { kind: 'vulnerability' })).total).toBe(3)
    expect((await s.api.codebases.findings(7, { q: 'lodash' })).items.map(f => f.rule_id)).toEqual(['CVE-2021-23337'])
    expect((await s.api.codebases.findings(7, { q: 'cve-2024-999' })).items).toHaveLength(1)

    const mixed = await s.api.codebases.findings(8)
    expect(mixed.facets.kind).toEqual({ code: 1, vulnerability: 1 })
    expect((await s.api.codebases.findings(8, { kind: 'code' })).items.map(f => f.rule_id)).toEqual(['http-missing-csp'])
    // code-only codebases have no vulnerable packages
    expect((await s.api.codebases.findings(1)).facets).toMatchObject({ kind: { vulnerability: 0 }, vulnerable_packages: 0, cve: [] })

    expect(await fails(s.api.codebases.findings(7, { kind: 'other' as never }))).toMatchObject({ status: 400, code: 'bad_request' })
    expect(await fails(s.api.codebases.findings(7, { cve: 'x' }))).toMatchObject({ status: 400, code: 'bad_request' })
    expect(await fails(s.api.codebases.findings(7, { cve: 'CVE-2024-1; DROP' }))).toMatchObject({ status: 400 })
  })

  it('CVE findings are never low confidence at finding level: always listed, counted in summaries, outside the low-confidence filter', async () => {
    const s = createSession()
    await s.login('admin')
    const dast = await s.api.codebases.findings(8)
    const nginx = dast.items.find(f => f.rule_id === 'CVE-2021-23017')!
    expect(nginx.confidence).toBe('normal')
    expect(nginx.vulnerability!.confidence).toBe('low')
    expect((await s.api.codebases.get(8)).summary).toMatchObject({ high: 1, low: 1 })
    expect((await s.api.codebases.findings(8, { include_low_confidence: true })).total).toBe(dast.total)
    const all = await s.api.codebases.findings(7, { include_low_confidence: true })
    expect(all.items.every(f => f.confidence === 'normal')).toBe(true)
  })

  it('confidence= and scope= filters (400 otherwise) with facets that count CVE findings and ignore their own filter', async () => {
    const s = createSession()
    await s.login('admin')
    const sca = await s.api.codebases.findings(7)
    expect(sca.facets.confidence).toEqual({ high: 3, low: 0 })
    expect(sca.facets.scope).toEqual({ runtime: 2, dev: 1 })

    const dev = await s.api.codebases.findings(7, { scope: 'dev' })
    expect(dev.items.map(f => f.rule_id)).toEqual(['CVE-2024-99999'])
    expect(dev.facets.scope).toEqual({ runtime: 2, dev: 1 }) // ignores its own filter
    expect(dev.facets.confidence).toEqual({ high: 1, low: 0 }) // but honours the other filters
    expect((await s.api.codebases.findings(7, { scope: 'runtime' })).total).toBe(2)
    expect((await s.api.codebases.findings(7, { confidence: 'low' })).total).toBe(0)
    expect((await s.api.codebases.findings(7, { confidence: 'high', scope: 'runtime' })).total).toBe(2)

    const dast = await s.api.codebases.findings(8)
    expect(dast.facets.confidence).toEqual({ high: 0, low: 1 })
    expect(dast.facets.scope).toEqual({ runtime: 0, dev: 0 }) // the DAST CVE has no scope; code findings never count
    const low = await s.api.codebases.findings(8, { confidence: 'low' })
    expect(low.items.map(f => f.rule_id)).toEqual(['CVE-2021-23017']) // code findings never match
    expect(low.facets.confidence).toEqual({ high: 0, low: 1 })

    expect(await fails(s.api.codebases.findings(7, { confidence: 'medium' as never }))).toMatchObject({ status: 400, code: 'bad_request' })
    expect(await fails(s.api.codebases.findings(7, { scope: 'prod' as never }))).toMatchObject({ status: 400, code: 'bad_request' })
    expect((await s.api.codebases.findings(1)).facets).toMatchObject({ confidence: { high: 0, low: 0 }, scope: { runtime: 0, dev: 0 } })
  })

  it('scan findings and compare items include the vulnerability data', async () => {
    const s = createSession()
    await s.login('admin')
    const scanFindings = await s.api.scans.findings(73, { kind: 'vulnerability' })
    expect(scanFindings.total).toBe(3)
    const cmp = await s.api.codebases.compare(7)
    expect(cmp.head.id).toBe(73)
    const cmpDast = await s.api.codebases.compare(8)
    expect(cmpDast.items.every(i => 'vulnerability' in i.finding && 'kind' in i.finding)).toBe(true)
  })

  it('DAST CVE findings follow the URL visibility rule: invisible (404) for a Member without DAST access', async () => {
    const backend = createMockBackend()
    const admin = createSession({}, backend)
    await admin.login('admin')
    const member = createSession({}, backend)
    await member.login('member')
    const dast = createSession({}, backend)
    await dast.login('dastMember')
    const cve = (await admin.api.codebases.findings(8, { kind: 'vulnerability' })).items[0]!
    expect(await fails(member.api.codebases.findings(8, { cve: 'CVE-2021-23017' }))).toMatchObject({ status: 404, code: 'not_found' })
    expect(await fails(member.api.scans.findings(74))).toMatchObject({ status: 404 })
    expect(await fails(member.api.findings.get(cve.id))).toMatchObject({ status: 404 })
    expect((await dast.api.codebases.findings(8, { cve: 'CVE-2021-23017' })).total).toBe(1)
    // SCA findings of repo codebases are visible to every Member
    expect((await member.api.codebases.findings(7, { kind: 'vulnerability' })).total).toBe(3)
  })
})

describe('vulnerability database endpoints (mock)', () => {
  it('is Admin only: Members get 403 forbidden_role on every endpoint', async () => {
    const backend = createMockBackend()
    const member = createSession({}, backend)
    await member.login('member')
    const dast = createSession({}, backend)
    await dast.login('dastMember')
    for (const who of [member, dast]) {
      for (const call of [() => who.api.system.vulndb(), () => who.api.system.vulndbUpdate({}), () => who.api.system.vulndbCancel()]) {
        expect(await fails(call())).toMatchObject({ status: 403, code: 'forbidden_role' })
      }
    }
  })

  it('reports status with sources, data age and no update yet', async () => {
    const s = createSession()
    await s.login('admin')
    const info = await s.api.system.vulndb()
    expect(info).toMatchObject({ configured: true, sca_enabled: true, db_present: true, tool: { available: true }, stale: false, stale_after_days: 7, update: null, status_error: null })
    expect(info.ecosystems).toEqual(['Packagist', 'npm', 'Go', 'crates.io'])
    expect(info.status!.installed).toBe(true)
    expect(info.status!.sources.map(x => `${x.name}/${x.ecosystem}`)).toEqual(['osv/Packagist', 'osv/npm', 'osv/Go', 'osv/crates.io', 'nvd/null'])
    // shape of `sdrscan-vuln status --json`: no `format` / `raw` any more
    expect(Object.keys(info.status!).sort()).toEqual(['advisory_count', 'age_days', 'format_version', 'installed', 'max_age_days', 'sources', 'updated_at'])
    expect(info.status).toMatchObject({ age_days: 2, max_age_days: 7, format_version: 1 })
    expect(Object.keys(info.status!.sources[0]!).sort()).toEqual(['advisories', 'age_days', 'ecosystem', 'name', 'products', 'updated_at'])
    expect(info.status!.sources[0]).toMatchObject({ name: 'osv', ecosystem: 'Packagist', age_days: 2, products: [] })
    const nvd = info.status!.sources.find(x => x.name === 'nvd')!
    expect(nvd).toMatchObject({ ecosystem: null, advisories: 215000, age_days: 2 })
    expect(nvd.products).toContain('cpe:2.3:a:nginx:nginx')
    expect(info.stale_after_days).toBe(info.status!.max_age_days)
    expect(info.status!.advisory_count).toBe(info.status!.sources.reduce((n, x) => n + x.advisories, 0))
  })

  it('one update at a time: 202, 409 update_in_progress, then succeeded and the data is refreshed', async () => {
    let clock = Date.parse('2026-10-28T10:00:00Z')
    const s = createSession({ now: () => clock })
    await s.login('admin')
    const before = (await s.api.system.vulndb()).status!
    const started = await s.api.system.vulndbUpdate({ ecosystems: ['Packagist', 'Go'], nvd: true })
    expect(started.update).toMatchObject({ id: 1, state: 'running', trigger: 'manual', requested_by: 'admin', ecosystems: ['Packagist', 'Go'], nvd: true, finished_at: null, exit_code: null, error_code: null })
    expect(await fails(s.api.system.vulndbUpdate({}))).toMatchObject({ status: 409, code: 'update_in_progress' })
    clock += 1500
    const mid = (await s.api.system.vulndb()).update!
    expect(mid.state).toBe('running')
    expect(mid.log_tail).toContain('downloading Packagist')
    clock += 2000
    const done = (await s.api.system.vulndb()).update!
    expect(done).toMatchObject({ state: 'succeeded', exit_code: 0, error_code: null })
    expect(done.finished_at).not.toBeNull()
    expect(done.log_tail.trim().endsWith('done')).toBe(true)
    const after = (await s.api.system.vulndb()).status!
    expect(after.advisory_count).toBeGreaterThan(before.advisory_count)
    expect(after.sources.find(x => x.ecosystem === 'Packagist')!.age_days).toBe(0)
    expect(after.sources.find(x => x.ecosystem === 'Packagist')!.updated_at).not.toBe(before.sources.find(x => x.ecosystem === 'Packagist')!.updated_at)
    // a new update may start now
    expect((await s.api.system.vulndbUpdate({})).update.id).toBe(2)
  })

  it('an npm-only update fails with update_failed; an update can be cancelled; cancel without a job is 409', async () => {
    let clock = Date.parse('2026-10-28T10:00:00Z')
    const s = createSession({ now: () => clock })
    await s.login('admin')
    expect(await fails(s.api.system.vulndbCancel())).toMatchObject({ status: 409, code: 'no_update_running' })
    await s.api.system.vulndbUpdate({ ecosystems: ['npm'] })
    clock += 4000
    const failed = (await s.api.system.vulndb()).update!
    expect(failed).toMatchObject({ state: 'failed', exit_code: 1, error_code: 'update_failed' })
    expect(failed.log_tail).toContain('error:')
    expect(await fails(s.api.system.vulndbCancel())).toMatchObject({ status: 409, code: 'no_update_running' })

    await s.api.system.vulndbUpdate({ ecosystems: ['Go'] })
    const cancelled = (await s.api.system.vulndbCancel()).update
    expect(cancelled).toMatchObject({ state: 'cancelled', error_code: 'cancelled' })
    clock += 5000
    expect((await s.api.system.vulndb()).update!.state).toBe('cancelled')
  })

  it('validates ecosystems (whitelist) and nvd', async () => {
    const s = createSession()
    await s.login('admin')
    expect(await fails(s.api.system.vulndbUpdate({ ecosystems: ['Packagist', 'rubygems'] }))).toMatchObject({ status: 422, code: 'validation_failed' })
    expect(await fails(s.api.system.vulndbUpdate({ ecosystems: ['Packagist; rm -rf /'] }))).toMatchObject({ status: 422 })
    expect(await fails(s.api.system.vulndbUpdate({ nvd: 'yes' as never }))).toMatchObject({ status: 422 })
  })

  it('scenarios: not configured (409), tool missing (409), stale data, update recorded in the audit log', async () => {
    const off = createSession({ vulndb: { configured: false } })
    await off.login('admin')
    // the tool works, so status is not null: it says "not installed"
    expect(await off.api.system.vulndb()).toMatchObject({ configured: false, db_path: null, db_present: false, status_error: null,
      status: { installed: false, advisory_count: 0, updated_at: null, age_days: null, max_age_days: 7, format_version: null, sources: [] } })
    expect(await fails(off.api.system.vulndbUpdate({}))).toMatchObject({ status: 409, code: 'vulndb_not_configured' })

    const notool = createSession({ vulndb: { toolAvailable: false } })
    await notool.login('admin')
    expect(await fails(notool.api.system.vulndbUpdate({}))).toMatchObject({ status: 409, code: 'vuln_tool_unavailable' })
    // status is null only when the tool is unavailable, and then status_error says why
    expect(await notool.api.system.vulndb()).toMatchObject({ status: null, tool: { available: false }, status_error: expect.stringContaining('sdrscan-vuln') })

    const empty = createSession({ vulndb: { installed: false } })
    await empty.login('admin')
    expect((await empty.api.system.vulndb()).status).toEqual({ installed: false, advisory_count: 0, updated_at: null, age_days: null, max_age_days: 7, format_version: null, sources: [] })

    const stale = createSession({ vulndb: { dataAgeDays: 12 } })
    await stale.login('admin')
    const staleInfo = await stale.api.system.vulndb()
    expect(staleInfo).toMatchObject({ stale: true, stale_after_days: 7, status: { age_days: 12, max_age_days: 7 } })
    await stale.api.system.vulndbUpdate({})
    expect((await stale.api.audit.list()).items.some(a => a.action === 'vulndb_update_started')).toBe(true)
  })
})

describe('DAST authentication and crawl (mock backend, same rules as the real one)', () => {
  const PASS = 'Sup3r-Secret-Pw!'
  const TOKEN = 'tok-0123456789abcdef'
  const body = (over: Record<string, unknown> = {}) => ({
    type: 'form+header' as const,
    login: { url: 'https://admin.example.com/login', method: 'POST' as const, body_format: 'json' as const, username_field: 'user', password_field: 'password', username: 'tester', password: PASS,
      extra_fields: { otp: 'otp-424242' }, csrf: { source: 'html_input' as const, name: '_csrf', send_as: 'field' as const }, success: { statuses: [200, 302], redirect_not_to: '/login' } },
    headers: { Authorization: `Bearer ${TOKEN}` }, cookies: { sid: 'cookie-value-ABCDEF' },
    ...over,
  })

  it('is write-only: PUT, GET and the codebase carry names and has_secret, never a value', async () => {
    const backend = createMockBackend()
    const s = createSession({}, backend)
    await s.login('dastMember')
    expect(await s.api.dastAuth.get(3)).toMatchObject({ type: 'none', has_secret: false, header_names: [] })
    const put = await s.api.dastAuth.put(3, body())
    expect(put).toMatchObject({ type: 'form+header', has_secret: true, username: 'tester', header_names: ['Authorization'], cookie_names: ['sid'], extra_field_names: ['otp'], updated_by: { username: 'dast-member' } })
    const everything = JSON.stringify([put, await s.api.dastAuth.get(3), await s.api.codebases.get(3), await s.api.codebases.get(3).then(c => c.dast_auth)])
    for (const secret of [PASS, TOKEN, 'cookie-value-ABCDEF', 'otp-424242']) expect(everything).not.toContain(secret)
    // blank secrets keep the stored ones
    const again = await s.api.dastAuth.put(3, body({ login: { ...body().login, password: '', extra_fields: { otp: '' } }, headers: { authorization: '' }, cookies: { sid: '' } }))
    expect(again.has_secret).toBe(true)
  })

  it('token settings: stored as non-secret meta, validated with the backend field paths', async () => {
    const s = createSession({}, createMockBackend())
    await s.login('dastMember')
    const login = { ...body().login, token: { from: 'json' as const, path: 'data.access_token', send_as: 'header' as const }, success: { json_path_exists: 'data.access_token', json_path_equals: { path: 'status', value: 'ok' } } }
    const put = await s.api.dastAuth.put(3, { type: 'form', login } as never)
    expect(put.token).toEqual({ from: 'json', path: 'data.access_token', send_as: 'header', header_name: 'Authorization', prefix: 'Bearer ', cookie_name: null })
    expect(put.success).toMatchObject({ json_path_exists: 'data.access_token', json_path_equals: { path: 'status', value: 'ok' } })
    expect((await s.api.codebases.get(3)).dast_auth?.token?.path).toBe('data.access_token')
    const bad = async (token: Record<string, unknown>) => (await fails(s.api.dastAuth.put(3, { type: 'form', login: { ...login, token } } as never))) as { status: number, details: { field: string } }
    expect(await bad({ path: 'a..b' })).toMatchObject({ status: 422, details: { field: 'login.token.path' } })
    expect(await bad({ path: 'a', header_name: 'Host' })).toMatchObject({ details: { field: 'login.token.header_name' } })
    expect(await bad({ path: 'a', prefix: 'x\r\ny' })).toMatchObject({ details: { field: 'login.token.prefix' } })
    expect(await bad({ path: 'a', send_as: 'cookie' })).toMatchObject({ details: { field: 'login.token.cookie_name' } })
    expect(await bad({ path: 'a', send_as: 'body' })).toMatchObject({ details: { field: 'login.token.send_as' } })
    expect(await fails(s.api.dastAuth.put(3, { type: 'form', login: { ...login, success: { json_path_exists: 'a[' } } } as never))).toMatchObject({ details: { field: 'login.success.json_path_exists' } })
  })

  it('validates like the server: origin, CRLF, forbidden headers, counts, secret key', async () => {
    const s = createSession()
    await s.login('admin')
    const put = (b: unknown) => s.api.dastAuth.put(3, b as never)
    expect(await fails(put(body({ login: { ...body().login, url: 'https://evil.example.net/login' } })))).toMatchObject({ status: 422, details: { field: 'login.url' } })
    expect(await fails(put(body({ headers: { 'X-A': 'abcd\r\nX-Evil: 1' } })))).toMatchObject({ status: 422, details: { field: 'headers.X-A' } })
    expect(await fails(put(body({ headers: { Host: 'evil.example.net' } })))).toMatchObject({ status: 422 })
    expect(await fails(put({ type: 'none' }))).toMatchObject({ status: 422, details: { field: 'type' } })
    expect(await fails(put(body({ login: { ...body().login, password: '' } })))).toMatchObject({ status: 422, details: { field: 'login.password' } })
    const noKey = createSession({ secretKey: false })
    await noKey.login('admin')
    expect(await fails(noKey.api.dastAuth.put(3, body()))).toMatchObject({ status: 503, code: 'secret_key_required' })
  })

  it('a Member without DAST access gets the same 404 as for a missing id; repositories answer 409', async () => {
    const backend = createMockBackend()
    const member = createSession({}, backend)
    await member.login('member')
    const real = await fails(member.api.dastAuth.get(3))
    const ghost = await fails(member.api.dastAuth.get(9999))
    expect([real.status, real.code, real.message]).toEqual([ghost.status, ghost.code, ghost.message.replace('9999', '3')])
    expect(await fails(member.api.dastAuth.put(3, body()))).toMatchObject({ status: 404 })
    expect(await fails(member.api.dastAuth.test(3))).toMatchObject({ status: 404 })
    const admin = createSession({}, backend)
    await admin.login('admin')
    expect(await fails(admin.api.dastAuth.get(1))).toMatchObject({ status: 409, code: 'not_a_url_target' })
    expect((await member.api.codebases.get(1)).dast_auth).toBeNull()
  })

  it('tests the login only for confirmed targets with a login form', async () => {
    const backend = createMockBackend()
    const s = createSession({}, backend)
    await s.login('admin')
    expect(await fails(s.api.dastAuth.test(3))).toMatchObject({ status: 409, code: 'no_auth_configured' })
    await s.api.dastAuth.put(2, body({ login: { ...body().login, url: 'https://shop.example.com/login' } }))
    expect(await fails(s.api.dastAuth.test(2))).toMatchObject({ status: 409, code: 'target_not_confirmed' })
    await s.api.dastAuth.put(3, body())
    const ok = await s.api.dastAuth.test(3)
    expect(ok.ok).toBe(true)
    expect(JSON.stringify(ok)).not.toContain(PASS)
    await s.api.dastAuth.put(3, body({ login: { ...body().login, password: 'wrong-password' } }))
    expect(await s.api.dastAuth.test(3)).toMatchObject({ ok: false })
    await s.api.dastAuth.put(3, { type: 'header', headers: { 'X-Api-Key': 'abcdef12' } })
    expect(await fails(s.api.dastAuth.test(3))).toMatchObject({ status: 409, code: 'no_login_configured' })
    await s.api.dastAuth.remove(3)
    expect((await s.api.codebases.get(3)).dast_auth).toMatchObject({ type: 'none', has_secret: false })
  })

  it('changing the target origin removes the credentials; a path change keeps them', async () => {
    const s = createSession()
    await s.login('admin')
    await s.api.dastAuth.put(3, body())
    expect((await s.api.codebases.patch(3, { base_url: 'https://admin.example.com/app' })).dast_auth?.type).toBe('form+header')
    const moved = await s.api.codebases.patch(3, { base_url: 'https://admin2.example.com' })
    expect(moved.dast_auth).toMatchObject({ type: 'none', has_secret: false, login_url: null })
    expect(moved.dast?.status).toBe('pending_confirmation')
  })

  it('crawl settings: defaults, PATCH, validation and URL targets only', async () => {
    const s = createSession()
    await s.login('admin')
    expect((await s.api.codebases.get(3)).dast_crawl).toEqual({ enabled: false, max_depth: 3, max_pages: 50, exclude: [] })
    const cb = await s.api.codebases.patch(3, { dast_crawl_enabled: true, dast_crawl_max_depth: 5, dast_crawl_max_pages: 120, dast_crawl_exclude: ['^/admin', '\\.pdf$'] })
    expect(cb.dast_crawl).toEqual({ enabled: true, max_depth: 5, max_pages: 120, exclude: ['^/admin', '\\.pdf$'] })
    for (const bad of [{ dast_crawl_max_depth: 0 }, { dast_crawl_max_depth: 11 }, { dast_crawl_max_pages: 0 }, { dast_crawl_max_pages: 501 }, { dast_crawl_exclude: ['(x'] }, { dast_crawl_exclude: ['(?=x)'] },
      { dast_crawl_exclude: Array.from({ length: 21 }, () => 'a') }, { dast_crawl_exclude: ['a'.repeat(201)] }]) {
      expect(await fails(s.api.codebases.patch(3, bad))).toMatchObject({ status: 422, code: 'validation_failed' })
    }
    expect(await fails(s.api.codebases.patch(1, { dast_crawl_enabled: true }))).toMatchObject({ status: 422 })
    expect((await s.api.codebases.get(3)).dast_crawl?.max_depth).toBe(5)
  })

  it('a scan of an authenticated, crawled target logs it without any credential', async () => {
    let clock = 1_800_000_000_000
    const s = createSession({ now: () => clock })
    await s.login('admin')
    await s.api.dastAuth.put(3, body())
    await s.api.codebases.patch(3, { dast_crawl_enabled: true, dast_crawl_max_pages: 30 })
    const scan = await s.api.scans.create(3)
    clock += 9000
    const done = await s.api.scans.get(scan.id)
    expect(done.status).toBe('succeeded')
    expect(done.log_tail).toContain('authenticated scan (form+header)')
    expect(done.log_tail).toContain('scan summary: 12 pages scanned')
    for (const secret of [PASS, TOKEN]) expect(done.log_tail).not.toContain(secret)
  })
})
