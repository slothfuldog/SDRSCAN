import { describe, expect, it, vi } from 'vitest'
import { mountSuspended, mockNuxtImport } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import SeverityBadge from '~/components/SeverityBadge.vue'
import SeverityCounts from '~/components/SeverityCounts.vue'
import SnippetView from '~/components/SnippetView.vue'
import RunScanButton from '~/components/RunScanButton.vue'
import ConfirmDeleteDialog from '~/components/ConfirmDeleteDialog.vue'
import ScheduleSettings from '~/components/ScheduleSettings.vue'
import AdminOnly from '~/components/AdminOnly.vue'
import CveBadge from '~/components/CveBadge.vue'
import FindingTypeChip from '~/components/FindingTypeChip.vue'
import FindingTable from '~/components/FindingTable.vue'
import VulnerabilityPanel from '~/components/VulnerabilityPanel.vue'
import { DAST_VULN_TEMPLATES, SCA_TEMPLATES } from '../../mock/seed.ts'
import { useAuth } from '~/stores/auth'
import type { Codebase, FindingSummary, User } from '~/types/api'

const setUser = (u: Partial<User>) => {
  const auth = useAuth()
  auth.user = { id: 1, username: 'u', role: 'member', can_run_dast: false, ...u } as User
  auth.loaded = true
}

describe('SeverityBadge / SeverityCounts', () => {
  it('always shows the severity as text', async () => {
    const w = await mountSuspended(SeverityBadge, { props: { severity: 'critical' } })
    expect(w.text()).toBe('Critical')
    const c = await mountSuspended(SeverityCounts, { props: { summary: { critical: 2, high: 0, medium: 5, low: 0, info: 1 } } })
    expect(c.text()).toMatch(/Critical\s*2/)
    expect(c.text()).toMatch(/Medium\s*5/)
  })
})

describe('SnippetView renders text, never HTML', () => {
  const payload = '<img src=x onerror=alert(1)><script>alert(2)</script>'

  it('escapes markup in file snippets and numbers the lines from start_line', async () => {
    const w = await mountSuspended(SnippetView, { props: { snippet: `echo "${payload}";\nsecond`, kind: 'file', startLine: 40, endLine: 41, startColumn: 3 } })
    expect(w.find('img').exists()).toBe(false)
    expect(w.find('script').exists()).toBe(false)
    expect(w.text()).toContain(payload)
    const rows = w.findAll('code')
    expect(rows).toHaveLength(2)
    expect(rows[0]!.text().startsWith('40')).toBe(true)
    expect(rows[1]!.text().startsWith('41')).toBe(true)
    // every line of the flagged region is highlighted; the column start is shown as indentation
    expect(rows.every(r => r.attributes('data-hot') === 'true')).toBe(true)
    expect(rows[0]!.text()).toContain('  echo')
  })

  it('shows URL evidence without line numbers and marks redactions', async () => {
    const w = await mountSuspended(SnippetView, { props: { snippet: 'GET / HTTP/1.1\nSet-Cookie: sid=[REDACTED]', kind: 'url', redacted: true } })
    expect(w.findAll('code')).toHaveLength(2)
    expect(w.find('[aria-hidden="true"].tabular-nums').exists()).toBe(false)
    expect(w.text()).toContain('Value hidden')
    expect(w.text()).toContain('[REDACTED]')
  })
})

describe('RunScanButton follows the role rules', () => {
  it('SAST: visible and enabled for a Member', async () => {
    setUser({ role: 'member' })
    const w = await mountSuspended(RunScanButton, { props: { codebase: { id: 1, name: 'a', target_type: 'repo', dast_status: null } } })
    const btn = w.find('[data-testid="run-scan"]')
    expect(btn.exists()).toBe(true)
    expect(btn.attributes('disabled')).toBeUndefined()
  })

  it('DAST: hidden for a Member without DAST access', async () => {
    setUser({ role: 'member', can_run_dast: false })
    const w = await mountSuspended(RunScanButton, { props: { codebase: { id: 2, name: 'b', target_type: 'url', dast_status: 'confirmed' } } })
    expect(w.find('[data-testid="run-scan"]').exists()).toBe(false)
  })

  it('DAST: disabled with the reason while the target is pending confirmation', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const w = await mountSuspended(RunScanButton, { props: { codebase: { id: 2, name: 'b', target_type: 'url', dast_status: 'pending_confirmation' } } })
    expect(w.find('[data-testid="run-scan"]').attributes('disabled')).toBeDefined()
    expect(w.text()).toContain('An Admin must confirm authorization for this target first.')
  })

  it('DAST: enabled for an Admin on a confirmed target', async () => {
    setUser({ role: 'admin' })
    const w = await mountSuspended(RunScanButton, { props: { codebase: { id: 2, name: 'b', target_type: 'url', dast_status: 'confirmed' } } })
    expect(w.find('[data-testid="run-scan"]').attributes('disabled')).toBeUndefined()
  })
})

describe('AdminOnly', () => {
  it('shows the access message to Members and the content to Admins', async () => {
    setUser({ role: 'member' })
    const m = await mountSuspended(AdminOnly, { slots: { default: () => 'secret admin content' } })
    expect(m.text()).toContain('You do not have access to this page.')
    expect(m.text()).not.toContain('secret admin content')
    setUser({ role: 'admin' })
    const a = await mountSuspended(AdminOnly, { slots: { default: () => 'secret admin content' } })
    expect(a.text()).toContain('secret admin content')
  })
})

describe('ConfirmDeleteDialog', () => {
  it('only enables permanent delete after typing the exact name', async () => {
    const action = vi.fn(async () => ({}))
    const w = await mountSuspended(ConfirmDeleteDialog, { props: { open: true, kind: 'Project', name: 'Online Shop', action }, attachTo: document.body })
    await flushPromises()
    const btn = () => document.body.querySelector<HTMLButtonElement>('button[type="submit"]')!
    const input = document.body.querySelector<HTMLInputElement>('#confirm-name')!
    // The button stays clickable; a wrong or empty name is explained under the field and nothing is deleted.
    btn().click()
    await flushPromises()
    expect(action).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Type the exact name')
    input.value = 'online shop'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    btn().click()
    await flushPromises()
    expect(action).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('does not match')
    input.value = 'Online Shop'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    btn().click()
    await flushPromises()
    expect(action).toHaveBeenCalledTimes(1)
    expect(w.emitted('deleted')).toBeTruthy()
    w.unmount()
  })
})

const baseCodebase = (over: Partial<Codebase>): Codebase => ({
  id: 3, project: { id: 1, name: 'Online Shop' }, name: 'admin-portal', target_type: 'url', language: '', repo_url: null, branch: null, subdirectory: null, git_auth_kind: null, git_username: null,
  has_credential: null, base_url: 'https://admin.example.com', dast_max_rps: 5, dast: { status: 'confirmed', registered_by: null, confirmed_by: null, confirmed_at: null }, confirmation_statement: null,
  summary: null, latest_scan: null, base_scan: null, state: null, active_scan: null, created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z',
  schedule: { cron: '0 2 * * 1', status: 'active', owner: { id: 3, username: 'dast-member' }, suspended_reason: null, suspended_at: null, last_enqueued_at: null, next_run_at: '2026-11-02T02:00:00Z' },
  dast_auth: null, dast_crawl: null, dast_active: null,
  ...over,
})

describe('ScheduleSettings', () => {
  it('shows owner, status, next run and a preview of the next three runs', async () => {
    setUser({ role: 'admin' })
    const w = await mountSuspended(ScheduleSettings, { props: { codebase: baseCodebase({}) } })
    expect(w.text()).toContain('Weekly')
    expect(w.find('[data-testid="schedule-owner"]').text()).toBe('dast-member')
    expect(w.find('[data-testid="schedule-status"]').text()).toBe('Active')
    expect(w.findAll('[data-testid="schedule-preview"] li')).toHaveLength(3)
    expect(w.find('[data-testid="resume-schedule"]').exists()).toBe(false)
  })

  it('suspended: shows the reason and a Resume button that calls the resume endpoint', async () => {
    setUser({ role: 'admin' })
    const calls: string[] = []
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method} ${url}`)
      return new Response(JSON.stringify({ schedule: {} }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    const cb = baseCodebase({ schedule: { cron: '0 2 * * 1', status: 'suspended', owner: { id: 3, username: 'dast-member' }, suspended_reason: 'owner_lost_permission', suspended_at: '2026-10-27T10:00:00Z', last_enqueued_at: null, next_run_at: null } })
    const w = await mountSuspended(ScheduleSettings, { props: { codebase: cb } })
    expect(w.find('[data-testid="schedule-status"]').text()).toBe('Suspended')
    expect(w.find('[data-testid="schedule-suspended"]').text()).toContain('Owner no longer has permission.')
    expect(w.text()).toContain('None scheduled')
    await w.find('[data-testid="resume-schedule"]').trigger('click')
    await flushPromises()
    expect(calls).toContain('POST /api/v1/codebases/3/schedule/resume')
    expect(w.emitted('saved')).toBeTruthy()
    vi.unstubAllGlobals()
  })

  it('saves with PUT {cron} and blocks too-frequent schedules before calling the server', async () => {
    setUser({ role: 'member' })
    const calls: Array<{ m?: string, u: string, b?: unknown }> = []
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      calls.push({ m: init?.method, u: url, b: init?.body })
      return new Response(JSON.stringify({ schedule: {} }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    const repo = baseCodebase({ id: 1, target_type: 'repo', dast: null, schedule: null })
    const w = await mountSuspended(ScheduleSettings, { props: { codebase: repo } })
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls[0]).toMatchObject({ m: 'PUT', u: '/api/v1/codebases/1/schedule', b: JSON.stringify({ cron: '0 2 * * *' }) })
    await w.find('[role="radio"][value="custom"]').trigger('click')
    await w.find('#sched-cron').setValue('*/5 * * * *')
    await flushPromises()
    // Save stays clickable: pressing it shows the problem under the cron field and sends nothing.
    expect(w.find('[data-testid="save-schedule"]').attributes('disabled')).toBeUndefined()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls).toHaveLength(1)
    expect(w.find('[data-field="cron"]').text()).toContain('minimum interval is 15 minutes')
    expect(w.find('[data-testid="form-errors"]').text()).toContain('Cron expression')
    vi.unstubAllGlobals()
  })

  it('is read-only for a Member without DAST access on a URL target (no Save, no Resume)', async () => {
    setUser({ role: 'member', can_run_dast: false })
    const cb = baseCodebase({ schedule: { cron: '0 2 * * 1', status: 'suspended', owner: { id: 3, username: 'dast-member' }, suspended_reason: 'owner_deactivated', suspended_at: null, last_enqueued_at: null, next_run_at: null } })
    const w = await mountSuspended(ScheduleSettings, { props: { codebase: cb } })
    expect(w.text()).toContain('You need DAST access')
    expect(w.find('[data-testid="save-schedule"]').exists()).toBe(false)
    expect(w.find('[data-testid="resume-schedule"]').exists()).toBe(false)
    expect(w.find('[data-testid="delete-schedule"]').exists()).toBe(false)
  })
})

const sca = (key: string) => SCA_TEMPLATES.find(t => t.key === key)!
const summaryOf = (t: (typeof SCA_TEMPLATES)[number], id: number): FindingSummary => ({
  id, rule_id: t.rule_id, severity: t.severity, confidence: t.confidence ?? 'normal', message: t.message, redacted: false,
  location: t.url ? { kind: 'url', url: t.url } : { kind: 'file', path: t.path!, start_line: t.start_line ?? null },
  kind: t.vulnerability ? 'vulnerability' : 'code', vulnerability: t.vulnerability ?? null,
})

describe('CveBadge', () => {
  it('shows the id as text; with link it links only valid CVE and GHSA ids, in a new tab with noopener noreferrer', async () => {
    const plain = await mountSuspended(CveBadge, { props: { id: 'CVE-2023-46734' } })
    expect(plain.text()).toBe('CVE-2023-46734')
    expect(plain.find('a').exists()).toBe(false)

    const cve = await mountSuspended(CveBadge, { props: { id: 'CVE-2023-46734', link: true } })
    const a = cve.find('a')
    expect(a.attributes('href')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2023-46734')
    expect(a.attributes('target')).toBe('_blank')
    expect(a.attributes('rel')).toBe('noopener noreferrer')

    const ghsa = await mountSuspended(CveBadge, { props: { id: 'GHSA-q847-2q57-wmr3', link: true } })
    expect(ghsa.find('a').attributes('href')).toBe('https://github.com/advisories/GHSA-q847-2q57-wmr3')

    for (const bad of ['GHSA-<b>bad</b>', 'cve-2024-1', 'CVE-2024-12345"><img src=x onerror=alert(1)>', 'RUSTSEC-2021-0001', 'javascript:alert(1)']) {
      const w = await mountSuspended(CveBadge, { props: { id: bad, link: true } })
      expect(w.find('a').exists(), bad).toBe(false)
      expect(w.find('img').exists()).toBe(false)
      expect(w.text()).toBe(bad)
    }
  })
})

describe('FindingTypeChip', () => {
  it('labels findings as Code or Vulnerability', async () => {
    expect((await mountSuspended(FindingTypeChip, { props: { kind: 'vulnerability' } })).text()).toBe('Vulnerability')
    expect((await mountSuspended(FindingTypeChip, { props: { kind: 'code' } })).text()).toBe('Code')
  })
})

describe('FindingTable with vulnerability findings', () => {
  it('shows type chips, CVE badges and package@version; hostile package names stay text', async () => {
    const items: FindingSummary[] = [
      summaryOf(sca('sca:symfony'), 1), summaryOf(sca('sca:xss'), 2), summaryOf(DAST_VULN_TEMPLATES[0]!, 3), summaryOf(DAST_VULN_TEMPLATES[1]!, 4),
    ]
    const w = await mountSuspended(FindingTable, { props: { items } })
    const rows = w.findAll('tbody tr')
    expect(rows).toHaveLength(4)
    expect(rows[0]!.find('[data-testid="finding-kind"]').text()).toBe('Vulnerability')
    expect(rows[0]!.findAll('[data-testid="cve-badge"]').map(b => b.text())).toEqual(['CVE-2023-46734', 'GHSA-q847-2q57-wmr3', 'PKSA-2099-FRAM-0001'])
    expect(rows[0]!.find('[data-testid="vuln-package"]').text()).toBe('symfony/twig-bridge@5.4.30')
    // the list rows link to the detail page, not to the advisory sites
    expect(rows[0]!.find('a[href^="https://"]').exists()).toBe(false)
    expect(rows[1]!.text()).toContain('<img src=x onerror=alert(1)>/pkg@1.0.0"><script>alert(2)</script>')
    expect(w.find('img').exists()).toBe(false)
    expect(w.find('script').exists()).toBe(false)
    // DAST: a CPE prefix is shown as a friendly "vendor product version" (equal vendor and product once); the raw CPE is a title
    expect(rows[2]!.find('[data-testid="vuln-package"]').text()).toBe('nginx 1.18.0')
    expect(rows[2]!.find('[data-testid="vuln-package"]').attributes('title')).toBe('cpe:2.3:a:nginx:nginx')
    // low-confidence CVE (DAST): a "Confidence: low" badge next to the severity; dev dependencies get a Dev badge
    expect(rows[2]!.find('[data-testid="vuln-low-confidence"]').text()).toBe('Confidence: low')
    expect(rows[0]!.find('[data-testid="vuln-low-confidence"]').exists()).toBe(false)
    expect(rows[1]!.find('[data-testid="vuln-dev-badge"]').text()).toBe('Dev')
    expect(rows[0]!.find('[data-testid="vuln-dev-badge"]').exists()).toBe(false)
    expect(rows[3]!.find('[data-testid="finding-kind"]').text()).toBe('Code')
    expect(rows[3]!.find('[data-testid="vuln-cell"]').exists()).toBe(false)
    expect(rows[3]!.text()).toContain('http-missing-csp')
  })
})

describe('VulnerabilityPanel', () => {
  const mountPanel = (t: (typeof SCA_TEMPLATES)[number]) =>
    mountSuspended(VulnerabilityPanel, { props: { vulnerability: t.vulnerability!, location: t.url ? { kind: 'url', url: t.url } : { kind: 'file', path: t.path!, start_line: t.start_line ?? null } } })

  it('SCA: ids, package, installed version, upgrade hint, CVSS, source, scope and the lockfile location', async () => {
    const w = await mountPanel(sca('sca:symfony'))
    const ids = w.findAll('[data-testid="vuln-ids"] a')
    expect(ids.map(a => a.attributes('href'))).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2023-46734', 'https://github.com/advisories/GHSA-q847-2q57-wmr3'])
    expect(w.find('[data-testid="vuln-package-name"]').text()).toContain('symfony/twig-bridge')
    expect(w.find('[data-testid="vuln-package-name"]').text()).toContain('Packagist')
    expect(w.find('[data-testid="vuln-version"]').text()).toBe('5.4.30')
    expect(w.find('[data-testid="vuln-upgrade"]').text()).toBe('Upgrade to 5.4.31 or 6.3.8')
    expect(w.find('[data-testid="vuln-cvss"]').text()).toContain('7.5')
    expect(w.find('[data-testid="vuln-cvss"]').text()).toContain('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')
    expect(w.find('[data-testid="vuln-source"]').text()).toBe('OSV')
    expect(w.find('[data-testid="vuln-confidence"]').text()).toBe('High')
    expect(w.find('[data-testid="vuln-scope"]').text()).toContain('Runtime')
    expect(w.find('[data-testid="vuln-location"]').text()).toBe('composer.lock:1204')
    expect(w.find('[data-testid="vuln-dast-note"]').exists()).toBe(false)
  })

  it('references: only http/https are links (noopener noreferrer, new tab); javascript:, ftp: and credentials URLs stay plain text', async () => {
    const w = await mountPanel(sca('sca:symfony'))
    const links = w.findAll('[data-testid="vuln-references"] a')
    expect(links.map(a => a.attributes('href'))).toEqual(['https://symfony.com/cve-2023-46734', 'https://github.com/advisories/GHSA-q847-2q57-wmr3'])
    for (const a of links) {
      expect(a.attributes('target')).toBe('_blank')
      expect(a.attributes('rel')).toBe('noopener noreferrer')
    }
    const items = w.findAll('[data-testid="vuln-references"] li')
    expect(items).toHaveLength(5)
    expect(items[2]!.text()).toBe('javascript:alert(document.cookie)')
    expect(items[2]!.find('a').exists()).toBe(false)
    expect(items[3]!.find('a').exists()).toBe(false)
    expect(items[4]!.find('a').exists()).toBe(false)
    expect(w.findAll('a').every(a => /^https?:\/\//.test(a.attributes('href') ?? ''))).toBe(true)
  })

  it('XSS payloads in names, versions, ids and references render as text and are never linked', async () => {
    const w = await mountPanel(sca('sca:xss'))
    expect(w.find('img').exists()).toBe(false)
    expect(w.find('script').exists()).toBe(false)
    expect(w.find('b').exists()).toBe(false)
    expect(w.find('[data-testid="vuln-package-name"]').text()).toContain('<img src=x onerror=alert(1)>/pkg')
    expect(w.find('[data-testid="vuln-version"]').text()).toBe('1.0.0"><script>alert(2)</script>')
    expect(w.find('[data-testid="vuln-upgrade"]').text()).toBe('Upgrade to <b>2.0</b>')
    const ids = w.findAll('[data-testid="cve-badge"]')
    expect(ids.map(b => b.text())).toEqual(['CVE-2024-99999', 'GHSA-<b>bad</b>', 'cve-2024-1'])
    expect(w.findAll('[data-testid="vuln-ids"] a').map(a => a.attributes('href'))).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2024-99999'])
    expect(w.find('[data-testid="vuln-scope"]').text()).toContain('Dev')
    expect(w.find('[data-testid="vuln-cvss"]').exists()).toBe(false)
  })

  it('DAST: product and detected version, the version-based note, low confidence and the URL', async () => {
    const w = await mountPanel(DAST_VULN_TEMPLATES[0]!)
    expect(w.find('[data-testid="vuln-package-name"]').text()).toBe('nginx')
    expect(w.find('[data-testid="vuln-cpe"]').text()).toBe('cpe:2.3:a:nginx:nginx')
    expect(w.find('[data-testid="vuln-cpe"]').element.tagName).toBe('DD')
    expect(w.findAll('a').some(a => (a.attributes('href') ?? '').includes('cpe:'))).toBe(false)
    expect(w.find('[data-testid="vuln-version"]').text()).toBe('1.18.0')
    expect(w.find('[data-testid="vuln-confidence"]').text()).toBe('Low')
    expect(w.find('[data-testid="vuln-dast-note"]').text()).toBe('Version-based detection, may be patched by the vendor.')
    expect(w.find('[data-testid="vuln-source"]').text()).toBe('NVD')
    expect(w.find('[data-testid="vuln-location"]').text()).toBe('https://status.example.com/')
    expect(w.find('[data-testid="vuln-scope"]').exists()).toBe(false)
    expect(w.text()).toContain('Upgrade to 1.20.1 or 1.21.0')
  })

  it('DAST: vendor and product differ -> "vendor product"; a value that is not a CPE stays as is; ids that fail the strict GHSA pattern are not linked', async () => {
    const t = DAST_VULN_TEMPLATES[0]!
    const apache = await mountSuspended(VulnerabilityPanel, { props: { vulnerability: { ...t.vulnerability!, package: { product: 'cpe:2.3:a:apache:http_server', version: '2.4.41' }, ids: ['CVE-2021-41773', 'GHSA-2099-fram-0001', 'PKSA-2099-FRAM-0001'] }, location: { kind: 'url', url: 'https://x.example.com/' } } })
    expect(apache.find('[data-testid="vuln-package-name"]').text()).toBe('apache http_server')
    expect(apache.find('[data-testid="vuln-cpe"]').text()).toBe('cpe:2.3:a:apache:http_server')
    expect(apache.find('[data-testid="vuln-version"]').text()).toBe('2.4.41')
    expect(apache.findAll('[data-testid="vuln-ids"] a').map(a => a.attributes('href'))).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'])
    expect(apache.findAll('[data-testid="cve-badge"]').map(b => b.text())).toEqual(['CVE-2021-41773', 'GHSA-2099-fram-0001', 'PKSA-2099-FRAM-0001'])

    const plain = await mountSuspended(VulnerabilityPanel, { props: { vulnerability: { ...t.vulnerability!, package: { product: 'Custom <b>Server</b>', version: '1' } }, location: { kind: 'url', url: 'https://x.example.com/' } } })
    expect(plain.find('[data-testid="vuln-package-name"]').text()).toBe('Custom <b>Server</b>')
    expect(plain.find('[data-testid="vuln-cpe"]').exists()).toBe(false)
    expect(plain.find('b').exists()).toBe(false)
  })

  it('Go packages get a one-line go.sum over-reporting hint; other ecosystems do not', async () => {
    const t = sca('sca:lodash')
    const go = await mountSuspended(VulnerabilityPanel, { props: { vulnerability: { ...t.vulnerability!, package: { ecosystem: 'Go', name: 'golang.org/x/net', version: 'v0.7.0' } }, location: { kind: 'file', path: 'go.sum', start_line: 12 } } })
    expect(go.find('[data-testid="vuln-go-note"]').text()).toBe('Go: detected from go.sum, may over-report (the module may not be used).')
    const npm = await mountPanel(sca('sca:lodash'))
    expect(npm.find('[data-testid="vuln-go-note"]').exists()).toBe(false)
  })

  it('says so when no fixed version is known', async () => {
    const t = sca('sca:lodash')
    const w = await mountSuspended(VulnerabilityPanel, { props: { vulnerability: { ...t.vulnerability!, fixed_versions: [], cvss: null, source: null, confidence: null, references: [] }, location: { kind: 'file', path: 'package-lock.json' } } })
    expect(w.find('[data-testid="vuln-upgrade"]').text()).toBe('No fixed version is known.')
    expect(w.text()).toContain('Not available')
    expect(w.find('[data-testid="vuln-references"]').exists()).toBe(false)
  })
})

mockNuxtImport('navigateTo', () => vi.fn())
