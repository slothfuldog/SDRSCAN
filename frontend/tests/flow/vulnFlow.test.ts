import { afterEach, describe, expect, it, vi } from 'vitest'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import App from '~/app.vue'
import { createMockBackend, SEED_CREDENTIALS } from '../../mock/core.ts'
import type { MockOptions } from '../../mock/core.ts'
import { createMockFetch } from '../helpers/mockClient'
import { useAuth } from '~/stores/auth'

// Vulnerability features through the whole app against the in-memory mock: lists, detail page, admin database page.
async function settle(ms = 30) {
  for (let i = 0; i < 6; i++) {
    await flushPromises()
    await new Promise(r => setTimeout(r, ms))
  }
}
async function until(check: () => boolean, label: string) {
  for (let i = 0; i < 80; i++) {
    if (check()) return
    await settle(10)
  }
  throw new Error(`timed out waiting for: ${label}`)
}

let wrapper: VueWrapper | undefined

async function start(who: keyof typeof SEED_CREDENTIALS, options: MockOptions = {}) {
  const backend = createMockBackend(options)
  vi.stubGlobal('fetch', createMockFetch(backend).fetch)
  useAuth().clear()
  useAuth().loaded = false
  wrapper = await mountSuspended(App, { route: '/login' })
  const router = useRouter()
  await until(() => wrapper!.find('#username').exists(), 'login form')
  await wrapper.find('#username').setValue(SEED_CREDENTIALS[who].username)
  await wrapper.find('#password').setValue(SEED_CREDENTIALS[who].password)
  await wrapper.find('form').trigger('submit')
  await until(() => wrapper!.find('[data-testid="projects-table"]').exists(), 'projects')
  return { w: wrapper, router, backend }
}

afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const body = () => document.body

describe('vulnerability findings in the codebase findings list and the detail page', () => {
  it('lists CVE badges and package@version, the vulnerable dependency count, and filters by type and CVE (URL state)', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/7')
    await until(() => w.find('[data-testid="finding-table"]').exists(), 'findings table')
    expect(w.find('[data-testid="vulnerable-packages"]').text()).toContain('3 vulnerable dependencies')
    const rows = () => w.findAll('[data-testid="finding-table"] tbody tr')
    expect(rows()).toHaveLength(3)
    expect(w.text()).toContain('symfony/twig-bridge@5.4.30')
    expect(w.text()).toContain('CVE-2021-23337')
    expect(w.text()).toContain('<img src=x onerror=alert(1)>/pkg@1.0.0"><script>alert(2)</script>') // hostile text is shown as text
    expect(w.find('img').exists()).toBe(false)

    // exact id in the CVE box -> cve= filter
    await w.find('#f-cve').setValue('cve-2021-23337')
    await until(() => router.currentRoute.value.query.cve === 'cve-2021-23337' && rows().length === 1, 'cve filter')
    expect(rows()[0]!.text()).toContain('lodash@4.17.15')

    // partial text -> text search over ids and package names
    await w.find('#f-cve').setValue('twig')
    await until(() => router.currentRoute.value.query.cve === 'twig' && rows().length === 1 && rows()[0]!.text().includes('symfony'), 'partial search')

    await router.push('/codebases/7?kind=code')
    await until(() => w.text().includes('No findings match these filters'), 'empty for code type')
    await router.push('/codebases/7?kind=vulnerability&cve=GHSA-q847-2q57-wmr3')
    await until(() => rows().length === 1, 'alias filter')

    // code-only codebase: no vulnerable dependency line
    await router.push('/codebases/1')
    await until(() => rows().length > 1 && !w.text().includes('CVE-2023'), 'code codebase')
    expect(w.find('[data-testid="vulnerable-packages"]').exists()).toBe(false)
    expect(w.find('[data-testid="finding-kind"]').text()).toBe('Code')
  }, 30000)

  it('finding detail shows the Vulnerability panel with safe links; code findings have no panel', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/7')
    await until(() => w.find('[data-testid="finding-table"]').exists(), 'findings table')
    const href = w.findAll('[data-testid="finding-table"] tbody tr').find(r => r.text().includes('CVE-2023-46734'))!.find('a[href^="/findings/"]').attributes('href')!
    await router.push(href)
    await until(() => w.find('[data-testid="vuln-panel"]').exists(), 'vulnerability panel')
    const panel = w.find('[data-testid="vuln-panel"]')
    expect(panel.find('[data-testid="vuln-upgrade"]').text()).toBe('Upgrade to 5.4.31 or 6.3.8')
    expect(panel.findAll('a').every(a => a.attributes('rel') === 'noopener noreferrer' && /^https?:\/\//.test(a.attributes('href')!))).toBe(true)
    expect(w.text()).toContain('Vulnerability')
    expect(panel.text()).not.toContain('Version-based detection')

    await router.push('/codebases/1')
    await until(() => w.find('[data-testid="finding-table"]').exists(), 'code findings')
    const codeHref = w.find('[data-testid="finding-table"] tbody tr a[href^="/findings/"]').attributes('href')!
    await router.push(codeHref)
    await until(() => w.find('[data-testid="finding-message"]').exists(), 'code finding')
    expect(w.find('[data-testid="vuln-panel"]').exists()).toBe(false)
  }, 30000)

  it('a DAST CVE finding explains that the detection is version based', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/8')
    await until(() => w.find('[data-testid="finding-table"]').exists(), 'dast findings')
    expect(w.find('[data-testid="vulnerable-packages"]').text()).toContain('1 vulnerable dependency')
    const href = w.findAll('[data-testid="finding-table"] tbody tr').find(r => r.text().includes('CVE-2021-23017'))!.find('a[href^="/findings/"]').attributes('href')!
    await router.push(href)
    await until(() => w.find('[data-testid="vuln-dast-note"]').exists(), 'dast note')
    expect(w.find('[data-testid="vuln-dast-note"]').text()).toBe('Version-based detection, may be patched by the vendor.')
    expect(w.find('[data-testid="vuln-package-name"]').text()).toContain('nginx')
    expect(w.find('[data-testid="vuln-low-confidence"]').text()).toBe('Confidence: low')
    expect(w.text()).not.toContain('Low confidence') // finding-level confidence is always normal for CVEs
  }, 30000)
})

describe('confidence and scope filters', () => {
  it('are kept in the URL, show facet counts and filter the list; a low-confidence CVE is listed by default', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/8')
    await until(() => w.find('[data-testid="finding-table"]').exists(), 'dast findings')
    const rows = () => w.findAll('[data-testid="finding-table"] tbody tr')
    expect(rows()).toHaveLength(2) // the low-confidence CVE is in the default list
    expect(w.find('[data-testid="vuln-low-confidence"]').exists()).toBe(true)
    expect(w.find('#f-confidence').exists()).toBe(true)

    await router.push('/codebases/8?confidence=low')
    await until(() => rows().length === 1 && rows()[0]!.text().includes('CVE-2021-23017'), 'confidence=low')
    await router.push('/codebases/8?confidence=high')
    await until(() => w.text().includes('No findings match these filters'), 'confidence=high is empty')

    await router.push('/codebases/7?scope=dev')
    await until(() => rows().length === 1 && rows()[0]!.text().includes('CVE-2024-99999'), 'scope=dev')
    expect(rows()[0]!.find('[data-testid="vuln-dev-badge"]').exists()).toBe(true)
    expect(w.find('#f-scope').text()).toContain('Dev (1)')

    // code-only codebases do not show the vulnerability filters
    await router.push('/codebases/1')
    await until(() => rows().length > 1 && !w.text().includes('CVE-2023'), 'code codebase')
    expect(w.find('#f-confidence').exists()).toBe(false)
    expect(w.find('#f-scope').exists()).toBe(false)
  }, 30000)

  it('the detail page shows the confidence and scope badges next to the severity', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/7?scope=dev')
    await until(() => w.find('[data-testid="finding-table"] tbody tr a[href^="/findings/"]').exists(), 'dev finding')
    await router.push(w.find('[data-testid="finding-table"] tbody tr a[href^="/findings/"]').attributes('href')!)
    await until(() => w.find('[data-testid="vuln-scope-badge"]').exists(), 'detail')
    expect(w.find('[data-testid="vuln-scope-badge"]').text()).toBe('Dev')
    expect(w.find('[data-testid="vuln-low-confidence"]').exists()).toBe(false)
  }, 30000)
})

describe('Vulnerability database page (Admin)', () => {
  it('is in the Admin menu and shows status, sources and data age without warnings when the data is fresh', async () => {
    const { w, router } = await start('admin')
    expect(w.find('nav[aria-label="Main"]').text()).toContain('Vulnerability database')
    await router.push('/settings/vulndb')
    await until(() => w.find('[data-testid="vulndb-status"]').exists(), 'status cards')
    expect(w.find('[data-testid="advisory-count"]').text()).toBe('290675')
    expect(w.find('[data-testid="data-age"]').text()).toBe('2 days ago')
    expect(w.find('[data-testid="vulndb-path"]').text()).toBe('/var/lib/sdrscan/vulndb')
    expect(w.findAll('[data-testid="sources-table"] tbody tr')).toHaveLength(5)
    expect(w.find('[data-testid="sources-table"]').text()).toContain('Packagist')
    expect(w.find('[data-testid="sources-table"]').text()).toContain('NVD')
    // NVD lists the CPE products it covers as small text; OSV rows list none
    expect(w.findAll('[data-testid="nvd-products"] li').map(l => l.text())).toEqual(['cpe:2.3:a:apache:http_server', 'cpe:2.3:a:nginx:nginx', 'cpe:2.3:a:php:php'])
    expect(w.findAll('[data-testid="source-age"]').every(a => a.text() === '(2 days ago)')).toBe(true)
    expect(w.text()).not.toContain('Raw status output')
    for (const id of ['warn-off', 'warn-stale', 'warn-tool', 'warn-sca-off']) expect(w.find(`[data-testid="${id}"]`).exists()).toBe(false)
    expect(w.find('[data-testid="no-update"]').exists()).toBe(true)
    expect(w.find('[data-testid="update-now"]').attributes('disabled')).toBeUndefined()
  }, 30000)

  it('Update now: pick ecosystems, the job runs, the page polls every 2 seconds and shows the log until it succeeds', async () => {
    let clock = Date.parse('2026-10-28T10:00:00Z')
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const { w, router } = await start('admin', { now: () => clock })
    await router.push('/settings/vulndb')
    await until(() => w.find('[data-testid="vulndb-status"]').exists(), 'status cards')
    const before = w.find('[data-testid="advisory-count"]').text()

    await w.find('[data-testid="update-now"]').trigger('click')
    await until(() => body().querySelectorAll('#vulndb-form [role="checkbox"], #vulndb-form button[role="checkbox"]').length >= 5, 'dialog checkboxes')
    const labels = [...body().querySelectorAll('#vulndb-form label')].map(l => l.textContent?.trim())
    expect(labels).toEqual(expect.arrayContaining(['Packagist', 'npm', 'Go', 'crates.io', 'Also update NVD data']))
    // NVD stays opt-in and the dialog explains when it is needed
    expect(body().querySelector('#vulndb-form')!.textContent).toContain('Only needed for CVEs of products found by DAST')
    expect(body().querySelector('#vulndb-form')!.textContent).toContain('OSV')
    body().querySelector<HTMLButtonElement>('[data-testid="start-update"]')!.click()
    await until(() => w.find('[data-testid="update-state"]').exists(), 'running job')
    expect(w.find('[data-testid="update-state"]').text()).toBe('Running')
    expect(w.find('[data-testid="cancel-update"]').exists()).toBe(true)
    expect(w.find('[data-testid="update-now"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-testid="update-job"]').text()).toContain('Packagist, npm, Go, crates.io')

    // the job takes 3 s on the mock clock; the page only learns about it through its 2 s poll
    clock += 3500
    expect(w.find('[data-testid="update-state"]').text()).toBe('Running')
    vi.advanceTimersByTime(2000)
    await until(() => w.find('[data-testid="update-state"]').text() === 'Succeeded', 'job succeeded')
    expect(w.find('[data-testid="cancel-update"]').exists()).toBe(false)
    expect(w.find('[data-testid="update-log"]').text()).toContain('downloading Packagist')
    expect(w.find('[data-testid="update-log"]').text()).toContain('done')
    expect(w.find('[data-testid="advisory-count"]').text()).not.toBe(before)
    // polling stops once the job is finished
    expect(vi.getTimerCount()).toBe(0)
  }, 30000)

  it('a failed job shows the error, exit code and the log tail', async () => {
    let clock = Date.parse('2026-10-28T10:00:00Z')
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const { w, router } = await start('admin', { now: () => clock })
    await router.push('/settings/vulndb')
    await until(() => w.find('[data-testid="vulndb-status"]').exists(), 'status cards')
    await w.find('[data-testid="update-now"]').trigger('click')
    await until(() => body().querySelectorAll('#vulndb-form button[role="checkbox"]').length >= 5, 'dialog checkboxes')
    const boxes = [...body().querySelectorAll<HTMLButtonElement>('#vulndb-form button[role="checkbox"]')]
    // untick everything except npm
    for (const b of boxes.slice(0, 4)) {
      const label = body().querySelector(`label[for="${b.id}"]`)?.textContent?.trim()
      if (label !== 'npm') { b.click(); await settle(5) } // one click at a time, like a user
    }
    await settle()
    body().querySelector<HTMLButtonElement>('[data-testid="start-update"]')!.click()
    await until(() => w.find('[data-testid="update-state"]').exists(), 'running job')
    clock += 3500
    vi.advanceTimersByTime(2000)
    await until(() => w.find('[data-testid="update-state"]').text() === 'Failed', 'job failed')
    expect(w.find('[data-testid="update-error"]').text()).toContain('The update tool reported an error.')
    expect(w.find('[data-testid="update-error"]').text()).toContain('exit code 1')
    expect(w.find('[data-testid="update-log"]').text()).toContain('HTTP 503')
    expect(w.find('[data-testid="update-now"]').attributes('disabled')).toBeUndefined()
  }, 30000)

  it('the update dialog says what is missing instead of silently disabling Start', async () => {
    const { w, router } = await start('admin')
    await router.push('/settings/vulndb')
    await until(() => w.find('[data-testid="vulndb-status"]').exists(), 'status cards')
    await w.find('[data-testid="update-now"]').trigger('click')
    await until(() => body().querySelectorAll('#vulndb-form button[role="checkbox"]').length >= 5, 'dialog checkboxes')
    for (const b of [...body().querySelectorAll<HTMLButtonElement>('#vulndb-form button[role="checkbox"]')].slice(0, 4)) { b.click(); await settle(5) }
    const start1 = body().querySelector<HTMLButtonElement>('[data-testid="start-update"]')!
    expect(start1.disabled).toBe(false)
    start1.click()
    await until(() => !!body().querySelector('[data-field="ecosystems"]')?.textContent?.includes('Select at least one ecosystem.'), 'field error')
    expect(body().querySelector('[data-testid="form-errors"]')?.getAttribute('role')).toBe('alert')
    // choosing one clears the error and the update starts
    body().querySelector<HTMLButtonElement>('#vulndb-form button[role="checkbox"]')!.click()
    await settle(5)
    expect(body().querySelector('[data-field="ecosystems"]')?.textContent).not.toContain('Select at least one ecosystem.')
  }, 30000)

  it('warns that CVE checks are off when the database is not configured, and disables Update now', async () => {
    const { w, router } = await start('admin', { vulndb: { configured: false } })
    await router.push('/settings/vulndb')
    await until(() => w.find('[data-testid="warn-off"]').exists(), 'warning')
    expect(w.find('[data-testid="warn-off"]').text()).toContain('CVE checks are off until the database is installed.')
    expect(w.find('[data-testid="warn-off"]').text()).toContain('SDRSCAN_VULN_DB')
    expect(w.find('[data-testid="update-now"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-testid="advisory-count"]').text()).toBe('0')
    expect(w.find('[data-testid="data-age"]').text()).toBe('No data')
    expect(w.find('[data-testid="sources-table"]').exists()).toBe(false)
  }, 30000)

  it('warns when the data is not installed yet, the tool is missing, SCA is switched off or the data is stale', async () => {
    const a = await start('admin', { vulndb: { installed: false, toolAvailable: false, scaEnabled: false } })
    await a.router.push('/settings/vulndb')
    await until(() => a.w.find('[data-testid="warn-off"]').exists(), 'warnings')
    expect(a.w.find('[data-testid="warn-off"]').text()).toContain('CVE checks are off until the database is installed.')
    expect(a.w.find('[data-testid="warn-tool"]').text()).toContain('sdrscan-vuln')
    expect(a.w.find('[data-testid="warn-status-error"]').exists()).toBe(false) // the tool warning already says it
    expect(a.w.find('[data-testid="warn-sca-off"]').exists()).toBe(true)
    expect(a.w.find('[data-testid="update-now"]').attributes('disabled')).toBeDefined()
    a.w.unmount()
    wrapper = undefined
    vi.unstubAllGlobals()

    const b = await start('admin', { vulndb: { dataAgeDays: 12 } })
    await b.router.push('/settings/vulndb')
    await until(() => b.w.find('[data-testid="warn-stale"]').exists(), 'stale warning')
    expect(b.w.find('[data-testid="warn-stale"]').text()).toContain('older than 7 days')
    expect(b.w.find('[data-testid="warn-stale"]').text()).toContain('12 days ago')
    expect(b.w.find('[data-testid="data-age"]').text()).toBe('12 days ago')
    expect(b.w.find('[data-testid="warn-off"]').exists()).toBe(false)
    expect(b.w.find('[data-testid="update-now"]').attributes('disabled')).toBeUndefined()
  }, 30000)
})

describe('Vulnerability database page (role rules)', () => {
  it('Members do not see the menu entry; opening the page directly shows the access message and loads nothing', async () => {
    const { w, router } = await start('member')
    expect(w.find('nav[aria-label="Main"]').text()).not.toContain('Vulnerability database')
    const spy = vi.fn(globalThis.fetch)
    vi.stubGlobal('fetch', spy)
    await router.push('/settings/vulndb')
    await until(() => w.find('[data-testid="no-access"]').exists(), 'no access')
    expect(w.text()).toContain('You do not have access to this page.')
    expect(w.find('[data-testid="update-now"]').exists()).toBe(false)
    expect(spy.mock.calls.some(c => String(c[0]).includes('/system/vulndb'))).toBe(false)
  }, 30000)

  it('a Member can still read SCA findings of repo codebases (type chip and badges), but DAST CVE targets are not found', async () => {
    const { w, router } = await start('member')
    await router.push('/codebases/7')
    await until(() => w.find('[data-testid="finding-table"]').exists(), 'sca findings')
    expect(w.find('[data-testid="vulnerable-packages"]').exists()).toBe(true)
    await router.push('/codebases/8')
    await until(() => w.find('[data-testid="error-state"]').exists(), 'not found')
    expect(w.find('[data-testid="error-state"]').text()).toContain('Codebase not found.')
    expect(w.text()).not.toContain('CVE-2021-23017')
  }, 30000)
})
