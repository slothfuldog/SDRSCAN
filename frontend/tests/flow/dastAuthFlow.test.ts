import { afterEach, describe, expect, it, vi } from 'vitest'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import App from '~/app.vue'
import { createMockBackend, SEED_CREDENTIALS } from '../../mock/core.ts'
import type { MockOptions } from '../../mock/core.ts'
import { createMockFetch } from '../helpers/mockClient'
import { useAuth } from '~/stores/auth'

// Authentication and crawl settings, and the scan detail page, through the whole app against the in-memory mock.
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

const PASSWORD = 'Sup3r-Secret-Pw!'

describe('Authentication and Crawling panels on the Codebase settings page', () => {
  it('a DAST member configures a login, sees "Credential saved", tests it and removes it; the password never appears in the page', async () => {
    const { w, router } = await start('dastMember')
    await router.push('/codebases/3/settings')
    await until(() => w.find('[data-testid="dast-auth"]').exists() && w.find('[data-testid="dast-crawl"]').exists(), 'panels')
    expect(w.find('[data-testid="credential-saved"]').exists()).toBe(false)

    await w.find('[data-testid="dast-auth"] [role="radio"][value="form"]').trigger('click')
    await until(() => w.find('#auth-password').exists(), 'form')
    expect((w.find('#auth-login-url').element as HTMLInputElement).value).toBe('https://admin.example.com/login')
    await w.find('#auth-username').setValue('tester')
    await w.find('#auth-password').setValue(PASSWORD)
    await w.find('[data-testid="auth-form"]').trigger('submit')
    await until(() => w.find('[data-testid="credential-saved"]').exists(), 'saved view')
    expect(w.html()).not.toContain(PASSWORD)
    expect(w.find('input[type="password"]').exists()).toBe(false)
    expect(w.find('[data-testid="auth-summary"]').text()).toContain('as tester')

    await w.find('[data-testid="test-login"]').trigger('click')
    await until(() => w.find('[data-testid="login-check-result"]').exists(), 'test result')
    expect(w.find('[data-testid="login-check-result"]').text()).toContain('Login succeeded')
    expect(w.html()).not.toContain(PASSWORD)

    await w.find('[data-testid="remove-auth"]').trigger('click')
    await until(() => !!document.body.querySelector('[data-testid="confirm-remove-auth"]'), 'confirm dialog')
    document.body.querySelector<HTMLButtonElement>('[data-testid="confirm-remove-auth"]')!.click()
    await until(() => w.find('[data-testid="auth-form"]').exists() && !w.find('[data-testid="credential-saved"]').exists(), 'removed')
  })

  it('saves the crawl settings', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/3/settings')
    await until(() => w.find('[data-testid="dast-crawl"]').exists(), 'crawl panel')
    await w.find('[data-testid="crawl-enabled"]').trigger('click')
    await w.find('#crawl-depth').setValue('4')
    await w.find('[data-testid="dast-crawl"] form').trigger('submit')
    // Saved: the codebase reloads and the Save button is disabled again (nothing left to save).
    await until(() => w.find('[data-testid="save-crawl"]').attributes('disabled') !== undefined && (w.find('#crawl-depth').element as HTMLInputElement).value === '4', 'saved')
    await router.push('/codebases/3')
    await router.push('/codebases/3/settings')
    await until(() => w.find('[data-testid="dast-crawl"]').exists(), 'crawl panel again')
    expect((w.find('#crawl-depth').element as HTMLInputElement).value).toBe('4')
  })

  it('a repository codebase has neither panel', async () => {
    const { w, router } = await start('admin')
    await router.push('/codebases/1/settings')
    await until(() => w.find('[data-testid="schedule"]').exists(), 'settings page')
    expect(w.find('[data-testid="dast-auth"]').exists()).toBe(false)
    expect(w.find('[data-testid="dast-crawl"]').exists()).toBe(false)
  })

  it('a Member without DAST access cannot open the URL target at all (404), so no panel exists for them', async () => {
    const { w, router } = await start('member')
    await router.push('/codebases/3/settings')
    await until(() => w.text().toLowerCase().includes('not found'), 'not found')
    expect(w.find('[data-testid="dast-auth"]').exists()).toBe(false)
  })
})

describe('Scan detail shows "Authenticated scan" and the pages scanned', () => {
  it('for a scan of an authenticated, crawled target; not for a plain one', async () => {
    let clock = 1_800_000_000_000
    const { w, router, backend } = await start('admin', { now: () => clock })
    // Configure through the API client path the UI uses.
    const login = backend.handle({ method: 'POST', path: '/api/v1/auth/login', query: new URLSearchParams(), headers: { 'content-type': 'application/json' }, body: { username: 'admin', password: SEED_CREDENTIALS.admin.password } })
    const cookie = login.headers['Set-Cookie']!.split(';')[0]!
    const csrf = (login.body as { csrf_token: string }).csrf_token
    const call = (method: string, path: string, body?: unknown) => backend.handle({ method, path: `/api/v1${path}`, query: new URLSearchParams(), headers: { cookie, 'x-csrf-token': csrf, 'content-type': 'application/json' }, body })
    expect(call('PUT', '/codebases/3/dast-auth', { type: 'header', headers: { 'X-Api-Key': 'abcdef12' } }).status).toBe(200)
    expect(call('PATCH', '/codebases/3', { dast_crawl_enabled: true, dast_crawl_max_pages: 30 }).status).toBe(200)
    const scan = call('POST', '/scans', { codebase_id: 3 }).body as { id: number }
    clock += 9000
    await router.push(`/scans/${scan.id}`)
    await until(() => w.find('[data-testid="authenticated-scan"]').exists(), 'authenticated badge')
    expect(w.find('[data-testid="authenticated-scan"]').text()).toBe('Authenticated scan')
    expect(w.find('[data-testid="scan-pages"]').text()).toBe('12')
    expect(w.find('[data-testid="scan-log"]').text()).not.toContain('abcdef12')

    // A plain scan (target 8 has no authentication): no badge.
    clock += 1000
    const plain = call('POST', '/scans', { codebase_id: 8 }).body as { id: number }
    clock += 9000
    await router.push(`/scans/${plain.id}`)
    await until(() => w.find('[data-testid="scan-log"]').exists() && w.find('[data-testid="scan-log"]').text().includes('done'), 'plain scan done')
    expect(w.find('[data-testid="authenticated-scan"]').exists()).toBe(false)
  })
})
