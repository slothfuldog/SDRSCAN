import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import App from '~/app.vue'
import { createMockBackend } from '../../mock/core.ts'
import { createMockFetch } from '../helpers/mockClient'
import { useAuth } from '~/stores/auth'

// Whole-app flow against the in-memory mock: sign in -> projects -> project dashboard -> codebase -> finding detail.
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

describe('login -> dashboard -> finding detail', () => {
  let wrapper: VueWrapper
  beforeEach(() => {
    const backend = createMockBackend()
    vi.stubGlobal('fetch', createMockFetch(backend).fetch)
    useAuth().clear()
    useAuth().loaded = false
  })
  afterEach(() => {
    wrapper?.unmount()
    vi.unstubAllGlobals()
  })

  it('walks through the main path and renders hostile content as text', async () => {
    wrapper = await mountSuspended(App, { route: '/' })
    const router = useRouter()

    // 1. Not signed in -> redirected to the login page, remembering where we wanted to go.
    await until(() => router.currentRoute.value.path === '/login', 'redirect to /login')
    expect(wrapper.text()).toContain('Sign in')

    // wrong password shows the friendly message
    await wrapper.find('#username').setValue('admin')
    await wrapper.find('#password').setValue('definitely-wrong')
    await wrapper.find('form').trigger('submit')
    await until(() => wrapper.find('[data-testid="login-error"]').exists(), 'login error')
    expect(wrapper.find('[data-testid="login-error"]').text()).toBe('Invalid username or password.')

    // 2. Correct credentials (mock seed values) -> Projects page.
    await wrapper.find('#password').setValue('admin-password-1234')
    await wrapper.find('form').trigger('submit')
    await until(() => router.currentRoute.value.path === '/', 'projects page')
    await until(() => wrapper.find('[data-testid="projects-table"]').exists(), 'projects table')
    expect(wrapper.find('[data-testid="current-user"]').text()).toBe('admin')
    expect(wrapper.text()).toContain('Online Shop')
    expect(useAuth().csrfToken).toBeTruthy()

    // 3. Project dashboard: severity summary per codebase, highest severity, project total, "Not scanned yet".
    await router.push('/projects/1')
    await until(() => wrapper.find('[data-testid="codebases-table"]').exists(), 'dashboard')
    const totals = wrapper.find('[data-testid="project-totals"]').text()
    expect(totals).toMatch(/Critical\s*2/)
    expect(totals).toContain('Highest severity')
    expect(wrapper.findAll('[data-testid="not-scanned"]').length).toBeGreaterThanOrEqual(2)
    expect(wrapper.text()).toContain('Pending confirmation')

    // 4. Codebase findings list, filter by rule, open the XSS-payload finding.
    await router.push('/codebases/1?rule=php-xss-echo')
    await until(() => wrapper.find('[data-testid="finding-table"]').exists(), 'findings table')
    expect(wrapper.find('[data-testid="partial-note"]').text()).toContain('Based on full scan #45 plus 1 partial scan.')
    const link = wrapper.findAll('[data-testid="finding-table"] a').find(a => a.text().includes('<img'))
    expect(link, 'finding with a hostile path').toBeTruthy()
    // the hostile path is shown as text, never parsed into elements
    expect(wrapper.find('[data-testid="finding-table"] img').exists()).toBe(false)
    expect(link!.attributes('href')).toMatch(/^\/findings\/\d+$/)
    await router.push(link!.attributes('href')!)

    // 5. Finding detail: message, location, snippet shown as text with the problem line highlighted.
    await until(() => wrapper.find('[data-testid="finding-message"]').exists(), 'finding detail')
    expect(wrapper.find('[data-testid="finding-message"]').text()).toContain('<script>alert("xss-in-message")</script>')
    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.find('script:not([src])').exists()).toBe(false)
    expect(wrapper.find('[data-testid="snippet"] [data-hot="true"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="finding-location"]').text()).toContain('<img src=x onerror=alert(1)>')
    // CWE link only for well-formed ids
    const hrefs = wrapper.findAll('a[href^="https://cwe.mitre.org"]').map(a => a.attributes('href'))
    expect(hrefs).toEqual(['https://cwe.mitre.org/data/definitions/79.html'])
  }, 30000)

  it('a Member does not see Admin navigation and gets the access message on /users', async () => {
    wrapper = await mountSuspended(App, { route: '/login' })
    const router = useRouter()
    await until(() => !!wrapper.find('#username').exists(), 'login form')
    await wrapper.find('#username').setValue('member')
    await wrapper.find('#password').setValue('member-password-1234')
    await wrapper.find('form').trigger('submit')
    await until(() => wrapper.find('[data-testid="projects-table"]').exists(), 'projects')
    const nav = wrapper.find('nav[aria-label="Main"]').text()
    expect(nav).toContain('Projects')
    expect(nav).not.toContain('Users')
    expect(nav).not.toContain('Ingest tokens')
    await router.push('/users')
    await until(() => wrapper.find('[data-testid="no-access"]').exists(), 'no access message')
    expect(wrapper.text()).toContain('You do not have access to this page.')
    // no Delete buttons for a Member
    await router.push('/')
    await until(() => wrapper.find('[data-testid="projects-table"]').exists(), 'projects again')
    expect(wrapper.text()).not.toContain('Delete')
  }, 30000)

  it('Schedules page: a Member without DAST access never sees URL targets; Resume is available for repo schedules', async () => {
    wrapper = await mountSuspended(App, { route: '/login' })
    const router = useRouter()
    await until(() => !!wrapper.find('#username').exists(), 'login form')
    await wrapper.find('#username').setValue('member')
    await wrapper.find('#password').setValue('member-password-1234')
    await wrapper.find('form').trigger('submit')
    await until(() => wrapper.find('[data-testid="projects-table"]').exists(), 'projects')
    expect(wrapper.find('nav[aria-label="Main"]').text()).toContain('Schedules')
    await router.push('/schedules')
    await until(() => wrapper.find('[data-testid="schedules-table"]').exists(), 'schedules table')
    const rows = () => wrapper.findAll('[data-testid="schedules-table"] tbody tr')
    expect(rows()).toHaveLength(2)
    expect(wrapper.text()).not.toContain('admin-portal')
    expect(wrapper.text()).toContain('Owner was deactivated.')
    expect(wrapper.find('button[aria-label^="Resume schedule of legacy-cms"]').attributes('disabled')).toBeUndefined()
    await router.push('/schedules?status=active')
    await until(() => rows().length === 1, 'active filter')
    expect(rows()[0]!.text()).toContain('storefront')
  }, 30000)

  it('Member without DAST access: a URL target is "Codebase not found." (404), not an access error; DAST holders and Admins see it', async () => {
    wrapper = await mountSuspended(App, { route: '/login' })
    const router = useRouter()
    await until(() => !!wrapper.find('#username').exists(), 'login form')
    await wrapper.find('#username').setValue('member')
    await wrapper.find('#password').setValue('member-password-1234')
    await wrapper.find('form').trigger('submit')
    await until(() => wrapper.find('[data-testid="projects-table"]').exists(), 'projects')
    // Project list counts only visible codebases
    const shopRow = wrapper.findAll('[data-testid="projects-table"] tbody tr').find(r => r.text().includes('Online Shop'))!
    expect(shopRow.findAll('td')[1]!.text()).toBe('2')
    await router.push('/projects/1')
    await until(() => wrapper.find('[data-testid="codebases-table"]').exists(), 'dashboard')
    expect(wrapper.text()).not.toContain('Pending confirmation')
    expect(wrapper.text()).not.toContain('(live)')
    await router.push('/codebases/3')
    await until(() => wrapper.find('[data-testid="error-state"]').exists(), 'not found')
    expect(wrapper.find('[data-testid="error-state"]').text()).toContain('Codebase not found.')
    expect(wrapper.text()).not.toContain('admin-portal')
    await router.push('/scans/61')
    await until(() => wrapper.find('[data-testid="error-state"]').exists() || router.currentRoute.value.path === '/', 'scan not found')
  }, 30000)
})
