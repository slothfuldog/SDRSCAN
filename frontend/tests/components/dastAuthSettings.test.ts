import { describe, expect, it, vi } from 'vitest'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import DastAuthSettings from '~/components/DastAuthSettings.vue'
import DastCrawlSettings from '~/components/DastCrawlSettings.vue'
import { useAuth } from '~/stores/auth'
import type { Codebase, DastAuth, User } from '~/types/api'

const PASSWORD = 'Sup3r-Secret-Pw!'
const TOKEN = 'tok-0123456789abcdef'

const setUser = (u: Partial<User>) => {
  const auth = useAuth()
  auth.user = { id: 1, username: 'u', role: 'member', can_run_dast: false, ...u } as User
  auth.loaded = true
}

const none = (): DastAuth => ({ type: 'none', has_secret: false, login_url: null, method: null, body_format: null, username_field: null, password_field: null, username: null,
  extra_field_names: [], csrf: null, success: null, header_names: [], cookie_names: [], updated_at: null, updated_by: null })
const savedAuth = (over: Partial<DastAuth> = {}): DastAuth => ({
  ...none(), type: 'form+header', has_secret: true, login_url: 'https://admin.example.com/login', method: 'POST', body_format: 'json', username_field: 'user', password_field: 'password',
  username: 'tester', header_names: ['Authorization'], cookie_names: [], updated_at: '2026-10-28T08:00:00Z', updated_by: { id: 3, username: 'dast-member' }, ...over,
})

const cb = (over: Partial<Codebase> = {}): Codebase => ({
  id: 3, project: { id: 1, name: 'Online Shop' }, name: 'admin-portal', target_type: 'url', language: '', repo_url: null, branch: null, subdirectory: null, git_auth_kind: null, git_username: null,
  has_credential: null, base_url: 'https://admin.example.com', dast_max_rps: 5, dast: { status: 'confirmed', registered_by: null, confirmed_by: null, confirmed_at: null }, confirmation_statement: null,
  summary: null, latest_scan: null, base_scan: null, state: null, active_scan: null, schedule: null, created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z',
  dast_auth: none(), dast_crawl: { enabled: false, max_depth: 3, max_pages: 50, exclude: [] }, dast_active: null, ...over,
})

interface Call { m?: string, u: string, b?: unknown }
function stubFetch(handler: (c: Call) => { status?: number, body?: unknown }) {
  const calls: Call[] = []
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    const call = { m: init?.method, u: url, b: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined }
    calls.push(call)
    const r = handler(call)
    return new Response(r.status === 204 ? null : JSON.stringify(r.body ?? {}), { status: r.status ?? 200, headers: { 'Content-Type': 'application/json' } })
  })
  return calls
}

describe('DastAuthSettings', () => {
  it('is not rendered for a Member without DAST access', async () => {
    setUser({ role: 'member', can_run_dast: false })
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    expect(w.find('[data-testid="dast-auth"]').exists()).toBe(false)
    const c = await mountSuspended(DastCrawlSettings, { props: { codebase: cb() } })
    expect(c.find('[data-testid="dast-crawl"]').exists()).toBe(false)
  })

  it('offers the four types and explains what is (not) supported', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    for (const label of ['None', 'Login form', 'Fixed header(s)', 'Login form + headers']) expect(w.text()).toContain(label)
    expect(w.find('[data-testid="auth-limits"]').text()).toMatch(/OAuth.*multi-factor/s)
    expect(w.text()).toContain('minimum rights')
    expect(w.text()).toContain('only sent to the target host')
  })

  it('saved credentials: shows "Credential saved" with Replace and Remove and never renders a value', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb({ dast_auth: savedAuth() }) } })
    expect(w.find('[data-testid="credential-saved"]').text()).toBe('Credential saved')
    expect(w.find('[data-testid="replace-auth"]').exists()).toBe(true)
    expect(w.find('[data-testid="remove-auth"]').exists()).toBe(true)
    expect(w.find('[data-testid="auth-summary"]').text()).toContain('https://admin.example.com/login as tester')
    expect(w.find('[data-testid="auth-summary"]').text()).toContain('Authorization')
    expect(w.find('input[type="password"]').exists()).toBe(false)
    expect(w.html()).not.toContain(PASSWORD)
    expect(w.html()).not.toContain(TOKEN)
  })

  it('saves a login form with PUT, then drops every typed secret from the page', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const calls = stubFetch(c => (c.m === 'PUT' ? { body: savedAuth({ type: 'form', header_names: [] }) } : {}))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    await w.find('[role="radio"][value="form"]').trigger('click')
    await flushPromises()
    await w.find('#auth-username').setValue('tester')
    await w.find('#auth-password').setValue(PASSWORD)
    await w.find('form').trigger('submit')
    await flushPromises()
    const put = calls.find(c => c.m === 'PUT')!
    expect(put.u).toBe('/api/v1/codebases/3/dast-auth')
    expect(put.b).toMatchObject({ type: 'form', login: { url: 'https://admin.example.com/login', username: 'tester', password: PASSWORD, method: 'POST', body_format: 'form' } })
    expect(w.emitted('saved')).toBeTruthy()
    // after saving: the saved view, no input, and the password is nowhere in the DOM
    expect(w.find('[data-testid="credential-saved"]').exists()).toBe(true)
    expect(w.find('input[type="password"]').exists()).toBe(false)
    expect(w.html()).not.toContain(PASSWORD)
    vi.unstubAllGlobals()
  })

  it('token in login response: the section explains the JS-app case and saves the token settings', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const calls = stubFetch(c => (c.m === 'PUT' ? { body: savedAuth({ type: 'form', header_names: [] }) } : {}))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    await w.find('[role="radio"][value="form"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="auth-token-help"]').text()).toContain('browser DevTools → Network')
    expect(w.find('[data-testid="auth-token-help"]').text()).toContain('data.access_token')
    expect(w.find('[data-testid="auth-token-path"]').exists()).toBe(false)
    await w.find('[data-testid="auth-token-toggle"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="auth-token-example"]').text()).toContain('Authorization: Bearer')
    await w.find('#auth-username').setValue('tester')
    await w.find('#auth-password').setValue(PASSWORD)
    // an empty path is rejected on the field, without calling the server
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls).toHaveLength(0)
    expect(w.text()).toContain('Path is required')
    await w.find('[data-testid="auth-token-path"]').setValue('data.access_token')
    await w.find('[data-testid="auth-json-exists"]').setValue('data.access_token')
    await w.find('form').trigger('submit')
    await flushPromises()
    const put = calls.find(c => c.m === 'PUT')!
    expect(put.b).toMatchObject({ login: { token: { from: 'json', path: 'data.access_token', send_as: 'header', header_name: 'Authorization', prefix: 'Bearer ' }, success: { json_path_exists: 'data.access_token' } } })
    vi.unstubAllGlobals()
  })

  it('maps a server error on login.token.path to the token field', async () => {
    setUser({ role: 'member', can_run_dast: true })
    stubFetch(() => ({ status: 422, body: { error: { code: 'validation_failed', message: 'x', details: { field: 'login.token.path', fields: [{ field: 'login.token.path', message: 'login.token.path must be a dotted JSON path such as data.access_token or items[0].token (at most 200 characters).' }] } } } }))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    await w.find('[role="radio"][value="form"]').trigger('click')
    await flushPromises()
    await w.find('[data-testid="auth-token-toggle"]').trigger('click')
    await flushPromises()
    await w.find('#auth-username').setValue('tester')
    await w.find('#auth-password').setValue(PASSWORD)
    await w.find('[data-testid="auth-token-path"]').setValue('data.access_token')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('must be a dotted JSON path')
    vi.unstubAllGlobals()
  })

  it('blocks a login URL on another origin without calling the server', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => ({}))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    await w.find('[role="radio"][value="form"]').trigger('click')
    await flushPromises()
    await w.find('#auth-login-url').setValue('https://evil.example.net/login')
    await w.find('#auth-username').setValue('tester')
    await w.find('#auth-password').setValue(PASSWORD)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls).toHaveLength(0)
    expect(w.text()).toContain('same origin as the base URL')
    vi.unstubAllGlobals()
  })

  it('shows a friendly server error and keeps the form (secret key missing)', async () => {
    setUser({ role: 'admin' })
    stubFetch(() => ({ status: 503, body: { error: { code: 'secret_key_required', message: 'x' } } }))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb() } })
    await w.find('[role="radio"][value="form"]').trigger('click')
    await flushPromises()
    await w.find('#auth-username').setValue('tester')
    await w.find('#auth-password').setValue(PASSWORD)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-testid="auth-error"]').text()).toContain('SDRSCAN_SECRET_KEY')
    expect(w.find('[data-testid="auth-form"]').exists()).toBe(true)
    vi.unstubAllGlobals()
  })

  it('Replace opens the form with empty secret inputs and a "keep" hint', async () => {
    setUser({ role: 'admin' })
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb({ dast_auth: savedAuth() }) } })
    await w.find('[data-testid="replace-auth"]').trigger('click')
    await flushPromises()
    const pw = w.find<HTMLInputElement>('#auth-password')
    expect(pw.element.value).toBe('')
    expect(pw.attributes('placeholder')).toContain('leave blank to keep')
    expect((w.find('#auth-username').element as HTMLInputElement).value).toBe('tester')
    expect(w.text()).toContain('Leave a password, header value or cookie value empty to keep the saved one')
    expect(w.html()).not.toContain(PASSWORD)
  })

  it('Test login calls the test endpoint and shows success or failure with the message', async () => {
    setUser({ role: 'admin' })
    let reply: { ok: boolean, message: string } = { ok: true, message: 'Login succeeded: HTTP 302 -> /app.' }
    const calls = stubFetch(() => ({ body: reply }))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb({ dast_auth: savedAuth() }) } })
    await w.find('[data-testid="test-login"]').trigger('click')
    await flushPromises()
    expect(calls[0]).toMatchObject({ m: 'POST', u: '/api/v1/codebases/3/dast-auth/test' })
    expect(w.find('[data-testid="login-check-result"]').text()).toContain('Login succeeded')
    reply = { ok: false, message: 'Login failed: HTTP 401.' }
    await w.find('[data-testid="test-login"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="login-check-result"]').text()).toContain('Login failed')
    expect(w.find('[data-testid="login-check-result"]').text()).toContain('HTTP 401')
    vi.unstubAllGlobals()
  })

  it('Test login is disabled until the target is confirmed, and absent for header-only auth', async () => {
    setUser({ role: 'admin' })
    const pending = await mountSuspended(DastAuthSettings, { props: { codebase: cb({ dast_auth: savedAuth(), dast: { status: 'pending_confirmation', registered_by: null, confirmed_by: null, confirmed_at: null } }) } })
    expect(pending.find('[data-testid="test-login"]').attributes('disabled')).toBeDefined()
    expect(pending.find('[data-testid="test-hint"]').text()).toContain('An Admin must confirm authorization')
    const hdr = await mountSuspended(DastAuthSettings, { props: { codebase: cb({ dast_auth: savedAuth({ type: 'header', login_url: null, username: null }) }) } })
    expect(hdr.find('[data-testid="test-login"]').exists()).toBe(false)
    expect(hdr.find('[data-testid="no-login-test"]').exists()).toBe(true)
  })

  it('Remove asks for confirmation, then calls DELETE and shows the empty form', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(c => (c.m === 'DELETE' ? { status: 204 } : {}))
    const w = await mountSuspended(DastAuthSettings, { props: { codebase: cb({ dast_auth: savedAuth() }) } })
    await w.find('[data-testid="remove-auth"]').trigger('click')
    await flushPromises()
    expect(calls).toHaveLength(0)
    document.body.querySelector<HTMLButtonElement>('[data-testid="confirm-remove-auth"]')!.click()
    await flushPromises()
    expect(calls[0]).toMatchObject({ m: 'DELETE', u: '/api/v1/codebases/3/dast-auth' })
    expect(w.emitted('saved')?.[0]).toEqual([null])
    expect(w.find('[data-testid="auth-form"]').exists()).toBe(true)
    w.unmount()
    vi.unstubAllGlobals()
  })
})

describe('DastCrawlSettings', () => {
  it('shows the defaults, the built-in exclusion note and the JavaScript limitation', async () => {
    setUser({ role: 'admin' })
    const w = await mountSuspended(DastCrawlSettings, { props: { codebase: cb() } })
    expect((w.find('#crawl-depth').element as HTMLInputElement).value).toBe('3')
    expect((w.find('#crawl-pages').element as HTMLInputElement).value).toBe('50')
    expect(w.text()).toContain('logout, delete')
    expect(w.text()).toMatch(/JavaScript/)
    // Save is never disabled silently: pressing it without a change says so.
    expect(w.find('[data-testid="save-crawl"]').attributes('disabled')).toBeUndefined()
  })

  it('saves with PATCH (enabled, depth, pages, exclusions)', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const calls = stubFetch(() => ({ body: {} }))
    const w = await mountSuspended(DastCrawlSettings, { props: { codebase: cb() } })
    await w.find('[data-testid="crawl-enabled"]').trigger('click')
    await flushPromises()
    await w.find('#crawl-depth').setValue('5')
    await w.find('#crawl-pages').setValue('120')
    await w.find('[data-testid="crawl-exclude-add"]').trigger('click')
    await flushPromises()
    await w.find('[data-testid="crawl-exclude"] input').setValue('^/admin')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls[0]).toMatchObject({ m: 'PATCH', u: '/api/v1/codebases/3', b: { dast_crawl_enabled: true, dast_crawl_max_depth: 5, dast_crawl_max_pages: 120, dast_crawl_exclude: ['^/admin'] } })
    expect(w.emitted('saved')).toBeTruthy()
    vi.unstubAllGlobals()
  })

  it('blocks out-of-range numbers and invalid regular expressions before calling the server', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => ({}))
    const w = await mountSuspended(DastCrawlSettings, { props: { codebase: cb({ dast_crawl: { enabled: true, max_depth: 3, max_pages: 50, exclude: [] } }) } })
    await w.find('#crawl-depth').setValue('11')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('whole number from 1 to 10')
    await w.find('#crawl-depth').setValue('3')
    await w.find('#crawl-pages').setValue('501')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('whole number from 1 to 500')
    await w.find('#crawl-pages').setValue('50')
    await w.find('[data-testid="crawl-exclude-add"]').trigger('click')
    await flushPromises()
    await w.find('[data-testid="crawl-exclude"] input').setValue('(unclosed')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(calls).toHaveLength(0)
    expect(w.text()).toContain('not a valid regular expression')
    vi.unstubAllGlobals()
  })
})
