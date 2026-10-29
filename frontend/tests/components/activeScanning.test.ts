import { afterEach, describe, expect, it, vi } from 'vitest'
import { mountSuspended, mockNuxtImport } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import ActiveScanningSettings from '~/components/ActiveScanningSettings.vue'
import RunScanButton from '~/components/RunScanButton.vue'
import { useAuth } from '~/stores/auth'
import type { Codebase, User } from '~/types/api'

mockNuxtImport('navigateTo', () => vi.fn())

// Dialog content is teleported to document.body: every mount that opens one is tracked and unmounted,
// and the body is cleared, so one test's leftover DOM never leaks into the next.
const mounted: VueWrapper[] = []
const mount = async (...args: Parameters<typeof mountSuspended>) => {
  const w = await mountSuspended(args[0], args[1] as never)
  mounted.push(w as never)
  return w as VueWrapper
}
afterEach(() => {
  for (const w of mounted.splice(0)) w.unmount()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})

const setUser = (u: Partial<User>) => {
  const auth = useAuth()
  auth.user = { id: 1, username: 'admin', role: 'member', can_run_dast: false, ...u } as User
  auth.loaded = true
}

const cb = (over: Partial<Codebase> = {}): Codebase => ({
  id: 3, project: { id: 1, name: 'Online Shop' }, name: 'admin-portal', target_type: 'url', language: '', repo_url: null, branch: null, subdirectory: null, git_auth_kind: null, git_username: null,
  has_credential: null, base_url: 'https://admin.example.com', dast_max_rps: 5, dast: { status: 'confirmed', registered_by: null, confirmed_by: null, confirmed_at: null },
  dast_active: { authorized: false, authorized_at: null, authorized_by: null, openapi_spec_url: null },
  confirmation_statement: null, summary: null, latest_scan: null, base_scan: null, state: null, active_scan: null, schedule: null,
  created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z',
  dast_auth: { type: 'none', has_secret: false, login_url: null, method: null, body_format: null, username_field: null, password_field: null, username: null,
    extra_field_names: [], csrf: null, success: null, header_names: [], cookie_names: [], updated_at: null, updated_by: null },
  dast_crawl: { enabled: false, max_depth: 3, max_pages: 50, exclude: [] }, ...over,
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

describe('ActiveScanningSettings: visibility', () => {
  it('is not rendered for a Member without DAST access', async () => {
    setUser({ role: 'member', can_run_dast: false })
    const w = await mount(ActiveScanningSettings, { props: { codebase: cb() } })
    expect(w.find('[data-testid="active-scanning"]').exists()).toBe(false)
  })

  it('is rendered for a Member with can_run_dast and for an Admin', async () => {
    setUser({ role: 'member', can_run_dast: true })
    const w = await mount(ActiveScanningSettings, { props: { codebase: cb() } })
    expect(w.find('[data-testid="active-scanning"]').exists()).toBe(true)
    expect(w.text()).toContain('SQL injection')
    expect(w.text()).toContain('OpenAPI/Swagger')
    setUser({ role: 'admin' })
    const a = await mount(ActiveScanningSettings, { props: { codebase: cb() } })
    expect(a.find('[data-testid="active-scanning"]').exists()).toBe(true)
  })
})

describe('ActiveScanningSettings: authorize dialog', () => {
  it('not authorized: shows the Authorize button; wrong name is rejected; the exact name submits the right body', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(({ u }) => {
      if (u.includes('/authorize-active-scanning')) return { status: 200, body: cb({ dast_active: { authorized: true, authorized_at: '2026-10-28T08:00:00Z', authorized_by: { id: 1, username: 'admin' }, openapi_spec_url: null } }) }
      return { status: 200, body: {} }
    })
    const w = await mount(ActiveScanningSettings, { props: { codebase: cb() }, attachTo: document.body })
    expect(w.find('[data-testid="authorize-active-scanning"]').exists()).toBe(true)
    await w.find('[data-testid="authorize-active-scanning"]').trigger('click')
    await flushPromises()

    const submit = () => document.body.querySelector<HTMLButtonElement>('[data-testid="authorize-active-submit"]')!
    const checkbox = document.body.querySelector<HTMLButtonElement>('[data-testid="active-statement"]')!
    const nameInput = document.body.querySelector<HTMLInputElement>('[data-testid="active-confirm-name"]')!

    // Nothing accepted / typed yet: refused client-side, no request sent.
    submit().click()
    await flushPromises()
    expect(calls.some(c => c.u.includes('/authorize-active-scanning'))).toBe(false)
    expect(document.body.textContent).toContain('Check the box')

    checkbox.click()
    nameInput.value = 'wrong-name'
    nameInput.dispatchEvent(new Event('input'))
    await flushPromises()
    submit().click()
    await flushPromises()
    expect(calls.some(c => c.u.includes('/authorize-active-scanning'))).toBe(false)
    expect(document.body.textContent).toContain('does not match')

    nameInput.value = 'admin-portal'
    nameInput.dispatchEvent(new Event('input'))
    await flushPromises()
    submit().click()
    await flushPromises()
    const call = calls.find(c => c.u.includes('/authorize-active-scanning'))
    expect(call?.m).toBe('POST')
    expect(call?.b).toEqual({ statement_accepted: true, codebase_name: 'admin-portal' })
    expect(w.emitted('saved')).toBeTruthy()
  })

  it('authorized: shows who/when and a Revoke button that sends DELETE', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => ({ status: 204 }))
    const authorizedCb = cb({ dast_active: { authorized: true, authorized_at: '2026-10-28T08:00:00Z', authorized_by: { id: 1, username: 'admin' }, openapi_spec_url: null } })
    const w = await mount(ActiveScanningSettings, { props: { codebase: authorizedCb } })
    expect(w.find('[data-testid="active-scanning-status"]').text()).toContain('Active scanning authorized')
    expect(w.text()).toContain('admin')
    await w.find('[data-testid="revoke-active-scanning"]').trigger('click')
    await flushPromises()
    const call = calls.find(c => c.u.includes('/authorize-active-scanning'))
    expect(call?.m).toBe('DELETE')
    expect(w.emitted('saved')).toBeTruthy()
  })

  it('saves the OpenAPI/Swagger spec URL via PATCH, same-origin only', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(({ u }) => ({ status: 200, body: u.endsWith('/codebases/3') ? cb() : {} }))
    const w = await mount(ActiveScanningSettings, { props: { codebase: cb() }, attachTo: document.body })
    const input = document.body.querySelector<HTMLInputElement>('#openapi-spec-url')!
    input.value = 'https://evil.example.com/spec.json'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    await w.find('[data-testid="openapi-spec-form"]').trigger('submit')
    await flushPromises()
    expect(calls.some(c => c.m === 'PATCH')).toBe(false)
    expect(document.body.textContent).toContain('same origin')

    input.value = 'https://admin.example.com/openapi.json'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    await w.find('[data-testid="openapi-spec-form"]').trigger('submit')
    await flushPromises()
    const call = calls.find(c => c.m === 'PATCH')
    expect(call?.b).toEqual({ dast_openapi_spec_url: 'https://admin.example.com/openapi.json' })
  })
})

describe('RunScanButton / RunDastScanDialog for a DAST target', () => {
  it('hides the active toggle and links to settings when active scanning is not authorized', async () => {
    setUser({ role: 'admin' })
    const w = await mount(RunScanButton, {
      props: { codebase: { id: 3, name: 'admin-portal', target_type: 'url', dast: { status: 'confirmed' }, dast_active: { authorized: false, authorized_at: null, authorized_by: null, openapi_spec_url: null } } },
      attachTo: document.body,
    })
    await w.find('[data-testid="run-scan"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="active-scan-toggle"]')).toBeFalsy()
    expect(document.body.textContent).toContain('Authorize active scanning first.')
    expect(document.body.querySelector('a[href$="/codebases/3/settings#active-scanning"]')).toBeTruthy()
  })

  it('offers active scanning once authorized, with a timing sub-toggle and a confirmation summary, and submits the right flags', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(({ u }) => (u.endsWith('/scans') ? { status: 202, body: { id: 99 } } : { status: 200, body: {} }))
    const w = await mount(RunScanButton, {
      props: { codebase: { id: 3, name: 'admin-portal', target_type: 'url', dast: { status: 'confirmed' }, dast_active: { authorized: true, authorized_at: 'x', authorized_by: null, openapi_spec_url: null } } },
      attachTo: document.body,
    })
    await w.find('[data-testid="run-scan"]').trigger('click')
    await flushPromises()
    const toggle = () => document.body.querySelector<HTMLButtonElement>('[data-testid="active-scan-toggle"]')!
    expect(toggle()).toBeTruthy()
    expect(document.body.querySelector('[data-testid="active-scan-summary"]')).toBeFalsy()

    toggle().click()
    await flushPromises()
    expect(document.body.textContent).toContain('This will send SQL injection, XSS, and other test payloads to this target.')
    const timing = document.body.querySelector<HTMLButtonElement>('[data-testid="active-scan-timing-toggle"]')!
    expect(timing).toBeTruthy()
    timing.click()
    await flushPromises()

    document.body.querySelector<HTMLButtonElement>('[data-testid="confirm-run-scan"]')!.click()
    await flushPromises()
    const call = calls.find(c => c.u.endsWith('/scans'))
    expect(call?.b).toEqual({ codebase_id: 3, active: true, active_timing: true })
  })

  it('a passive run (toggle left off) sends no active flags', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(({ u }) => (u.endsWith('/scans') ? { status: 202, body: { id: 99 } } : { status: 200, body: {} }))
    const w = await mount(RunScanButton, {
      props: { codebase: { id: 3, name: 'admin-portal', target_type: 'url', dast: { status: 'confirmed' }, dast_active: { authorized: true, authorized_at: 'x', authorized_by: null, openapi_spec_url: null } } },
      attachTo: document.body,
    })
    await w.find('[data-testid="run-scan"]').trigger('click')
    await flushPromises()
    document.body.querySelector<HTMLButtonElement>('[data-testid="confirm-run-scan"]')!.click()
    await flushPromises()
    const call = calls.find(c => c.u.endsWith('/scans'))
    expect(call?.b).toEqual({ codebase_id: 3 })
  })
})
