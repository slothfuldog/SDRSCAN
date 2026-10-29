import { afterEach, describe, expect, it, vi } from 'vitest'
import { mountSuspended } from '@nuxt/test-utils/runtime'
import { flushPromises } from '@vue/test-utils'
import type { VueWrapper } from '@vue/test-utils'
import LoginPage from '~/pages/login.vue'
import AccountPage from '~/pages/account.vue'
import TokensPage from '~/pages/settings/tokens.vue'
import ProjectFormDialog from '~/components/ProjectFormDialog.vue'
import CodebaseForm from '~/components/CodebaseForm.vue'
import CreateUserDialog from '~/components/CreateUserDialog.vue'
import ResetPasswordDialog from '~/components/ResetPasswordDialog.vue'
import DastAuthSettings from '~/components/DastAuthSettings.vue'
import DastCrawlSettings from '~/components/DastCrawlSettings.vue'
import ConfirmAuthorizationDialog from '~/components/ConfirmAuthorizationDialog.vue'
import { useAuth } from '~/stores/auth'
import type { Codebase, DastAuth, User } from '~/types/api'

// Every main form shows its errors per field: all missing or wrong fields at once on submit (no request is sent),
// the first one gets focus, server errors with details.field / details.fields land on the field, and an edit clears the error.

const setUser = (u: Partial<User>) => {
  const auth = useAuth()
  auth.user = { id: 1, username: 'admin', role: 'admin', can_run_dast: true, ...u } as User
  auth.loaded = true
}

interface Call { m?: string, u: string, b?: unknown }
type Reply = { status?: number, body?: unknown }
function stubFetch(handler: (c: Call) => Reply | undefined) {
  const calls: Call[] = []
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    const call = { m: init?.method, u: url, b: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined }
    calls.push(call)
    const r = handler(call) ?? {}
    return new Response(r.status === 204 ? null : JSON.stringify(r.body ?? {}), { status: r.status ?? 200, headers: { 'Content-Type': 'application/json' } })
  })
  return calls
}
const fail = (status: number, code: string, message: string, details?: unknown): Reply => ({ status, body: { error: { code, message, details } } })
const multi = (fields: Array<[string, string]>) => fail(422, 'validation_failed', fields[0]![1], { field: fields[0]![0], fields: fields.map(([field, message]) => ({ field, message })) })

const none = (): DastAuth => ({ type: 'none', has_secret: false, login_url: null, method: null, body_format: null, username_field: null, password_field: null, username: null,
  extra_field_names: [], csrf: null, success: null, header_names: [], cookie_names: [], updated_at: null, updated_by: null })
const urlTarget = (over: Partial<Codebase> = {}): Codebase => ({
  id: 3, project: { id: 1, name: 'Online Shop' }, name: 'admin-portal', target_type: 'url', language: '', repo_url: null, branch: null, subdirectory: null, git_auth_kind: null, git_username: null,
  has_credential: null, base_url: 'https://admin.example.com', dast_max_rps: 5, dast: { status: 'confirmed', registered_by: null, confirmed_by: null, confirmed_at: null }, confirmation_statement: 'I am authorized.',
  summary: null, latest_scan: null, base_scan: null, state: null, active_scan: null, schedule: null, created_at: '2026-10-20T00:00:00Z', updated_at: '2026-10-20T00:00:00Z',
  dast_auth: none(), dast_crawl: { enabled: true, max_depth: 3, max_pages: 50, exclude: [] }, dast_active: null, ...over,
})

const body = () => document.body
const mounted: VueWrapper[] = []
const mount = async (...args: Parameters<typeof mountSuspended>) => {
  const w = await mountSuspended(args[0], { attachTo: document.body, ...(args[1] ?? {}) } as never)
  mounted.push(w as never)
  return w as VueWrapper
}
afterEach(() => {
  for (const w of mounted.splice(0)) w.unmount()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})
const text = (sel: string) => body().querySelector(sel)?.textContent ?? ''
const field = (name: string) => body().querySelector<HTMLElement>(`[data-field="${name}"]`)
const fieldText = (name: string) => field(name)?.textContent ?? ''
const type = async (selector: string, value: string) => {
  const el = body().querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!
  el.value = value
  el.dispatchEvent(new Event('input', { bubbles: true }))
  await flushPromises()
}
const submit = async (selector = 'form') => {
  body().querySelector<HTMLFormElement>(selector)!.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }))
  await flushPromises()
}
const focusedId = () => (document.activeElement as HTMLElement | null)?.id
const summary = () => text('[data-testid="form-errors"]')

describe('login', () => {
  it('shows Username and Password as required at once, focuses the first and sends nothing', async () => {
    const calls = stubFetch(() => ({}))
    await mount(LoginPage)
    await submit()
    expect(fieldText('username')).toContain('Username is required.')
    expect(fieldText('password')).toContain('Password is required.')
    expect(field('username')!.textContent).toContain('Username')
    expect(focusedId()).toBe('username')
    expect(summary()).toContain('Fix these 2 fields to continue')
    expect(calls).toHaveLength(0)
    // the submit button is never disabled silently
    expect(body().querySelector('button[type="submit"]')!.hasAttribute('disabled')).toBe(false)
    await type('#username', 'admin')
    expect(fieldText('username')).not.toContain('required')
    expect(fieldText('password')).toContain('Password is required.')
  })

  it('shows a wrong password in the form (not on a field) and keeps the form', async () => {
    stubFetch(() => fail(401, 'invalid_credentials', 'Invalid username or password.'))
    await mount(LoginPage)
    await type('#username', 'admin')
    await type('#password', 'nope')
    await submit()
    expect(text('[data-testid="login-error"]')).toBe('Invalid username or password.')
    expect(fieldText('username')).not.toContain('Invalid')
  })

  it('puts a 422 from the server on the field it names', async () => {
    stubFetch(() => fail(422, 'validation_failed', 'Password is required.', { field: 'password' }))
    await mount(LoginPage)
    await type('#username', 'admin')
    await type('#password', 'x')
    await submit()
    expect(fieldText('password')).toContain('Password is required.')
  })
})

describe('project dialog', () => {
  it('requires the name, and shows server errors for name and description together', async () => {
    const calls = stubFetch(() => multi([['name', 'name is required.'], ['description', 'description must be at most 1000 characters.']]))
    const w = await mount(ProjectFormDialog, { props: { open: true } })
    await flushPromises()
    await submit('#project-form')
    expect(fieldText('name')).toContain('Name is required.')
    expect(focusedId()).toBe('project-name')
    expect(calls).toHaveLength(0)
    await type('#project-name', 'Shop')
    await submit('#project-form')
    expect(calls).toHaveLength(1)
    expect(fieldText('name')).toContain('name is required.')
    expect(fieldText('description')).toContain('at most 1000')
    expect(summary()).toContain('Fix these 2 fields')
    // editing the name clears only its error
    await type('#project-name', 'Shop 2')
    expect(fieldText('name')).not.toContain('name is required.')
    expect(fieldText('description')).toContain('at most 1000')
    w.unmount()
  })

  it('shows a taken name under the name field', async () => {
    stubFetch(() => fail(409, 'name_taken', 'Project name is already in use.', { field: 'name' }))
    await mount(ProjectFormDialog, { props: { open: true } })
    await flushPromises()
    await type('#project-name', 'Online Shop')
    await submit('#project-form')
    expect(fieldText('name')).toContain('Project name is already in use.')
  })
})

describe('codebase form', () => {
  it('create (repository): name and repository URL are required together; server errors land on repo_url and branch', async () => {
    setUser({ role: 'member', can_run_dast: false })
    const calls = stubFetch(() => multi([['repo_url', 'Private network addresses are not allowed.'], ['branch', 'branch must match ^[A-Za-z0-9._/-]{1,200}$.']]))
    await mount(CodebaseForm, { props: { mode: 'create', projectId: 1 } })
    await submit('form')
    expect(fieldText('name')).toContain('Name is required.')
    expect(fieldText('repo_url')).toContain('Repository URL is required.')
    expect(focusedId()).toBe('cb-name')
    expect(calls).toHaveLength(0)
    await type('#cb-name', 'api')
    await type('#cb-repo', 'https://git.example.com/api.git')
    await submit('form')
    expect(calls).toHaveLength(1)
    expect(fieldText('repo_url')).toContain('Private network addresses are not allowed.')
    expect(fieldText('branch')).toContain('branch must match')
    expect(focusedId()).toBe('cb-repo')
  })

  it('edit (repository with a token): the username and the token are both reported when missing', async () => {
    setUser({ role: 'member', can_run_dast: false })
    const calls = stubFetch(() => ({}))
    const repo = urlTarget({ id: 1, target_type: 'repo', repo_url: 'https://git.example.com/api.git', branch: 'main', subdirectory: '', git_auth_kind: 'https_token', git_username: null, has_credential: false, base_url: null, dast: null })
    await mount(CodebaseForm, { props: { mode: 'edit', codebase: repo } })
    await submit('form')
    expect(fieldText('git_username')).toContain('Username is required for token authentication.')
    expect(fieldText('git_secret')).toContain('Access token is required')
    expect(focusedId()).toBe('cb-guser')
    expect(calls).toHaveLength(0)
    // every field of the form is marked required where it is
    expect(field('repo_url')!.querySelector('label')!.className).toContain("after:content-['*']")
    expect(field('branch')!.querySelector('label')!.className).not.toContain("after:content-['*']") // optional field
  })

  it('create (URL): the base URL is required and checked; every field shows its own message', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => ({}))
    const w = await mount(CodebaseForm, { props: { mode: 'create', projectId: 1 } })
    await w.find('[role="radio"][value="url"]').trigger('click')
    await flushPromises()
    await submit('form')
    expect(fieldText('name')).toContain('Name is required.')
    expect(fieldText('base_url')).toContain('Base URL is required.')
    await type('#cb-name', 'shop')
    await type('#cb-base', 'ftp://shop.example.com')
    await submit('form')
    expect(fieldText('base_url')).toContain('http:// and https://')
    expect(calls).toHaveLength(0)
  })

  it('edit: a taken name from the server (409) is shown under the name', async () => {
    setUser({ role: 'admin' })
    stubFetch(() => fail(409, 'name_taken', 'Codebase name is already in use.', { field: 'name' }))
    await mount(CodebaseForm, { props: { mode: 'edit', codebase: urlTarget() } })
    await type('#cb-name', 'taken')
    await submit('form')
    expect(fieldText('name')).toContain('Codebase name is already in use.')
  })

  it('shows a server error without details (older server) on the field named at the start of the message', async () => {
    setUser({ role: 'admin' })
    stubFetch(() => fail(422, 'validation_failed', 'base_url must use http or https.'))
    await mount(CodebaseForm, { props: { mode: 'edit', codebase: urlTarget() } })
    await type('#cb-base', 'https://other.example.com')
    await submit('form')
    expect(fieldText('base_url')).toContain('base_url must use http or https.')
  })

  it('a server failure that is not about input (500) shows in the form and marks no field', async () => {
    setUser({ role: 'admin' })
    stubFetch(() => fail(500, 'internal', 'Internal server error.'))
    await mount(CodebaseForm, { props: { mode: 'edit', codebase: urlTarget() } })
    await type('#cb-name', 'renamed')
    await submit('form')
    expect(text('[data-testid="form-error"]')).toContain('The server could not complete the request')
    expect(body().querySelectorAll('[aria-invalid="true"]')).toHaveLength(0)
  })
})

describe('authentication panel', () => {
  const open = async (over: Partial<Codebase> = {}) => {
    setUser({ role: 'admin' })
    const w = await mount(DastAuthSettings, { props: { codebase: urlTarget(over) } })
    return w
  }
  const choose = async (w: VueWrapper, value: string) => { await w.find(`[role="radio"][value="${value}"]`).trigger('click'); await flushPromises() }

  it('saving an empty login form shows every missing field at once and sends nothing', async () => {
    const calls = stubFetch(() => ({}))
    const w = await open()
    await choose(w, 'form')
    await submit('[data-testid="auth-form"]')
    for (const name of ['login.username', 'login.password']) expect(fieldText(name)).toContain('required')
    expect(fieldText('login.username')).toContain('Username is required')
    expect(fieldText('login.password')).toContain('Password is required')
    expect(focusedId()).toBe('auth-username')
    expect(summary()).toContain('Fix these 2 fields')
    expect(summary()).toContain('Username:')
    expect(calls).toHaveLength(0)
  })

  it('reports each bad header row on its own row, and clears a row when it is edited', async () => {
    const calls = stubFetch(() => ({}))
    const w = await open()
    await choose(w, 'header')
    await w.find('[data-testid="auth-headers-add"]').trigger('click')
    await w.find('[data-testid="auth-headers-add"]').trigger('click')
    await flushPromises()
    const rows = [...body().querySelectorAll<HTMLInputElement>('[data-testid="auth-headers"] input')]
    const set = async (el: HTMLInputElement, v: string) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); await flushPromises() }
    await set(rows[0]!, 'Host')
    await set(rows[1]!, 'abcdef')
    await set(rows[2]!, 'X-Empty')
    await submit('[data-testid="auth-form"]')
    expect(calls).toHaveLength(0)
    expect(fieldText('headers.Host')).toContain('cannot be set here')
    expect(fieldText('headers.X-Empty')).toContain('Value is required for X-Empty')
    expect(summary()).toContain('Header 1 “Host”')
    expect(summary()).toContain('Header 2 “X-Empty”')
    // rows are validated one by one: the other row has no error
    await set(rows[0]!, 'X-Api-Key')
    expect(fieldText('headers.Host')).toBe('')
    expect(fieldText('headers.X-Empty')).toContain('Value is required')
  })

  it('maps server errors on login.url, login.password and headers.<name> to the fields and rows', async () => {
    const calls = stubFetch(() => multi([
      ['login.url', 'login.url must have the same origin (scheme, host and port) as the target base URL.'],
      ['login.password', 'login.password is required.'],
      ['headers.Authorization', 'A header value must be at least 4 characters.'],
    ]))
    const w = await open()
    await choose(w, 'form+header')
    await type('#auth-username', 'tester')
    await type('#auth-password', 'secret-pw-1')
    await w.find('[data-testid="auth-headers-add"]').trigger('click')
    await flushPromises()
    const inputs = [...body().querySelectorAll<HTMLInputElement>('[data-testid="auth-headers"] input')]
    inputs[0]!.value = 'Authorization'; inputs[0]!.dispatchEvent(new Event('input', { bubbles: true }))
    inputs[1]!.value = 'Bearer abcdef'; inputs[1]!.dispatchEvent(new Event('input', { bubbles: true }))
    await flushPromises()
    await submit('[data-testid="auth-form"]')
    expect(calls.filter(c => c.m === 'PUT')).toHaveLength(1)
    expect(fieldText('login.url')).toContain('same origin')
    expect(fieldText('login.password')).toContain('login.password is required.')
    expect(fieldText('headers.Authorization')).toContain('at least 4 characters')
    expect(summary()).toContain('Fix these 3 fields')
    expect(JSON.stringify(calls)).toContain('secret-pw-1') // sent to the server, but never echoed in an error
    expect(summary()).not.toContain('secret-pw-1')
  })

  it('a 503 (no secret key) is shown in the form, not on a field', async () => {
    stubFetch(() => fail(503, 'secret_key_required', 'x'))
    const w = await open()
    await choose(w, 'form')
    await type('#auth-username', 'tester')
    await type('#auth-password', 'secret-pw-1')
    await submit('[data-testid="auth-form"]')
    expect(text('[data-testid="auth-error"]')).toContain('SDRSCAN_SECRET_KEY')
    expect(body().querySelectorAll('[aria-invalid="true"]')).toHaveLength(0)
  })
})

describe('crawling panel', () => {
  it('reports the numbers and every bad exclusion row on its own row', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => ({}))
    const w = await mount(DastCrawlSettings, { props: { codebase: urlTarget() } })
    await type('#crawl-depth', '11')
    await type('#crawl-pages', '')
    await w.find('[data-testid="crawl-exclude-add"]').trigger('click')
    await w.find('[data-testid="crawl-exclude-add"]').trigger('click')
    await w.find('[data-testid="crawl-exclude-add"]').trigger('click')
    await flushPromises()
    const rows = [...body().querySelectorAll<HTMLInputElement>('[data-testid="crawl-exclude"] input')]
    const set = async (el: HTMLInputElement, v: string) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); await flushPromises() }
    await set(rows[0]!, '^/ok')
    await set(rows[1]!, '(unclosed')
    await submit('[data-testid="crawl-form"]')
    expect(calls).toHaveLength(0)
    expect(fieldText('max_depth')).toContain('from 1 to 10')
    expect(fieldText('max_pages')).toContain('Max pages is required.')
    expect(fieldText('exclude[0]')).not.toContain('Pattern')
    expect(fieldText('exclude[1]')).toContain('not a valid regular expression')
    expect(fieldText('exclude[2]')).toContain('Enter a pattern')
    expect(summary()).toContain('Excluded path 2')
    expect(focusedId()).toBe('crawl-depth')
  })

  it('maps dast_crawl_exclude[i], dast_crawl_max_pages from the server to the form fields', async () => {
    setUser({ role: 'admin' })
    stubFetch(() => multi([['dast_crawl_max_pages', 'dast_crawl_max_pages must be a whole number between 1 and 500.'], ['dast_crawl_exclude[1]', 'Pattern 2 is not a valid regular expression: "^/b".']]))
    const w = await mount(DastCrawlSettings, { props: { codebase: urlTarget({ dast_crawl: { enabled: true, max_depth: 3, max_pages: 50, exclude: ['^/a', '^/b'] } }) } })
    await type('#crawl-pages', '60')
    await submit('[data-testid="crawl-form"]')
    expect(fieldText('max_pages')).toContain('between 1 and 500')
    expect(fieldText('exclude[1]')).toContain('Pattern 2 is not a valid regular expression')
    expect(fieldText('exclude[0]')).not.toContain('Pattern')
    w.unmount()
  })
})

describe('user dialogs', () => {
  it('create user: username, password and role problems are shown together; a taken username lands on the username', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => fail(409, 'username_taken', 'That username is already taken.', { field: 'username' }))
    await mount(CreateUserDialog, { props: { open: true } })
    await flushPromises()
    await submit('#create-user-form')
    expect(fieldText('username')).toContain('Username is required.')
    expect(fieldText('password')).toContain('Password is required.')
    expect(focusedId()).toBe('nu-name')
    expect(calls).toHaveLength(0)
    await type('#nu-name', 'bo')
    await type('#nu-pw', 'short')
    await submit('#create-user-form')
    expect(fieldText('username')).toContain('3 to 64 characters')
    expect(fieldText('password')).toContain('at least 12 characters')
    await type('#nu-name', 'newhire')
    await type('#nu-pw', 'a-long-enough-password')
    await submit('#create-user-form')
    expect(calls).toHaveLength(1)
    expect(fieldText('username')).toContain('That username is already taken.')
  })

  it('reset password: the temporary password is required and checked', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => fail(422, 'validation_failed', 'Password must be at least 12 characters.', { field: 'new_password' }))
    await mount(ResetPasswordDialog, { props: { open: true, user: { id: 5, username: 'bo', role: 'member', can_run_dast: false, is_active: true, last_login_at: null, must_change_password: false } } })
    await flushPromises()
    await submit('#reset-pw-form')
    expect(fieldText('new_password')).toContain('New password is required.')
    await type('#rp-pw', 'short')
    await submit('#reset-pw-form')
    expect(fieldText('new_password')).toContain('at least 12 characters')
    expect(calls).toHaveLength(0)
  })
})

describe('change password (Account)', () => {
  it('shows the three fields as required, mismatches and short passwords; a wrong current password comes back on its field', async () => {
    setUser({ role: 'member', username: 'member', can_run_dast: false })
    const calls = stubFetch(() => multi([['current_password', 'Current password is incorrect.'], ['new_password', 'Password must be at least 12 characters.']]))
    await mount(AccountPage)
    await submit('form')
    expect(fieldText('current_password')).toContain('Current password is required.')
    expect(fieldText('new_password')).toContain('New password is required.')
    expect(fieldText('confirm_password')).toContain('Confirm the new password.')
    expect(focusedId()).toBe('cur-pw')
    await type('#cur-pw', 'wrong')
    await type('#new-pw', 'short')
    await type('#conf-pw', 'different')
    await submit('form')
    expect(fieldText('new_password')).toContain('at least 12 characters')
    expect(fieldText('confirm_password')).toContain('do not match')
    expect(calls).toHaveLength(0)
    await type('#new-pw', 'a-long-enough-password')
    await type('#conf-pw', 'a-long-enough-password')
    await submit('form')
    expect(calls).toHaveLength(1)
    expect(fieldText('current_password')).toContain('Current password is incorrect.')
    expect(fieldText('new_password')).toContain('at least 12 characters')
    expect(summary()).toContain('Fix these 2 fields')
  })
})

describe('ingest token dialog', () => {
  it('requires a name; a server error for project_id lands on the project field', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch((c) => {
      if (c.m === 'POST') return fail(422, 'validation_failed', 'project_id does not exist.', { field: 'project_id' })
      return { body: { items: [], total: 0, page: 1, page_size: 200 } }
    })
    const w = await mount(TokensPage)
    await flushPromises()
    body().querySelector<HTMLButtonElement>('[data-testid="create-token"]')!.click()
    await flushPromises()
    await submit('#token-form')
    expect(fieldText('name')).toContain('name is required.')
    expect(focusedId()).toBe('tk-name')
    expect(calls.filter(c => c.m === 'POST')).toHaveLength(0)
    await type('#tk-name', 'ci')
    await submit('#token-form')
    expect(fieldText('project')).toContain('project_id does not exist.')
    w.unmount()
  })
})

describe('authorization dialog', () => {
  it('stays clickable without the checkbox and says what is missing', async () => {
    setUser({ role: 'admin' })
    const calls = stubFetch(() => ({}))
    await mount(ConfirmAuthorizationDialog, { props: { open: true, codebase: urlTarget({ dast: { status: 'pending_confirmation', registered_by: null, confirmed_by: null, confirmed_at: null } }) } })
    await flushPromises()
    await submit('#confirm-auth-form')
    expect(fieldText('accepted')).toContain('Accept the statement')
    expect(calls).toHaveLength(0)
  })
})
