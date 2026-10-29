// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { createSession } from '../helpers/mockClient'
import type { ApiError } from '~/utils/errors'

// The mock returns the validation errors of the real backend: details.field (the first failing field) and, when several
// fields fail in one request, details.fields (every one, in order). Single errors keep their specific code.

const fails = async (p: Promise<unknown>): Promise<ApiError> => {
  try { await p } catch (e) { return e as ApiError }
  throw new Error('expected the request to fail')
}
const fieldsOf = (e: ApiError) => ((e.details as { fields?: Array<{ field: string }> } | undefined)?.fields ?? []).map(f => f.field)
const fieldOf = (e: ApiError) => (e.details as { field?: string } | undefined)?.field

describe('mock backend: per-field validation errors', () => {
  it('login: missing username and password are reported together', async () => {
    const s = createSession()
    const e = await fails(s.api.auth.login('', ''))
    expect(e).toMatchObject({ status: 422, code: 'validation_failed', message: 'Username is required.' })
    expect(fieldOf(e)).toBe('username')
    expect(fieldsOf(e)).toEqual(['username', 'password'])
    expect(fieldOf(await fails(s.api.auth.login('admin', '')))).toBe('password')
  })

  it('change password: current and new password errors together, with specific messages', async () => {
    const s = createSession()
    await s.login('member')
    const e = await fails(s.api.auth.changePassword('wrong', 'short'))
    expect(fieldsOf(e)).toEqual(['current_password', 'new_password'])
    expect(e.message).toBe('Current password is incorrect.')
    expect((e.details as { fields: Array<{ message: string }> }).fields[1]!.message).toBe('Password must be at least 12 characters.')
    expect(fieldOf(await fails(s.api.auth.changePassword('', 'a-long-enough-password')))).toBe('current_password')
  })

  it('users: username, role and password together; a taken username is a 409 on the username', async () => {
    const s = createSession()
    await s.login('admin')
    const e = await fails(s.api.users.create({ username: 'a b', password: 'short', role: 'root' as never }))
    expect(fieldsOf(e)).toEqual(['username', 'role', 'password'])
    expect(fieldsOf(await fails(s.api.users.create({ username: '', password: '', role: 'member' })))).toEqual(['username', 'password'])
    const taken = await fails(s.api.users.create({ username: 'MEMBER', password: 'a-long-enough-password', role: 'member' }))
    expect(taken).toMatchObject({ status: 409, code: 'username_taken' })
    expect(fieldOf(taken)).toBe('username')
    const reset = await fails(s.api.users.resetPassword(2, 'short'))
    expect(fieldOf(reset)).toBe('new_password')
  })

  it('projects: name and description together; a taken name is a 409 on the name', async () => {
    const s = createSession()
    await s.login('admin')
    expect(fieldOf(await fails(s.api.projects.create({ name: '', description: '' })))).toBe('name')
    expect(fieldsOf(await fails(s.api.projects.create({ name: '', description: 'd'.repeat(1001) })))).toEqual(['name', 'description'])
    const taken = await fails(s.api.projects.create({ name: 'online shop', description: '' }))
    expect(taken).toMatchObject({ status: 409, code: 'name_taken' })
    expect(fieldOf(taken)).toBe('name')
  })

  it('codebases: every failing field of a create or update is listed', async () => {
    const s = createSession()
    await s.login('dastMember')
    const e = await fails(s.api.codebases.create(1, { name: '', target_type: 'repo', repo_url: 'ftp://x', branch: 'bad branch', subdirectory: '/abs', git_auth_kind: 'ssh_key' } as never))
    expect(fieldsOf(e)).toEqual(['name', 'repo_url', 'branch', 'subdirectory', 'git_secret'])
    const missing = await fails(s.api.codebases.create(1, { name: 'x', target_type: 'repo' } as never))
    expect(fieldOf(missing)).toBe('repo_url')
    expect(missing.message).toBe('repo_url is required.')
    expect(fieldOf(await fails(s.api.codebases.create(1, { name: 'x' } as never)))).toBe('target_type')
    const priv = await fails(s.api.codebases.create(1, { name: 'x', target_type: 'url', base_url: 'http://192.168.1.10/' }))
    expect(priv).toMatchObject({ status: 422, code: 'address_not_allowed' })
    expect(fieldOf(priv)).toBe('base_url')
    const upd = await fails(s.api.codebases.patch(3, { name: '', base_url: 'ftp://x', dast_max_rps: 500 } as never))
    expect(fieldsOf(upd)).toEqual(['name', 'base_url', 'dast_max_rps'])
    const taken = await fails(s.api.codebases.patch(3, { name: 'storefront', project_id: 1 }))
    expect(taken).toMatchObject({ status: 409, code: 'name_taken' })
    expect(fieldOf(taken)).toBe('name')
  })

  it('crawl settings: numbers and each bad pattern row (dast_crawl_exclude[i])', async () => {
    const s = createSession()
    await s.login('dastMember')
    const e = await fails(s.api.codebases.patch(3, { dast_crawl_max_depth: 0, dast_crawl_max_pages: 9999, dast_crawl_exclude: ['^/ok', '(', ''] } as never))
    expect(fieldsOf(e)).toEqual(['dast_crawl_max_depth', 'dast_crawl_max_pages', 'dast_crawl_exclude[1]', 'dast_crawl_exclude[2]'])
    const one = await fails(s.api.codebases.patch(3, { dast_crawl_exclude: ['[a-'] } as never))
    expect(fieldOf(one)).toBe('dast_crawl_exclude[0]')
    expect(fieldsOf(one)).toEqual([])
  })

  it('dast-auth: nested paths for the login form, headers and cookies, all failing fields at once', async () => {
    const s = createSession()
    await s.login('dastMember')
    const e = await fails(s.api.dastAuth.put(3, {
      type: 'form+header',
      login: { url: 'https://other.example.net/login', method: 'GET', username_field: '', password_field: 'p', username: '', password: '', success: { statuses: [200, 700] } },
      headers: { Host: 'evil', 'X-Short': 'ab', Authorization: 'Bearer abcdef' }, cookies: { sid: '' },
    } as never))
    expect(fieldOf(e)).toBe('login.url')
    expect(fieldsOf(e)).toEqual(['login.url', 'login.method', 'login.username_field', 'login.username', 'login.password', 'login.success.statuses[1]', 'headers.Host', 'headers.X-Short', 'cookies.sid'])
  })

  it('schedule: invalid and too frequent cron name the field "cron" and keep their codes', async () => {
    const s = createSession()
    await s.login('dastMember')
    const bad = await fails(s.api.schedules.put(3, 'garbage'))
    expect(bad).toMatchObject({ status: 422, code: 'invalid_cron' })
    expect(fieldOf(bad)).toBe('cron')
    const often = await fails(s.api.schedules.put(3, '* * * * *'))
    expect(often).toMatchObject({ status: 422, code: 'schedule_too_frequent' })
    expect(fieldOf(often)).toBe('cron')
    expect(fieldOf(await fails(s.api.schedules.put(3, '')))).toBe('cron')
  })

  it('tokens, scans, vulndb, delete confirmation and authorization name their field', async () => {
    const s = createSession()
    await s.login('admin')
    expect(fieldsOf(await fails(s.api.tokens.create({ name: '', project_id: 9999 })))).toEqual(['name', 'project_id'])
    expect(fieldOf(await fails(s.client.post('/scans', {})))).toBe('codebase_id')
    const eco = await fails(s.api.system.vulndbUpdate({ ecosystems: ['x', 'npm', 'y'] }))
    expect(fieldsOf(eco)).toEqual(['ecosystems[0]', 'ecosystems[2]'])
    expect(fieldOf(await fails(s.client.del('/projects/1')))).toBe('confirm')
    expect(fieldOf(await fails(s.client.post('/codebases/3/confirm-authorization', { statement_accepted: false })))).toBe('statement_accepted')
  })
})
