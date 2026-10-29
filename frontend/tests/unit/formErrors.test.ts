// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { ApiError } from '~/utils/errors'
import { humanizeField, issueFromMessage, issuesFromDetails, mapServerError, resolveFieldName } from '~/utils/formErrors'

const err = (status: number, code: string, message: string, details?: unknown) => new ApiError({ status, code, message, details })

describe('issuesFromDetails', () => {
  it('reads a single field from details.field, with the error message', () => {
    expect(issuesFromDetails(err(422, 'validation_failed', 'name is required.', { field: 'name' }))).toEqual([{ field: 'name', message: 'name is required.' }])
  })

  it('keeps a specific error code of a single field error (invalid_cron, address_not_allowed, ...)', () => {
    expect(issuesFromDetails(err(422, 'invalid_cron', 'bad cron', { field: 'cron' }))).toEqual([{ field: 'cron', message: 'bad cron', code: 'invalid_cron' }])
  })

  it('reads the list in details.fields, with a message per field', () => {
    const e = err(422, 'validation_failed', 'name is required.', {
      field: 'name',
      fields: [{ field: 'name', message: 'name is required.' }, { field: 'repo_url', message: 'repo_url is required.' }, { field: 'dast_crawl_exclude[2]', message: 'Pattern 3 is empty.', code: 'x' }],
    })
    expect(issuesFromDetails(e)).toEqual([
      { field: 'name', message: 'name is required.' }, { field: 'repo_url', message: 'repo_url is required.' }, { field: 'dast_crawl_exclude[2]', message: 'Pattern 3 is empty.', code: 'x' },
    ])
  })

  it('ignores details without a usable field', () => {
    expect(issuesFromDetails(err(422, 'validation_failed', 'x'))).toEqual([])
    expect(issuesFromDetails(err(422, 'validation_failed', 'x', { allowed: ['a'] }))).toEqual([])
    expect(issuesFromDetails(err(422, 'validation_failed', 'x', { fields: [{ message: 'no field' }, 5, null] }))).toEqual([])
  })
})

describe('resolveFieldName', () => {
  it('uses the API name when there is no alias', () => {
    expect(resolveFieldName('repo_url')).toBe('repo_url')
    expect(resolveFieldName('login.password')).toBe('login.password')
  })

  it('applies exact aliases and path-prefix aliases (list elements keep their index)', () => {
    const aliases = { new_password: 'next', dast_crawl_exclude: 'exclude', dast_crawl_max_pages: 'max_pages' }
    expect(resolveFieldName('new_password', { aliases })).toBe('next')
    expect(resolveFieldName('dast_crawl_exclude[2]', { aliases })).toBe('exclude[2]')
    expect(resolveFieldName('dast_crawl_max_pages', { aliases })).toBe('max_pages')
    // a prefix must end at a path boundary
    expect(resolveFieldName('new_password_extra', { aliases })).toBe('new_password_extra')
  })

  it('falls back to the list field and to the parent path when the form has no field of that name', () => {
    const fields = ['ecosystems', 'headers', 'login.csrf.name']
    expect(resolveFieldName('ecosystems[1]', { fields })).toBe('ecosystems')
    expect(resolveFieldName('headers.Authorization', { fields })).toBe('headers')
    expect(resolveFieldName('headers.Authorization', { fields: [...fields, 'headers.Authorization'] })).toBe('headers.Authorization')
    expect(resolveFieldName('login.csrf.name', { fields })).toBe('login.csrf.name')
    expect(resolveFieldName('unknown.thing', { fields })).toBe('unknown.thing')
  })

  it('maps the token-login and success-check paths: exact field when the form has it, else the nearest parent', () => {
    const exact = ['login.token.path', 'login.token.header_name', 'login.token.prefix', 'login.token.cookie_name', 'login.success.json_path_exists', 'login.success.json_path_equals.path', 'login.success.json_path_equals.value']
    for (const f of exact) expect(resolveFieldName(f, { fields: exact })).toBe(f)
    // a form without a separate field for the pair falls back to the group, then to the login section
    expect(resolveFieldName('login.success.json_path_equals.value', { fields: ['login.success.json_path_equals'] })).toBe('login.success.json_path_equals')
    expect(resolveFieldName('login.token.send_as', { fields: ['login.token'] })).toBe('login.token')
    // a form that renamed its fields maps them with the alias table
    expect(resolveFieldName('login.token.cookie_name', { aliases: { 'login.token.cookie_name': 'login.token_cookie_name' }, fields: ['login.token_cookie_name'] })).toBe('login.token_cookie_name')
  })

  it('asks the form (has) as well as the field list', () => {
    expect(resolveFieldName('cookies.sid', { has: n => n === 'cookies' })).toBe('cookies')
  })
})

describe('mapServerError', () => {
  const fields = ['name', 'repo_url', 'branch', 'login.url', 'login.password', 'headers', 'headers.Authorization', 'exclude', 'exclude[2]', 'username', 'password']

  it('maps one field error', () => {
    const m = mapServerError(err(422, 'validation_failed', 'repo_url is required.', { field: 'repo_url' }), { fields })
    expect(m.source).toBe('details')
    expect(m.fields).toEqual([{ name: 'repo_url', message: 'repo_url is required.', apiField: 'repo_url' }])
    expect(m.unmapped).toEqual([])
  })

  it('maps several field errors at once, nested paths and list elements', () => {
    const e = err(422, 'validation_failed', 'login.url must be an absolute http(s) URL.', {
      field: 'login.url',
      fields: [
        { field: 'login.url', message: 'login.url must be an absolute http(s) URL.' },
        { field: 'login.password', message: 'login.password is required.' },
        { field: 'headers.Authorization', message: 'A header value must be at least 4 characters.' },
        { field: 'dast_crawl_exclude[2]', message: 'Pattern 3 is empty.' },
      ],
    })
    const m = mapServerError(e, { fields, aliases: { dast_crawl_exclude: 'exclude' } })
    expect(m.fields.map(f => f.name)).toEqual(['login.url', 'login.password', 'headers.Authorization', 'exclude[2]'])
    expect(m.fields[2]).toMatchObject({ apiField: 'headers.Authorization', message: 'A header value must be at least 4 characters.' })
  })

  it('puts messages of fields the form does not have in `unmapped`', () => {
    const m = mapServerError(err(422, 'validation_failed', 'schedule_cron is wrong.', { field: 'schedule_cron' }), { fields })
    expect(m.fields).toEqual([])
    expect(m.unmapped).toEqual(['schedule_cron is wrong.'])
  })

  it('handles 409 conflicts that name a field (name_taken, username_taken)', () => {
    const m = mapServerError(err(409, 'name_taken', 'Project name is already in use.', { field: 'name' }), { fields })
    expect(m.fields).toEqual([{ name: 'name', message: 'Project name is already in use.', apiField: 'name', code: 'name_taken' }])
  })

  it('without details it falls back to the start of the message ("<field> must ...", "<field> is required", "New password must ...")', () => {
    expect(mapServerError(err(422, 'validation_failed', 'repo_url is required.'), { fields }).fields[0]).toMatchObject({ name: 'repo_url' })
    expect(mapServerError(err(422, 'validation_failed', 'branch must match ^[A-Za-z0-9._/-]{1,200}$.'), { fields }).fields[0]).toMatchObject({ name: 'branch' })
    expect(mapServerError(err(422, 'validation_failed', 'Username must be 3 to 64 characters.'), { fields }).fields[0]).toMatchObject({ name: 'username' })
    expect(mapServerError(err(422, 'validation_failed', 'Password must be at least 12 characters.'), { fields }).fields[0]).toMatchObject({ name: 'password' })
    const aliased = mapServerError(err(422, 'validation_failed', 'New password must be different from the current password.'), { fields: ['next'], aliases: { new_password: 'next' } })
    expect(aliased.fields[0]).toMatchObject({ name: 'next' })
    expect(aliased.source).toBe('message')
    expect(mapServerError(err(422, 'validation_failed', 'login.password is required.'), { fields }).fields[0]).toMatchObject({ name: 'login.password' })
  })

  it('does not guess a field from messages that are not about one', () => {
    expect(mapServerError(err(422, 'validation_failed', 'The schedule is not a valid cron expression.'), { fields }).source).toBe('none')
    expect(mapServerError(err(422, 'validation_failed', 'Something odd happened'), { fields }).fields).toEqual([])
  })

  it('leaves other errors (401/403/404/5xx/network, non-API errors) to the form-level alert', () => {
    for (const status of [0, 401, 403, 404, 500, 503]) expect(mapServerError(err(status, 'x', 'name is required.', { field: 'name' }), { fields }).fields).toEqual([])
    expect(mapServerError(new Error('boom'), { fields }).source).toBe('none')
  })
})

describe('helpers', () => {
  it('guesses a field only from a known name', () => {
    expect(issueFromMessage('foo is required.', n => n === 'bar')).toBeNull()
    expect(issueFromMessage('current password is incorrect.', n => n === 'current_password')).toEqual({ field: 'current_password', message: 'current password is incorrect.' })
  })

  it('humanizes a field path for the summary', () => {
    expect(humanizeField('login.csrf_name')).toBe('Login csrf name')
    expect(humanizeField('exclude[2]')).toBe('Exclude')
  })
})
