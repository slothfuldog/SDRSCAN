import { describe, expect, it } from 'vitest'
import {
  authFormFrom, authSummary, buildAuthBody, crawlFieldErrors, defaultLoginUrl, emptyLoginForm, isValidJsonPath, newRow, openapiSpecUrlIssue, parseStatuses, scanActiveInfo, scanAuthInfo, validateAuthForm,
  validateExcludePattern, validateLoginUrl,
} from '~/utils/dastAuth'
import type { AuthForm } from '~/utils/dastAuth'
import type { DastAuth } from '~/types/api'

const BASE = 'https://shop.example.com'

const saved = (over: Partial<DastAuth> = {}): DastAuth => ({
  type: 'form+header', has_secret: true, login_url: `${BASE}/login`, method: 'POST', body_format: 'json', username_field: 'user', password_field: 'password', username: 'tester',
  extra_field_names: ['otp'], csrf: { source: 'html_input', name: '_csrf', send_as: 'field', header_name: null },
  success: { statuses: [200, 302], cookie_set: 'sid', body_contains: null, body_not_contains: null, redirect_not_to: '/login' },
  header_names: ['Authorization'], cookie_names: ['sid'], updated_at: '2026-10-28T08:00:00Z', updated_by: { id: 1, username: 'admin' }, ...over,
})

const formFor = (type: AuthForm['type'], patch: (f: AuthForm) => void = () => {}): AuthForm => {
  const f = authFormFrom(null, BASE, type)
  f.login.username = 'tester'
  f.login.password = 'pw-123456'
  patch(f)
  return f
}

describe('login URL', () => {
  it('defaults to the base URL origin + /login and must stay on that origin', () => {
    expect(defaultLoginUrl('https://shop.example.com/app?x=1')).toBe('https://shop.example.com/login')
    expect(defaultLoginUrl('nope')).toBe('')
    expect(validateLoginUrl(`${BASE}/signin`, BASE)).toBeNull()
    expect(validateLoginUrl('https://shop.example.com:443/x', BASE)).toBeNull()
    expect(validateLoginUrl('https://evil.example.net/login', BASE)).toMatch(/same origin/)
    expect(validateLoginUrl('http://shop.example.com/login', BASE)).toMatch(/same origin/)
    expect(validateLoginUrl('https://shop.example.com:8443/login', BASE)).toMatch(/same origin/)
    expect(validateLoginUrl('https://u:p@shop.example.com/login', BASE)).toMatch(/credentials/)
    expect(validateLoginUrl('/login', BASE)).toMatch(/full URL/)
    expect(validateLoginUrl('', BASE)).toMatch(/required/)
    expect(validateLoginUrl('ftp://shop.example.com/login', BASE)).toMatch(/http/)
  })
})

describe('validateAuthForm', () => {
  it('accepts a complete login form and builds the PUT body with the password', () => {
    const f = formFor('form', (x) => {
      x.login.body_format = 'json'
      x.login.extra = [{ ...newRow('remember'), value: '1' }]
      x.login.csrf_enabled = true
      x.login.csrf_name = '_csrf'
      x.login.success_redirect_not_to = '/login'
    })
    expect(validateAuthForm(f, BASE, null)).toEqual({})
    const body = buildAuthBody(f)
    expect(body).toMatchObject({
      type: 'form',
      login: { url: `${BASE}/login`, method: 'POST', body_format: 'json', username_field: 'username', password_field: 'password', username: 'tester', password: 'pw-123456',
        extra_fields: { remember: '1' }, csrf: { source: 'html_input', name: '_csrf', send_as: 'field' }, success: { statuses: [200, 302], redirect_not_to: '/login' } },
    })
    expect(body.headers).toBeUndefined()
  })

  it('requires the login fields and a password (unless one is stored)', () => {
    const f = formFor('form', (x) => { x.login.password = ''; x.login.username = ''; x.login.password_field = x.login.username_field })
    const e = validateAuthForm(f, BASE, null)
    expect(Object.keys(e).sort()).toEqual(['login.password', 'login.password_field', 'login.username'])
    // with a stored login a blank password is fine (it keeps the saved one)
    const f2 = formFor('form', (x) => { x.login.password = '' })
    expect(validateAuthForm(f2, BASE, saved({ type: 'form' }))['login.password']).toBeUndefined()
    // ... but not when the stored credentials were header-only
    expect(validateAuthForm(f2, BASE, saved({ type: 'header' }))['login.password']).toMatch(/Password is required/)
    expect(validateAuthForm(formFor('form', (x) => { x.login.password = 'abc' }), BASE, null)['login.password']).toMatch(/4 to 1024/)
    expect(e['login.username']).toMatch(/required/)
    expect(e['login.password']).toMatch(/Password is required/)
  })

  it('blocks a login URL on another origin before anything is sent', () => {
    const f = formFor('form', (x) => { x.login.url = 'https://evil.example.net/login' })
    expect(validateAuthForm(f, BASE, null)['login.url']).toMatch(/same origin/)
  })

  it('checks headers: names, CR/LF, forbidden names, duplicates, counts, values (one error per row)', () => {
    const rowOf = (name: string, value: string, stored = false) => ({ ...newRow(name, stored), value })
    const hdr = (rows: ReturnType<typeof rowOf>[]) => formFor('header', (x) => { x.headers = rows })
    expect(validateAuthForm(hdr([rowOf('Authorization', 'Bearer abcdef')]), BASE, null)).toEqual({})
    expect(validateAuthForm(hdr([]), BASE, null).headers).toMatch(/at least one/)
    expect(validateAuthForm(hdr([rowOf('X-A', 'abcd\r\nX-Evil: 1')]), BASE, null)['headers.X-A']).toMatch(/line breaks/)
    expect(validateAuthForm(hdr([rowOf('X A', 'abcdef')]), BASE, null)['headers.X A']).toMatch(/Header names/)
    for (const bad of ['Host', 'cookie', 'Content-Length', 'Transfer-Encoding', 'Connection']) {
      expect(validateAuthForm(hdr([rowOf(bad, 'abcdef')]), BASE, null)[`headers.${bad}`]).toMatch(/cannot be set/)
    }
    expect(validateAuthForm(hdr([rowOf('X-A', 'abcdef'), rowOf('x-a', 'abcdef')]), BASE, null)['headers.x-a']).toMatch(/unique/)
    expect(validateAuthForm(hdr([rowOf('X-A', '')]), BASE, null)['headers.X-A']).toMatch(/Value is required/)
    expect(validateAuthForm(hdr([rowOf('X-A', '', true)]), BASE, saved())).toEqual({}) // stored value kept
    expect(validateAuthForm(hdr([rowOf('X-A', 'v'.repeat(4097))]), BASE, null)['headers.X-A']).toMatch(/4 KiB/)
    const eleven = Array.from({ length: 11 }, (_, i) => rowOf(`X-H${i}`, 'abcdef'))
    expect(validateAuthForm(hdr(eleven), BASE, null).headers).toMatch(/At most 10/)
  })

  it('reports every bad row at once, a blank row on its own field, and rows without a name by key', () => {
    const rowOf = (name: string, value: string) => ({ ...newRow(name), value })
    const f = formFor('header', (x) => { x.headers = [rowOf('Host', 'abcdef'), rowOf('X-Ok', 'abcdef'), rowOf('X-Empty', ''), rowOf('', ''), rowOf('', 'abcdef')]; x.cookies = [rowOf('sid', 'ab')] })
    const e = validateAuthForm(f, BASE, null)
    expect(Object.keys(e)).toEqual(expect.arrayContaining(['headers.Host', 'headers.X-Empty', `headers.#${f.headers[3]!.key}`, `headers.#${f.headers[4]!.key}`, 'cookies.sid']))
    expect(e['headers.X-Ok']).toBeUndefined()
    expect(e[`headers.#${f.headers[3]!.key}`]).toMatch(/or remove this row/)
    expect(e[`headers.#${f.headers[4]!.key}`]).toMatch(/name is required/)
  })

  it('checks cookies and the 16 KiB total', () => {
    const rowOf = (name: string, value: string) => ({ ...newRow(name), value })
    const c = (rows: ReturnType<typeof rowOf>[]) => formFor('header', (x) => { x.cookies = rows })
    expect(validateAuthForm(c([rowOf('sid', 'abcd1234')]), BASE, null)).toEqual({})
    expect(validateAuthForm(c([rowOf('sid', 'ab;cd1234')]), BASE, null)['cookies.sid']).toMatch(/spaces/)
    expect(validateAuthForm(c([rowOf('s id', 'abcd1234')]), BASE, null)['cookies.s id']).toMatch(/Cookie names/)
    const big = formFor('header', (x) => { x.headers = Array.from({ length: 5 }, (_, i) => ({ ...newRow(`X-B${i}`), value: 'v'.repeat(4096) })) })
    expect(validateAuthForm(big, BASE, null).total).toMatch(/16 KiB/)
  })

  it('checks CSRF and success settings', () => {
    const f = formFor('form', (x) => { x.login.csrf_enabled = true; x.login.csrf_send_as = 'header'; x.login.csrf_header_name = 'X Bad'; x.login.success_statuses = '200, 99' })
    const e = validateAuthForm(f, BASE, null)
    expect(e['login.csrf.name']).toBeDefined()
    expect(e['login.csrf.header_name']).toBeDefined()
    expect(e['login.success.statuses']).toBeDefined()
    expect(parseStatuses('200, 302 302')).toEqual([200, 302])
    expect(parseStatuses('abc')).toBeNull()
    expect(parseStatuses('')).toEqual([])
  })

  it('type none needs nothing; the body of a header type has no login', () => {
    expect(validateAuthForm(authFormFrom(null, BASE, 'none'), BASE, null)).toEqual({})
    const body = buildAuthBody(formFor('header', (x) => { x.headers = [{ ...newRow('X-Api-Key'), value: 'abcdef' }] }))
    expect(body).toEqual({ type: 'header', headers: { 'X-Api-Key': 'abcdef' } })
  })
})

describe('token in the login response', () => {
  it('is off by default and adds nothing to the body', () => {
    const f = formFor('form')
    expect(f.login.token_enabled).toBe(false)
    expect(validateAuthForm(f, BASE, null)).toEqual({})
    expect(buildAuthBody(f).login!.token).toBeUndefined()
  })

  it('builds the body for an Authorization header, a custom header, and a cookie', () => {
    const tok = (patch: (f: AuthForm) => void) => buildAuthBody(formFor('form', (x) => { x.login.body_format = 'json'; x.login.token_enabled = true; x.login.token_path = 'data.access_token'; patch(x) })).login!.token
    expect(tok(() => {})).toEqual({ from: 'json', path: 'data.access_token', send_as: 'header', header_name: 'Authorization', prefix: 'Bearer ' })
    expect(tok((x) => { x.login.token_prefix = '' })).toMatchObject({ header_name: 'Authorization', prefix: '' })
    expect(tok((x) => { x.login.token_from = 'header'; x.login.token_path = 'X-Auth'; x.login.token_send_mode = 'header'; x.login.token_header_name = ' X-Api-Token '; x.login.token_prefix = '' }))
      .toEqual({ from: 'header', path: 'X-Auth', send_as: 'header', header_name: 'X-Api-Token', prefix: '' })
    expect(tok((x) => { x.login.token_send_mode = 'cookie'; x.login.token_cookie_name = 'jwt' })).toEqual({ from: 'json', path: 'data.access_token', send_as: 'cookie', cookie_name: 'jwt' })
  })

  it('reports each failing token field with the API field path', () => {
    const errs = (patch: (f: AuthForm) => void) => validateAuthForm(formFor('form', (x) => { x.login.token_enabled = true; x.login.token_path = 'a.b'; patch(x) }), BASE, null)
    expect(errs(() => {})).toEqual({})
    expect(errs((x) => { x.login.token_path = '' })['login.token.path']).toMatch(/required/)
    expect(errs((x) => { x.login.token_path = 'a..b' })['login.token.path']).toMatch(/dotted JSON path/)
    expect(errs((x) => { x.login.token_from = 'header'; x.login.token_path = 'bad header' })['login.token.path']).toMatch(/header name/)
    expect(errs((x) => { x.login.token_send_mode = 'header'; x.login.token_header_name = '' })['login.token.header_name']).toMatch(/required/)
    expect(errs((x) => { x.login.token_send_mode = 'header'; x.login.token_header_name = 'Host' })['login.token.header_name']).toMatch(/cannot be used/)
    expect(errs((x) => { x.login.token_prefix = 'x'.repeat(33) })['login.token.prefix']).toMatch(/at most 32/)
    expect(errs((x) => { x.login.token_prefix = 'a\nb' })['login.token.prefix']).toBeDefined()
    expect(errs((x) => { x.login.token_send_mode = 'cookie'; x.login.token_cookie_name = '' })['login.token.cookie_name']).toMatch(/required/)
    // a stale prefix does not matter for a cookie
    expect(errs((x) => { x.login.token_send_mode = 'cookie'; x.login.token_cookie_name = 'jwt'; x.login.token_prefix = 'x'.repeat(40) })).toEqual({})
  })

  it('checks the JSON success indicators', () => {
    const errs = (patch: (f: AuthForm) => void) => validateAuthForm(formFor('form', patch), BASE, null)
    expect(errs((x) => { x.login.success_json_exists = 'data.id'; x.login.success_json_equals_path = 'status'; x.login.success_json_equals_value = 'ok' })).toEqual({})
    expect(errs((x) => { x.login.success_json_exists = 'a[' })['login.success.json_path_exists']).toBeDefined()
    expect(errs((x) => { x.login.success_json_equals_path = 'status' })['login.success.json_path_equals.value']).toMatch(/Enter the value/)
    expect(errs((x) => { x.login.success_json_equals_value = 'ok' })['login.success.json_path_equals.path']).toBeDefined()
    const body = buildAuthBody(formFor('form', (x) => { x.login.success_json_exists = 'data.id'; x.login.success_json_equals_path = 'status'; x.login.success_json_equals_value = 'ok' }))
    expect(body.login!.success).toMatchObject({ json_path_exists: 'data.id', json_path_equals: { path: 'status', value: 'ok' } })
  })

  it('validates paths like the engine', () => {
    for (const ok of ['data.access_token', 'items[0].token', '[0].token', 'a[1][2]', 'token']) expect(isValidJsonPath(ok), ok).toBe(true)
    for (const bad of ['', '.', 'a.', '.a', 'a..b', 'a[', 'a[]', 'a[x]', 'a[-1]', 'a]b', 'x.[0]', 'a[1]b', 'a'.repeat(201)]) expect(isValidJsonPath(bad), bad).toBe(false)
  })

  it('restores the settings from the saved description (no value exists to restore)', () => {
    const tk = { from: 'json' as const, path: 'data.access_token', send_as: 'header' as const, header_name: 'Authorization', prefix: 'Bearer ', cookie_name: null }
    const f = authFormFrom(saved({ type: 'form', header_names: [], cookie_names: [], token: tk, success: { statuses: [], cookie_set: null, body_contains: null, body_not_contains: null, redirect_not_to: null, json_path_exists: 'data.access_token', json_path_equals: { path: 'status', value: 'ok' } } }), BASE)
    expect(f.login).toMatchObject({ token_enabled: true, token_from: 'json', token_path: 'data.access_token', token_send_mode: 'authorization', token_prefix: 'Bearer ', success_json_exists: 'data.access_token', success_json_equals_path: 'status', success_json_equals_value: 'ok' })
    const g = authFormFrom(saved({ type: 'form', token: { ...tk, from: 'header', path: 'X-T', header_name: 'X-Api-Token', prefix: null } }), BASE)
    expect(g.login).toMatchObject({ token_send_mode: 'header', token_header_name: 'X-Api-Token', token_prefix: '' })
    const c = authFormFrom(saved({ type: 'form', token: { ...tk, send_as: 'cookie', header_name: null, prefix: null, cookie_name: 'jwt' } }), BASE)
    expect(c.login).toMatchObject({ token_send_mode: 'cookie', token_cookie_name: 'jwt' })
    expect(authSummary(saved({ type: 'form', header_names: [], cookie_names: [], token: tk }))).toContain('token: JSON data.access_token → header Authorization')
  })
})

describe('the form never receives secrets from the server', () => {
  it('restores names and settings but leaves every secret input empty and marks stored rows', () => {
    const f = authFormFrom(saved(), BASE)
    expect(f.type).toBe('form+header')
    expect(f.login).toMatchObject({ url: `${BASE}/login`, username: 'tester', password: '', body_format: 'json', csrf_enabled: true, csrf_name: '_csrf', success_statuses: '200, 302', success_redirect_not_to: '/login' })
    expect(f.login.extra.map(r => [r.name, r.value, r.stored])).toEqual([['otp', '', true]])
    expect(f.headers.map(r => [r.name, r.value, r.stored])).toEqual([['Authorization', '', true]])
    expect(f.cookies.map(r => [r.name, r.value, r.stored])).toEqual([['sid', '', true]])
    // blank values go to the server as "" (keep)
    expect(buildAuthBody(f).headers).toEqual({ Authorization: '' })
    expect(buildAuthBody(f).login!.password).toBe('')
    expect(JSON.stringify(f)).not.toMatch(/pw-|Bearer [A-Za-z0-9]/)
  })

  it('summarises the saved settings without values', () => {
    expect(authSummary(saved())).toBe(`POST ${BASE}/login as tester · headers: Authorization · cookies: sid`)
  })

  it('empty form uses sensible defaults', () => {
    const l = emptyLoginForm(BASE)
    expect(l).toMatchObject({ url: `${BASE}/login`, method: 'POST', body_format: 'form', success_statuses: '200, 302' })
  })
})

describe('crawl settings validation', () => {
  it('checks depth 1..10, pages 1..500 and the exclusion patterns', () => {
    const c = (o: Partial<{ max_depth: number | string, max_pages: number | string, exclude: string[] }> = {}) => crawlFieldErrors({ max_depth: 3, max_pages: 50, exclude: [], ...o })
    expect(c({ exclude: ['^/admin'] })).toEqual({})
    expect(c({ max_depth: 0 }).max_depth).toBeDefined()
    expect(c({ max_depth: 11 }).max_depth).toBeDefined()
    expect(c({ max_depth: 2.5 }).max_depth).toBeDefined()
    expect(c({ max_depth: '' }).max_depth).toBe('Max depth is required.')
    expect(c({ max_pages: 0 }).max_pages).toBeDefined()
    expect(c({ max_pages: 501 }).max_pages).toBeDefined()
    expect(c({ max_pages: 500 })).toEqual({})
    expect(c({ exclude: Array.from({ length: 21 }, () => 'a') }).exclude).toMatch(/At most 20/)
  })

  it('reports one error per bad pattern row, with its index', () => {
    const e = crawlFieldErrors({ max_depth: 3, max_pages: 50, exclude: ['^/ok', '(unclosed', '', '[a-'] })
    expect(Object.keys(e)).toEqual(['exclude[1]', 'exclude[2]', 'exclude[3]'])
    expect(e['exclude[1]']).toMatch(/Pattern 2: .*not a valid regular expression/)
    expect(e['exclude[2]']).toMatch(/Pattern 3: Enter a pattern/)
  })

  it('rejects patterns the server cannot compile', () => {
    expect(validateExcludePattern('\\.(pdf|zip)$')).toBeNull()
    expect(validateExcludePattern('a'.repeat(200))).toBeNull()
    expect(validateExcludePattern('a'.repeat(201))).toMatch(/200/)
    expect(validateExcludePattern('(?=x)')).toMatch(/Look-around/)
    expect(validateExcludePattern('(a)\\1')).toMatch(/back-references/)
    expect(validateExcludePattern('   ')).toMatch(/Enter a pattern/)
  })
})

describe('scan log', () => {
  it('detects an authenticated scan and the page count from the job log only', () => {
    expect(scanAuthInfo(['resolving https://x', 'running sdrscan-dast against https://x'])).toEqual({ authenticated: false, mode: null, pages: null })
    expect(scanAuthInfo(['authenticated scan (form+header)', 'crawl enabled (max depth 3, max pages 50, 0 excluded patterns)', 'scan summary: 12 pages scanned', 'done']))
      .toEqual({ authenticated: true, mode: 'form+header', pages: 12 })
    expect(scanAuthInfo(['scan summary: 1 page scanned']).pages).toBe(1)
    expect(scanAuthInfo(['a line mentioning authenticated scan (x) in the middle']).authenticated).toBe(false)
  })

  it('detects active scanning, its kind and the active-request count from the job log only', () => {
    expect(scanActiveInfo(['resolving https://x', 'running sdrscan-dast against https://x'])).toEqual({ active: false, kind: null, requests: null })
    expect(scanActiveInfo([
      'authenticated scan (form+header)',
      'active scanning authorized by admin on 2026-10-28, type: boolean/error-based/XSS/open-redirect/header-injection/time-based',
      'scan summary: 12 pages scanned',
      '7 active requests sent',
      'done',
    ])).toEqual({ active: true, kind: 'boolean/error-based/XSS/open-redirect/header-injection/time-based', requests: 7 })
    // The engine's own stderr summary line ("N permintaan aktif dikirim, M temuan aktif") is copied into
    // the job log verbatim; only the request count (not the finding count) must be picked up.
    expect(scanActiveInfo(['active scanning authorized by dewi on 2026-10-20, type: boolean/error-based/XSS/open-redirect/header-injection', '23 permintaan aktif dikirim, 4 temuan aktif']))
      .toEqual({ active: true, kind: 'boolean/error-based/XSS/open-redirect/header-injection', requests: 23 })
    expect(scanActiveInfo(['a line mentioning active scanning authorized by x on y, type: z in the middle']).active).toBe(false)
  })
})

describe('openapiSpecUrlIssue', () => {
  const BASE2 = 'https://admin.example.com'
  it('is optional, must be a valid http(s) URL without credentials, and same-origin as the base URL', () => {
    expect(openapiSpecUrlIssue('', BASE2)).toBeNull()
    expect(openapiSpecUrlIssue('   ', BASE2)).toBeNull()
    expect(openapiSpecUrlIssue(`${BASE2}/openapi.json`, BASE2)).toBeNull()
    expect(openapiSpecUrlIssue(`${BASE2}:443/v3/api-docs`, BASE2)).toBeNull()
    expect(openapiSpecUrlIssue('not-a-url', BASE2)).toMatch(/Enter a full URL/)
    expect(openapiSpecUrlIssue('ftp://admin.example.com/x', BASE2)).toMatch(/http:\/\/ or https:\/\//)
    expect(openapiSpecUrlIssue('https://user:pass@admin.example.com/x', BASE2)).toMatch(/credentials/)
    expect(openapiSpecUrlIssue('https://evil.example.com/openapi.json', BASE2)).toMatch(/same origin/)
  })
})
