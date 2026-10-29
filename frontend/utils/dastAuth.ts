import type { CsrfSendAs, CsrfSource, DastAuth, DastAuthBody, DastAuthType, DastCrawl, LoginBodyFormat, LoginMethod, TokenFrom } from '~/types/api'

// DAST authentication (login form, fixed headers / cookies) and crawl settings: the form model, the
// client-side checks and the request body. The checks only give early feedback; the server validates
// again and stays authoritative. Secrets (password, header/cookie values, extra-field values) live in
// the form state only until they are sent; the server never returns them. A blank secret in the
// request keeps the stored value of the same name.

export const AUTH_TYPE_ITEMS: Array<{ label: string, value: DastAuthType }> = [
  { label: 'None', value: 'none' },
  { label: 'Login form', value: 'form' },
  { label: 'Fixed header(s)', value: 'header' },
  { label: 'Login form + headers', value: 'form+header' },
]

export const AUTH_TYPE_LABEL: Record<DastAuthType, string> = {
  none: 'None',
  form: 'Login form',
  header: 'Fixed header(s)',
  'form+header': 'Login form + headers',
}

export const usesLogin = (t: DastAuthType): boolean => t === 'form' || t === 'form+header'
export const usesHeaders = (t: DastAuthType): boolean => t === 'header' || t === 'form+header'

export const MAX_HEADERS = 10
export const MAX_COOKIES = 10
export const MAX_EXTRA_FIELDS = 20
export const MAX_VALUE_BYTES = 4096
export const MAX_TOTAL_BYTES = 16 * 1024
export const MIN_SECRET_LENGTH = 4
export const MAX_CRAWL_DEPTH = 10
export const MAX_CRAWL_PAGES = 500
export const MAX_EXCLUDE_PATTERNS = 20
export const MAX_EXCLUDE_LENGTH = 200
export const DEFAULT_CRAWL: DastCrawl = { enabled: false, max_depth: 3, max_pages: 50, exclude: [] }

/** Paths the engine never visits while crawling, whatever you configure. */
/** What the engine can and cannot do; shown as help text next to the Authentication and Crawling panels. */
export const AUTH_LIMITS_NOTE = 'Supported: a username and password login form (POST, form or JSON body, optional CSRF token, and an optional token returned in the login response) and fixed headers or cookies. Not supported: OAuth or single sign-on, multi-factor authentication, and CAPTCHAs.'
export const CRAWL_LIMITS_NOTE = 'The crawl reads server-rendered HTML pages only. Single-page apps that build their pages with JavaScript are not explored.'
/** Help for the "Token in login response" section. */
export const TOKEN_HELP = 'If your app is a JavaScript app, use the API endpoint your browser calls when you sign in (browser DevTools → Network), not the /login page. If the API returns a token in the response body, set its path here, e.g. data.access_token.'
export const TOKEN_EXAMPLE = 'Example: for a response {"data":{"access_token":"…"}} use source "JSON body", path data.access_token, send as "Authorization header" with the prefix "Bearer ". Every request of the scan then carries Authorization: Bearer <token>.'
export const MAX_JSON_PATH = 200
export const MAX_TOKEN_PREFIX = 32

export type TokenSendMode = 'authorization' | 'header' | 'cookie'
export const TOKEN_FROM_ITEMS: Array<{ label: string, value: TokenFrom }> = [
  { label: 'JSON body', value: 'json' },
  { label: 'Response header', value: 'header' },
]
export const TOKEN_SEND_ITEMS: Array<{ label: string, value: TokenSendMode }> = [
  { label: 'Authorization header', value: 'authorization' },
  { label: 'Custom header', value: 'header' },
  { label: 'Cookie', value: 'cookie' },
]

/** Same syntax as the engine and the backend: dot-separated keys, each optionally followed by [n] indexes; a path may start with [n]. */
export function isValidJsonPath(p: string): boolean {
  if (!p || p.length > MAX_JSON_PATH) return false
  let n = 0
  const parts = p.split('.')
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!
    const b = part.indexOf('[')
    const name = b >= 0 ? part.slice(0, b) : part
    let rest = b >= 0 ? part.slice(b) : ''
    if (name.includes(']') || hasCtl(name)) return false
    if (!name) { if (i !== 0 || !rest) return false } else n++
    while (rest) {
      const m = /^\[(\d{1,6})\]/.exec(rest)
      if (!m) return false
      n++
      rest = rest.slice(m[0].length)
    }
  }
  return n > 0 && n <= 32
}

export const BUILT_IN_EXCLUSIONS_NOTE = 'The engine already skips risky paths such as logout, delete, remove, signout and similar. Add your own patterns on top.'

const FIELD_NAME_RE = /^[A-Za-z0-9_.:[\]-]{1,100}$/
const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$/
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'connection', 'cookie', 'upgrade', 'te', 'trailer', 'keep-alive', 'expect', 'proxy-authorization', 'proxy-connection', 'x-forwarded-host'])

export interface PairRow {
  /** Stable key for v-for. */
  key: number
  name: string
  /** Write-only: empty while a value is stored; typing replaces it. */
  value: string
  /** The name came from the server: a value is stored under it. */
  stored: boolean
}

export interface LoginForm {
  url: string
  method: LoginMethod
  body_format: LoginBodyFormat
  username_field: string
  password_field: string
  username: string
  password: string
  extra: PairRow[]
  csrf_enabled: boolean
  csrf_source: CsrfSource
  csrf_name: string
  csrf_send_as: CsrfSendAs
  csrf_header_name: string
  token_enabled: boolean
  token_from: TokenFrom
  token_path: string
  token_send_mode: TokenSendMode
  /** Request header name when the mode is a custom header. */
  token_header_name: string
  token_prefix: string
  token_cookie_name: string
  success_json_exists: string
  success_json_equals_path: string
  success_json_equals_value: string
  success_statuses: string
  success_cookie_set: string
  success_body_contains: string
  success_body_not_contains: string
  success_redirect_not_to: string
}

export interface AuthForm {
  type: DastAuthType
  login: LoginForm
  headers: PairRow[]
  cookies: PairRow[]
}

let rowKey = 0
export const newRow = (name = '', stored = false): PairRow => ({ key: ++rowKey, name, value: '', stored })

/** Default login URL: the base URL's origin plus /login. */
export function defaultLoginUrl(baseUrl: string | null | undefined): string {
  try {
    const u = new URL(baseUrl ?? '')
    return `${u.origin}/login`
  } catch {
    return ''
  }
}

export function emptyLoginForm(baseUrl: string | null | undefined): LoginForm {
  return {
    url: defaultLoginUrl(baseUrl), method: 'POST', body_format: 'form', username_field: 'username', password_field: 'password', username: '', password: '',
    extra: [], csrf_enabled: false, csrf_source: 'html_input', csrf_name: '', csrf_send_as: 'field', csrf_header_name: '',
    token_enabled: false, token_from: 'json', token_path: '', token_send_mode: 'authorization', token_header_name: '', token_prefix: 'Bearer ', token_cookie_name: '',
    success_json_exists: '', success_json_equals_path: '', success_json_equals_value: '',
    success_statuses: '200, 302', success_cookie_set: '', success_body_contains: '', success_body_not_contains: '', success_redirect_not_to: '',
  }
}

/** Form state from the stored (non-secret) description. Secret inputs start empty. */
export function authFormFrom(auth: DastAuth | null | undefined, baseUrl: string | null | undefined, wantedType?: DastAuthType): AuthForm {
  const login = emptyLoginForm(baseUrl)
  const type = wantedType ?? auth?.type ?? 'none'
  if (auth && auth.type !== 'none') {
    if (auth.login_url) login.url = auth.login_url
    if (auth.method) login.method = auth.method
    if (auth.body_format) login.body_format = auth.body_format
    if (auth.username_field) login.username_field = auth.username_field
    if (auth.password_field) login.password_field = auth.password_field
    login.username = auth.username ?? ''
    login.extra = auth.extra_field_names.map(n => newRow(n, true))
    if (auth.csrf) {
      login.csrf_enabled = true
      login.csrf_source = auth.csrf.source
      login.csrf_name = auth.csrf.name
      login.csrf_send_as = auth.csrf.send_as
      login.csrf_header_name = auth.csrf.header_name ?? ''
    }
    if (auth.token) {
      login.token_enabled = true
      login.token_from = auth.token.from
      login.token_path = auth.token.path
      login.token_send_mode = auth.token.send_as === 'cookie' ? 'cookie' : (!auth.token.header_name || auth.token.header_name.toLowerCase() === 'authorization' ? 'authorization' : 'header')
      login.token_header_name = login.token_send_mode === 'header' ? (auth.token.header_name ?? '') : ''
      login.token_prefix = auth.token.prefix ?? ''
      login.token_cookie_name = auth.token.cookie_name ?? ''
    }
    if (auth.success) {
      login.success_json_exists = auth.success.json_path_exists ?? ''
      if (auth.success.json_path_equals) {
        login.success_json_equals_path = auth.success.json_path_equals.path
        login.success_json_equals_value = String(auth.success.json_path_equals.value)
      }
      login.success_statuses = auth.success.statuses.join(', ')
      login.success_cookie_set = auth.success.cookie_set ?? ''
      login.success_body_contains = auth.success.body_contains ?? ''
      login.success_body_not_contains = auth.success.body_not_contains ?? ''
      login.success_redirect_not_to = auth.success.redirect_not_to ?? ''
    } else {
      login.success_statuses = ''
    }
  }
  return {
    type, login,
    headers: (auth?.header_names ?? []).map(n => newRow(n, true)),
    cookies: (auth?.cookie_names ?? []).map(n => newRow(n, true)),
  }
}

/** "200, 302" -> [200, 302]; null when something is not a status code. */
export function parseStatuses(text: string): number[] | null {
  const parts = text.split(/[\s,]+/).filter(Boolean)
  const out: number[] = []
  for (const p of parts) {
    if (!/^\d{3}$/.test(p)) return null
    const n = Number(p)
    if (n < 100 || n > 599) return null
    if (!out.includes(n)) out.push(n)
  }
  return out
}

export function originOf(url: string): string | null {
  try {
    const u = new URL(url.trim())
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    return u.origin.toLowerCase()
  } catch {
    return null
  }
}

export function validateLoginUrl(url: string, baseUrl: string | null | undefined): string | null {
  const v = url.trim()
  if (!v) return 'Login URL is required: enter the URL of the login form.'
  if (v.length > 2000 || /[\s\\]/.test(v)) return 'The login URL is not valid.'
  let u: URL
  try { u = new URL(v) } catch { return 'Enter a full URL such as https://shop.example.com/login.' }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'The login URL must start with http:// or https://.'
  if (u.username || u.password) return 'The login URL must not contain credentials.'
  if (u.hash) return 'The login URL must not contain a fragment.'
  const base = originOf(baseUrl ?? '')
  if (base && originOf(v) !== base) return `The login URL must be on the same origin as the base URL (${base}). Credentials are only sent to the target host.`
  return null
}

const hasCtl = (s: string, allowTab = false) => [...s].some((c) => { const n = c.charCodeAt(0); return (n < 0x20 && !(allowTab && n === 9)) || n === 0x7f })

export type AuthErrors = Record<string, string>

/** Name of the form field (and of the error) of one row of a pair list: "headers.Authorization", "cookies.sid", "login.extra_fields.tenant".
 *  A row without a name gets its key, so that it still has a field of its own. */
export const rowField = (prefix: string, r: PairRow): string => `${prefix}.${r.name.trim() || `#${r.key}`}`

/**
 * Early checks of the whole form; every failing field is reported at once. The keys are the API's field paths:
 * type, login.url, login.username_field, login.password_field, login.username, login.password, login.extra_fields (the list) and
 * login.extra_fields.<name> (one row), login.csrf.name, login.csrf.header_name, login.success.statuses, login.success.cookie_set,
 * login.success.body_contains, login.success.body_not_contains, login.success.redirect_not_to, headers and headers.<name>,
 * cookies and cookies.<name>, total.
 */
export function validateAuthForm(form: AuthForm, baseUrl: string | null | undefined, stored: DastAuth | null | undefined): AuthErrors {
  const e: AuthErrors = {}
  const add = (k: string, m: string) => { if (!(k in e)) e[k] = m }
  if (form.type === 'none') return e
  const hasStored = !!stored && stored.type !== 'none' && stored.has_secret
  if (usesLogin(form.type)) {
    const l = form.login
    const urlErr = validateLoginUrl(l.url, baseUrl)
    if (urlErr) add('login.url', urlErr)
    if (!FIELD_NAME_RE.test(l.username_field.trim())) add('login.username_field', l.username_field.trim() ? 'Username field may contain only letters, digits and _ . : [ ] - (at most 100).' : 'Username field is required: enter the name of the login form field for the username.')
    if (!FIELD_NAME_RE.test(l.password_field.trim())) add('login.password_field', l.password_field.trim() ? 'Password field may contain only letters, digits and _ . : [ ] - (at most 100).' : 'Password field is required: enter the name of the login form field for the password.')
    else if (l.password_field.trim() === l.username_field.trim()) add('login.password_field', 'The username and password fields must differ.')
    if (!l.username.trim()) add('login.username', 'Username is required: enter the username of the test account.')
    else if (l.username.length > 256 || hasCtl(l.username)) add('login.username', 'Username must be at most 256 characters without control characters.')
    const storedLogin = hasStored && usesLogin(stored!.type)
    if (!l.password && !storedLogin) add('login.password', 'Password is required: enter the password of the test account.')
    else if (l.password && (l.password.length < MIN_SECRET_LENGTH || l.password.length > 1024 || hasCtl(l.password))) add('login.password', 'Password must be 4 to 1024 characters without control characters.')
    const seen = new Set<string>()
    if (l.extra.length > MAX_EXTRA_FIELDS) add('login.extra_fields', `At most ${MAX_EXTRA_FIELDS} extra fields are allowed.`)
    for (const r of l.extra) {
      const n = r.name.trim()
      const key = rowField('login.extra_fields', r)
      if (!n) add(key, r.value ? 'Field name is required.' : 'Enter a field name or remove this row.')
      else if (!FIELD_NAME_RE.test(n)) add(key, 'Field name may contain only letters, digits and _ . : [ ] - (at most 100).')
      else if (n === l.username_field.trim() || n === l.password_field.trim()) add(key, 'An extra field must not repeat the username or password field.')
      else if (seen.has(n)) add(key, 'Extra field names must be unique.')
      else if (r.value.length > 1024 || hasCtl(r.value)) add(key, 'Value must be at most 1024 characters without control characters.')
      seen.add(n)
    }
    if (l.csrf_enabled) {
      if (!l.csrf_name.trim()) add('login.csrf.name', 'Name is required: enter the name of the CSRF input, cookie or header to read.')
      else if (l.csrf_name.trim().length > 100) add('login.csrf.name', 'Name must be at most 100 characters.')
      if (l.csrf_send_as === 'header' && l.csrf_header_name.trim() && (!TOKEN_RE.test(l.csrf_header_name.trim()) || FORBIDDEN_HEADERS.has(l.csrf_header_name.trim().toLowerCase()))) add('login.csrf.header_name', 'Enter a valid header name, or leave it empty for X-CSRF-Token.')
    }
    if (l.success_statuses.trim()) {
      const sts = parseStatuses(l.success_statuses)
      if (sts === null) add('login.success.statuses', 'Use status codes between 100 and 599, separated by commas.')
      else if (sts.length > 10) add('login.success.statuses', 'Use at most 10 status codes.')
    }
    if (l.success_cookie_set.trim() && !TOKEN_RE.test(l.success_cookie_set.trim())) add('login.success.cookie_set', 'Enter a valid cookie name.')
    if (l.token_enabled) {
      const path = l.token_path.trim()
      if (!path) add('login.token.path', l.token_from === 'json' ? 'Path is required: enter the JSON path of the token, for example data.access_token.' : 'Header name is required: enter the response header that carries the token.')
      else if (l.token_from === 'json' && !isValidJsonPath(path)) add('login.token.path', 'Use a dotted JSON path such as data.access_token or items[0].token (at most 200 characters).')
      else if (l.token_from === 'header' && !TOKEN_RE.test(path)) add('login.token.path', 'Enter a valid response header name.')
      if (l.token_send_mode === 'header') {
        const h = l.token_header_name.trim()
        if (!h) add('login.token.header_name', 'Header name is required for a custom header.')
        else if (!TOKEN_RE.test(h) || FORBIDDEN_HEADERS.has(h.toLowerCase()) || h.toLowerCase().startsWith('proxy-') || h.toLowerCase().startsWith('sec-')) add('login.token.header_name', `The header ${h.slice(0, 40)} cannot be used here. Enter a valid header name.`)
      }
      if (l.token_send_mode !== 'cookie' && (l.token_prefix.length > MAX_TOKEN_PREFIX || hasCtl(l.token_prefix) || [...l.token_prefix].some(c => c.charCodeAt(0) > 0x7f))) add('login.token.prefix', `Prefix must be at most ${MAX_TOKEN_PREFIX} plain characters without line breaks.`)
      if (l.token_send_mode === 'cookie') {
        const c = l.token_cookie_name.trim()
        if (!c) add('login.token.cookie_name', 'Cookie name is required: enter the cookie that should carry the token.')
        else if (!TOKEN_RE.test(c)) add('login.token.cookie_name', 'Cookie names may not contain spaces, = ; , or control characters.')
      }
    }
    if (l.success_json_exists.trim() && !isValidJsonPath(l.success_json_exists.trim())) add('login.success.json_path_exists', 'Use a dotted JSON path such as data.access_token or items[0].token (at most 200 characters).')
    if (l.success_json_equals_path.trim() || l.success_json_equals_value) {
      if (!isValidJsonPath(l.success_json_equals_path.trim())) add('login.success.json_path_equals.path', 'Use a dotted JSON path such as status or data.ok.')
      if (!l.success_json_equals_value) add('login.success.json_path_equals.value', 'Enter the value the path must have, for example ok.')
      else if (l.success_json_equals_value.length > 200 || hasCtl(l.success_json_equals_value)) add('login.success.json_path_equals.value', 'At most 200 characters, no control characters.')
    }
    for (const [k, v] of [['body_contains', l.success_body_contains], ['body_not_contains', l.success_body_not_contains], ['redirect_not_to', l.success_redirect_not_to]] as const) {
      if (v.length > 200 || hasCtl(v)) add(`login.success.${k}`, 'At most 200 characters, no control characters.')
    }
  }
  if (usesHeaders(form.type)) {
    const headers = form.headers
    const cookies = form.cookies
    if (!headers.length && !cookies.length) add('headers', 'Add at least one header or cookie.')
    if (headers.length > MAX_HEADERS) add('headers', `At most ${MAX_HEADERS} headers are allowed.`)
    const names = new Set<string>()
    for (const r of headers) {
      const n = r.name.trim()
      const lower = n.toLowerCase()
      const key = rowField('headers', r)
      if (!n) add(key, r.value ? 'Header name is required.' : 'Enter a header name or remove this row.')
      else if (!TOKEN_RE.test(n)) add(key, 'Header names may only contain letters, digits and - _ . ! # $ % & \' * + ^ ` | ~ (no spaces or line breaks).')
      else if (FORBIDDEN_HEADERS.has(lower) || lower.startsWith('proxy-') || lower.startsWith('sec-')) add(key, `The header ${n} cannot be set here${lower === 'cookie' ? ' (use the cookie list)' : ''}.`)
      else if (names.has(lower)) add(key, 'Header names must be unique.')
      else if (!r.value && !r.stored) add(key, `Value is required for ${n}.`)
      else if (r.value && (/[\r\n\0]/.test(r.value) || hasCtl(r.value, true))) add(key, 'Header values must not contain line breaks or control characters.')
      else if (r.value && (r.value.length < MIN_SECRET_LENGTH || r.value.length > MAX_VALUE_BYTES)) add(key, 'Header values must be 4 characters to 4 KiB long.')
      names.add(lower)
    }
    if (cookies.length > MAX_COOKIES) add('cookies', `At most ${MAX_COOKIES} cookies are allowed.`)
    for (const r of cookies) {
      const n = r.name.trim()
      const key = rowField('cookies', r)
      if (!n) add(key, r.value ? 'Cookie name is required.' : 'Enter a cookie name or remove this row.')
      else if (!TOKEN_RE.test(n)) add(key, 'Cookie names may not contain spaces, = ; , or control characters.')
      else if (!r.value && !r.stored) add(key, `Value is required for the cookie ${n}.`)
      else if (r.value && (r.value.length < MIN_SECRET_LENGTH || r.value.length > MAX_VALUE_BYTES || /[;,\s]/.test(r.value) || hasCtl(r.value))) add(key, 'Cookie values must be 4 characters to 4 KiB without spaces, ";", "," or control characters.')
    }
  }
  if (!Object.keys(e).length) {
    const size = new TextEncoder().encode(JSON.stringify(buildAuthBody(form))).length
    if (size > MAX_TOTAL_BYTES) e.total = 'The authentication settings are larger than 16 KiB in total.'
  }
  return e
}

const pairs = (rows: PairRow[]): Record<string, string> => Object.fromEntries(rows.filter(r => r.name.trim()).map(r => [r.name.trim(), r.value]))

/** Request body for PUT /codebases/{id}/dast-auth. Blank secrets stay blank: the server keeps the stored value of the same name. */
export function buildAuthBody(form: AuthForm): DastAuthBody {
  const body: DastAuthBody = { type: form.type as DastAuthBody['type'] }
  if (usesLogin(form.type)) {
    const l = form.login
    const extra = pairs(l.extra)
    const statuses = parseStatuses(l.success_statuses) ?? []
    const success = {
      ...(statuses.length ? { statuses } : {}),
      ...(l.success_cookie_set.trim() ? { cookie_set: l.success_cookie_set.trim() } : {}),
      ...(l.success_body_contains ? { body_contains: l.success_body_contains } : {}),
      ...(l.success_body_not_contains ? { body_not_contains: l.success_body_not_contains } : {}),
      ...(l.success_redirect_not_to.trim() ? { redirect_not_to: l.success_redirect_not_to.trim() } : {}),
      ...(l.success_json_exists.trim() ? { json_path_exists: l.success_json_exists.trim() } : {}),
      ...(l.success_json_equals_path.trim() && l.success_json_equals_value ? { json_path_equals: { path: l.success_json_equals_path.trim(), value: l.success_json_equals_value } } : {}),
    }
    const token: NonNullable<NonNullable<DastAuthBody['login']>['token']> | null = l.token_enabled
      ? {
          from: l.token_from, path: l.token_path.trim(),
          send_as: l.token_send_mode === 'cookie' ? 'cookie' : 'header',
          ...(l.token_send_mode === 'authorization' ? { header_name: 'Authorization', prefix: l.token_prefix } : {}),
          ...(l.token_send_mode === 'header' ? { header_name: l.token_header_name.trim(), prefix: l.token_prefix } : {}),
          ...(l.token_send_mode === 'cookie' ? { cookie_name: l.token_cookie_name.trim() } : {}),
        }
      : null
    body.login = {
      url: l.url.trim(), method: l.method, body_format: l.body_format, username_field: l.username_field.trim(), password_field: l.password_field.trim(),
      username: l.username.trim(), password: l.password,
      ...(Object.keys(extra).length ? { extra_fields: extra } : {}),
      ...(l.csrf_enabled ? { csrf: { source: l.csrf_source, name: l.csrf_name.trim(), send_as: l.csrf_send_as, ...(l.csrf_send_as === 'header' && l.csrf_header_name.trim() ? { header_name: l.csrf_header_name.trim() } : {}) } } : {}),
      ...(token ? { token } : {}),
      ...(Object.keys(success).length ? { success } : {}),
    }
  }
  if (usesHeaders(form.type)) {
    const h = pairs(form.headers)
    const c = pairs(form.cookies)
    if (Object.keys(h).length) body.headers = h
    if (Object.keys(c).length) body.cookies = c
  }
  return body
}

/** One-line summary of the saved (non-secret) settings. */
export function authSummary(a: DastAuth): string {
  const parts: string[] = []
  if (a.login_url) parts.push(`${a.method ?? 'POST'} ${a.login_url} as ${a.username ?? '?'}`)
  if (a.token) parts.push(`token: ${a.token.from === 'json' ? 'JSON' : 'header'} ${a.token.path} → ${a.token.send_as === 'cookie' ? `cookie ${a.token.cookie_name ?? ''}` : `header ${a.token.header_name ?? 'Authorization'}`}`)
  if (a.header_names.length) parts.push(`headers: ${a.header_names.join(', ')}`)
  if (a.cookie_names.length) parts.push(`cookies: ${a.cookie_names.join(', ')}`)
  return parts.join(' · ')
}

// ---- crawl -----------------------------------------------------------------------------------------

/** Light check of one exclusion pattern. The server compiles with RE2 (no look-around, no back-references). */
export function validateExcludePattern(p: string): string | null {
  const v = p.trim()
  if (!v) return 'Enter a pattern or remove the row.'
  if (v.length > MAX_EXCLUDE_LENGTH) return `At most ${MAX_EXCLUDE_LENGTH} characters.`
  if (hasCtl(v)) return 'No control characters.'
  if (/\(\?[=!<]/.test(v) || /\\[1-9]/.test(v)) return 'Look-around and back-references are not supported.'
  try { new RegExp(v) } catch { return 'This is not a valid regular expression.' }
  return null
}

/** Field-level checks of the crawl form: max_depth, max_pages, exclude (the list as a whole) and exclude[i] (one row each). */
export function crawlFieldErrors(c: { max_depth: number | string, max_pages: number | string, exclude: string[] }): Record<string, string> {
  const e: Record<string, string> = {}
  const d = c.max_depth === '' ? Number.NaN : Number(c.max_depth)
  const p = c.max_pages === '' ? Number.NaN : Number(c.max_pages)
  if (c.max_depth === '' || c.max_depth === null) e.max_depth = 'Max depth is required.'
  else if (!Number.isInteger(d) || d < 1 || d > MAX_CRAWL_DEPTH) e.max_depth = `Max depth must be a whole number from 1 to ${MAX_CRAWL_DEPTH}.`
  if (c.max_pages === '' || c.max_pages === null) e.max_pages = 'Max pages is required.'
  else if (!Number.isInteger(p) || p < 1 || p > MAX_CRAWL_PAGES) e.max_pages = `Max pages must be a whole number from 1 to ${MAX_CRAWL_PAGES}.`
  if (c.exclude.length > MAX_EXCLUDE_PATTERNS) e.exclude = `At most ${MAX_EXCLUDE_PATTERNS} patterns are allowed.`
  c.exclude.forEach((x, i) => {
    const err = validateExcludePattern(x)
    if (err) e[`exclude[${i}]`] = `Pattern ${i + 1}: ${err}`
  })
  return e
}

// ---- scan log ---------------------------------------------------------------------------------------

export interface ScanAuthInfo {
  authenticated: boolean
  /** e.g. "form+header" */
  mode: string | null
  /** Pages scanned by the crawl, when the log says so. */
  pages: number | null
}

/** Reads the backend's job-log lines "authenticated scan (<type>)" and "scan summary: N pages scanned". */
export function scanAuthInfo(lines: string[]): ScanAuthInfo {
  const info: ScanAuthInfo = { authenticated: false, mode: null, pages: null }
  for (const line of lines) {
    const a = /^authenticated scan \(([^)]*)\)/.exec(line.trim())
    if (a) { info.authenticated = true; info.mode = a[1] ?? null }
    const p = /^scan summary: (\d{1,6}) pages? scanned/.exec(line.trim())
    if (p) info.pages = Number(p[1])
  }
  return info
}

// ---- active scanning ---------------------------------------------------------------------------------

/** Shown in the Active scanning settings panel and (strengthened) in the authorization dialog. */
export const ACTIVE_SCANNING_RISK_NOTE = 'Active scanning sends SQL injection, reflected XSS, open redirect and '
  + 'header-injection test payloads to parameters found on this target — in GET query parameters, in HTML POST forms '
  + 'found by the crawler, and, when an OpenAPI/Swagger spec is available, in the API operations it describes '
  + '(GET, POST, PUT and PATCH; DELETE is never tested), sending payloads in JSON request bodies too. This may create, '
  + 'modify or delete real data, especially on applications that mutate state via GET or expose POST/PUT/PATCH without '
  + 'a confirmation step. Prefer a staging or test environment you fully control. This authorization is separate from, '
  + 'and in addition to, the basic DAST target confirmation above: it does not replace it.'

/** Checkbox label of the authorization dialog. */
export const ACTIVE_SCANNING_STATEMENT = 'I understand that active scanning sends test payloads (SQL injection, XSS, '
  + 'open redirect, header injection) to this target, including its POST forms and API operations, and that this may '
  + 'modify or delete real data. I am authorized to run active scans against this target.'

/** Shown just before a "Run scan" submission that enables active scanning. */
export const ACTIVE_SCAN_RUN_SUMMARY = 'This will send SQL injection, XSS, and other test payloads to this target.'

export const ACTIVE_SCAN_TIMING_HELP = 'Also test for time-based blind SQL injection (the engine waits for a delayed '
  + 'response). This adds extra load to the target server, on top of the other active checks.'

export const AUTHORIZE_ACTIVE_SCANNING_FIRST_HINT = 'Authorize active scanning first.'

export interface ScanActiveInfo {
  /** The job log said active scanning ran. */
  active: boolean
  /** The "type: ..." part of the authorization line, e.g. "boolean/error-based/XSS/open-redirect/header-injection". */
  kind: string | null
  /** Number of active test requests sent, when the log says so. */
  requests: number | null
}

// Matches both the backend's own "N active requests sent" line and the engine's raw stderr summary
// copied verbatim ("N permintaan aktif dikirim, M temuan aktif" — only the request count, never the
// finding count, is picked up).
const ACTIVE_REQUESTS_RE = /\b(\d{1,7})\s+(?:active requests?|permintaan aktif)\b/i

/**
 * Reads the backend's job-log lines "active scanning authorized by <user> on <date>, type: ..." and
 * the active-request count ("N active requests sent" or "N permintaan aktif dikirim, ...").
 */
export function scanActiveInfo(lines: string[]): ScanActiveInfo {
  const info: ScanActiveInfo = { active: false, kind: null, requests: null }
  for (const line of lines) {
    const t = line.trim()
    const a = /^active scanning authorized by \S+ on \S+, type: (.+)$/.exec(t)
    if (a) { info.active = true; info.kind = a[1] ?? null }
    const n = ACTIVE_REQUESTS_RE.exec(t)
    if (n) info.requests = Number(n[1])
  }
  return info
}

/** Field errors of the optional OpenAPI/Swagger spec URL field (same-origin check mirrors the login URL). */
export function openapiSpecUrlIssue(url: string, baseUrl: string | null | undefined): string | null {
  const v = url.trim()
  if (!v) return null
  if (v.length > 2000 || /[\s\\]/.test(v)) return 'The OpenAPI/Swagger spec URL is not valid.'
  let u: URL
  try { u = new URL(v) } catch { return 'Enter a full URL such as https://shop.example.com/openapi.json.' }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'The spec URL must start with http:// or https://.'
  if (u.username || u.password) return 'The spec URL must not contain credentials.'
  const base = originOf(baseUrl ?? '')
  if (base && originOf(v) !== base) return `The spec URL must be on the same origin as the base URL (${base}).`
  return null
}
