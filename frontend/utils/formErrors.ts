import { isApiError } from '~/utils/errors'
import type { ApiError } from '~/utils/errors'

// Per-field form errors: maps the API's validation errors onto the fields of a form.
//
// Contract of the backend (see backend/README.md, "Validation errors"):
//   details.field   name of the first failing JSON field ("name", "login.password", "headers.Authorization",
//                   "dast_crawl_exclude[2]")
//   details.fields  [{ field, message, code? }] when several fields failed in one request
// Older servers send no details; then the field is guessed from the start of the message
// ("repo_url is required.", "New password must be ...").

export interface FieldIssue {
  /** Field name as the API sent it (a path: "login.url", "dast_crawl_exclude[2]"). */
  field: string
  message: string
  code?: string
}

export interface FieldMapOptions {
  /** API field -> form field, exact ("new_password" -> "next") or by path prefix ("dast_crawl_exclude" -> "exclude" also maps "dast_crawl_exclude[2]" to "exclude[2]"). */
  aliases?: Record<string, string>
  /** Whether the form has a field with this (form) name. Names that are not known fall back to their parent ("headers.X" -> "headers"). */
  has?: (name: string) => boolean
  /** Extra form field names that exist (used by the message-prefix fallback and by `has`). */
  fields?: readonly string[]
}

export interface MappedField {
  /** Form field name. */
  name: string
  message: string
  /** The name the API used. */
  apiField: string
  code?: string
}

export interface MappedError {
  fields: MappedField[]
  /** Messages that belong to no known field. */
  unmapped: string[]
  /** How the fields were found. */
  source: 'details' | 'message' | 'none'
}

const INDEX_RE = /\[\d+\]$/

/** The field issues carried in `details` (single or list); [] when there are none. */
export function issuesFromDetails(e: ApiError): FieldIssue[] {
  const d = e.details
  if (!d || typeof d !== 'object') return []
  const rec = d as Record<string, unknown>
  const out: FieldIssue[] = []
  if (Array.isArray(rec.fields)) {
    for (const it of rec.fields) {
      if (!it || typeof it !== 'object') continue
      const { field, message, code } = it as Record<string, unknown>
      if (typeof field !== 'string' || !field) continue
      out.push({ field, message: typeof message === 'string' && message ? message : e.message, ...(typeof code === 'string' && code ? { code } : {}) })
    }
    if (out.length) return out
  }
  if (typeof rec.field === 'string' && rec.field) return [{ field: rec.field, message: e.message, ...(e.code && e.code !== 'validation_failed' ? { code: e.code } : {}) }]
  return []
}

/**
 * Cadangan untuk server tanpa `details`: "<field> must ...", "<field> is required", "New password must ...".
 * The words before the verb, joined with "_", must be a known field name ("new password" -> "new_password").
 */
export function issueFromMessage(message: string, known: (apiName: string) => boolean): FieldIssue | null {
  const m = /^([A-Za-z_][\w.[\]-]*(?: [A-Za-z]+){0,2}?) (?:must|is|are|cannot|needs|does|applies|has)\b/.exec(message.trim())
  if (!m) return null
  const raw = m[1]!
  const candidates = [raw.replace(/ /g, '_').toLowerCase(), raw.split(' ')[0]!.toLowerCase()]
  for (const c of candidates) if (known(c)) return { field: c, message }
  return null
}

/** API field -> form field, applying the alias table, then the fallbacks (index removed, parent path). */
export function resolveFieldName(apiField: string, o: FieldMapOptions = {}): string {
  const aliases = o.aliases ?? {}
  const known = new Set(o.fields ?? [])
  const has = (n: string) => known.has(n) || !!o.has?.(n)
  const alias = (name: string): string => {
    if (aliases[name] !== undefined) return aliases[name]!
    // Longest alias that is a path prefix: "a.b" matches "a.b.c" and "a.b[2]".
    let best: string | null = null
    for (const k of Object.keys(aliases)) {
      if (name.startsWith(k) && (name[k.length] === '.' || name[k.length] === '[') && (best === null || k.length > best.length)) best = k
    }
    return best === null ? name : aliases[best]! + name.slice(best.length)
  }
  const resolved = alias(apiField)
  if (has(resolved)) return resolved
  // "x[2]" -> "x" (a single input holding a list), "a.b.c" -> "a.b" -> "a".
  let cur = resolved
  for (let i = 0; i < 6; i++) {
    const next = INDEX_RE.test(cur) ? cur.replace(INDEX_RE, '') : (cur.includes('.') ? cur.slice(0, cur.lastIndexOf('.')) : '')
    if (!next) break
    if (has(next)) return next
    cur = next
  }
  return resolved
}

/** Maps a server error onto form fields. Errors that are not about input (no details, other statuses) come back with `source: 'none'`. */
export function mapServerError(e: unknown, o: FieldMapOptions = {}): MappedError {
  if (!isApiError(e) || ![400, 409, 422].includes(e.status)) return { fields: [], unmapped: [], source: 'none' }
  const known = new Set(o.fields ?? [])
  const apiKnown = (n: string) => known.has(n) || !!o.has?.(n) || n in (o.aliases ?? {}) || !!o.has?.(resolveFieldName(n, o))
  let issues = issuesFromDetails(e)
  let source: MappedError['source'] = issues.length ? 'details' : 'none'
  if (!issues.length && e.message) {
    const guess = issueFromMessage(e.message, apiKnown)
    if (guess) { issues = [guess]; source = 'message' }
  }
  const fields: MappedField[] = []
  const unmapped: string[] = []
  const seen = new Set<string>()
  const knowsFields = !!o.has || known.size > 0
  const isKnown = (n: string) => known.has(n) || !!o.has?.(n)
  for (const it of issues) {
    const name = resolveFieldName(it.field, o)
    if (knowsFields && !isKnown(name)) {
      if (!unmapped.includes(it.message)) unmapped.push(it.message)
      continue
    }
    if (seen.has(name) && fields.some(f => f.name === name && f.message === it.message)) continue
    seen.add(name)
    fields.push({ name, message: it.message, apiField: it.field, ...(it.code ? { code: it.code } : {}) })
  }
  return { fields, unmapped, source }
}

/** "login.csrf_name" -> "Login csrf name" for the summary when a field has no label. */
export function humanizeField(name: string): string {
  const s = name.replace(/\[\d+\]/g, '').replace(/[._]+/g, ' ').trim()
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : name
}
