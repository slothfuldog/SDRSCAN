import type { Codebase, UserRef } from '~/types/api'

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

/** Local (browser time zone) rendering of an API timestamp (UTC). Empty string for null. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : dtf.format(d)
}

/** The exact UTC value used for the `title` attribute. */
export function utcTitle(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : `${d.toISOString().replace('.000Z', 'Z')} (UTC)`
}

export function formatDuration(start: string | null | undefined, end: string | null | undefined): string {
  if (!start || !end) return ''
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (!Number.isFinite(ms) || ms < 0) return ''
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

export function displayUser(u: UserRef | string | number | null | undefined): string {
  if (u === null || u === undefined) return ''
  if (typeof u === 'object') return u.username
  return typeof u === 'number' ? `user #${u}` : u
}

/** CWE link only for values that exactly match ^CWE-[0-9]+$ (never builds URLs from other input). */
export function cweUrl(cwe: string): string | null {
  const m = /^CWE-([0-9]+)$/.exec(cwe)
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null
}

/** Only same-app absolute paths are allowed as a post-login destination (prevents open redirects). */
export function safeNextPath(value: unknown, fallback = '/'): string {
  if (typeof value !== 'string' || !value.startsWith('/')) return fallback
  if (value.startsWith('//') || value.startsWith('/\\') || /[\r\n]/.test(value)) return fallback
  if (value.startsWith('/login')) return fallback
  return value
}

export function locationLabel(loc: { kind: string; path?: string; url?: string; start_line?: number | null }): string {
  if (loc.kind === 'url') return loc.url ?? ''
  const path = loc.path ?? ''
  return loc.start_line ? `${path}:${loc.start_line}` : path
}

export function codebaseTarget(cb: Pick<Codebase, 'target_type' | 'repo_url' | 'base_url'>): string {
  return (cb.target_type === 'url' ? cb.base_url : cb.repo_url) ?? ''
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}
