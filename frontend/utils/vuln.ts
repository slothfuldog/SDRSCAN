import type { FindingSummary, VulnPackage, Vulnerability } from '~/types/api'

// Helpers for vulnerability findings (CVE / SCA / DAST). Pure functions: no DOM, safe for tests.
// Links are only built from values that match a strict pattern; everything else stays plain text.

export const CVE_RE = /^CVE-[0-9]{4}-[0-9]{4,19}$/
export const GHSA_RE = /^GHSA-[2-9a-z]{4}-[2-9a-z]{4}-[2-9a-z]{4}$/i
/** Other OSV-style ids (RUSTSEC-2021-0001, GO-2021-0001, PYSEC-...) are accepted as search input but never linked. */
const OTHER_ADVISORY_RE = /^[A-Z][A-Z0-9]*-[0-9]{4}-[0-9]{3,}$/i

/** NVD page of a CVE id, or null when the id does not match ^CVE-[0-9]{4}-[0-9]{4,19}$. */
export function nvdUrl(id: string): string | null {
  return CVE_RE.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : null
}

/** GitHub advisory page of a GHSA id, or null when the id is not a well-formed GHSA id. */
export function ghsaUrl(id: string): string | null {
  return GHSA_RE.test(id) ? `https://github.com/advisories/${id}` : null
}

/** External page of an advisory id (CVE -> NVD, GHSA -> GitHub), null for everything else. */
export function advisoryUrl(id: string): string | null {
  return nvdUrl(id) ?? ghsaUrl(id)
}

/** A complete advisory id as accepted by the `cve=` filter (exact match on the server). */
export function isAdvisoryId(text: string): boolean {
  const t = text.trim()
  return CVE_RE.test(t.toUpperCase()) || GHSA_RE.test(t) || OTHER_ADVISORY_RE.test(t)
}

/** Only absolute http(s) URLs without credentials are linkable; returns the normalised URL or null. */
export function safeReferenceUrl(ref: string): string | null {
  if (typeof ref !== 'string' || ref.length > 2048) return null
  let u: URL
  try {
    u = new URL(ref)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  if (u.username || u.password || !u.hostname) return null
  return u.href
}

export function isVulnerability(f: Pick<FindingSummary, 'kind' | 'vulnerability'>): boolean {
  return f.kind === 'vulnerability' || !!f.vulnerability
}

const CPE_RE = /^cpe:2\.3:[aho]:([A-Za-z0-9._~-]+):([A-Za-z0-9._~-]+)(?::[^\s]*)?$/

/** Friendly name of a CPE prefix ("cpe:2.3:a:apache:http_server" -> "apache http_server"; equal vendor and product show once). Null when it is not a CPE. */
export function cpeLabel(cpe: string | null | undefined): string | null {
  const m = typeof cpe === 'string' ? CPE_RE.exec(cpe) : null
  if (!m) return null
  return m[1] === m[2] ? m[2]! : `${m[1]} ${m[2]}`
}

/** Display name of a DAST product: the friendly CPE name, or the value as is when it is not a CPE. */
export function productName(product: string | null | undefined): string {
  return cpeLabel(product) ?? product ?? ''
}

/** "name@version" (SCA) or "vendor product version" (DAST, from a CPE; otherwise "product version"); empty when nothing is known. */
export function packageLabel(p: VulnPackage | null | undefined): string {
  if (!p) return ''
  if (p.name) return p.version ? `${p.name}@${p.version}` : p.name
  if (p.product) {
    const name = productName(p.product)
    return p.version ? `${name} ${p.version}` : name
  }
  return ''
}

/** "Upgrade to 1.2.3 or 2.0.1" / null when there is no fix. */
export function upgradeHint(v: Pick<Vulnerability, 'fixed_versions'>): string | null {
  const list = (v.fixed_versions ?? []).filter(x => typeof x === 'string' && x !== '')
  return list.length ? `Upgrade to ${list.join(' or ')}` : null
}

/** Human age of a timestamp: "just now", "5 minutes ago", "3 days ago". Empty for null/invalid. */
export function formatAge(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const s = Math.max(0, Math.round((now - t) / 1000))
  const unit = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'} ago`
  if (s < 60) return 'just now'
  if (s < 3600) return unit(Math.floor(s / 60), 'minute')
  if (s < 86400) return unit(Math.floor(s / 3600), 'hour')
  return unit(Math.floor(s / 86400), 'day')
}

/** "N days ago" from the CLI's `age_days` ("today" for 0); falls back to the timestamp when the CLI gave no age. */
export function ageLabel(ageDays: number | null | undefined, iso?: string | null, now: number = Date.now()): string {
  if (typeof ageDays === 'number' && Number.isFinite(ageDays) && ageDays >= 0) {
    const d = Math.floor(ageDays)
    return d === 0 ? 'today' : `${d} day${d === 1 ? '' : 's'} ago`
  }
  return formatAge(iso, now)
}

export const SOURCE_LABEL: Record<string, string> = { osv: 'OSV', nvd: 'NVD' }
export const sourceLabel = (s: string | null | undefined): string => (s ? (SOURCE_LABEL[s] ?? s) : '')
