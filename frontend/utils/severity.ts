import type { Severity, SeveritySummary } from '~/types/api'

/** Severity order, highest first (critical > high > medium > low > info). */
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'] as const

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

/**
 * Nuxt UI colour aliases (see app.config.ts) used by badges. The label text is always shown too, never colour alone.
 * critical = red, high = orange, medium = amber, low = sky, info = zinc.
 */
export type SeverityColor = 'critical' | 'high' | 'medium' | 'low' | 'notice'
export const SEVERITY_COLOR: Record<Severity, SeverityColor> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'notice',
}

export function isSeverity(v: unknown): v is Severity {
  return typeof v === 'string' && v in RANK
}

/** Numeric rank: info = 0 ... critical = 4. Unknown values rank below info (-1). */
export function severityRank(s: string | null | undefined): number {
  return isSeverity(s) ? RANK[s] : -1
}

/** Sort comparator: highest severity first. */
export function compareSeverityDesc(a: string, b: string): number {
  return severityRank(b) - severityRank(a)
}

export function emptySummary(): SeveritySummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, highest_severity: null }
}

/** Highest severity with a count greater than zero, or null (also for null/undefined input). */
export function highestSeverity(summary: Partial<Record<Severity, number>> | null | undefined): Severity | null {
  if (!summary) return null
  for (const s of SEVERITIES) {
    if ((summary[s] ?? 0) > 0) return s
  }
  return null
}

export function totalCount(summary: Partial<Record<Severity, number>> | null | undefined): number {
  if (!summary) return 0
  return SEVERITIES.reduce((n, s) => n + (summary[s] ?? 0), 0)
}

/** Sum several summaries. Null summaries ("not scanned yet") contribute nothing. */
export function sumSummaries(list: Array<Partial<Record<Severity, number>> | null | undefined>): SeveritySummary {
  const out = emptySummary()
  for (const item of list) {
    if (!item) continue
    for (const s of SEVERITIES) out[s] += item[s] ?? 0
  }
  out.highest_severity = highestSeverity(out)
  return out
}

/** Parse the comma separated `severity` query value into a clean, ordered list. */
export function parseSeverityList(value: unknown): Severity[] {
  if (typeof value !== 'string' || !value) return []
  const set = new Set(value.split(',').map(s => s.trim().toLowerCase()).filter(isSeverity))
  return SEVERITIES.filter(s => set.has(s))
}
