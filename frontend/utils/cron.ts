// Small 5-field cron evaluator (UTC) used for the schedule preview and early feedback.
// The backend parses and validates the expression for real (422 invalid_cron / schedule_too_frequent).

export interface CronFields {
  minute: number[]
  hour: number[]
  dom: number[]
  month: number[]
  dow: number[]
  domAny: boolean
  dowAny: boolean
}

export type CronResult = { ok: true, fields: CronFields } | { ok: false, error: string }

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']

function num(token: string, names: string[] | null, offset: number): number {
  if (/^\d+$/.test(token)) return Number(token)
  const i = names ? names.indexOf(token.toLowerCase()) : -1
  return i < 0 ? Number.NaN : i + offset
}

function parseField(src: string, min: number, max: number, names: string[] | null, nameOffset: number, label: string): number[] | string {
  const out = new Set<number>()
  for (const part of src.split(',')) {
    if (!part) return `${label}: empty list item`
    const [rangeRaw, stepRaw, ...extra] = part.split('/')
    if (extra.length) return `${label}: invalid step in "${part}"`
    const step = stepRaw === undefined ? 1 : Number(stepRaw)
    if (stepRaw !== undefined && (!/^\d+$/.test(stepRaw) || step < 1)) return `${label}: invalid step in "${part}"`
    let lo: number
    let hi: number
    if (rangeRaw === '*') {
      lo = min
      hi = max
    } else if (rangeRaw!.includes('-')) {
      const [a, b, ...more] = rangeRaw!.split('-')
      if (more.length) return `${label}: invalid range "${rangeRaw}"`
      lo = num(a!, names, nameOffset)
      hi = num(b!, names, nameOffset)
    } else {
      lo = num(rangeRaw!, names, nameOffset)
      hi = stepRaw === undefined ? lo : max
    }
    if (Number.isNaN(lo) || Number.isNaN(hi)) return `${label}: invalid value "${part}"`
    if (lo < min || hi > max || lo > hi) return `${label}: "${part}" is out of range ${min}-${max}`
    for (let v = lo; v <= hi; v += step) out.add(v)
  }
  return [...out].sort((a, b) => a - b)
}

export function parseCron(expr: string): CronResult {
  const parts = expr.trim().split(/\s+/)
  if (!expr.trim() || parts.length !== 5) return { ok: false, error: 'Use a 5-field cron expression (minute hour day-of-month month day-of-week), for example "0 2 * * 1".' }
  const [mi, ho, dm, mo, dw] = parts as [string, string, string, string, string]
  const minute = parseField(mi, 0, 59, null, 0, 'minute')
  if (typeof minute === 'string') return { ok: false, error: minute }
  const hour = parseField(ho, 0, 23, null, 0, 'hour')
  if (typeof hour === 'string') return { ok: false, error: hour }
  const dom = parseField(dm, 1, 31, null, 0, 'day of month')
  if (typeof dom === 'string') return { ok: false, error: dom }
  const month = parseField(mo, 1, 12, MONTHS, 1, 'month')
  if (typeof month === 'string') return { ok: false, error: month }
  const dowRaw = parseField(dw, 0, 7, DAYS, 0, 'day of week')
  if (typeof dowRaw === 'string') return { ok: false, error: dowRaw }
  const dow = [...new Set(dowRaw.map(d => d % 7))].sort((a, b) => a - b)
  return { ok: true, fields: { minute, hour, dom, month, dow, domAny: dm.startsWith('*'), dowAny: dw.startsWith('*') } }
}

function dayMatches(f: CronFields, d: Date): boolean {
  if (!f.month.includes(d.getUTCMonth() + 1)) return false
  const domOk = f.dom.includes(d.getUTCDate())
  const dowOk = f.dow.includes(d.getUTCDay())
  // Classic cron: when both day fields are restricted, either may match.
  if (!f.domAny && !f.dowAny) return domOk || dowOk
  return domOk && dowOk
}

/** The next `count` run times strictly after `from` (UTC). Empty when the expression never fires within 5 years. */
export function nextRuns(expr: string, from: Date, count = 3): Date[] {
  const parsed = parseCron(expr)
  if (!parsed.ok) return []
  const f = parsed.fields
  const out: Date[] = []
  const day = new Date(Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate()))
  for (let i = 0; i < 366 * 5 && out.length < count; i++, day.setUTCDate(day.getUTCDate() + 1)) {
    if (!dayMatches(f, day)) continue
    for (const h of f.hour) {
      for (const m of f.minute) {
        const t = new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth(), day.getUTCDate(), h, m))
        if (t.getTime() > from.getTime()) {
          out.push(t)
          if (out.length >= count) return out
        }
      }
    }
  }
  return out
}

/** Smallest gap in minutes between consecutive runs (looked at over the next `sample` runs); null if fewer than two runs. */
export function minIntervalMinutes(expr: string, sample = 200): number | null {
  const runs = nextRuns(expr, new Date(Date.UTC(2026, 0, 1)), sample)
  if (runs.length < 2) return null
  let min = Number.POSITIVE_INFINITY
  for (let i = 1; i < runs.length; i++) min = Math.min(min, (runs[i]!.getTime() - runs[i - 1]!.getTime()) / 60_000)
  return min
}
