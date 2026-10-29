// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { minIntervalMinutes, nextRuns, parseCron } from '~/utils/cron'

const from = new Date('2026-10-27T10:30:00Z')
const iso = (d: Date[]) => d.map(x => x.toISOString())

describe('cron evaluator (UTC)', () => {
  it('computes the next three runs for the presets', () => {
    expect(iso(nextRuns('0 * * * *', from))).toEqual(['2026-10-27T11:00:00.000Z', '2026-10-27T12:00:00.000Z', '2026-10-27T13:00:00.000Z'])
    expect(iso(nextRuns('0 2 * * *', from))).toEqual(['2026-10-28T02:00:00.000Z', '2026-10-29T02:00:00.000Z', '2026-10-30T02:00:00.000Z'])
    // 2026-10-27 is a Tuesday; next Mondays are Nov 2, 9, 16
    expect(iso(nextRuns('0 2 * * 1', from))).toEqual(['2026-11-02T02:00:00.000Z', '2026-11-09T02:00:00.000Z', '2026-11-16T02:00:00.000Z'])
  })

  it('supports lists, ranges, steps, names and day-of-week 7', () => {
    expect(iso(nextRuns('15,45 9-10 * * *', from))).toEqual(['2026-10-27T10:45:00.000Z', '2026-10-28T09:15:00.000Z', '2026-10-28T09:45:00.000Z'])
    expect(iso(nextRuns('*/20 11 * * *', from, 2))).toEqual(['2026-10-27T11:00:00.000Z', '2026-10-27T11:20:00.000Z'])
    expect(iso(nextRuns('0 0 1 jan *', from, 1))).toEqual(['2027-01-01T00:00:00.000Z'])
    expect(nextRuns('0 12 * * 7', from, 1)[0]!.getUTCDay()).toBe(0)
    expect(nextRuns('0 12 * * sun', from, 1)[0]!.getUTCDay()).toBe(0)
  })

  it('uses OR when both day-of-month and day-of-week are restricted (classic cron)', () => {
    const runs = nextRuns('0 6 13 * 5', from, 6)
    expect(runs.every(d => d.getUTCDate() === 13 || d.getUTCDay() === 5)).toBe(true)
  })

  it('rejects malformed expressions with a reason', () => {
    for (const bad of ['', '* * * *', '* * * * * *', '60 * * * *', '* 24 * * *', '* * 0 * *', '* * * 13 *', '*/0 * * * *', '5-1 * * * *', 'a * * * *', '$(id) * * * *']) {
      const r = parseCron(bad)
      expect(r.ok, bad).toBe(false)
    }
    expect(nextRuns('nope', from)).toEqual([])
  })

  it('measures the smallest interval between runs', () => {
    expect(minIntervalMinutes('*/5 * * * *')).toBe(5)
    expect(minIntervalMinutes('0 * * * *')).toBe(60)
    expect(minIntervalMinutes('0,10 * * * *')).toBe(10)
    expect(minIntervalMinutes('0 2 * * *')).toBe(1440)
  })
})
