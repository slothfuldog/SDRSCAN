// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL, compareSeverityDesc, highestSeverity, parseSeverityList, severityRank, sumSummaries, totalCount,
} from '~/utils/severity'

describe('severity ordering and mapping', () => {
  it('orders critical > high > medium > low > info', () => {
    expect([...SEVERITIES]).toEqual(['critical', 'high', 'medium', 'low', 'info'])
    expect(['low', 'critical', 'info', 'high', 'medium'].sort(compareSeverityDesc)).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })

  it('ranks info 0 to critical 4 and unknown values below info', () => {
    expect(SEVERITIES.map(severityRank)).toEqual([4, 3, 2, 1, 0])
    expect(severityRank('bogus')).toBe(-1)
    expect(severityRank(null)).toBe(-1)
  })

  it('has a distinct colour alias and a text label for every severity', () => {
    const colors = SEVERITIES.map(s => SEVERITY_COLOR[s])
    expect(new Set(colors).size).toBe(5)
    for (const s of SEVERITIES) expect(SEVERITY_LABEL[s].length).toBeGreaterThan(0)
  })

  it('computes the highest severity with a count above zero', () => {
    expect(highestSeverity({ critical: 0, high: 0, medium: 2, low: 9, info: 1 })).toBe('medium')
    expect(highestSeverity({ critical: 1, high: 5 })).toBe('critical')
    expect(highestSeverity({ critical: 0, high: 0, medium: 0, low: 0, info: 0 })).toBeNull()
    expect(highestSeverity(null)).toBeNull()
  })

  it('sums summaries and ignores codebases that were not scanned (null)', () => {
    const sum = sumSummaries([{ critical: 1, high: 2, medium: 0, low: 0, info: 1 }, null, { critical: 0, high: 1, medium: 4, low: 0, info: 0 }, undefined])
    expect(sum).toMatchObject({ critical: 1, high: 3, medium: 4, low: 0, info: 1, highest_severity: 'critical' })
    expect(totalCount(sum)).toBe(9)
    expect(sumSummaries([null]).highest_severity).toBeNull()
  })

  it('parses the severity query list, dropping junk and keeping severity order', () => {
    expect(parseSeverityList('low,CRITICAL,nope, high')).toEqual(['critical', 'high', 'low'])
    expect(parseSeverityList('')).toEqual([])
    expect(parseSeverityList(undefined)).toEqual([])
  })
})
