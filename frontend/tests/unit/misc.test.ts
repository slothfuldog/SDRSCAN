// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { cweUrl, formatDuration, safeNextPath, utcTitle } from '~/utils/format'
import { appendLogLine, applyStatusEvent, isActive, isTerminal, scanErrorText, splitLog } from '~/utils/scanStream'
import { SCHEDULE_PRESETS, describeSchedule, presetFor, scheduleStatusLabel, suspendedReasonText, validateSchedule } from '~/utils/schedule'
import { ingestCurlExample } from '~/utils/curl'
import type { Scan } from '~/types/api'

describe('format helpers', () => {
  it('links only well-formed CWE ids', () => {
    expect(cweUrl('CWE-79')).toBe('https://cwe.mitre.org/data/definitions/79.html')
    expect(cweUrl('CWE-javascript:alert(1)')).toBeNull()
    expect(cweUrl('cwe-79')).toBeNull()
    expect(cweUrl('CWE-79 ')).toBeNull()
  })

  it('only allows same-app paths after login (no open redirect)', () => {
    expect(safeNextPath('/projects/3?x=1')).toBe('/projects/3?x=1')
    for (const bad of ['https://evil.example', '//evil.example', '/\\evil', 'javascript:alert(1)', '/login', undefined, 5, '/a\nb']) expect(safeNextPath(bad)).toBe('/')
  })

  it('formats UTC titles and durations', () => {
    expect(utcTitle('2026-10-27T08:30:00Z')).toBe('2026-10-27T08:30:00Z (UTC)')
    expect(formatDuration('2026-10-27T08:30:00Z', '2026-10-27T08:30:41Z')).toBe('41s')
    expect(formatDuration('2026-10-27T08:30:00Z', '2026-10-27T08:32:05Z')).toBe('2m 5s')
    expect(formatDuration(null, null)).toBe('')
  })
})

describe('scan stream helpers', () => {
  const scan = { id: 1, status: 'queued', started_at: null, finished_at: null } as Scan

  it('knows terminal and active statuses', () => {
    expect(['succeeded', 'failed', 'cancelled'].every(isTerminal)).toBe(true)
    expect(isTerminal('running')).toBe(false)
    expect(isActive('queued') && isActive('running')).toBe(true)
  })

  it('applies status events and splits logs', () => {
    const next = applyStatusEvent(scan, { status: 'running', started_at: '2026-10-27T08:30:04Z' })
    expect(next).toMatchObject({ status: 'running', started_at: '2026-10-27T08:30:04Z' })
    expect(splitLog('a\r\nb\n\nc')).toEqual(['a', 'b', 'c'])
  })

  it('skips replayed log lines and appends new ones', () => {
    let state = { lines: ['one', 'two'], replayCursor: 0 }
    state = appendLogLine(state, 'one')
    state = appendLogLine(state, 'two')
    expect(state.lines).toEqual(['one', 'two'])
    state = appendLogLine(state, 'three')
    expect(state.lines).toEqual(['one', 'two', 'three'])
  })

  it('has friendly texts for scan error codes, including private network addresses', () => {
    expect(scanErrorText('clone_failed')).toMatch(/cloned/)
    expect(scanErrorText('private_address')).toBe('Private network addresses are not allowed.')
    expect(scanErrorText('weird')).toContain('weird')
    expect(scanErrorText(null)).toBe('')
  })
})

describe('schedule helpers', () => {
  it('maps presets (Hourly, Daily 02:00 UTC, Weekly) and falls back to custom', () => {
    expect(SCHEDULE_PRESETS.map(p => p.key)).toEqual(['hourly', 'daily', 'weekly'])
    expect(SCHEDULE_PRESETS[1]!.cron).toBe('0 2 * * *')
    expect(presetFor('0 * * * *')).toBe('hourly')
    expect(presetFor('0 2 * * *')).toBe('daily')
    expect(presetFor('0  2 * * 1')).toBe('weekly')
    expect(presetFor('*/15 * * * *')).toBe('custom')
    expect(describeSchedule(null)).toBe('No schedule')
    expect(describeSchedule('*/15 * * * *')).toContain('Custom cron')
  })

  it('validates syntax and the minimum interval (SAST 15 min, DAST 60 min)', () => {
    expect(validateSchedule('0 2 * * 1', 'repo')).toBeNull()
    expect(validateSchedule('*/15 * * * *', 'repo')).toBeNull()
    expect(validateSchedule('*/10 * * * *', 'repo')).toMatch(/minimum interval is 15 minutes/)
    expect(validateSchedule('*/30 * * * *', 'url')).toMatch(/minimum interval is 60 minutes/)
    expect(validateSchedule('0 * * * *', 'url')).toBeNull()
    expect(validateSchedule('0 3 * *', 'repo')).not.toBeNull()
    expect(validateSchedule('0 3 * * $(id)', 'repo')).not.toBeNull()
    expect(validateSchedule('', 'repo')).not.toBeNull()
  })

  it('labels the status and the suspension reason', () => {
    expect(scheduleStatusLabel('suspended').tone).toBe('warn')
    expect(scheduleStatusLabel('active').label).toBe('Active')
    expect(suspendedReasonText('owner_deactivated')).toBe('Owner was deactivated.')
    expect(suspendedReasonText('owner_lost_permission')).toBe('Owner no longer has permission.')
  })

  it('builds the CI example from the current origin', () => {
    expect(ingestCurlExample('https://sdr.example.com')).toContain('https://sdr.example.com/api/v1/ingest?project=')
  })
})
