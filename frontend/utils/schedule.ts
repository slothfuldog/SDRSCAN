import type { Codebase, ScheduleStatus, SuspendedReason } from '~/types/api'
import { minIntervalMinutes, parseCron } from './cron'

// Scheduled scans (v2). One schedule per Codebase: cron (5 fields, UTC), owner, status (active | suspended).
// Endpoints: GET /schedules, PUT|DELETE /codebases/{id}/schedule, POST /codebases/{id}/schedule/resume.
export type SchedulePresetKey = 'hourly' | 'daily' | 'weekly' | 'custom'

export const SCHEDULE_PRESETS: Array<{ key: Exclude<SchedulePresetKey, 'custom'>, label: string, cron: string, hint: string }> = [
  { key: 'hourly', label: 'Hourly', cron: '0 * * * *', hint: 'At minute 0 of every hour (UTC)' },
  { key: 'daily', label: 'Daily 02:00 UTC', cron: '0 2 * * *', hint: 'Every day at 02:00 UTC' },
  { key: 'weekly', label: 'Weekly', cron: '0 2 * * 1', hint: 'Every Monday at 02:00 UTC' },
]

/** Minimum interval between runs in minutes (TRD proposal; the server enforces it): SAST 15, DAST 60. */
export const MIN_INTERVAL_MINUTES = { repo: 15, url: 60 } as const

export function presetFor(cron: string | null | undefined): SchedulePresetKey {
  const v = (cron ?? '').trim().replace(/\s+/g, ' ')
  return SCHEDULE_PRESETS.find(p => p.cron === v)?.key ?? 'custom'
}

export function describeSchedule(cron: string | null | undefined): string {
  const v = (cron ?? '').trim().replace(/\s+/g, ' ')
  if (!v) return 'No schedule'
  const p = SCHEDULE_PRESETS.find(x => x.cron === v)
  return p ? `${p.label}: ${p.hint}` : `Custom cron: ${v} (UTC)`
}

/** Early feedback only: syntax and minimum interval. The backend answers 422 invalid_cron / schedule_too_frequent. */
export function validateSchedule(cron: string, targetType: Codebase['target_type']): string | null {
  const parsed = parseCron(cron)
  if (!parsed.ok) return parsed.error
  const min = MIN_INTERVAL_MINUTES[targetType]
  const gap = minIntervalMinutes(cron)
  if (gap !== null && gap < min) {
    return `This schedule runs too often. The minimum interval is ${min} minutes for ${targetType === 'url' ? 'DAST' : 'SAST'} scans.`
  }
  return null
}

export function scheduleStatusLabel(status: ScheduleStatus | string | null | undefined): { label: string, tone: 'ok' | 'warn' } {
  return status === 'suspended' ? { label: 'Suspended', tone: 'warn' } : { label: 'Active', tone: 'ok' }
}

const REASONS: Record<string, string> = {
  owner_deactivated: 'Owner was deactivated.',
  owner_lost_permission: 'Owner no longer has permission.',
}

export function suspendedReasonText(reason: SuspendedReason | string | null | undefined): string {
  if (!reason) return 'The schedule was suspended.'
  return REASONS[reason] ?? `Suspended (${reason}).`
}
