// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  TARGET_NOT_CONFIRMED_HINT, allowedTargetTypes, canConfirmTarget, canDeleteEntities, canEditSchedule, canManageTokens, canManageUsers, canManageVulnDb,
  canRegisterUrlTarget, hasDastAccess, runScanState,
} from '~/utils/permissions'

const admin = { role: 'admin', can_run_dast: false } as const
const member = { role: 'member', can_run_dast: false } as const
const dastMember = { role: 'member', can_run_dast: true } as const

describe('role rules in the UI', () => {
  it('only Admin deletes entities, manages users and tokens, and confirms targets', () => {
    for (const fn of [canDeleteEntities, canManageUsers, canManageTokens, canConfirmTarget, canManageVulnDb]) {
      expect(fn(admin)).toBe(true)
      expect(fn(member)).toBe(false)
      expect(fn(dastMember)).toBe(false)
      expect(fn(null)).toBe(false)
    }
  })

  it('DAST access: Admin always, Member only with can_run_dast', () => {
    expect(hasDastAccess(admin)).toBe(true)
    expect(hasDastAccess(member)).toBe(false)
    expect(hasDastAccess(dastMember)).toBe(true)
    expect(canRegisterUrlTarget(member)).toBe(false)
    expect(canRegisterUrlTarget(dastMember)).toBe(true)
  })

  it('offers the URL target type only with DAST access', () => {
    expect(allowedTargetTypes(member)).toEqual(['repo'])
    expect(allowedTargetTypes(dastMember)).toEqual(['repo', 'url'])
    expect(allowedTargetTypes(admin)).toEqual(['repo', 'url'])
  })

  it('Run scan: SAST for everyone signed in', () => {
    expect(runScanState(member, { target_type: 'repo', dast_status: null })).toEqual({ visible: true, enabled: true, reason: null })
    expect(runScanState(null, { target_type: 'repo', dast_status: null }).visible).toBe(false)
  })

  it('Run scan: DAST hidden without access, disabled with a reason until confirmed', () => {
    expect(runScanState(member, { target_type: 'url', dast_status: 'confirmed' }).visible).toBe(false)
    expect(runScanState(dastMember, { target_type: 'url', dast_status: 'pending_confirmation' })).toEqual({ visible: true, enabled: false, reason: TARGET_NOT_CONFIRMED_HINT })
    expect(runScanState(admin, { target_type: 'url', dast_status: 'confirmed' })).toEqual({ visible: true, enabled: true, reason: null })
    expect(TARGET_NOT_CONFIRMED_HINT).toBe('An Admin must confirm authorization for this target first.')
  })

  it('schedules: repo for everyone, URL targets only with DAST access', () => {
    expect(canEditSchedule(member, { target_type: 'repo' })).toBe(true)
    expect(canEditSchedule(member, { target_type: 'url' })).toBe(false)
    expect(canEditSchedule(dastMember, { target_type: 'url' })).toBe(true)
  })
})
