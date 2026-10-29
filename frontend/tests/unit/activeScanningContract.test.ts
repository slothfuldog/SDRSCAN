// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { createMockBackend } from '../../mock/core.ts'
import { createSession } from '../helpers/mockClient'
import type { ApiError } from '~/utils/errors'

const fails = async (p: Promise<unknown>): Promise<ApiError> => {
  try { await p } catch (e) { return e as ApiError }
  throw new Error('expected the request to fail')
}

// storefront (live): id 2, pending_confirmation. admin-portal (live): id 3, confirmed, active scanning
// already authorized in the seed. status-page (live): id 8, confirmed, NOT active-authorized.
const PENDING = 2
const ALREADY_ACTIVE = 3
const CONFIRMED_NOT_ACTIVE = 8
const REPO = 1

describe('Active scanning: a separate, stricter layer on top of confirm-authorization', () => {
  it('authorize-active-scanning requires the target confirmed first', async () => {
    const s = createSession()
    await s.login('admin')
    expect(await fails(s.api.codebases.authorizeActiveScanning(PENDING, { statement_accepted: true, codebase_name: 'storefront (live)' })))
      .toMatchObject({ status: 409, code: 'target_not_confirmed' })
  })

  it('statement and name validation, in that order, and a repo answers not_a_url_target', async () => {
    const s = createSession()
    await s.login('admin')
    const codebase = (await s.api.codebases.get(CONFIRMED_NOT_ACTIVE))
    expect(codebase.dast_active?.authorized).toBe(false)

    expect(await fails(s.api.codebases.authorizeActiveScanning(CONFIRMED_NOT_ACTIVE, { statement_accepted: false, codebase_name: codebase.name })))
      .toMatchObject({ status: 422, details: { field: 'statement_accepted' } })
    expect(await fails(s.api.codebases.authorizeActiveScanning(CONFIRMED_NOT_ACTIVE, { statement_accepted: true, codebase_name: 'not the name' })))
      .toMatchObject({ status: 422, details: { field: 'codebase_name' } })
    expect(await fails(s.api.codebases.authorizeActiveScanning(REPO, { statement_accepted: true, codebase_name: 'storefront' })))
      .toMatchObject({ status: 409, code: 'not_a_url_target' })

    const updated = await s.api.codebases.authorizeActiveScanning(CONFIRMED_NOT_ACTIVE, { statement_accepted: true, codebase_name: codebase.name })
    expect(updated.dast_active).toMatchObject({ authorized: true, authorized_by: { username: 'admin' } })
    expect(updated.dast_active?.authorized_at).toBeTruthy()
  })

  it('a Member with can_run_dast may authorize and revoke too; without it, the target is invisible (404)', async () => {
    const backend = createMockBackend()
    const dastMember = createSession({}, backend)
    await dastMember.login('dastMember')
    const r = await dastMember.api.codebases.authorizeActiveScanning(CONFIRMED_NOT_ACTIVE, { statement_accepted: true, codebase_name: 'status-page (live)' })
    expect(r.dast_active?.authorized).toBe(true)
    await dastMember.api.codebases.revokeActiveScanning(CONFIRMED_NOT_ACTIVE)
    expect((await dastMember.api.codebases.get(CONFIRMED_NOT_ACTIVE)).dast_active?.authorized).toBe(false)

    const member = createSession({}, backend)
    await member.login('member')
    expect(await fails(member.api.codebases.authorizeActiveScanning(CONFIRMED_NOT_ACTIVE, { statement_accepted: true, codebase_name: 'status-page (live)' })))
      .toMatchObject({ status: 404 })
  })

  it('revoke is idempotent (204 again, no error)', async () => {
    const s = createSession()
    await s.login('admin')
    await s.api.codebases.revokeActiveScanning(ALREADY_ACTIVE)
    expect((await s.api.codebases.get(ALREADY_ACTIVE)).dast_active?.authorized).toBe(false)
    await s.api.codebases.revokeActiveScanning(ALREADY_ACTIVE) // no throw
  })

  it('changing base_url revokes the active-scanning authorization too, cleared with dast_auth on an origin change', async () => {
    const s = createSession()
    await s.login('admin')
    const before = await s.api.codebases.get(ALREADY_ACTIVE)
    expect(before.dast_active?.authorized).toBe(true)
    const after = await s.api.codebases.patch(ALREADY_ACTIVE, { base_url: 'https://admin.example.com/v2' })
    expect(after.dast_active?.authorized).toBe(false)
    const other = await s.api.codebases.patch(ALREADY_ACTIVE, { base_url: 'https://another-host.example.com' })
    expect(other.dast_auth?.type).toBe('none')
  })

  it('POST /scans: active_timing without active, then confirmed, then authorized, in that order', async () => {
    const s = createSession()
    await s.login('admin')
    // The typed scans.create() wrapper never sends active_timing without active (the UI never needs to);
    // exercise the raw request to confirm the server itself still rejects that combination.
    expect(await fails(s.client.post('/scans', { codebase_id: CONFIRMED_NOT_ACTIVE, active_timing: true })))
      .toMatchObject({ status: 422, details: { field: 'active_timing' } })
    expect(await fails(s.api.scans.create(PENDING, { active: true })))
      .toMatchObject({ status: 409, code: 'target_not_confirmed' })
    expect(await fails(s.api.scans.create(CONFIRMED_NOT_ACTIVE, { active: true })))
      .toMatchObject({ status: 409, code: 'active_scanning_not_authorized' })
    // A plain passive scan still works.
    const passive = await s.api.scans.create(CONFIRMED_NOT_ACTIVE)
    expect(passive.active).toBe(false)
  })

  it('POST /scans: authorized active (+ timing) is accepted and recorded on the scan', async () => {
    const s = createSession()
    await s.login('admin')
    const scan = await s.api.scans.create(ALREADY_ACTIVE, { active: true, active_timing: true })
    expect(scan.active).toBe(true)
    expect(scan.active_timing).toBe(true)
    const fetched = await s.api.scans.get(scan.id)
    expect(fetched.active).toBe(true)
    expect(fetched.active_timing).toBe(true)
  })

  it('a schedule rejects active/active_timing rather than ignoring them', async () => {
    const s = createSession()
    await s.login('admin')
    expect(await fails(s.client.request('PUT', `/codebases/${ALREADY_ACTIVE}/schedule`, { body: { cron: '0 3 * * *', active: true } })))
      .toMatchObject({ status: 422, details: { field: 'active' } })
    expect(await fails(s.client.request('PUT', `/codebases/${ALREADY_ACTIVE}/schedule`, { body: { cron: '0 3 * * *', active_timing: true } })))
      .toMatchObject({ status: 422, details: { field: 'active_timing' } })
    const ok = await s.client.request('PUT', `/codebases/${ALREADY_ACTIVE}/schedule`, { body: { cron: '0 3 * * *' } })
    expect(ok).toBeTruthy()
  })
})
