// @vitest-environment node
import { describe, expect, it } from 'vitest'
import { ApiError, friendlyError, isPrivateNetworkError, parseErrorBody } from '~/utils/errors'

const err = (status: number, code: string, message = '', retryAfter: number | null = null) => new ApiError({ status, code, message, retryAfter })

describe('friendly errors', () => {
  it('401, 403, 404, 409 get friendly text', () => {
    expect(friendlyError(err(401, 'not_authenticated')).kind).toBe('auth')
    expect(friendlyError(err(403, 'forbidden_role', 'x')).message).toBe('You do not have permission to do this.')
    expect(friendlyError(err(403, 'dast_forbidden')).message).toMatch(/DAST access/)
    expect(friendlyError(err(404, 'not_found', 'Project not found.')).kind).toBe('not_found')
    expect(friendlyError(err(409, 'scan_in_progress')).message).toMatch(/already queued or running/)
    expect(friendlyError(err(409, 'last_admin')).message).toMatch(/at least one active Admin/)
    expect(friendlyError(err(409, 'target_not_confirmed')).message).toBe('An Admin must confirm authorization for this target first.')
  })

  it('shows the throttle wait time and offers retry only for transient errors', () => {
    expect(friendlyError(err(429, 'login_throttled', '', 900)).message).toBe('Too many attempts. Try again in 15 minutes.')
    expect(friendlyError(err(0, 'network_error')).retryable).toBe(true)
    expect(friendlyError(err(500, 'internal')).retryable).toBe(true)
    expect(friendlyError(err(403, 'forbidden_role')).retryable).toBe(false)
  })

  it('uses the plain message for private network addresses', () => {
    expect(isPrivateNetworkError(err(422, 'validation_failed', 'base_url resolves to a private network address'))).toBe(true)
    expect(isPrivateNetworkError(err(422, 'private_address', ''))).toBe(true)
    expect(isPrivateNetworkError(err(422, 'validation_failed', 'name too long'))).toBe(false)
    expect(friendlyError(err(422, 'validation_failed', 'repo_url points to a loopback address')).message).toBe('Private network addresses are not allowed.')
  })

  it('parses the documented error body shape only', () => {
    expect(parseErrorBody({ error: { code: 'x', message: 'm', details: [1] } })).toEqual({ code: 'x', message: 'm', details: [1] })
    expect(parseErrorBody({ message: 'nope' })).toBeNull()
    expect(parseErrorBody(null)).toBeNull()
  })
})
