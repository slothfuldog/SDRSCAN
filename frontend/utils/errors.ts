import type { ApiErrorBody } from '~/types/api'

/** Error thrown by the API client for every non-2xx response and for network failures. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown
  readonly retryAfter: number | null
  readonly requestId: string | null

  constructor(init: {
    status: number
    code: string
    message: string
    details?: unknown
    retryAfter?: number | null
    requestId?: string | null
  }) {
    super(init.message)
    this.name = 'ApiError'
    this.status = init.status
    this.code = init.code
    this.details = init.details
    this.retryAfter = init.retryAfter ?? null
    this.requestId = init.requestId ?? null
  }

  get isNetwork(): boolean {
    return this.status === 0
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError
}

export const PRIVATE_NETWORK_TEXT = 'Private network addresses are not allowed.'

const PRIVATE_CODES = new Set(['private_address', 'private_network', 'address_not_allowed', 'blocked_address', 'forbidden_address', 'private_network_blocked'])

/** The backend refuses clone / DAST targets in loopback, link-local, metadata and private ranges. */
export function isPrivateNetworkError(e: unknown): boolean {
  if (!isApiError(e)) return false
  if (PRIVATE_CODES.has(e.code)) return true
  if (e.status === 422 || e.status === 400) return /private network|loopback|link-local|metadata|rfc ?1918|private address/i.test(e.message)
  return false
}

export function parseErrorBody(body: unknown): { code: string; message: string; details?: unknown } | null {
  if (!body || typeof body !== 'object') return null
  const err = (body as Partial<ApiErrorBody>).error
  if (!err || typeof err !== 'object') return null
  const { code, message, details } = err as ApiErrorBody['error']
  if (typeof code !== 'string') return null
  return { code, message: typeof message === 'string' ? message : '', details }
}

export type ErrorKind = 'auth' | 'forbidden' | 'not_found' | 'conflict' | 'validation' | 'throttled' | 'network' | 'server' | 'other'

export interface FriendlyError {
  kind: ErrorKind
  title: string
  message: string
  /** Whether a "Try again" button makes sense. */
  retryable: boolean
}

const FORBIDDEN_MESSAGES: Record<string, string> = {
  forbidden_role: 'You do not have permission to do this.',
  dast_forbidden: 'You need DAST access to do this. Ask an Admin to enable it for your account.',
  csrf_invalid: 'Your session security token is out of date. Reload the page and try again.',
  forbidden_origin: 'This request was rejected because it came from an unexpected origin.',
}

/** Turns any error into text suited for the UI. The backend message (English) is shown as-is when it adds information. */
export function friendlyError(e: unknown): FriendlyError {
  if (!isApiError(e)) {
    return {
      kind: 'other',
      title: 'Something went wrong',
      message: e instanceof Error && e.message ? e.message : 'An unexpected error occurred.',
      retryable: true,
    }
  }
  const msg = e.message
  if (isPrivateNetworkError(e)) return { kind: 'validation', title: 'Address not allowed', message: PRIVATE_NETWORK_TEXT, retryable: false }
  switch (true) {
    case e.status === 0:
      return { kind: 'network', title: 'Cannot reach the server', message: 'Check your connection and try again.', retryable: true }
    case e.status === 401:
      return { kind: 'auth', title: 'Sign in required', message: 'Your session has ended. Please sign in again.', retryable: false }
    case e.status === 403:
      return {
        kind: 'forbidden',
        title: 'Not allowed',
        message: FORBIDDEN_MESSAGES[e.code] ?? (msg || 'You do not have permission to do this.'),
        retryable: false,
      }
    case e.status === 404:
      return { kind: 'not_found', title: 'Not found', message: msg && e.code !== 'not_found' ? msg : 'We could not find what you were looking for. It may have been deleted or moved.', retryable: false }
    case e.status === 409:
      return { kind: 'conflict', title: 'Conflict', message: conflictMessage(e), retryable: false }
    case e.status === 429:
      return {
        kind: 'throttled',
        title: 'Too many attempts',
        message: e.retryAfter ? `Too many attempts. Try again in ${formatRetry(e.retryAfter)}.` : 'Too many attempts. Please wait and try again.',
        retryable: false,
      }
    case e.code === 'invalid_cron':
      return { kind: 'validation', title: 'Check your input', message: msg || 'The cron expression is not valid. Use 5 fields, for example "0 2 * * 1" (UTC).', retryable: false }
    case e.code === 'schedule_too_frequent':
      return { kind: 'validation', title: 'Check your input', message: msg || 'This schedule runs too often. The minimum interval is 15 minutes for SAST and 60 minutes for DAST.', retryable: false }
    case e.status === 422 || e.status === 400:
      return { kind: 'validation', title: 'Check your input', message: msg || 'The request was not valid.', retryable: false }
    case e.code === 'secret_key_required':
      return { kind: 'server', title: 'Credentials cannot be stored', message: 'The server has no encryption key (SDRSCAN_SECRET_KEY), so credentials cannot be stored. Ask the operator to configure it.', retryable: false }
    case e.code === 'engine_unsupported':
      return { kind: 'server', title: 'Engine too old', message: 'The installed DAST engine does not support authenticated scans yet. Ask the operator to update it.', retryable: false }
    case e.status >= 500:
      return { kind: 'server', title: 'Server error', message: e.status === 503 ? (msg || 'The service is busy or unavailable. Try again shortly.') : 'The server could not complete the request. Try again shortly.', retryable: true }
    default:
      return { kind: 'other', title: 'Request failed', message: msg || `The request failed (${e.status}).`, retryable: true }
  }
}

function conflictMessage(e: ApiError): string {
  switch (e.code) {
    case 'scan_in_progress': return 'A scan is already queued or running for this codebase.'
    case 'target_not_confirmed': return 'An Admin must confirm authorization for this target first.'
    case 'last_admin': return 'There must be at least one active Admin.'
    case 'username_taken': return 'That username is already taken.'
    case 'name_taken': return 'That name is already in use.'
    case 'baseline_required': return 'A full scan is required first.'
    case 'update_in_progress': return 'A vulnerability database update is already running.'
    case 'vulndb_not_configured': return 'The vulnerability database is not configured on the server (SDRSCAN_VULN_DB is empty).'
    case 'vuln_tool_unavailable': return 'The sdrscan-vuln tool is not available on the server, so the database cannot be updated.'
    case 'no_update_running': return 'No vulnerability database update is running.'
    case 'schedule_not_suspended': return 'This schedule is not suspended, so there is nothing to resume.'
    case 'no_auth_configured': return 'No authentication is saved for this target yet.'
    case 'no_login_configured': return 'Only a login form can be tested. Fixed headers and cookies have no login step.'
    case 'test_in_progress': return 'A login test is already running for this target. Wait a moment and try again.'
    case 'target_changed': return 'The target URL changed while saving. Reload the page and try again.'
    case 'auth_unreadable': return 'The saved credentials cannot be read (the server key changed). Remove them and enter them again.'
    case 'not_a_url_target': return 'Authentication applies only to URL targets.'
    default: return e.message || 'This action conflicts with the current state. Reload and try again.'
  }
}

/** "5 minutes" / "30 seconds" for Retry-After values (seconds). */
export function formatRetry(seconds: number): string {
  if (seconds >= 60) {
    const m = Math.ceil(seconds / 60)
    return `${m} minute${m === 1 ? '' : 's'}`
  }
  const s = Math.max(1, Math.ceil(seconds))
  return `${s} second${s === 1 ? '' : 's'}`
}
