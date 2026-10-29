// @vitest-environment node
import { describe, expect, it, vi } from 'vitest'
import { buildQuery, createApiClient, joinUrl } from '~/utils/apiClient'
import { createEndpoints } from '~/utils/endpoints'
import { ApiError } from '~/utils/errors'

function jsonResponse(status: number, body?: unknown, headers: Record<string, string> = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

function setup(fetchImpl: typeof fetch, csrf: string | null = 'csrf-123') {
  const onUnauthorized = vi.fn()
  const client = createApiClient({ baseURL: '/api/v1', fetch: fetchImpl, getCsrfToken: () => csrf, onUnauthorized })
  return { client, onUnauthorized, api: createEndpoints(client) }
}

describe('api client', () => {
  it('builds query strings without empty values and joins arrays with commas', () => {
    expect(buildQuery({ page: 2, severity: ['high', 'critical'], rule: '', q: undefined, flag: false, x: null })).toBe('?page=2&severity=high%2Ccritical&flag=false')
    expect(buildQuery({})).toBe('')
    expect(joinUrl('/api/v1/', '/projects')).toBe('/api/v1/projects')
  })

  it('uses a relative base path, same-origin credentials and no CSRF header on GET', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { items: [], total: 0, page: 1, page_size: 50 }))
    const { api } = setup(fetchMock as unknown as typeof fetch)
    await api.projects.list({ page: 1, page_size: 50 })
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/v1/projects?page=1&page_size=50')
    expect(init.method).toBe('GET')
    expect(init.credentials).toBe('same-origin')
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined()
  })

  it('sends X-CSRF-Token and a JSON content type on every write', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(201, { id: 1, name: 'x', description: '' }))
    const { api } = setup(fetchMock as unknown as typeof fetch)
    await api.projects.create({ name: 'x', description: '' })
    await api.scans.cancel(5)
    for (const call of fetchMock.mock.calls as unknown as Array<[string, RequestInit]>) {
      const h = call[1].headers as Record<string, string>
      expect(h['X-CSRF-Token']).toBe('csrf-123')
      expect(h['Content-Type']).toBe('application/json')
    }
    expect((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body).toBe(JSON.stringify({ name: 'x', description: '' }))
  })

  it('passes ?confirm=<name> on permanent deletes', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { deleted: { codebases: 1, scans: 2, findings: 3 } }))
    const { api } = setup(fetchMock as unknown as typeof fetch)
    await api.projects.remove(3, 'Online Shop')
    expect((fetchMock.mock.calls[0] as unknown as [string])[0]).toBe('/api/v1/projects/3?confirm=Online+Shop')
  })

  it('parses the error format and exposes code, message, details and Retry-After', async () => {
    const body = { error: { code: 'login_throttled', message: 'Too many attempts.', details: { n: 1 } } }
    const { api } = setup((async () => jsonResponse(429, body, { 'Retry-After': '900', 'X-Request-Id': 'rid-1' })) as unknown as typeof fetch)
    const err = await api.auth.login('a', 'b').catch(e => e) as ApiError
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 429, code: 'login_throttled', message: 'Too many attempts.', retryAfter: 900, requestId: 'rid-1', details: { n: 1 } })
  })

  it('calls onUnauthorized on 401, except for login and the session probe', async () => {
    const { api, onUnauthorized } = setup((async () => jsonResponse(401, { error: { code: 'not_authenticated', message: 'No' } })) as unknown as typeof fetch)
    await expect(api.projects.list()).rejects.toMatchObject({ status: 401 })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
    await expect(api.auth.me()).rejects.toMatchObject({ status: 401 })
    await expect(api.auth.login('a', 'b')).rejects.toMatchObject({ status: 401 })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  it('returns undefined for 204 and maps network failures to status 0', async () => {
    const { api } = setup((async () => new Response(null, { status: 204 })) as unknown as typeof fetch)
    await expect(api.auth.logout()).resolves.toBeUndefined()
    const down = setup((async () => { throw new TypeError('failed to fetch') }) as unknown as typeof fetch)
    const err = await down.api.projects.list().catch(e => e) as ApiError
    expect(err.isNetwork).toBe(true)
    expect(err.code).toBe('network_error')
  })

  it('survives non-JSON error bodies (proxy pages)', async () => {
    const { api } = setup((async () => new Response('<html>bad gateway</html>', { status: 502, statusText: 'Bad Gateway' })) as unknown as typeof fetch)
    const err = await api.projects.list().catch(e => e) as ApiError
    expect(err).toMatchObject({ status: 502, code: 'http_error' })
  })

  it('confirm-authorization sends statement_accepted: true', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { dast_status: 'confirmed' }))
    const { api } = setup(fetchMock as unknown as typeof fetch)
    await api.codebases.confirmAuthorization(8)
    expect((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body).toBe(JSON.stringify({ statement_accepted: true }))
  })
})
