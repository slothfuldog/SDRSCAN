import { createMockBackend, SEED_CREDENTIALS } from '../../mock/core.ts'
import type { MockBackend, MockOptions } from '../../mock/core.ts'
import { createApiClient } from '~/utils/apiClient'
import { createEndpoints } from '~/utils/endpoints'

export { SEED_CREDENTIALS }

/** A fetch() that talks to the in-memory mock backend and keeps a cookie jar, like a browser would. */
export function createMockFetch(backend: MockBackend) {
  let cookie = ''
  const impl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), 'http://localhost')
    const headers: Record<string, string> = {}
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) headers[k.toLowerCase()] = v
    if (cookie) headers.cookie = cookie
    const body = typeof init?.body === 'string' && init.body ? JSON.parse(init.body) : undefined
    const out = backend.handle({ method: init?.method ?? 'GET', path: url.pathname, query: url.searchParams, headers, body })
    const set = out.headers['Set-Cookie']
    if (set) cookie = set.includes('Max-Age=0') ? '' : (set.split(';')[0] ?? '')
    const respHeaders: Record<string, string> = { 'Content-Type': 'application/json' }
    if (out.headers['Retry-After']) respHeaders['Retry-After'] = out.headers['Retry-After']
    return new Response(out.status === 204 ? null : JSON.stringify(out.body), { status: out.status, headers: respHeaders })
  }
  return { fetch: impl as typeof fetch, getCookie: () => cookie }
}

export interface Session {
  backend: MockBackend
  api: ReturnType<typeof createEndpoints>
  client: ReturnType<typeof createApiClient>
  csrf: () => string | null
  login: (who: keyof typeof SEED_CREDENTIALS) => Promise<void>
}

export function createSession(options: MockOptions = {}, backend: MockBackend = createMockBackend(options)): Session {
  const { fetch } = createMockFetch(backend)
  let csrf: string | null = null
  const client = createApiClient({ baseURL: '/api/v1', fetch, getCsrfToken: () => csrf })
  const api = createEndpoints(client)
  return {
    backend,
    api,
    client,
    csrf: () => csrf,
    async login(who) {
      const c = SEED_CREDENTIALS[who]
      const res = await api.auth.login(c.username, c.password)
      csrf = res.csrf_token
    },
  }
}
