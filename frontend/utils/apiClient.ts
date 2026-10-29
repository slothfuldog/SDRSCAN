import { ApiError, parseErrorBody } from './errors'

export type Query = Record<string, string | number | boolean | Array<string | number> | null | undefined>

export interface ApiClientOptions {
  /** e.g. "/api/v1" (relative: one origin). */
  baseURL: string
  /** Defaults to globalThis.fetch. Injectable for tests. */
  fetch?: typeof fetch
  /** The CSRF token lives in memory only (never localStorage). */
  getCsrfToken: () => string | null | undefined
  /** Called on every 401 except for requests flagged `noAuthRedirect`. */
  onUnauthorized?: (err: ApiError) => void
}

export interface RequestOptions {
  query?: Query
  body?: unknown
  signal?: AbortSignal
  /** Login / session probe: a 401 is an expected answer, not a "session expired" event. */
  noAuthRedirect?: boolean
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/** Serialises query values; skips undefined/null/empty strings and joins arrays with commas. */
export function buildQuery(query?: Query): string {
  if (!query) return ''
  const params = new URLSearchParams()
  for (const [key, raw] of Object.entries(query)) {
    if (raw === undefined || raw === null || raw === '') continue
    if (Array.isArray(raw)) {
      if (raw.length === 0) continue
      params.set(key, raw.join(','))
    } else {
      params.set(key, String(raw))
    }
  }
  const s = params.toString()
  return s ? `?${s}` : ''
}

export function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`
}

function parseRetryAfter(value: string | null): number | null {
  if (!value) return null
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? n : null
}

export interface ApiClient {
  request<T>(method: string, path: string, opts?: RequestOptions): Promise<T>
  get<T>(path: string, query?: Query, opts?: Omit<RequestOptions, 'query' | 'body'>): Promise<T>
  post<T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'body'>): Promise<T>
  patch<T>(path: string, body?: unknown, opts?: Omit<RequestOptions, 'body'>): Promise<T>
  del<T>(path: string, query?: Query, opts?: Omit<RequestOptions, 'query' | 'body'>): Promise<T>
}

export function createApiClient(options: ApiClientOptions): ApiClient {
  async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis)
    const upper = method.toUpperCase()
    const headers: Record<string, string> = { Accept: 'application/json' }
    let body: string | undefined

    if (!SAFE_METHODS.has(upper)) {
      // The backend requires JSON on every write and the CSRF header on every non-GET request.
      headers['Content-Type'] = 'application/json'
      const csrf = options.getCsrfToken()
      if (csrf) headers['X-CSRF-Token'] = csrf
      if (opts.body !== undefined) body = JSON.stringify(opts.body)
    }

    const url = joinUrl(options.baseURL, path) + buildQuery(opts.query)
    let res: Response
    try {
      res = await fetchImpl(url, {
        method: upper,
        headers,
        body,
        credentials: 'same-origin',
        cache: 'no-store',
        signal: opts.signal,
      })
    } catch (cause) {
      if (opts.signal?.aborted) throw cause
      throw new ApiError({ status: 0, code: 'network_error', message: 'Cannot reach the server.' , details: cause instanceof Error ? cause.message : undefined })
    }

    if (res.status === 204) return undefined as T

    const text = await res.text()
    let parsed: unknown = undefined
    if (text) {
      try {
        parsed = JSON.parse(text)
      } catch {
        parsed = undefined
      }
    }

    if (!res.ok) {
      const info = parseErrorBody(parsed)
      const err = new ApiError({
        status: res.status,
        code: info?.code ?? 'http_error',
        message: info?.message || res.statusText || `Request failed (${res.status})`,
        details: info?.details,
        retryAfter: parseRetryAfter(res.headers.get('Retry-After')),
        requestId: res.headers.get('X-Request-Id'),
      })
      if (res.status === 401 && !opts.noAuthRedirect) options.onUnauthorized?.(err)
      throw err
    }

    if (parsed === undefined && text) {
      throw new ApiError({ status: res.status, code: 'invalid_response', message: 'The server sent a response that could not be read.' })
    }
    return parsed as T
  }

  return {
    request,
    get: (path, query, opts) => request('GET', path, { ...opts, query }),
    post: (path, body, opts) => request('POST', path, { ...opts, body }),
    patch: (path, body, opts) => request('PATCH', path, { ...opts, body }),
    del: (path, query, opts) => request('DELETE', path, { ...opts, query }),
  }
}
