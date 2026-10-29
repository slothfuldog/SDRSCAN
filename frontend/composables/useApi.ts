import { createApiClient } from '~/utils/apiClient'
import { createEndpoints } from '~/utils/endpoints'

/**
 * Typed API layer (single wrapper): adds X-CSRF-Token to writes, sends the session cookie,
 * and sends the user to the login page on any 401. Call it at the top of `setup`.
 */
export function useApi() {
  const config = useRuntimeConfig()
  const auth = useAuth()
  const client = createApiClient({
    baseURL: config.public.apiBase,
    getCsrfToken: () => auth.csrfToken,
    onUnauthorized: () => { void auth.sessionExpired() },
  })
  return { client, ...createEndpoints(client) }
}
