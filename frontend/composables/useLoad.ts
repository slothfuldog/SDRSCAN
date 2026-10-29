import type { WatchSource } from 'vue'
import { ApiError, isApiError } from '~/utils/errors'

export interface UseLoadOptions {
  /** Reload whenever one of these sources changes. */
  watch?: WatchSource[]
  immediate?: boolean
  /** Keep showing previous data while reloading (filters, paging). Default true. */
  keepPrevious?: boolean
}

/** Small data loader: { data, error, pending, reload }. Late responses of superseded loads are ignored. */
export function useLoad<T>(fn: () => Promise<T>, options: UseLoadOptions = {}) {
  const data = ref<T>() as Ref<T | undefined>
  const error = ref<ApiError | null>(null)
  const pending = ref(false)
  let ticket = 0

  async function reload(): Promise<void> {
    const mine = ++ticket
    pending.value = true
    error.value = null
    if (options.keepPrevious === false) data.value = undefined
    try {
      const res = await fn()
      if (mine !== ticket) return
      data.value = res
    } catch (e) {
      if (mine !== ticket) return
      error.value = isApiError(e) ? e : new ApiError({ status: 0, code: 'client_error', message: e instanceof Error ? e.message : 'Unexpected error' })
    } finally {
      if (mine === ticket) pending.value = false
    }
  }

  if (options.watch?.length) watch(options.watch, () => { void reload() })
  if (options.immediate !== false) void reload()

  return { data, error, pending, reload }
}
