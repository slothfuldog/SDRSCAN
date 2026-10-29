import type { ApiError } from '~/utils/errors';
import { isApiError } from '~/utils/errors'
import { appendLogLine, applyStatusEvent, isTerminal, splitLog } from '~/utils/scanStream'
import type { Scan, ScanStatusEvent } from '~/types/api'

/**
 * Live status of one Scan: SSE (GET /scans/{id}/events) with a polling fallback (GET /scans/{id} every 2 s)
 * when EventSource is unavailable or the stream breaks.
 */
export function useScanEvents(idSource: MaybeRefOrGetter<number | null | undefined>, options: { pollMs?: number, onFinished?: (scan: Scan) => void } = {}) {
  const config = useRuntimeConfig()
  const api = useApi()
  const scan = ref<Scan | null>(null)
  const lines = ref<string[]>([])
  const error = ref<ApiError | null>(null)
  const transport = ref<'idle' | 'sse' | 'polling'>('idle')
  const finished = computed(() => isTerminal(scan.value?.status))

  let es: EventSource | null = null
  let timer: ReturnType<typeof setInterval> | null = null
  let cursor = 0
  let run = 0

  function closeStreams() {
    if (es) { es.close(); es = null }
    if (timer) { clearInterval(timer); timer = null }
    transport.value = 'idle'
  }

  async function refreshOnce(mine: number): Promise<Scan | null> {
    try {
      const s = await api.scans.get(toValue(idSource) as number)
      if (mine !== run) return null
      scan.value = s
      lines.value = splitLog(s.log_tail)
      cursor = 0
      error.value = null
      return s
    } catch (e) {
      if (mine !== run) return null
      error.value = isApiError(e) ? e : null
      // The scan is gone or its codebase is no longer visible: stop streaming.
      if (isApiError(e) && e.status === 404) closeStreams()
      return null
    }
  }

  function done(s: Scan) {
    closeStreams()
    options.onFinished?.(s)
  }

  function startPolling(mine: number) {
    if (timer) return
    transport.value = 'polling'
    timer = setInterval(async () => {
      const s = await refreshOnce(mine)
      if (s && isTerminal(s.status)) done(s)
    }, options.pollMs ?? 2000)
  }

  function startSse(mine: number, id: number) {
    es = new EventSource(`${config.public.apiBase}/scans/${id}/events`)
    transport.value = 'sse'
    es.addEventListener('status', (ev) => {
      if (mine !== run) return
      try {
        const payload = JSON.parse((ev as MessageEvent).data) as ScanStatusEvent
        scan.value = applyStatusEvent(scan.value, payload)
        if (isTerminal(payload.status)) {
          // Final read for log_tail / error_code; the server closes the stream when the scan ends.
          closeStreams()
          void refreshOnce(mine).then((s) => { if (s) options.onFinished?.(s) })
        }
      } catch { /* ignore malformed event */ }
    })
    es.addEventListener('log', (ev) => {
      if (mine !== run) return
      try {
        const { line } = JSON.parse((ev as MessageEvent).data) as { line: string }
        const next = appendLogLine({ lines: lines.value, replayCursor: cursor }, line)
        lines.value = next.lines
        cursor = next.replayCursor
      } catch { /* ignore */ }
    })
    es.onerror = () => {
      if (mine !== run) return
      // Broken stream (proxy, restart): drop to polling.
      if (es) { es.close(); es = null }
      startPolling(mine)
    }
  }

  async function start() {
    closeStreams()
    const id = toValue(idSource)
    const mine = ++run
    scan.value = null
    lines.value = []
    error.value = null
    if (!id) return
    const s = await refreshOnce(mine)
    if (mine !== run) return
    if (!s) { if ((error.value as ApiError | null)?.status !== 404) startPolling(mine); return }
    if (isTerminal(s.status)) { options.onFinished?.(s); return }
    if (typeof EventSource !== 'undefined') startSse(mine, id)
    else startPolling(mine)
  }

  watch(() => toValue(idSource), () => { void start() }, { immediate: true })
  onScopeDispose(() => { run++; closeStreams() })

  return { scan, lines, error, transport, finished, restart: start, stop: closeStreams }
}
