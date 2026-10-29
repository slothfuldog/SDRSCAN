import type { Scan, ScanStatus, ScanStatusEvent } from '~/types/api'

export const TERMINAL_STATUSES: readonly ScanStatus[] = ['succeeded', 'failed', 'cancelled']

export function isTerminal(status: ScanStatus | string | null | undefined): boolean {
  return !!status && (TERMINAL_STATUSES as readonly string[]).includes(status)
}

export function isActive(status: ScanStatus | string | null | undefined): boolean {
  return status === 'queued' || status === 'running'
}

export function splitLog(tail: string | null | undefined): string[] {
  if (!tail) return []
  return tail.split('\n').map(l => l.replace(/\r$/, '')).filter(l => l.length > 0)
}

/** Merge an SSE `status` payload into the scan we already hold. */
export function applyStatusEvent(scan: Scan | null, ev: ScanStatusEvent): Scan | null {
  if (!scan) return scan
  return {
    ...scan,
    status: ev.status,
    started_at: ev.started_at ?? scan.started_at,
    finished_at: ev.finished_at ?? scan.finished_at,
    summary: ev.summary ?? scan.summary,
  }
}

/**
 * Append one SSE `log` line. The server may replay the lines we already got from `log_tail`;
 * `replayCursor` walks through the known lines so replayed ones are skipped, new ones appended.
 */
export function appendLogLine(
  state: { lines: string[]; replayCursor: number },
  line: string,
): { lines: string[]; replayCursor: number } {
  if (state.replayCursor < state.lines.length && state.lines[state.replayCursor] === line) {
    return { lines: state.lines, replayCursor: state.replayCursor + 1 }
  }
  return { lines: [...state.lines, line], replayCursor: state.lines.length + 1 }
}

export const STATUS_LABEL: Record<ScanStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  succeeded: 'Succeeded',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

const ERROR_TEXT: Record<string, string> = {
  clone_failed: 'The repository could not be cloned. Check the URL, branch and credentials.',
  repo_too_large: 'The repository is too large to scan.',
  engine_failed: 'The scan engine failed.',
  engine_not_found: 'The scan engine is not installed on the server.',
  timeout: 'The scan took too long and was stopped.',
  invalid_sarif: 'The engine produced a result that could not be read.',
  worker_lost: 'The worker handling this scan was lost. Run the scan again.',
  target_not_confirmed: 'The target is no longer confirmed. An Admin must confirm authorization again.',
  private_address: 'Private network addresses are not allowed.',
  private_network: 'Private network addresses are not allowed.',
  address_not_allowed: 'Private network addresses are not allowed.',
  blocked_address: 'Private network addresses are not allowed.',
}

export function scanErrorText(code: string | null | undefined): string {
  if (!code) return ''
  return ERROR_TEXT[code] ?? `The scan failed (${code}).`
}
