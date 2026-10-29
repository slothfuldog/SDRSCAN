import type { Codebase, CodebaseRow, DastActiveInfo, DastStatus, Role } from '~/types/api'

// UI-side role rules (TRD "Hak per peran"). They only hide or disable controls; the server stays
// authoritative and answers 403 when a rule is violated.

export interface Actor {
  role: Role
  can_run_dast: boolean
}

type MaybeActor = Actor | null | undefined
/** Anything with a target type and (for url targets) a DAST status: Codebase rows (dast_status) or GET /codebases/{id} (dast.status).
 *  `dast_active` is only ever known on the full Codebase DTO; it is undefined (treated as "not authorized") elsewhere. */
export type TargetLike = {
  target_type: Codebase['target_type']
  dast_status?: DastStatus | null
  dast?: { status: DastStatus } | null
  dast_active?: DastActiveInfo | null
}

export function dastStatusOf(cb: TargetLike | Pick<CodebaseRow, 'target_type' | 'dast_status'>): DastStatus | null {
  const c = cb as TargetLike
  return c.dast?.status ?? c.dast_status ?? null
}

export const isAdmin = (u: MaybeActor): boolean => u?.role === 'admin'

/** Admin always; a Member only with can_run_dast. */
export const hasDastAccess = (u: MaybeActor): boolean => !!u && (u.role === 'admin' || u.can_run_dast === true)

/** Delete Project / Codebase: Admin only. */
export const canDeleteEntities = isAdmin
/** Users, ingest tokens and the activity log: Admin only. */
export const canManageUsers = isAdmin
export const canManageTokens = isAdmin
export const canViewActivity = isAdmin
/** Vulnerability database status and updates: Admin only. */
export const canManageVulnDb = isAdmin
/** Confirm authorization of a URL target: Admin only. */
export const canConfirmTarget = isAdmin
/** Register URL targets, change base URL / schedule: Admin or can_run_dast. */
export const canRegisterUrlTarget = hasDastAccess
export const canEditUrlTarget = hasDastAccess
/** Authorize/revoke active (payload-sending) scanning: Admin or can_run_dast, same as confirm's siblings. */
export const canAuthorizeActiveScanning = hasDastAccess

/** Whether active scanning is authorized for a target (false/undefined both mean "no", the safe default). */
export const activeScanningAuthorized = (cb: TargetLike): boolean => cb.dast_active?.authorized === true
/** Everyone logged in can create/edit Projects and repo Codebases. */
export const canEditProjects = (u: MaybeActor): boolean => !!u
export const canCancelScan = (u: MaybeActor): boolean => !!u

export type RunScanState =
  | { visible: false; enabled: false; reason: null }
  | { visible: true; enabled: true; reason: null }
  | { visible: true; enabled: false; reason: string }

export const TARGET_NOT_CONFIRMED_HINT = 'An Admin must confirm authorization for this target first.'

/**
 * Run scan control for one Codebase.
 * - repo: SAST for Admin and Member.
 * - url: hidden without DAST access; disabled until the target is confirmed.
 */
export function runScanState(u: MaybeActor, cb: TargetLike): RunScanState {
  if (!u) return { visible: false, enabled: false, reason: null }
  if (cb.target_type === 'repo') return { visible: true, enabled: true, reason: null }
  if (!hasDastAccess(u)) return { visible: false, enabled: false, reason: null }
  if (dastStatusOf(cb) !== 'confirmed') return { visible: true, enabled: false, reason: TARGET_NOT_CONFIRMED_HINT }
  return { visible: true, enabled: true, reason: null }
}

/** Target types that may be offered in the "Add codebase" form. */
export function allowedTargetTypes(u: MaybeActor): Array<'repo' | 'url'> {
  return hasDastAccess(u) ? ['repo', 'url'] : ['repo']
}

/**
 * Scan schedule: for repo codebases any user may set it; for URL targets only Admin or can_run_dast
 * (the owner of a DAST schedule must keep that permission, otherwise the schedule is suspended).
 */
export function canEditSchedule(u: MaybeActor, cb: Pick<Codebase, 'target_type'> | Pick<CodebaseRow, 'target_type'>): boolean {
  if (!u) return false
  return cb.target_type === 'repo' ? true : hasDastAccess(u)
}
