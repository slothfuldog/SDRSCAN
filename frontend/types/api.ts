// DTOs of the SDRScan REST API (TRD "API REST backend", base path /api/v1).
// Where the TRD only shows examples, optional fields are marked with `?` and read defensively.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Role = 'admin' | 'member'
export type TargetType = 'repo' | 'url'
export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'
export type ScanCoverage = 'full' | 'partial'
export type ScanTrigger = 'manual' | 'schedule' | 'ci'
export type ScanType = 'sast' | 'dast'
export type DastStatus = 'pending_confirmation' | 'confirmed'
export type GitAuthKind = 'none' | 'https_token' | 'ssh_key'
export type ScheduleStatus = 'active' | 'suspended'
export type SuspendedReason = 'owner_deactivated' | 'owner_lost_permission'
export type CompareStatus = 'new' | 'unchanged' | 'fixed'

/** Error body: { "error": { "code", "message", "details" } } */
export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown }
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

/** Five counters; `highest_severity` is null when there are no findings. */
export interface SeveritySummary {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  highest_severity?: Severity | null
}

// ---- auth and users -------------------------------------------------------

export interface User {
  id: number
  username: string
  role: Role
  can_run_dast: boolean
  is_active?: boolean
  last_login_at?: string | null
  must_change_password?: boolean
}

export interface LoginResponse {
  user: User
  csrf_token: string
  must_change_password?: boolean
}

export interface MeResponse {
  user: User
  csrf_token: string
  must_change_password: boolean
}

export interface UserRow extends User {
  is_active: boolean
  last_login_at: string | null
}

export interface CreateUserBody {
  username: string
  password: string
  role: Role
  can_run_dast?: boolean
}

export interface PatchUserBody {
  role?: Role
  is_active?: boolean
  can_run_dast?: boolean
}

// ---- projects and codebases -------------------------------------------------

export interface Project {
  id: number
  name: string
  description: string
  created_at?: string
  updated_at?: string
}

/** Row of GET /projects. Counts and totals only cover Codebases visible to the caller. */
export interface ProjectListItem extends Project {
  codebase_count: number
  /** Always an object (zeros when nothing was scanned). */
  totals: SeveritySummary
  highest_severity: Severity | null
  created_at: string
}

export interface ScanRef {
  id: number
  coverage: ScanCoverage
  status: ScanStatus
  started_at: string | null
  ref: string
  type?: ScanType
}

export interface CodebaseState {
  base_scan_id: number
  partial_scans_since_base: number
}

export interface CodebaseRow {
  id: number
  name: string
  target_type: TargetType
  subdirectory?: string
  language?: string
  dast_status?: DastStatus | null
  latest_scan: ScanRef | null
  state: CodebaseState | null
  /** null = "Not scanned yet" */
  summary: SeveritySummary | null
}

export interface ProjectDashboard {
  project: Project
  totals: SeveritySummary
  codebases: CodebaseRow[]
}

export interface UserRef {
  id: number
  username: string
}

export interface DastInfo {
  status: DastStatus
  registered_by: UserRef | null
  confirmed_by: UserRef | null
  confirmed_at: string | null
}

/**
 * Active (payload-sending) DAST scanning authorization: a SEPARATE, stricter layer on top of `dast`
 * above. While `authorized` is false, a DAST scan can only ever run passively, whatever is requested.
 */
export interface DastActiveInfo {
  authorized: boolean
  authorized_at: string | null
  authorized_by: UserRef | null
  /** Optional OpenAPI/Swagger spec location; null relies on auto-discovery during the crawl only. */
  openapi_spec_url: string | null
}

/** Queued or running Scan embedded in GET /codebases/{id}. */
export interface ActiveScan {
  id: number
  type: ScanType
  status: ScanStatus
  trigger: ScanTrigger
  queued_at: string | null
  started_at: string | null
}

/** GET /codebases/{id}. Keys that do not apply are null, never missing. */
export interface Codebase {
  id: number
  project_id?: number
  project: { id: number, name: string }
  name: string
  target_type: TargetType
  language: string
  repo_url: string | null
  branch: string | null
  subdirectory: string | null
  git_auth_kind: GitAuthKind | null
  git_username: string | null
  /** The secret itself is write-only and never returned. */
  has_credential: boolean | null
  base_url: string | null
  dast_max_rps: number | null
  /** url targets only. */
  dast: DastInfo | null
  /** url targets only: a separate, stricter authorization on top of `dast`. */
  dast_active: DastActiveInfo | null
  /** Text the Admin approves; only for url targets in pending_confirmation. Shown as sent by the server. */
  confirmation_statement: string | null
  summary: SeveritySummary | null
  latest_scan: ScanRef | null
  base_scan: ScanRef | null
  state: CodebaseState | null
  active_scan: ActiveScan | null
  schedule: CodebaseSchedule | null
  /** url targets only (null for repositories). Never carries a password, token or header/cookie value. */
  dast_auth: DastAuth | null
  /** url targets only. */
  dast_crawl: DastCrawl | null
  created_at: string
  updated_at: string
}

// ---- DAST authentication and crawling ---------------------------------------

export type DastAuthType = 'none' | 'form' | 'header' | 'form+header'
export type LoginMethod = 'POST' | 'PUT' | 'PATCH'
export type LoginBodyFormat = 'form' | 'json'
export type CsrfSource = 'html_input' | 'cookie' | 'header'
export type CsrfSendAs = 'field' | 'header'

export interface DastAuthCsrf {
  source: CsrfSource
  name: string
  send_as: CsrfSendAs
  header_name: string | null
}

export type TokenFrom = 'json' | 'header'
export type TokenSendAs = 'header' | 'cookie'

/** Where to read a token from the login response and how to send it back. The token value itself is dynamic and never stored. */
export interface DastAuthToken {
  from: TokenFrom
  /** Dotted JSON path (data.access_token, items[0].token) or a response header name when `from` is header. */
  path: string
  send_as: TokenSendAs
  header_name: string | null
  /** Value prefix, for example "Bearer ". Null means none / the default. */
  prefix: string | null
  cookie_name: string | null
}

export interface DastAuthSuccess {
  statuses: number[]
  cookie_set: string | null
  body_contains: string | null
  body_not_contains: string | null
  redirect_not_to: string | null
  json_path_exists?: string | null
  json_path_equals?: { path: string, value: string | number | boolean } | null
}

/** GET/PUT /codebases/{id}/dast-auth and `dast_auth` of GET /codebases/{id}: the non-secret description. */
export interface DastAuth {
  type: DastAuthType
  /** True while credentials are stored (write-only: the values are never returned). */
  has_secret: boolean
  login_url: string | null
  method: LoginMethod | null
  body_format: LoginBodyFormat | null
  username_field: string | null
  password_field: string | null
  username: string | null
  extra_field_names: string[]
  csrf: DastAuthCsrf | null
  /** Token read from the login response (optional in fixtures; the API always sends it, null when unused). */
  token?: DastAuthToken | null
  success: DastAuthSuccess | null
  header_names: string[]
  cookie_names: string[]
  updated_at: string | null
  updated_by: { id: number, username: string } | null
}

/** Body of PUT /codebases/{id}/dast-auth. A blank secret keeps the stored value of the same name. */
export interface DastAuthBody {
  type: Exclude<DastAuthType, 'none'>
  login?: {
    url: string
    method: LoginMethod
    body_format: LoginBodyFormat
    username_field: string
    password_field: string
    username: string
    password: string
    extra_fields?: Record<string, string>
    csrf?: { source: CsrfSource, name: string, send_as: CsrfSendAs, header_name?: string }
    token?: { from: TokenFrom, path: string, send_as: TokenSendAs, header_name?: string, prefix?: string, cookie_name?: string }
    success?: {
      statuses?: number[], cookie_set?: string, body_contains?: string, body_not_contains?: string, redirect_not_to?: string
      json_path_exists?: string, json_path_equals?: { path: string, value: string }
    }
  }
  headers?: Record<string, string>
  cookies?: Record<string, string>
}

export interface LoginCheckResult {
  ok: boolean
  message: string
}

export interface DastCrawl {
  enabled: boolean
  max_depth: number
  max_pages: number
  exclude: string[]
}

export interface CreateCodebaseBody {
  name: string
  target_type: TargetType
  language?: string
  repo_url?: string
  branch?: string
  subdirectory?: string
  git_auth_kind?: GitAuthKind
  git_username?: string
  git_secret?: string
  base_url?: string
}

export type PatchCodebaseBody = Partial<Omit<CreateCodebaseBody, 'target_type'>> & {
  project_id?: number
  dast_max_rps?: number
  dast_crawl_enabled?: boolean
  dast_crawl_max_depth?: number
  dast_crawl_max_pages?: number
  dast_crawl_exclude?: string[]
  /** Optional OpenAPI/Swagger spec URL for active scanning; empty string or null clears it. */
  dast_openapi_spec_url?: string | null
}

/** Body of POST/DELETE /codebases/{id}/authorize-active-scanning. */
export interface AuthorizeActiveScanningBody {
  statement_accepted: boolean
  /** Must exactly match the codebase's name: deliberate friction for this riskier authorization. */
  codebase_name: string
}

export interface DeleteResult {
  deleted: { codebases?: number; scans?: number; findings?: number }
}

// ---- scans ---------------------------------------------------------------

export interface Scan {
  id: number
  codebase_id: number
  type: ScanType
  coverage: ScanCoverage
  trigger: ScanTrigger
  status: ScanStatus
  queued_at?: string | null
  started_at: string | null
  finished_at: string | null
  ref?: string
  engine?: string | null
  engine_version?: string | null
  scanned_file_count?: number | null
  summary?: SeveritySummary | null
  log_tail?: string | null
  error_code?: string | null
  /** Active (payload-sending) DAST scanning, and its time-based SQLi extra. Always false for sast. */
  active?: boolean
  active_timing?: boolean
}

/** Payload of SSE `event: status`. */
export interface ScanStatusEvent {
  status: ScanStatus
  started_at?: string | null
  finished_at?: string | null
  summary?: SeveritySummary
}

// ---- findings --------------------------------------------------------------

export interface FileLocation {
  kind: 'file'
  path: string
  start_line?: number | null
  start_column?: number | null
  end_line?: number | null
  end_column?: number | null
}

export interface UrlLocation {
  kind: 'url'
  url: string
}

export type FindingLocation = FileLocation | UrlLocation

export type FindingKind = 'code' | 'vulnerability'
export type VulnSource = 'osv' | 'nvd'
export type VulnConfidence = 'high' | 'low'
export type VulnScope = 'runtime' | 'dev'

/** SCA packages carry {ecosystem, name, version}; DAST products {product, version}. Keys that do not apply may be missing or null. */
export interface VulnPackage {
  ecosystem?: string | null
  name?: string | null
  version?: string | null
  product?: string | null
}

/** `vulnerability` of a finding (null for code findings). All keys are always present; ids: CVE first, then GHSA/OSV ids. */
export interface Vulnerability {
  ids: string[]
  package: VulnPackage | null
  fixed_versions: string[]
  source: VulnSource | null
  /** At most 5; the server only sends http/https, the UI checks again before linking. */
  references: string[]
  cvss: { score: number, vector: string | null } | null
  confidence: VulnConfidence | null
  scope: VulnScope | null
}

/** List row of the findings endpoints and of compare. */
export interface FindingSummary {
  id: number
  rule_id: string
  severity: Severity
  confidence: 'normal' | 'low'
  message: string
  location: FindingLocation
  redacted: boolean
  kind: FindingKind
  vulnerability: Vulnerability | null
}

/** GET /findings/{id}. */
export interface Finding extends FindingSummary {
  scan_id: number
  codebase_id: number
  is_current: boolean
  snippet: string
  cwe: string[]
  fingerprint: string
}

export interface FacetRule {
  id: string
  count: number
}

export interface FindingFacets {
  /** Always the five severities. */
  severity: Record<Severity, number>
  /** Sorted by count descending, then id; the selected rule is present even with count 0. */
  rule: FacetRule[]
  /** Counts ignoring the `kind` filter. */
  kind: Record<FindingKind, number>
  /** CVE ids only, top 100, ignoring the `cve` filter. */
  cve: FacetRule[]
  /** Vulnerability findings per `vulnerability.confidence`, ignoring the `confidence` filter. */
  confidence: Record<VulnConfidence, number>
  /** Vulnerability findings per `vulnerability.scope`, ignoring the `scope` filter. */
  scope: Record<VulnScope, number>
  /** Distinct package@version among vulnerability findings, ignoring the kind and cve filters. */
  vulnerable_packages: number
}

export interface FindingsPage extends Page<FindingSummary> {
  facets: FindingFacets
}

export interface FileRow extends Partial<SeveritySummary> {
  location: string
  total: number
  kind?: 'file' | 'url'
}

export interface CompareScan {
  id: number
  started_at: string | null
  coverage: ScanCoverage
}

export interface CompareItem {
  status: CompareStatus
  finding: FindingSummary
}

export interface CompareResponse extends Page<CompareItem> {
  /** null when the codebase has only one scan. */
  base: CompareScan | null
  head: CompareScan
  counts: Record<CompareStatus, number>
  scope: { kind: 'all' | 'partial', file_count?: number }
  /** empty_scope when two partial scans share no scanned file. */
  warning: { code: string, message: string } | null
  status: CompareStatus
}

// ---- tokens and system -------------------------------------------------------

export interface IngestToken {
  id: number
  name: string
  token_prefix: string
  project: { id: number, name: string } | null
  created_by: UserRef | null
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
  status: 'active' | 'revoked'
}

/** POST /ingest-tokens (201): the raw secret appears only in this response. */
export interface CreatedIngestToken {
  token: IngestToken
  secret: string
}

export interface SystemInfo {
  backend_version: string
  sast_version?: string | null
  dast_version?: string | null
  jobs_queued?: number
  jobs_running?: number
}

export interface AuditEntry {
  id: number
  at: string
  actor_name: string
  action: string
  target?: string | null
}

/** Object `schedule` on GET /codebases/{id} (null when there is no schedule). */
export interface CodebaseSchedule {
  cron: string
  status: ScheduleStatus
  owner: UserRef | null
  suspended_reason: SuspendedReason | null
  suspended_at: string | null
  last_enqueued_at: string | null
  /** null while suspended. */
  next_run_at: string | null
}

/** Row of GET /schedules (only Codebases visible to the caller). */
export interface ScheduleListItem extends CodebaseSchedule {
  codebase: { id: number, name: string, target_type: TargetType }
  project: { id: number, name: string }
}

// ---- vulnerability database (Admin) ----------------------------------------

export type VulnDbUpdateState = 'running' | 'succeeded' | 'failed' | 'cancelled'
export type VulnDbErrorCode = 'timeout' | 'update_failed' | 'tool_not_found' | 'cancelled'

export interface VulnDbSource {
  /** "osv" or "nvd". */
  name: string
  ecosystem: string | null
  advisories: number
  updated_at: string | null
  /** Whole days since `updated_at` (from the CLI). */
  age_days: number | null
  /** NVD only: CPE products covered, e.g. "cpe:2.3:a:nginx:nginx". OSV sources: []. */
  products: string[]
}

/** `sdrscan-vuln status --json`. Never null while the tool works, even when nothing is installed (installed: false). */
export interface VulnDbStatus {
  installed: boolean
  advisory_count: number
  /** Oldest source. */
  updated_at: string | null
  age_days: number | null
  max_age_days: number | null
  format_version: number | null
  sources: VulnDbSource[]
}

export interface VulnDbUpdate {
  id: number
  state: VulnDbUpdateState
  trigger: 'manual' | 'schedule'
  requested_by: string | null
  ecosystems: string[]
  nvd: boolean
  started_at: string
  finished_at: string | null
  exit_code: number | null
  error_code: VulnDbErrorCode | null
  log_tail: string
}

/** GET /system/vulndb (Admin only). */
export interface VulnDbInfo {
  configured: boolean
  sca_enabled: boolean
  db_path: string | null
  db_present: boolean
  tool: { available: boolean, path: string }
  /** null only when the tool is unavailable or failed (then `status_error` is set). */
  status: VulnDbStatus | null
  status_error: string | null
  /** From the CLI: older than max_age_days. */
  stale: boolean
  /** Equals status.max_age_days. */
  stale_after_days: number
  ecosystems: string[]
  update_timeout_seconds: number
  update_cron: string | null
  update: VulnDbUpdate | null
}

export interface VulnDbUpdateBody {
  ecosystems?: string[]
  nvd?: boolean
}
