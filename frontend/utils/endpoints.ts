import type { ApiClient, Query } from './apiClient'
import type {
  AuditEntry, CodebaseSchedule, DastAuth, DastAuthBody, LoginCheckResult, CompareResponse, ScheduleListItem, CompareStatus, Codebase, CreateCodebaseBody, CreatedIngestToken, CreateUserBody,
  DeleteResult, FileRow, Finding, FindingsPage, IngestToken, LoginResponse, MeResponse, Page, PatchCodebaseBody,
  PatchUserBody, Project, ProjectDashboard, ProjectListItem, Scan, SystemInfo, UserRow, VulnDbInfo, VulnDbUpdate, VulnDbUpdateBody,
  AuthorizeActiveScanningBody,
} from '~/types/api'

export interface PageQuery { page?: number; page_size?: number }

export interface FindingQuery extends PageQuery {
  severity?: string[]
  rule?: string
  path?: string
  q?: string
  include_low_confidence?: boolean
  sort?: 'severity'
  /** code | vulnerability */
  kind?: 'code' | 'vulnerability'
  /** Exact advisory id (CVE, GHSA or OSV id), case-insensitive. */
  cve?: string
  /** Filters on vulnerability.confidence (code findings never match). */
  confidence?: 'high' | 'low'
  /** Filters on vulnerability.scope. */
  scope?: 'runtime' | 'dev'
}

export interface CompareQuery extends PageQuery {
  base?: number
  head?: number
  status?: CompareStatus
}

/** Typed wrappers for every endpoint the web UI uses (TRD "API REST backend"). */
export function createEndpoints(c: ApiClient) {
  const q = (o: object | undefined): Query | undefined => o as Query | undefined
  return {
    auth: {
      login: (username: string, password: string) =>
        c.post<LoginResponse>('/auth/login', { username, password }, { noAuthRedirect: true }),
      logout: () => c.post<void>('/auth/logout', undefined, { noAuthRedirect: true }),
      me: () => c.get<MeResponse>('/auth/me', undefined, { noAuthRedirect: true }),
      changePassword: (current_password: string, new_password: string) =>
        c.post<void>('/auth/password', { current_password, new_password }),
    },
    users: {
      list: (p?: PageQuery) => c.get<Page<UserRow>>('/users', q(p)),
      create: (body: CreateUserBody) => c.post<UserRow>('/users', body),
      patch: (id: number, body: PatchUserBody) => c.patch<UserRow>(`/users/${id}`, body),
      resetPassword: (id: number, new_password: string) => c.post<void>(`/users/${id}/reset-password`, { new_password }),
    },
    audit: { list: (p?: PageQuery) => c.get<Page<AuditEntry>>('/audit-log', q(p)) },
    projects: {
      list: (p?: PageQuery) => c.get<Page<ProjectListItem>>('/projects', q(p)),
      get: (id: number) => c.get<ProjectDashboard>(`/projects/${id}`),
      create: (body: { name: string; description: string }) => c.post<Project>('/projects', body),
      patch: (id: number, body: { name?: string; description?: string }) => c.patch<Project>(`/projects/${id}`, body),
      remove: (id: number, confirmName: string) => c.del<DeleteResult>(`/projects/${id}`, { confirm: confirmName }),
    },
    codebases: {
      create: (projectId: number, body: CreateCodebaseBody) => c.post<Codebase>(`/projects/${projectId}/codebases`, body),
      get: (id: number) => c.get<Codebase>(`/codebases/${id}`),
      patch: (id: number, body: PatchCodebaseBody) => c.patch<Codebase>(`/codebases/${id}`, body),
      confirmAuthorization: (id: number) => c.post<Codebase>(`/codebases/${id}/confirm-authorization`, { statement_accepted: true }),
      /** A separate, stricter layer on top of confirmAuthorization: see "Active scanning" in the codebase settings. */
      authorizeActiveScanning: (id: number, body: AuthorizeActiveScanningBody) => c.post<Codebase>(`/codebases/${id}/authorize-active-scanning`, body),
      revokeActiveScanning: (id: number) => c.del<void>(`/codebases/${id}/authorize-active-scanning`),
      remove: (id: number, confirmName: string) => c.del<DeleteResult>(`/codebases/${id}`, { confirm: confirmName }),
      scans: (id: number, p?: PageQuery & { status?: string }) => c.get<Page<Scan>>(`/codebases/${id}/scans`, q(p)),
      compare: (id: number, p?: CompareQuery) => c.get<CompareResponse>(`/codebases/${id}/compare`, q(p)),
      findings: (id: number, p?: FindingQuery) => c.get<FindingsPage>(`/codebases/${id}/findings`, q(p)),
      files: (id: number, p?: PageQuery & { q?: string }) => c.get<Page<FileRow>>(`/codebases/${id}/files`, q(p)),
    },
    /** URL targets only; Admin or DAST access. Secrets are write-only: no response carries them. */
    dastAuth: {
      get: (codebaseId: number) => c.get<DastAuth>(`/codebases/${codebaseId}/dast-auth`),
      put: (codebaseId: number, body: DastAuthBody) => c.request<DastAuth>('PUT', `/codebases/${codebaseId}/dast-auth`, { body }),
      remove: (codebaseId: number) => c.del<void>(`/codebases/${codebaseId}/dast-auth`),
      test: (codebaseId: number) => c.post<LoginCheckResult>(`/codebases/${codebaseId}/dast-auth/test`),
    },
    scans: {
      /** `active`/`active_timing` apply to DAST only; the server rejects `active_timing` without `active`. */
      create: (codebaseId: number, opts?: { active?: boolean, active_timing?: boolean }) =>
        c.post<Scan>('/scans', { codebase_id: codebaseId, ...(opts?.active ? { active: true, active_timing: !!opts.active_timing } : {}) }),
      get: (id: number) => c.get<Scan>(`/scans/${id}`),
      cancel: (id: number) => c.post<Scan>(`/scans/${id}/cancel`),
      findings: (id: number, p?: FindingQuery) => c.get<FindingsPage>(`/scans/${id}/findings`, q(p)),
      files: (id: number, p?: PageQuery) => c.get<Page<FileRow>>(`/scans/${id}/files`, q(p)),
    },
    schedules: {
      list: (p?: PageQuery & { status?: 'active' | 'suspended' }) => c.get<Page<ScheduleListItem>>('/schedules', q(p)),
      put: (codebaseId: number, cron: string) => c.request<{ schedule: CodebaseSchedule }>('PUT', `/codebases/${codebaseId}/schedule`, { body: { cron } }),
      resume: (codebaseId: number) => c.post<{ schedule: CodebaseSchedule }>(`/codebases/${codebaseId}/schedule/resume`),
      remove: (codebaseId: number) => c.del<void>(`/codebases/${codebaseId}/schedule`),
    },
    findings: { get: (id: number) => c.get<Finding>(`/findings/${id}`) },
    tokens: {
      list: (p?: PageQuery) => c.get<Page<IngestToken>>('/ingest-tokens', q(p)),
      create: (body: { name: string; project_id?: number | null }) => c.post<CreatedIngestToken>('/ingest-tokens', body),
      revoke: (id: number) => c.del<void>(`/ingest-tokens/${id}`),
    },
    system: {
      info: () => c.get<SystemInfo>('/system/info'),
      /** Admin only. */
      vulndb: () => c.get<VulnDbInfo>('/system/vulndb'),
      vulndbUpdate: (body: VulnDbUpdateBody = {}) => c.post<{ update: VulnDbUpdate }>('/system/vulndb/update', body),
      vulndbCancel: () => c.post<{ update: VulnDbUpdate }>('/system/vulndb/update/cancel'),
    },
  }
}

export type Endpoints = ReturnType<typeof createEndpoints>
