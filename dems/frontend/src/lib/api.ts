/**
 * Global API client.
 *
 * - Base URL is `/api`; the Vite dev proxy strips the prefix before it reaches FastAPI.
 * - A request interceptor attaches the in-memory access token.
 * - A response interceptor performs *silent token rotation* on 401: the backend's refresh tokens are
 *   single-use (rotated on every refresh, reuse revokes the whole session), so every concurrent 401
 *   must share ONE in-flight refresh call. That is what `refreshSession()` guarantees.
 * - This module never imports the auth store (the store binds itself through `bindAuthBridge`),
 *   which keeps the dependency graph one-directional.
 */
import axios, { AxiosHeaders, type AxiosError, type AxiosRequestConfig, type InternalAxiosRequestConfig } from 'axios'
import { hashesEqual, sha256File, type HashProgress } from '@/lib/crypto'

// --------------------------------------------------------------------------------------------
// Types mirroring the FastAPI schemas
// --------------------------------------------------------------------------------------------
export type Role = 'admin' | 'investigator' | 'auditor'
export type CaseStatus = 'open' | 'closed'
export type Outcome = 'SUCCESS' | 'DENIED' | 'FAILURE'

export interface User {
  id: string
  username: string
  email: string
  role: Role
  is_active: boolean
  must_change_password: boolean
  mfa_enabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  must_change_password: boolean
  mfa_enabled: boolean
}

export interface MeResponse {
  user: User
  session_mfa_verified: boolean
}

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface CaseRecord {
  id: string
  case_number: string
  title: string
  description: string | null
  status: CaseStatus
  lead_investigator_id: string | null
  lead_investigator_username?: string | null
  created_by: string
  created_at: string
  closed_at: string | null
  closed_by: string | null
  closure_manifest_hash: string | null
}

export interface EvidenceRecord {
  id: string
  case_id: string
  original_filename: string
  detected_mime: string
  size_bytes: number
  sha256_client: string
  sha256_server: string
  description: string | null
  source: string | null
  tags: string[]
  acquired_at: string | null
  uploaded_by: string
  uploaded_at: string
  last_verified_at: string | null
  last_verify_result: 'pass' | 'fail' | 'error' | null
}

export interface AuditEntry {
  id: string
  sequence_no: number
  occurred_at: string
  actor_id: string | null
  actor_username: string | null
  actor_username_attempted: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  outcome: Outcome
  source_ip: string
  details_json: Record<string, unknown>
  entry_hash: string
}

export interface LoginCredentials {
  username: string
  password: string
  totpCode?: string
  backupCode?: string
}

// --------------------------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------------------------
export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

interface ErrorBody {
  detail?: string
  code?: string
  errors?: { loc?: (string | number)[]; msg?: string }[]
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  if (axios.isCancel(error)) return new ApiError(0, 'cancelled', 'Request cancelled')
  if (axios.isAxiosError(error)) {
    if (!error.response) {
      return new ApiError(0, 'network_error', 'Cannot reach the server. Check that the backend is running.')
    }
    const body = (error.response.data ?? {}) as ErrorBody
    const fields = body.errors?.length
      ? body.errors.map((e) => `${(e.loc ?? []).slice(1).join('.') || 'request'}: ${e.msg ?? 'invalid'}`).join('; ')
      : undefined
    return new ApiError(error.response.status, body.code ?? 'http_error', fields ?? body.detail ?? error.message)
  }
  return new ApiError(0, 'unknown', error instanceof Error ? error.message : 'Unexpected error')
}

export function getErrorMessage(error: unknown): string {
  return toApiError(error).message
}

// --------------------------------------------------------------------------------------------
// Axios instances
// --------------------------------------------------------------------------------------------
const BASE_URL = '/api'

/** Authenticated client used by the whole application. */
export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: { Accept: 'application/json' },
})

/** Interceptor-free client for login/refresh, so they can never recurse into the refresh logic. */
const bareClient = axios.create({ baseURL: BASE_URL, timeout: 30_000, headers: { Accept: 'application/json' } })

/** Point both clients at another origin (tests, Electron shells, or a reverse proxy mounted elsewhere). */
export function setApiBaseUrl(url: string): void {
  apiClient.defaults.baseURL = url
  bareClient.defaults.baseURL = url
}

// --------------------------------------------------------------------------------------------
// Auth bridge (bound by the Zustand store)
// --------------------------------------------------------------------------------------------
export interface AuthBridge {
  getAccessToken: () => string | null
  getRefreshToken: () => string | null
  onTokens: (pair: TokenPair) => void
  onSessionExpired: () => void
}

let bridge: AuthBridge | null = null

export function bindAuthBridge(next: AuthBridge): void {
  bridge = next
}

let inflightRefresh: Promise<TokenPair> | null = null

/** Rotate the refresh token. Concurrent callers share one network request. */
export function refreshSession(): Promise<TokenPair> {
  if (inflightRefresh) return inflightRefresh
  const refreshToken = bridge?.getRefreshToken()
  if (!refreshToken) return Promise.reject(new ApiError(401, 'not_authenticated', 'No active session.'))

  inflightRefresh = bareClient
    .post<TokenPair>('/auth/refresh', { refresh_token: refreshToken })
    .then((res) => {
      bridge?.onTokens(res.data)
      return res.data
    })
    .catch((err: unknown) => {
      throw toApiError(err)
    })
    .finally(() => {
      inflightRefresh = null
    })
  return inflightRefresh
}

type RetriableConfig = InternalAxiosRequestConfig & { _retried?: boolean }

apiClient.interceptors.request.use((config) => {
  const token = bridge?.getAccessToken()
  if (token && !config.headers.has('Authorization')) config.headers.set('Authorization', `Bearer ${token}`)
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as RetriableConfig | undefined
    const canRotate =
      error.response?.status === 401 && original !== undefined && !original._retried && !!bridge?.getRefreshToken()

    if (!canRotate || !original) throw toApiError(error)
    original._retried = true

    try {
      const pair = await refreshSession()
      original.headers = AxiosHeaders.from(original.headers)
      original.headers.set('Authorization', `Bearer ${pair.access_token}`)
      return await apiClient.request(original)
    } catch (refreshError) {
      const apiError = toApiError(refreshError)
      // Only a definitive auth failure ends the session; a network blip must not log the user out.
      if (apiError.status === 401 || apiError.status === 403) bridge?.onSessionExpired()
      throw apiError
    }
  },
)

// --------------------------------------------------------------------------------------------
// Endpoint helpers
// --------------------------------------------------------------------------------------------
export const authApi = {
  async login(credentials: LoginCredentials): Promise<TokenPair> {
    try {
      const { data } = await bareClient.post<TokenPair>('/auth/login', {
        username: credentials.username,
        password: credentials.password,
        ...(credentials.totpCode ? { totp_code: credentials.totpCode } : {}),
        ...(credentials.backupCode ? { backup_code: credentials.backupCode } : {}),
      })
      return data
    } catch (err) {
      throw toApiError(err)
    }
  },

  async me(accessToken?: string): Promise<MeResponse> {
    const config: AxiosRequestConfig = accessToken ? { headers: { Authorization: `Bearer ${accessToken}` } } : {}
    const { data } = await apiClient.get<MeResponse>('/auth/me', config)
    return data
  },

  async logout(): Promise<void> {
    await apiClient.post('/auth/logout')
  },

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await apiClient.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword })
  },
}

export interface ListParams {
  limit?: number
  offset?: number
}

export const casesApi = {
  async list(params: ListParams & { status?: CaseStatus } = {}, signal?: AbortSignal): Promise<Page<CaseRecord>> {
    const { data } = await apiClient.get<Page<CaseRecord>>('/cases', { params, signal })
    return data
  },

  async close(caseId: string): Promise<CaseRecord> {
    const { data } = await apiClient.post<CaseRecord>(`/cases/${encodeURIComponent(caseId)}/close`)
    return data
  },
}

export const auditApi = {
  async list(
    params: ListParams & { action?: string; outcome?: Outcome } = {},
    signal?: AbortSignal,
  ): Promise<Page<AuditEntry>> {
    const { data } = await apiClient.get<Page<AuditEntry>>('/audit', { params, signal })
    return data
  },
}

// --------------------------------------------------------------------------------------------
// Evidence upload / download
// --------------------------------------------------------------------------------------------
export interface UploadOptions {
  caseId: string
  file: File
  description?: string
  source?: string
  tags?: string[]
  signal?: AbortSignal
  onHashProgress?: (progress: HashProgress) => void
  /** 0..1 of bytes sent */
  onUploadProgress?: (fraction: number) => void
}

export interface UploadResult {
  evidence: EvidenceRecord
  clientSha256: string
}

/**
 * Hash in the browser first, then upload. The digest travels in the `x-client-sha256` header and in the
 * `client_sha256` form field (the field is what the FastAPI endpoint validates; the header is kept for
 * proxies/audit tooling). The server re-hashes the bytes and rejects the upload on any mismatch.
 */
export async function uploadEvidence(options: UploadOptions): Promise<UploadResult> {
  const { caseId, file, description, source, tags, signal, onHashProgress, onUploadProgress } = options
  const clientSha256 = await sha256File(file, { signal, onProgress: onHashProgress })

  const form = new FormData()
  form.append('case_id', caseId)
  form.append('client_sha256', clientSha256)
  if (description) form.append('description', description)
  if (source) form.append('source', source)
  if (tags?.length) form.append('tags', tags.join(','))
  form.append('file', file, file.name)

  const { data } = await apiClient.post<EvidenceRecord>('/evidence/upload', form, {
    headers: { 'x-client-sha256': clientSha256 },
    timeout: 0, // large files; the user can cancel with `signal`
    signal,
    onUploadProgress: (e) => {
      if (e.total) onUploadProgress?.(Math.min(e.loaded / e.total, 1))
    },
  })
  return { evidence: data, clientSha256 }
}

export interface DownloadResult {
  blob: Blob
  filename: string
  serverSha256: string | null
  /** true/false when the server supplied a digest, null when it did not */
  verifiedLocally: boolean | null
}

function filenameFromDisposition(header: string | undefined): string {
  if (!header) return 'evidence'
  const star = /filename\*=UTF-8''([^;]+)/i.exec(header)
  if (star?.[1]) {
    try {
      return decodeURIComponent(star[1])
    } catch {
      /* fall through */
    }
  }
  const plain = /filename="([^"]+)"/i.exec(header)
  return plain?.[1] ?? 'evidence'
}

/** Download decrypted evidence and re-hash it locally against the digest the server advertised. */
export async function downloadEvidence(evidenceId: string, signal?: AbortSignal): Promise<DownloadResult> {
  const res = await apiClient.get<Blob | ArrayBuffer>(`/evidence/${encodeURIComponent(evidenceId)}/download`, {
    responseType: 'blob',
    timeout: 0,
    signal,
  })
  // Browsers return a Blob; non-browser runtimes (tests, Electron main) may hand back raw bytes.
  const blob = res.data instanceof Blob ? res.data : new Blob([res.data])
  const serverSha256 = (res.headers['x-content-sha256'] as string | undefined) ?? null
  const verifiedLocally = serverSha256 ? hashesEqual(await sha256File(blob), serverSha256) : null
  return {
    blob,
    filename: filenameFromDisposition(res.headers['content-disposition'] as string | undefined),
    serverSha256,
    verifiedLocally,
  }
}
