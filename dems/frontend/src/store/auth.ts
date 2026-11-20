/**
 * Authentication store.
 *
 * Token handling:
 *   - the ACCESS token (15 min) lives only in memory, so it is gone on reload and never touches storage;
 *   - the REFRESH token (single use, rotated on every refresh) is kept in sessionStorage so a page reload
 *     can silently restore the session; it is cleared when the tab closes and on logout.
 * sessionStorage is readable by any script on the page, so a strict CSP and escaped rendering of all
 * evidence metadata remain essential. (An HttpOnly cookie would be stronger; that is a backend change.)
 */
import { toast } from 'sonner'
import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import {
  authApi,
  bindAuthBridge,
  refreshSession,
  toApiError,
  type LoginCredentials,
  type Role,
  type TokenPair,
  type User,
} from '@/lib/api'

export type AuthStatus = 'unknown' | 'authenticated' | 'anonymous'

/** UI-level permissions mirroring the backend RBAC matrix. The server is authoritative; this only drives what is shown. */
export type Permission =
  | 'case:create'
  | 'case:manage'
  | 'evidence:upload'
  | 'evidence:download'
  | 'evidence:verify'
  | 'evidence:delete'
  | 'custody:read'
  | 'audit:read'
  | 'user:manage'

const PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  admin: new Set<Permission>([
    'case:create', 'case:manage', 'evidence:verify', 'evidence:delete', 'custody:read', 'audit:read', 'user:manage',
    'evidence:download', // only for cases the admin is assigned to (enforced server-side)
  ]),
  investigator: new Set<Permission>([
    'case:create', 'case:manage', 'evidence:upload', 'evidence:download', 'evidence:verify', 'custody:read',
  ]),
  auditor: new Set<Permission>(['evidence:verify', 'custody:read', 'audit:read']),
}

export const ROLE_LABELS: Record<Role, string> = {
  admin: 'Administrator',
  investigator: 'Investigator',
  auditor: 'Auditor',
}

interface AuthState {
  status: AuthStatus
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  mfaVerified: boolean
  mustChangePassword: boolean

  login: (credentials: LoginCredentials) => Promise<void>
  logout: () => Promise<void>
  bootstrap: () => Promise<void>
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
  reloadUser: () => Promise<void>

  /** Internal: store a freshly issued token pair. */
  applyTokens: (pair: TokenPair) => void
  /** Internal: drop all session state without calling the server. */
  clear: () => void

  hasRole: (...roles: Role[]) => boolean
  can: (permission: Permission) => boolean
}

const ANONYMOUS = {
  status: 'anonymous' as AuthStatus,
  user: null,
  accessToken: null,
  refreshToken: null,
  mfaVerified: false,
  mustChangePassword: false,
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      status: 'unknown',
      user: null,
      accessToken: null,
      refreshToken: null,
      mfaVerified: false,
      mustChangePassword: false,

      applyTokens: (pair) =>
        set({
          accessToken: pair.access_token,
          refreshToken: pair.refresh_token,
          mustChangePassword: pair.must_change_password,
        }),

      clear: () => set({ ...ANONYMOUS }),

      reloadUser: async () => {
        const me = await authApi.me()
        set({
          user: me.user,
          mfaVerified: me.session_mfa_verified,
          mustChangePassword: me.user.must_change_password,
          status: 'authenticated',
        })
      },

      login: async (credentials) => {
        const pair = await authApi.login(credentials) // throws ApiError (e.g. code "mfa_required")
        get().applyTokens(pair)
        try {
          await get().reloadUser()
        } catch (err) {
          get().clear()
          throw toApiError(err)
        }
      },

      bootstrap: async () => {
        if (!get().refreshToken) {
          set({ ...ANONYMOUS })
          return
        }
        try {
          await refreshSession() // rotates the stored refresh token and fills the access token via the bridge
          await get().reloadUser()
        } catch (err) {
          const e = toApiError(err)
          // A network failure should not destroy a valid session; only definitive auth errors do.
          if (e.status === 0) set({ status: 'anonymous', user: null, accessToken: null })
          else get().clear()
        }
      },

      logout: async () => {
        try {
          if (get().accessToken) await authApi.logout()
        } catch {
          /* the session is being discarded either way */
        } finally {
          get().clear()
        }
      },

      changePassword: async (currentPassword, newPassword) => {
        await authApi.changePassword(currentPassword, newPassword)
        set({ mustChangePassword: false })
        await get().reloadUser()
      },

      hasRole: (...roles) => {
        const role = get().user?.role
        return role !== undefined && roles.includes(role)
      },

      can: (permission) => {
        const role = get().user?.role
        return role !== undefined && PERMISSIONS[role].has(permission)
      },
    }),
    {
      name: 'dems.session',
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({ refreshToken: state.refreshToken }),
    },
  ),
)

// Wire the API client to this store (one-directional: the store imports the client, never the reverse).
bindAuthBridge({
  getAccessToken: () => useAuthStore.getState().accessToken,
  getRefreshToken: () => useAuthStore.getState().refreshToken,
  onTokens: (pair) => useAuthStore.getState().applyTokens(pair),
  onSessionExpired: () => {
    if (useAuthStore.getState().status === 'authenticated') {
      toast.error('Your session has ended. Please sign in again.')
    }
    useAuthStore.getState().clear()
  },
})

