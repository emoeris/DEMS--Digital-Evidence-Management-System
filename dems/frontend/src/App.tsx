import { CaseDetail } from '@/pages/CaseDetail'
import { UserManagement } from '@/pages/UserManagement'
import { useEffect } from 'react'
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { Toaster } from 'sonner'
import { AppShell } from '@/components/layout/AppShell'
import { Backdrop } from '@/components/layout/Backdrop'
import { AppMark } from '@/components/ui/primitives'
import type { Role } from '@/lib/api'
import { Audit } from '@/pages/Audit'
import { Cases } from '@/pages/Cases'
import { Dashboard } from '@/pages/Dashboard'
import { Login } from '@/pages/Login'
import { useAuthStore } from '@/store/auth'



let bootstrapPromise: Promise<void> | null = null

function Splash() {
  return (
    <div className="relative isolate flex min-h-screen items-center justify-center">
      <Backdrop />
      <div role="status" aria-label="Loading" className="animate-pulse"><AppMark size="lg" variant="dark" /></div>
    </div>
  )
}

function RequireAuth() {
  const status = useAuthStore((s) => s.status)
  const mustChangePassword = useAuthStore((s) => s.mustChangePassword)
  const location = useLocation()
  if (status === 'unknown') return <Splash />
  if (status === 'anonymous' || mustChangePassword) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  }
  return <Outlet />
}

function RequireRole({ roles }: { roles: Role[] }) {
  const allowed = useAuthStore((s) => (s.user ? roles.includes(s.user.role) : false))
  return allowed ? <Outlet /> : <Navigate to="/" replace />
}

export default function App() {
  useEffect(() => {
    // StrictMode mounts effects twice in development; share one bootstrap so the single-use refresh token is not replayed.
    bootstrapPromise ??= useAuthStore.getState().bootstrap()
  }, [])

  return (
    <BrowserRouter>
      <Toaster
        position="top-right"
        closeButton
        toastOptions={{
          style: {
            background: 'rgba(255,255,255,0.9)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(0,0,0,0.06)',
            borderRadius: '18px',
            color: '#1D1D1F',
            fontFamily: 'inherit',
            boxShadow: '0 10px 30px -10px rgba(0,0,0,0.18)',
          },
        }}
      />
     
      <Routes>
        <Route path="/login" element={<Login />} />

        <Route element={<RequireAuth />}>
          <Route element={<AppShell />}>
            <Route index element={<Dashboard />} />

            {/* Cases */}
            <Route path="cases" element={<Cases />} />
            <Route path="cases/:caseId" element={<CaseDetail />} />

            {/* Audit log: Admin and Auditor only */}
            <Route element={<RequireRole roles={['admin', 'auditor']} />}>
              <Route path="audit" element={<Audit />} />
            </Route>

            {/* User Management: Admin only */}
            <Route element={<RequireRole roles={['admin']} />}>
              <Route path="users" element={<UserManagement />} />
            </Route>

          </Route>
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>

    </BrowserRouter>
  )
}
