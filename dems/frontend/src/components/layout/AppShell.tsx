import {
  ChevronDown,
  FolderOpen,
  LayoutDashboard,
  LogOut,
  Menu,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Backdrop } from '@/components/layout/Backdrop'
import { AppMark, Badge } from '@/components/ui/primitives'
import type { Role } from '@/lib/api'
import { cn, initials } from '@/lib/utils'
import { ROLE_LABELS, useAuthStore } from '@/store/auth'

// --------------------------------------------------------------------------------------------
// Navigation registry: add a screen here and it appears (role-filtered) in the sidebar and drawer.
// --------------------------------------------------------------------------------------------
interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  roles: readonly Role[]
  end?: boolean
}

const ALL_ROLES: readonly Role[] = ['admin', 'investigator', 'auditor']

export const NAV_ITEMS: readonly NavItem[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, roles: ALL_ROLES, end: true },
  { to: '/cases', label: 'Cases', icon: FolderOpen, roles: ALL_ROLES },
  { to: '/audit', label: 'Audit log', icon: ScrollText, roles: ['admin', 'auditor'] },
  { to: '/users', label: 'Users', icon: Users, roles: ['admin'] },
]

function useVisibleNav(): NavItem[] {
  const role = useAuthStore((s) => s.user?.role)
  return NAV_ITEMS.filter((item) => role !== undefined && item.roles.includes(role))
}

function useCurrentSection(): string {
  const { pathname } = useLocation()
  const match = [...NAV_ITEMS]
    .sort((a, b) => b.to.length - a.to.length)
    .find((item) => (item.end ? pathname === item.to : pathname === item.to || pathname.startsWith(`${item.to}/`)))
  return match?.label ?? 'Overview'
}

// --------------------------------------------------------------------------------------------
// Sidebar content (shared by the desktop panel and the mobile drawer)
// --------------------------------------------------------------------------------------------
function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const items = useVisibleNav()
  const user = useAuthStore((s) => s.user)
  const mfaVerified = useAuthStore((s) => s.mfaVerified)

  return (
    <div className="flex h-full flex-col">
      <p className="px-3 pb-2 pt-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-soft">Workspace</p>

      <nav aria-label="Primary" className="flex flex-col gap-1">
        {items.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                'group relative flex items-center gap-3 rounded-2xl px-3 py-2.5 text-[15px] font-medium transition-all duration-200',
                isActive ? 'bg-white text-ink shadow-glass-sm' : 'text-ink-soft hover:bg-white/60 hover:text-ink',
              )
            }
          >
            {({ isActive }) => (
              <>
                {/* active indicator */}
                <span
                  aria-hidden
                  className={cn(
                    'absolute -left-1 top-2.5 bottom-2.5 w-1 rounded-full bg-gradient-to-b from-accent-soft to-accent-strong transition-all duration-200',
                    isActive ? 'scale-y-100 opacity-100' : 'scale-y-0 opacity-0',
                  )}
                />
                <span
                  className={cn(
                    'inline-flex h-8 w-8 items-center justify-center rounded-xl transition-colors',
                    isActive ? 'bg-accent/10 text-accent-strong' : 'bg-black/[0.04] text-ink-soft group-hover:text-ink',
                  )}
                >
                  <Icon className="h-[18px] w-[18px]" strokeWidth={2} />
                </span>
                <span className="flex-1">{label}</span>
                {isActive && <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-accent" />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto pt-6">
        <div className="rounded-2xl border border-hairline bg-gradient-to-br from-white/90 to-white/60 p-4 shadow-glass-sm">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            {user?.mfa_enabled && mfaVerified ? (
              <ShieldCheck className="h-4 w-4 text-apple-green-ink" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-apple-amber-ink" />
            )}
            {user?.mfa_enabled && mfaVerified ? 'Session secured' : 'Password-only session'}
          </div>
          <p className="mt-1 text-[13px] leading-relaxed text-ink-soft">
            {user?.mfa_enabled
              ? 'Two-step verification is active for this account.'
              : 'Two-step verification is not enabled for this account.'}
          </p>
          <div className="mt-3 flex items-center gap-2">
            <Badge tone="orange">{user ? ROLE_LABELS[user.role] : '—'}</Badge>
            <Badge tone={user?.mfa_enabled ? 'green' : 'amber'}>{user?.mfa_enabled ? 'MFA on' : 'MFA off'}</Badge>
          </div>
        </div>
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------------------------
// User menu
// --------------------------------------------------------------------------------------------
function UserMenu({ onSignOut }: { onSignOut: () => void }) {
  const user = useAuthStore((s) => s.user)
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onPointerDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  if (!user) return null

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-full bg-white/70 py-1 pl-1 pr-2.5 shadow-glass-sm ring-1 ring-hairline transition hover:bg-white sm:pr-3"
      >
        <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-ink text-[12px] font-bold text-white">
          {initials(user.username)}
        </span>
        <span className="hidden max-w-[9rem] truncate text-sm font-semibold text-ink sm:block">{user.username}</span>
        <ChevronDown className={cn('h-4 w-4 text-ink-soft transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div role="menu" className="apple-glass-strong absolute right-0 top-[calc(100%+10px)] z-50 w-64 origin-top-right animate-scale-in rounded-3xl p-2">
          <div className="px-3 pb-3 pt-2">
            <p className="truncate text-sm font-bold text-ink">{user.username}</p>
            <p className="truncate text-[13px] text-ink-soft">{user.email}</p>
            <div className="mt-2 flex gap-2">
              <Badge tone="orange">{ROLE_LABELS[user.role]}</Badge>
              <Badge tone={user.mfa_enabled ? 'green' : 'amber'}>{user.mfa_enabled ? 'MFA on' : 'MFA off'}</Badge>
            </div>
          </div>
          <div className="my-1 h-px bg-hairline" />
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false)
              onSignOut()
            }}
            className="flex w-full items-center gap-2.5 rounded-2xl px-3 py-2.5 text-sm font-semibold text-apple-red-ink transition hover:bg-apple-red/10"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </button>
        </div>
      )}
    </div>
  )
}

// --------------------------------------------------------------------------------------------
// Mobile drawer
// --------------------------------------------------------------------------------------------
function MobileDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const previouslyFocused = document.activeElement as HTMLElement | null
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    closeRef.current?.focus()
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
      previouslyFocused?.focus?.()
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
      <button type="button" aria-label="Close menu" onClick={onClose} className="absolute inset-0 bg-black/25 backdrop-blur-sm" />
      <div className="apple-glass-strong absolute bottom-3 left-3 top-3 w-[min(20rem,calc(100vw-1.5rem))] animate-slide-in-left rounded-4xl p-4">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <AppMark />
            <span className="text-base font-extrabold tracking-heading text-ink">DEMS</span>
          </div>
          <button ref={closeRef} type="button" aria-label="Close menu" onClick={onClose}
            className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-black/[0.05] text-ink transition hover:bg-black/10">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="h-[calc(100%-3.5rem)]">
          <SidebarContent onNavigate={onClose} />
        </div>
      </div>
    </div>
  )
}

// --------------------------------------------------------------------------------------------
// App shell
// --------------------------------------------------------------------------------------------
export function AppShell() {
  const navigate = useNavigate()
  const location = useLocation()
  const logout = useAuthStore((s) => s.logout)
  const section = useCurrentSection()
  const [drawerOpen, setDrawerOpen] = useState(false)
  const closeDrawer = useCallback(() => setDrawerOpen(false), [])

  useEffect(() => {
    document.title = `${section} · DEMS`
  }, [section])

  useEffect(() => {
    setDrawerOpen(false)
    window.scrollTo({ top: 0 })
  }, [location.pathname])

  const signOut = useCallback(async () => {
    await logout()
    toast.success('Signed out')
    navigate('/login', { replace: true })
  }, [logout, navigate])

  return (
    <div className="relative isolate min-h-screen">
      <Backdrop />

      <a
        href="#main"
        className="sr-only z-[60] rounded-full bg-ink px-4 py-2 text-sm font-semibold text-white focus:not-sr-only focus:fixed focus:left-4 focus:top-4"
      >
        Skip to content
      </a>

      {/* Floating frosted-glass pill navigation */}
      <header className="sticky top-0 z-40 px-3 pt-3 sm:px-6 lg:px-8">
        <div className="apple-glass mx-auto flex h-14 w-full max-w-[1440px] items-center justify-between rounded-full pl-2 pr-2 sm:pl-3">
          <div className="flex min-w-0 items-center gap-2 sm:gap-3">
            <button
              type="button"
              aria-label="Open menu"
              onClick={() => setDrawerOpen(true)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-full text-ink transition hover:bg-black/[0.05] lg:hidden"
            >
              <Menu className="h-5 w-5" />
            </button>
            <Link to="/" className="flex items-center gap-2.5 rounded-full pr-2" aria-label="DEMS home">
              <AppMark />
              <span className="text-[17px] font-extrabold tracking-heading text-ink">DEMS</span>
              <span className="hidden text-sm font-medium text-ink-soft md:inline">Evidence Management</span>
            </Link>
          </div>

          <div aria-live="polite" className="hidden items-center gap-2 text-sm md:flex">
            <span className="text-ink-soft">Workspace</span>
            <span aria-hidden className="text-ink-faint">/</span>
            <span className="font-semibold text-ink">{section}</span>
          </div>

          <UserMenu onSignOut={signOut} />
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-[1440px] gap-6 px-3 pb-12 pt-5 sm:px-6 lg:px-8">
        {/* Sidebar (desktop) */}
        <aside className="sticky top-[88px] hidden h-[calc(100vh-112px)] w-64 shrink-0 lg:block">
          <div className="apple-glass h-full rounded-4xl p-3">
            <SidebarContent />
          </div>
        </aside>

        {/* Main view container */}
        <main id="main" tabIndex={-1} className="min-w-0 flex-1 animate-fade-up outline-none" key={location.pathname}>
          <Outlet />
        </main>
      </div>

      <MobileDrawer open={drawerOpen} onClose={closeDrawer} />
    </div>
  )
}

export default AppShell
