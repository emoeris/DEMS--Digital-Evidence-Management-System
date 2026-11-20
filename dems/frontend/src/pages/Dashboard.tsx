import { ArrowRight, FolderOpen, FolderCheck, KeyRound, Link2, Lock, ScrollText, ShieldCheck, Fingerprint } from 'lucide-react'
import { Link } from 'react-router-dom'
import { AppMark, Badge, EmptyState, ErrorNote, Skeleton } from '@/components/ui/primitives'
import { casesApi } from '@/lib/api'
import { useAsync } from '@/lib/useAsync'
import { formatDate } from '@/lib/utils'
import { ROLE_LABELS, useAuthStore } from '@/store/auth'

const FEATURES = [
  { icon: Lock, label: 'AES-256-GCM at rest' },
  { icon: Fingerprint, label: 'SHA-256 pre-hash' },
  { icon: Link2, label: 'Hash-chained custody' },
  { icon: KeyRound, label: 'Two-step verification' },
  { icon: ScrollText, label: 'Append-only audit' },
]

export function Dashboard() {
  const user = useAuthStore((s) => s.user)
  const can = useAuthStore((s) => s.can)

  const overview = useAsync(
    async (signal) => {
      const [open, closed, recent] = await Promise.all([
        casesApi.list({ status: 'open', limit: 1 }, signal),
        casesApi.list({ status: 'closed', limit: 1 }, signal),
        casesApi.list({ limit: 5 }, signal),
      ])
      return { open: open.total, closed: closed.total, recent: recent.items }
    },
    [],
  )

  return (
    <div className="space-y-6">
      {/* ------------------------------------------------------------ Hero */}
      <section className="apple-glass-strong relative overflow-hidden rounded-4xl px-6 pb-10 pt-12 text-center sm:px-12 sm:pb-14 sm:pt-16">
        {/* luminous blue + orange light ribbons, after the reference */}
        <div aria-hidden className="pointer-events-none absolute inset-0">
          <div className="absolute -left-24 -top-16 h-[130%] w-[46%] rotate-[16deg] rounded-[120px] bg-gradient-to-b from-apple-blue/35 via-apple-blue/10 to-transparent blur-3xl" />
          <div className="absolute -right-24 -top-10 h-[130%] w-[46%] -rotate-[16deg] rounded-[120px] bg-gradient-to-b from-accent/35 via-accent-soft/10 to-transparent blur-3xl" />
          <div className="absolute inset-x-0 bottom-0 h-32 bg-gradient-to-t from-white/80 to-transparent" />
        </div>

        <div className="relative mx-auto flex max-w-3xl flex-col items-center">
          <AppMark size="lg" variant="dark" />

          <span className="apple-glass mt-6 inline-flex items-center gap-2 rounded-full px-3.5 py-1.5 text-xs font-medium text-ink-soft">
            <span className="h-1.5 w-1.5 rounded-full bg-apple-green" />
            Signed in as <b className="font-semibold text-ink">{user?.username}</b>
            <span aria-hidden>·</span>
            {user ? ROLE_LABELS[user.role] : ''}
          </span>

          <h1 className="mt-6 text-balance text-[2.6rem] font-extrabold leading-[1.02] tracking-display text-ink sm:text-6xl lg:text-7xl">
            Evidence you can <span className="bg-gradient-to-r from-apple-blue via-accent to-accent-soft bg-clip-text text-transparent">prove</span>.
          </h1>
          <p className="mt-5 max-w-xl text-pretty text-base leading-relaxed text-ink-soft sm:text-lg">
            Encrypted on arrival, hashed before it leaves your browser, and tracked by a tamper-evident chain of custody from first upload to case closure.
          </p>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link to="/cases" className="btn-dark px-6 py-3">
              Open cases <ArrowRight className="h-4 w-4" />
            </Link>
            {can('audit:read') && (
              <Link to="/audit" className="btn-glass px-6 py-3">
                View audit log
              </Link>
            )}
          </div>

          <ul className="mt-10 flex flex-wrap justify-center gap-2" aria-label="Security features">
            {FEATURES.map(({ icon: Icon, label }) => (
              <li key={label} className="apple-glass inline-flex items-center gap-2 rounded-full px-3.5 py-1.5 text-[13px] font-medium text-ink">
                <Icon className="h-3.5 w-3.5 text-accent-strong" /> {label}
              </li>
            ))}
          </ul>
        </div>
      </section>

      {overview.error && <ErrorNote error={overview.error} onRetry={overview.reload} />}

      {/* ------------------------------------------------------------ Stats */}
      <section aria-label="Case summary" className="grid gap-4 sm:grid-cols-3">
        <Stat icon={FolderOpen} tone="orange" label="Open cases" value={overview.data?.open} loading={overview.loading} />
        <Stat icon={FolderCheck} tone="blue" label="Closed cases" value={overview.data?.closed} loading={overview.loading} />
        <div className="apple-glass flex flex-col justify-between rounded-3xl p-6">
          <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-apple-green/15 text-apple-green-ink">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <div className="mt-6">
            <p className="text-2xl font-extrabold tracking-heading text-ink">{user ? ROLE_LABELS[user.role] : '—'}</p>
            <p className="mt-0.5 text-sm text-ink-soft">
              {user?.role === 'auditor' ? 'Read-only access to cases and logs' : user?.role === 'admin' ? 'Manages users and cases' : 'Works on assigned cases'}
            </p>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------ Recent cases */}
      <section className="apple-glass overflow-hidden rounded-4xl">
        <div className="flex items-center justify-between px-6 pb-3 pt-6">
          <h2 className="text-xl font-bold tracking-heading text-ink">Recent cases</h2>
          <Link to="/cases" className="inline-flex items-center gap-1 text-sm font-semibold text-accent-strong hover:underline">
            View all <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {overview.loading ? (
          <div className="space-y-3 p-6 pt-2">
            {[0, 1, 2].map((i) => <Skeleton key={i} className="h-14" />)}
          </div>
        ) : overview.data && overview.data.recent.length > 0 ? (
          <ul className="divide-y divide-hairline">
            {overview.data.recent.map((c) => (
              <li key={c.id} className="flex items-center gap-4 px-6 py-4">
                <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-black/[0.05] text-ink-soft">
                  <FolderOpen className="h-[18px] w-[18px]" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[15px] font-semibold text-ink">{c.title}</p>
                  <p className="truncate text-sm text-ink-soft">{c.case_number} · opened {formatDate(c.created_at)}</p>
                </div>
                <Badge tone={c.status === 'open' ? 'green' : 'neutral'}>{c.status === 'open' ? 'Open' : 'Closed'}</Badge>
              </li>
            ))}
          </ul>
        ) : !overview.error ? (
          <EmptyState icon={FolderOpen} title="No cases yet" description="Cases you can access will appear here." />
        ) : null}
      </section>
    </div>
  )
}

function Stat({ icon: Icon, tone, label, value, loading }: {
  icon: typeof FolderOpen
  tone: 'orange' | 'blue'
  label: string
  value: number | undefined
  loading: boolean
}) {
  const toneClass = tone === 'orange' ? 'bg-accent/10 text-accent-strong' : 'bg-apple-blue/10 text-apple-blue-ink'
  return (
    <div className="apple-glass flex flex-col justify-between rounded-3xl p-6">
      <span className={`inline-flex h-10 w-10 items-center justify-center rounded-2xl ${toneClass}`}>
        <Icon className="h-5 w-5" />
      </span>
      <div className="mt-6">
        {loading ? <Skeleton className="h-10 w-16" /> : (
          <p className="text-5xl font-extrabold leading-none tracking-display tabular-nums text-ink">{value ?? '—'}</p>
        )}
        <p className="mt-2 text-sm font-medium text-ink-soft">{label}</p>
      </div>
    </div>
  )
}

export default Dashboard
