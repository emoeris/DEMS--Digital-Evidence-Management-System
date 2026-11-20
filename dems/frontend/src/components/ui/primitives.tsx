import { ChevronLeft, ChevronRight, CircleAlert, RotateCw, ShieldCheck, type LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { getErrorMessage } from '@/lib/api'
import { cn } from '@/lib/utils'

// ------------------------------------------------------------------ App mark
export function AppMark({ size = 'sm', variant = 'accent', className }: {
  size?: 'sm' | 'lg'
  variant?: 'accent' | 'dark'
  className?: string
}) {
  const dims = size === 'lg' ? 'h-[72px] w-[72px] rounded-[22px]' : 'h-9 w-9 rounded-[11px]'
  const icon = size === 'lg' ? 'h-8 w-8' : 'h-[18px] w-[18px]'
  return (
    <span
      aria-hidden
      className={cn(
        'relative inline-flex shrink-0 items-center justify-center text-white',
        dims,
        variant === 'dark'
          ? 'bg-gradient-to-b from-[#2d2d31] to-[#09090B] shadow-[inset_0_1px_0_rgba(255,255,255,0.22),0_18px_40px_-14px_rgba(217,72,15,0.6),0_0_0_1px_rgba(0,0,0,0.5)]'
          : 'bg-gradient-to-br from-accent-soft via-accent to-accent-strong shadow-[inset_0_1px_0_rgba(255,255,255,0.35),0_6px_16px_-6px_rgba(194,65,12,0.7)]',
        className,
      )}
    >
      <ShieldCheck className={icon} strokeWidth={2.2} />
    </span>
  )
}

// ------------------------------------------------------------------ Badge
export type Tone = 'neutral' | 'orange' | 'blue' | 'green' | 'red' | 'amber'

const TONES: Record<Tone, string> = {
  neutral: 'bg-black/[0.05] text-ink-soft',
  orange: 'bg-accent/10 text-accent-strong',
  blue: 'bg-apple-blue/10 text-apple-blue-ink',
  green: 'bg-apple-green/15 text-apple-green-ink',
  red: 'bg-apple-red/10 text-apple-red-ink',
  amber: 'bg-apple-amber/15 text-apple-amber-ink',
}

export function Badge({ tone = 'neutral', children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-semibold', TONES[tone], className)}>
      {children}
    </span>
  )
}

// ------------------------------------------------------------------ Skeleton
export function Skeleton({ className }: { className?: string }) {
  return (
    <div aria-hidden className={cn('relative overflow-hidden rounded-xl bg-black/[0.06]', className)}>
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-white/70 to-transparent" />
    </div>
  )
}

// ------------------------------------------------------------------ Page header
export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-3xl font-extrabold tracking-display text-ink sm:text-4xl">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-[15px] leading-relaxed text-ink-soft">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

// ------------------------------------------------------------------ States
export function ErrorNote({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-2xl border border-apple-red/20 bg-apple-red/5 p-4 text-sm text-apple-red-ink">
      <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" />
      <p className="min-w-0 flex-1 leading-relaxed">{getErrorMessage(error)}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="inline-flex items-center gap-1.5 font-semibold underline-offset-2 hover:underline">
          <RotateCw className="h-3.5 w-3.5" /> Retry
        </button>
      )}
    </div>
  )
}

export function EmptyState({ icon: Icon, title, description }: { icon: LucideIcon; title: string; description?: string }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <span className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-black/[0.05] text-ink-soft">
        <Icon className="h-5 w-5" />
      </span>
      <p className="text-base font-semibold text-ink">{title}</p>
      {description && <p className="mt-1 max-w-sm text-sm leading-relaxed text-ink-soft">{description}</p>}
    </div>
  )
}

// ------------------------------------------------------------------ Pager
export function Pager({ offset, limit, total, onChange }: { offset: number; limit: number; total: number; onChange: (offset: number) => void }) {
  if (total <= limit) return null
  const from = offset + 1
  const to = Math.min(offset + limit, total)
  return (
    <div className="flex items-center justify-between border-t border-hairline px-5 py-3 text-sm text-ink-soft">
      <span className="tabular-nums">{from}–{to} of {total}</span>
      <div className="flex gap-1.5">
        <button type="button" aria-label="Previous page" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}
          className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-white/80 shadow-glass-sm transition hover:bg-white disabled:opacity-40">
          <ChevronLeft className="h-4 w-4" />
        </button>
        <button type="button" aria-label="Next page" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}
          className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-white/80 shadow-glass-sm transition hover:bg-white disabled:opacity-40">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// ------------------------------------------------------------------ Segmented control
export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T
  options: { value: T; label: string }[]
  onChange: (value: T) => void
  label: string
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-full bg-black/[0.05] p-1">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            'rounded-full px-4 py-1.5 text-sm font-semibold transition',
            value === o.value ? 'bg-white text-ink shadow-glass-sm' : 'text-ink-soft hover:text-ink',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
