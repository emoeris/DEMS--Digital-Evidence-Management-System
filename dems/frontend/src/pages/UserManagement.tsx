import { Check, Copy, Eye, EyeOff, Info, KeyRound, Loader2, RefreshCw, UserPlus, Users } from 'lucide-react'
import { useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Badge, EmptyState, ErrorNote, PageHeader, Pager, Segmented, Skeleton, type Tone } from '@/components/ui/primitives'
import { apiClient, auditApi, getErrorMessage, type AuditEntry, type Role, type User } from '@/lib/api'
import { useAsync } from '@/lib/useAsync'
import { cn, formatDateTime, initials, shortHash } from '@/lib/utils'
import { ROLE_LABELS, useAuthStore } from '@/store/auth'

type AssignableRole = Exclude<Role, 'admin'>

const PAGE_SIZE = 20
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,63}$/
const EMAIL_RE = /^[^@\s]{1,64}@[A-Za-z0-9.-]{1,185}\.[A-Za-z]{2,}$/
const ROLE_TONE: Record<string, Tone> = { admin: 'orange', investigator: 'blue', auditor: 'neutral' }

// ------------------------------------------------------------------------------------------
// Temporary password generator (cryptographically random, unbiased, mixed character classes)
// ------------------------------------------------------------------------------------------
const LOWER = 'abcdefghijkmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
const DIGITS = '23456789'
const SYMBOLS = '!@#$%&*?-_+='

function randomInt(max: number): number {
  const limit = Math.floor(0x100000000 / max) * max // rejection sampling avoids modulo bias
  const buf = new Uint32Array(1)
  let value: number
  do {
    crypto.getRandomValues(buf)
    value = buf[0] ?? 0
  } while (value >= limit)
  return value % max
}

const pick = (set: string): string => set.charAt(randomInt(set.length))

/** Mirrors the server rule: a password may not embed the username or the part of the email before the "@". */
function containsIdentity(password: string, username: string, email: string): boolean {
  const lower = password.toLowerCase()
  const emailName = email.trim().toLowerCase().split('@')[0] ?? ''
  return [username, emailName].some((id) => id.length >= 3 && lower.includes(id))
}

function generatePassword(length = 18): string {
  const all = LOWER + UPPER + DIGITS + SYMBOLS
  const chars = [pick(LOWER), pick(UPPER), pick(DIGITS), pick(SYMBOLS)]
  while (chars.length < length) chars.push(pick(all))
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1)
    const tmp = chars[i] as string
    chars[i] = chars[j] as string
    chars[j] = tmp
  }
  return chars.join('')
}

// ------------------------------------------------------------------------------------------
// Account list (derived from the audit trail: the API has no user-listing endpoint yet)
// ------------------------------------------------------------------------------------------
interface Account {
  id: string
  username: string
  role: string
  createdAt: string
  createdBy: string | null
  bootstrap: boolean
}

function toAccount(entry: AuditEntry): Account | null {
  const d = entry.details_json
  const username = typeof d.username === 'string' ? d.username : null
  if (!username || !entry.resource_id) return null
  return {
    id: entry.resource_id,
    username,
    role: typeof d.role === 'string' ? d.role : 'unknown',
    createdAt: entry.occurred_at,
    createdBy: entry.actor_id,
    bootstrap: d.bootstrap === true,
  }
}

interface Created {
  username: string
  password: string
  role: AssignableRole
}

export function UserManagement() {
  const me = useAuthStore((s) => s.user)
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin')
  const [offset, setOffset] = useState(0)
  const [created, setCreated] = useState<Created | null>(null)

  const accounts = useAsync(
    async (signal) => {
      const page = await auditApi.list({ action: 'USER_CREATE', outcome: 'SUCCESS', limit: PAGE_SIZE, offset }, signal)
      return { total: page.total, items: page.items.map(toAccount).filter((a): a is Account => a !== null) }
    },
    [offset],
  )

  const nameById = useMemo(() => {
    const map = new Map<string, string>()
    for (const a of accounts.data?.items ?? []) map.set(a.id, a.username)
    if (me) map.set(me.id, me.username)
    return map
  }, [accounts.data, me])

  if (!isAdmin) return <Navigate to="/" replace />

  return (
    <>
      <PageHeader
        title="Users"
        description="Register investigators and auditors. New accounts receive a temporary password and must choose their own at first sign-in."
      />

      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
        {/* ------------------------------------------------------------ register */}
        <div className="space-y-4">
          <RegisterForm
            onCreated={(c) => {
              setCreated(c)
              setOffset(0)
              accounts.reload()
            }}
          />
          {created && <CredentialsCard created={created} onDismiss={() => setCreated(null)} />}
        </div>

        {/* ------------------------------------------------------------ list */}
        <section aria-label="Registered accounts" className="apple-glass overflow-hidden rounded-4xl">
          <div className="flex items-center justify-between gap-3 px-6 pb-3 pt-6">
            <h2 className="text-xl font-bold tracking-heading text-ink">Registered accounts</h2>
            {accounts.data && <Badge>{accounts.data.total} total</Badge>}
          </div>

          <p className="mx-6 mb-3 flex items-start gap-2.5 rounded-2xl bg-apple-blue/5 px-4 py-3 text-[13px] leading-relaxed text-ink-soft">
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-apple-blue-ink" />
            <span>
              This list comes from the audit trail of account creations. Whether an account is active, its MFA status and last sign-in are not available from the API yet.
            </span>
          </p>

          {accounts.error && <div className="px-6 pb-4"><ErrorNote error={accounts.error} onRetry={accounts.reload} /></div>}

          {accounts.loading && !accounts.data ? (
            <div className="space-y-3 p-6 pt-2">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-14" />)}</div>
          ) : accounts.data && accounts.data.items.length > 0 ? (
            <ul className="divide-y divide-hairline">
              {accounts.data.items.map((a) => (
                <li key={`${a.id}-${a.createdAt}`} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-6 py-4">
                  <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-ink text-[12px] font-bold text-white">
                    {initials(a.username)}
                  </span>
                  <div className="min-w-0 flex-1 basis-40">
                    <p className="flex items-center gap-2 truncate text-[15px] font-semibold text-ink">
                      {a.username}
                      {a.id === me?.id && <Badge tone="green">You</Badge>}
                    </p>
                    <p className="hash text-[13px] text-ink-soft" title={a.id}>{shortHash(a.id, 8, 0)}</p>
                  </div>
                  <Badge tone={ROLE_TONE[a.role] ?? 'neutral'}>{ROLE_LABELS[a.role as Role] ?? a.role}</Badge>
                  <div className="basis-full text-[13px] leading-snug text-ink-soft sm:basis-auto sm:text-right">
                    <p>{formatDateTime(a.createdAt)}</p>
                    <p>
                      by {a.bootstrap ? 'setup script' : a.createdBy ? (nameById.get(a.createdBy) ?? shortHash(a.createdBy, 8, 0)) : 'system'}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          ) : !accounts.error ? (
            <EmptyState icon={Users} title="No accounts recorded" description="Accounts created through DEMS will appear here." />
          ) : null}

          {accounts.data && <Pager offset={offset} limit={PAGE_SIZE} total={accounts.data.total} onChange={setOffset} />}
        </section>
      </div>
    </>
  )
}

// ------------------------------------------------------------------------------------------
// Register form
// ------------------------------------------------------------------------------------------
function RegisterForm({ onCreated }: { onCreated: (created: Created) => void }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<AssignableRole>('investigator')
  const [password, setPassword] = useState('')
  const [reveal, setReveal] = useState(false)
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const normalizedUser = username.trim().toLowerCase()
  const problems = {
    username: USERNAME_RE.test(normalizedUser) ? null : '3–64 characters: letters, digits, dot, dash or underscore.',
    email: EMAIL_RE.test(email.trim()) ? null : 'Enter a valid email address.',
    password:
      password.length < 12 ? 'At least 12 characters.'
      : password.length > 128 ? 'At most 128 characters.'
      : containsIdentity(password, normalizedUser, email) ? 'Must not contain the username or email name.'
      : null,
  }
  const valid = !problems.username && !problems.email && !problems.password
  const show = (k: keyof typeof problems) => (touched[k] ? problems[k] : null)
  const touch = (k: string) => setTouched((t) => ({ ...t, [k]: true }))

  function generate() {
    setPassword(generatePassword())
    setReveal(true)
    touch('password')
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setTouched({ username: true, email: true, password: true })
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      const { data } = await apiClient.post<User>('/auth/register', {
        username: normalizedUser,
        email: email.trim().toLowerCase(),
        password,
        role,
      })
      toast.success(`Account created for ${data.username}`)
      onCreated({ username: data.username, password, role })
      setUsername('')
      setEmail('')
      setPassword('')
      setReveal(false)
      setTouched({})
      setRole('investigator')
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} noValidate className="apple-glass rounded-4xl p-6 sm:p-7">
      <div className="mb-5 flex items-center gap-3">
        <span className="inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-accent/10 text-accent-strong">
          <UserPlus className="h-5 w-5" />
        </span>
        <div>
          <h2 className="text-xl font-bold tracking-heading text-ink">Register account</h2>
          <p className="text-sm text-ink-soft">Creates a user with a temporary password.</p>
        </div>
      </div>

      {error && (
        <p role="alert" className="mb-4 rounded-2xl border border-apple-red/20 bg-apple-red/5 px-4 py-3 text-sm leading-relaxed text-apple-red-ink">{error}</p>
      )}

      <div className="space-y-4">
        <Field id="reg-username" label="Username" error={show('username')}>
          <input id="reg-username" className="field" autoComplete="off" spellCheck={false} value={username}
            onChange={(e) => setUsername(e.target.value)} onBlur={() => touch('username')} aria-invalid={!!show('username')} placeholder="jane.doe" />
        </Field>

        <Field id="reg-email" label="Email" error={show('email')}>
          <input id="reg-email" className="field" type="email" autoComplete="off" value={email}
            onChange={(e) => setEmail(e.target.value)} onBlur={() => touch('email')} aria-invalid={!!show('email')} placeholder="jane.doe@example.org" />
        </Field>

        <div>
          <span className="mb-1.5 block text-sm font-semibold text-ink">Role</span>
          <Segmented<AssignableRole>
            label="Role"
            value={role}
            onChange={setRole}
            options={[{ value: 'investigator', label: 'Investigator' }, { value: 'auditor', label: 'Auditor' }]}
          />
          <p className="mt-2 text-[13px] leading-relaxed text-ink-soft">
            {role === 'investigator'
              ? 'Works on cases they are assigned to: uploads, downloads and verifies evidence.'
              : 'Read-only: cases, custody chains and the audit log. Never sees evidence content.'}
          </p>
        </div>

        <Field id="reg-password" label="Temporary password" error={show('password')}>
          <div className="relative">
            <input id="reg-password" className="field pr-12" type={reveal ? 'text' : 'password'} autoComplete="new-password" spellCheck={false}
              value={password} onChange={(e) => setPassword(e.target.value)} onBlur={() => touch('password')} aria-invalid={!!show('password')} />
            <button type="button" aria-label={reveal ? 'Hide password' : 'Show password'} onClick={() => setReveal((v) => !v)}
              className="absolute right-2 top-1/2 inline-flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-full text-ink-soft transition hover:bg-black/[0.05] hover:text-ink">
              {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          <button type="button" onClick={generate} className="mt-2 inline-flex items-center gap-1.5 text-sm font-semibold text-apple-blue-ink hover:underline">
            <RefreshCw className="h-3.5 w-3.5" /> Generate a strong password
          </button>
        </Field>
      </div>

      <button type="submit" disabled={busy} className="btn-accent mt-6 w-full py-3">
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <><UserPlus className="h-4 w-4" /> Create account</>}
      </button>
    </form>
  )
}

function Field({ id, label, error, children }: { id: string; label: string; error: string | null; children: ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-semibold text-ink">{label}</label>
      {children}
      {error && <p role="alert" className="mt-1.5 text-[13px] text-apple-red-ink">{error}</p>}
    </div>
  )
}

// ------------------------------------------------------------------------------------------
// One-time credentials hand-over card
// ------------------------------------------------------------------------------------------
function CredentialsCard({ created, onDismiss }: { created: Created; onDismiss: () => void }) {
  const [copied, setCopied] = useState<string | null>(null)

  async function copy(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(label)
      setTimeout(() => setCopied((c) => (c === label ? null : c)), 1800)
    } catch {
      toast.error('Could not access the clipboard')
    }
  }

  const rows = [
    { label: 'Username', value: created.username },
    { label: 'Temporary password', value: created.password },
  ]

  return (
    <section aria-label="New account credentials" className="apple-glass-strong animate-scale-in rounded-4xl border-accent/20 p-6 sm:p-7">
      <div className="flex items-center gap-3">
        <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-apple-amber/15 text-apple-amber-ink"><KeyRound className="h-5 w-5" /></span>
        <div>
          <h3 className="text-lg font-bold tracking-heading text-ink">Hand over these credentials</h3>
          <p className="text-[13px] text-ink-soft">The password is shown only now. It cannot be retrieved later.</p>
        </div>
      </div>

      <dl className="mt-4 space-y-2.5">
        {rows.map((r) => (
          <div key={r.label} className="flex items-center justify-between gap-3 rounded-2xl border border-hairline bg-white/80 px-4 py-2.5">
            <div className="min-w-0">
              <dt className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">{r.label}</dt>
              <dd data-testid={`cred-${r.label === 'Username' ? 'user' : 'pass'}`} className="hash select-all text-[15px] font-semibold text-ink">{r.value}</dd>
            </div>
            <button type="button" aria-label={`Copy ${r.label.toLowerCase()}`} onClick={() => copy(r.label, r.value)}
              className={cn('inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition', copied === r.label ? 'bg-apple-green/15 text-apple-green-ink' : 'bg-black/[0.05] text-ink-soft hover:bg-black/10 hover:text-ink')}>
              {copied === r.label ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </button>
          </div>
        ))}
      </dl>

      <p className="mt-3 text-[13px] leading-relaxed text-ink-soft">
        {ROLE_LABELS[created.role]} will be asked to set a new password the first time they sign in. Share this securely, not by plain email.
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button type="button" className="btn-glass" onClick={() => copy('both', `Username: ${created.username}\nTemporary password: ${created.password}`)}>
          {copied === 'both' ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />} Copy both
        </button>
        <button type="button" className="btn-dark" onClick={onDismiss}>I've shared it</button>
      </div>
    </section>
  )
}

export default UserManagement
