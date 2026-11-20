import {
  ArrowLeft,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  FileText,
  FileUp,
  FolderOpen,
  Link2,
  Loader2,
  Lock,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UploadCloud,
  type LucideIcon,
} from 'lucide-react'
import { useCallback, useEffect, useId, useState } from 'react'
import { createPortal } from 'react-dom'
import { Link, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { EvidenceUploadModal } from '@/components/EvidenceUploadModal'
import { Badge, EmptyState, ErrorNote, Pager, Skeleton, type Tone } from '@/components/ui/primitives'
import {
  apiClient,
  casesApi,
  downloadEvidence,
  getErrorMessage,
  toApiError,
  type CaseRecord,
  type EvidenceRecord,
  type Outcome,
  type Page,
} from '@/lib/api'
import { useAsync } from '@/lib/useAsync'
import { cn, formatBytes, formatDate, formatDateTime, saveBlob, shortHash } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'

// ------------------------------------------------------------------------------------------
// API shapes not (yet) exported by lib/api.ts
// ------------------------------------------------------------------------------------------
interface CustodyEvent {
  id: string
  chain_id: string
  sequence_no: number
  evidence_id: string | null
  actor_id: string
  actor_username?: string | null
  actor_role: string
  action: string
  outcome: Outcome
  occurred_at: string
  source_ip: string
  details_json: Record<string, unknown>
  prev_event_hash: string
  event_hash: string
}

interface ChainVerify {
  valid: boolean
  events_checked: number
  head_hash: string | null
  broken_at_event_id: string | null
  broken_at_sequence: number | null
  failure_type: string | null
}

interface IntegrityResult {
  evidence_id: string
  status: 'pass' | 'fail' | 'error'
  expected_sha256: string
  actual_sha256: string | null
  detail: string
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const EVIDENCE_PAGE = 20
const CUSTODY_WINDOW = 500 // the API's maximum page size; we always show the newest events

const FAILURE_LABELS: Record<string, string> = {
  GAP: 'A custody event is missing from the sequence.',
  BAD_GENESIS: 'The chain does not start from its genesis anchor.',
  LINK_BROKEN: 'An event no longer links to the one before it.',
  CONTENT_TAMPERED: 'An event’s recorded data was altered after it was written.',
  HMAC_INVALID: 'An event’s authentication code is invalid (forged or re-hashed record).',
}

const ACTIONS: Record<string, { label: string; tone: Tone; icon: LucideIcon }> = {
  INGEST: { label: 'Evidence ingested', tone: 'blue', icon: FileUp },
  VIEW: { label: 'Metadata viewed', tone: 'neutral', icon: Eye },
  DOWNLOADED: { label: 'Evidence downloaded', tone: 'orange', icon: Download },
  INTEGRITY_VERIFIED: { label: 'Integrity verified', tone: 'green', icon: ShieldCheck },
  INTEGRITY_FAILED: { label: 'Integrity check failed', tone: 'red', icon: ShieldAlert },
  EVIDENCE_DELETED: { label: 'Evidence removed', tone: 'red', icon: Trash2 },
  CASE_CLOSE: { label: 'Case closed', tone: 'neutral', icon: Lock },
}

const DOT: Record<Tone, string> = {
  neutral: 'bg-ink-faint',
  orange: 'bg-accent',
  blue: 'bg-apple-blue',
  green: 'bg-apple-green',
  red: 'bg-apple-red',
  amber: 'bg-apple-amber',
}

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : null)
const num = (v: unknown): number | null => (typeof v === 'number' ? v : null)
const humanize = (s: string): string => s.replaceAll('_', ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())

function formatLeadInvestigator(caseRecord: CaseRecord, currentUserId: string | undefined): string {
  if (!caseRecord.lead_investigator_id) return 'Unassigned'
  const isCurrentUser = caseRecord.lead_investigator_id === currentUserId
  if (caseRecord.lead_investigator_username) {
    return isCurrentUser
      ? `${caseRecord.lead_investigator_username} (${caseRecord.lead_investigator_id}) · You`
      : `${caseRecord.lead_investigator_username} (${caseRecord.lead_investigator_id})`
  }
  return isCurrentUser
    ? `${caseRecord.lead_investigator_id} · You`
    : caseRecord.lead_investigator_id
}

function formatCustodyActor(e: CustodyEvent): string {
  if (e.actor_username && e.actor_id) return `${e.actor_username} (${e.actor_id})`
  if (e.actor_username) return e.actor_username
  return e.actor_id
}

function summarize(e: CustodyEvent): string | null {
  const d = e.details_json
  switch (e.action) {
    case 'INGEST': {
      const size = num(d.size_bytes)
      return [str(d.filename), size !== null ? formatBytes(size) : null].filter(Boolean).join(' · ') || null
    }
    case 'DOWNLOADED':
      return str(d.filename)
    case 'INTEGRITY_VERIFIED':
    case 'INTEGRITY_FAILED':
      return str(d.detail) ?? str(d.status)
    case 'EVIDENCE_DELETED':
      return str(d.reason) ? `Reason: ${str(d.reason)}` : null
    case 'CASE_CLOSE': {
      const count = num(d.evidence_count)
      return count !== null ? `${count} evidence item${count === 1 ? '' : 's'} sealed in the closure manifest` : null
    }
    case 'VIEW':
      return str(d.view) ? `Viewed ${str(d.view)}` : null
    default:
      return null
  }
}

/**
 * Downloads use `responseType: 'blob'`, so axios hands error bodies back as a Blob/bytes and the shared error
 * helper cannot read the server's JSON message (it reports code "http_error"). Map those statuses ourselves.
 */
function downloadErrorMessage(err: unknown): string {
  const e = toApiError(err)
  if (e.code !== 'http_error') return e.message
  switch (e.status) {
    case 409:
      return 'Integrity verification failed; the download was refused.'
    case 404:
      return 'Evidence not found, or you are not assigned to this case.'
    case 403:
      return 'You do not have permission to download this evidence.'
    default:
      return e.message
  }
}

async function copyText(text: string, what: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(`${what} copied`)
  } catch {
    toast.error('Could not access the clipboard')
  }
}

// ------------------------------------------------------------------------------------------
// Page
// ------------------------------------------------------------------------------------------
export function CaseDetail() {
  const { caseId = '' } = useParams<{ caseId: string }>()
  const validId = UUID_RE.test(caseId)
  const user = useAuthStore((s) => s.user)
  const can = useAuthStore((s) => s.can)

  const [evidenceOffset, setEvidenceOffset] = useState(0)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [closeOpen, setCloseOpen] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<EvidenceRecord | null>(null)
  const [busy, setBusy] = useState<Record<string, 'download' | 'verify'>>({})
  const [chain, setChain] = useState<ChainVerify | null>(null)
  const [chainBusy, setChainBusy] = useState(false)

  const caseQ = useAsync(
    async (signal) => (await apiClient.get<CaseRecord>(`/cases/${caseId}`, { signal })).data,
    [caseId],
  )
  const evidenceQ = useAsync(
    async (signal) =>
      (await apiClient.get<Page<EvidenceRecord>>(`/cases/${caseId}/evidence`, { params: { limit: EVIDENCE_PAGE, offset: evidenceOffset }, signal })).data,
    [caseId, evidenceOffset],
  )
  const custodyQ = useAsync(
    async (signal) => {
      const get = async (offset: number) =>
        (await apiClient.get<Page<CustodyEvent>>(`/custody/${caseId}`, { params: { limit: CUSTODY_WINDOW, offset }, signal })).data
      const first = await get(0)
      const page = first.total > CUSTODY_WINDOW ? await get(first.total - CUSTODY_WINDOW) : first
      return { total: first.total, events: [...page.items].reverse() } // newest first
    },
    [caseId],
  )

  useEffect(() => {
    setEvidenceOffset(0)
    setChain(null)
  }, [caseId])

  const refresh = useCallback(() => {
    evidenceQ.reload()
    custodyQ.reload()
    setChain(null) // a previous verdict no longer describes the current chain
  }, [evidenceQ, custodyQ])

  if (!validId) {
    return (
      <div className="space-y-4">
        <BackLink />
        <div className="apple-glass rounded-4xl"><EmptyState icon={FolderOpen} title="Case not found" description="That link does not point to a valid case." /></div>
      </div>
    )
  }

  const c = caseQ.data
  const isOpen = c?.status === 'open'
  const canCloseCase =
    !!c &&
    isOpen &&
    can('case:manage') &&
    (user?.role === 'admin' || c.lead_investigator_id === user?.id)

  const setItemBusy = (id: string, action: 'download' | 'verify' | null) =>
    setBusy((b) => {
      const next = { ...b }
      if (action) next[id] = action
      else delete next[id]
      return next
    })

  async function onDownload(ev: EvidenceRecord) {
    setItemBusy(ev.id, 'download')
    try {
      const result = await downloadEvidence(ev.id)
      saveBlob(result.blob, result.filename)
      if (result.verifiedLocally === false) toast.error('Warning: the downloaded bytes do not match the SHA-256 the server advertised.')
      else toast.success(result.verifiedLocally ? 'Downloaded. SHA-256 re-verified in your browser.' : 'Downloaded')
    } catch (err) {
      toast.error(downloadErrorMessage(err))
    } finally {
      setItemBusy(ev.id, null)
      refresh()
    }
  }

  async function onVerify(ev: EvidenceRecord) {
    setItemBusy(ev.id, 'verify')
    try {
      const { data } = await apiClient.post<IntegrityResult>(`/evidence/${ev.id}/verify`)
      if (data.status === 'pass') toast.success(`${ev.original_filename}: integrity verified`)
      else toast.error(`${ev.original_filename}: ${data.status === 'fail' ? 'INTEGRITY CHECK FAILED' : 'file could not be read'}`)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setItemBusy(ev.id, null)
      refresh()
    }
  }

  async function onVerifyChain() {
    setChainBusy(true)
    try {
      const { data } = await apiClient.get<ChainVerify>(`/custody/${caseId}/verify`)
      setChain(data)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setChainBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <BackLink />

      {caseQ.error ? (
        <div className="apple-glass rounded-4xl p-6">
          <ErrorNote
            error={caseQ.error.status === 404 ? new Error('Case not found, or you do not have access to it.') : caseQ.error}
            onRetry={caseQ.error.status === 404 ? undefined : caseQ.reload}
          />
        </div>
      ) : (
        <>
          {/* ------------------------------------------------------------ header */}
          <section className="apple-glass-strong relative overflow-hidden rounded-4xl p-6 sm:p-8">
            <div aria-hidden className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-accent/15 blur-3xl" />
            <div aria-hidden className="pointer-events-none absolute -left-24 -bottom-32 h-72 w-72 rounded-full bg-apple-blue/15 blur-3xl" />
            {!c ? (
              <div className="relative space-y-3"><Skeleton className="h-5 w-32" /><Skeleton className="h-10 w-2/3" /><Skeleton className="h-16 w-full" /></div>
            ) : (
              <div className="relative">
                <div className="flex flex-wrap items-center justify-between gap-2.5">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <Badge tone="neutral" className="hash">{c.case_number}</Badge>
                    <Badge tone={isOpen ? 'green' : 'neutral'}>{isOpen ? <>Open</> : <><Lock className="h-3 w-3" /> Closed</>}</Badge>
                  </div>
                  {canCloseCase && (
                    <button type="button" className="btn-glass" onClick={() => setCloseOpen(true)}>
                      <Lock className="h-4 w-4" /> Close case
                    </button>
                  )}
                </div>
                <h1 className="mt-3 text-balance text-3xl font-extrabold leading-tight tracking-display text-ink sm:text-5xl">{c.title}</h1>
                {c.description && <p className="mt-3 max-w-3xl whitespace-pre-line text-[15px] leading-relaxed text-ink-soft">{c.description}</p>}

                <dl className="mt-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
                  <Meta label="Opened" value={formatDate(c.created_at)} />
                  <Meta
                    label={isOpen ? 'Lead investigator' : 'Closed'}
                    value={isOpen ? formatLeadInvestigator(c, user?.id) : formatDate(c.closed_at)}
                  />
                  <Meta label="Evidence items" value={evidenceQ.data ? String(evidenceQ.data.total) : '—'} />
                  <Meta label="Custody events" value={custodyQ.data ? String(custodyQ.data.total) : '—'} />
                </dl>

                {c.closure_manifest_hash && (
                  <div className="mt-4 rounded-2xl border border-hairline bg-white/70 p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">Closure manifest · SHA-256 over all sealed evidence</p>
                    <p className="hash mt-1 text-[13px] font-medium text-ink">{c.closure_manifest_hash}</p>
                  </div>
                )}
              </div>
            )}
          </section>

          {/* ------------------------------------------------------------ evidence */}
          <section aria-label="Evidence" className="apple-glass overflow-hidden rounded-4xl">
            <div className="flex flex-wrap items-center justify-between gap-3 px-6 pb-4 pt-6">
              <div>
                <h2 className="text-xl font-bold tracking-heading text-ink">Evidence</h2>
                <p className="text-sm text-ink-soft">Encrypted at rest. Every access is recorded in the custody ledger.</p>
              </div>
              {can('evidence:upload') && (
                isOpen ? (
                  <button type="button" className="btn-accent" onClick={() => setUploadOpen(true)}><UploadCloud className="h-4 w-4" /> Upload evidence</button>
                ) : c ? (
                  <Badge tone="neutral"><Lock className="h-3 w-3" /> Uploads locked: case closed</Badge>
                ) : null
              )}
            </div>

            {evidenceQ.error && <div className="px-6 pb-4"><ErrorNote error={evidenceQ.error} onRetry={evidenceQ.reload} /></div>}

            {evidenceQ.loading && !evidenceQ.data ? (
              <div className="space-y-3 p-6 pt-2">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-16" />)}</div>
            ) : evidenceQ.data && evidenceQ.data.items.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] text-left text-sm">
                  <thead>
                    <tr className="border-y border-hairline text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">
                      <th className="px-6 py-3.5">File</th>
                      <th className="px-4 py-3.5">SHA-256</th>
                      <th className="px-4 py-3.5">Uploaded</th>
                      <th className="px-4 py-3.5">Integrity</th>
                      <th className="px-6 py-3.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-hairline">
                    {evidenceQ.data.items.map((ev) => (
                      <EvidenceRow
                        key={ev.id}
                        ev={ev}
                        busy={busy[ev.id]}
                        canDownload={can('evidence:download')}
                        canVerify={can('evidence:verify')}
                        canDelete={can('evidence:delete') && !!isOpen}
                        onDownload={() => void onDownload(ev)}
                        onVerify={() => void onVerify(ev)}
                        onDelete={() => setPendingDelete(ev)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            ) : !evidenceQ.error ? (
              <EmptyState icon={FileText} title="No evidence yet" description={can('evidence:upload') && isOpen ? 'Upload the first item to start the chain of custody.' : 'Evidence added to this case will appear here.'} />
            ) : null}

            {evidenceQ.data && <Pager offset={evidenceOffset} limit={EVIDENCE_PAGE} total={evidenceQ.data.total} onChange={setEvidenceOffset} />}
          </section>

          {/* ------------------------------------------------------------ custody ledger */}
          <section aria-label="Chain of custody" className="apple-glass rounded-4xl p-6 sm:p-8">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-xl font-bold tracking-heading text-ink">Chain of custody</h2>
                <p className="mt-0.5 max-w-xl text-sm leading-relaxed text-ink-soft">
                  An append-only ledger. Each event is sealed with the hash of the one before it, so any edit, deletion or insertion breaks the chain.
                </p>
              </div>
              <button type="button" className="btn-dark" disabled={chainBusy || !custodyQ.data} onClick={() => void onVerifyChain()}>
                {chainBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />} Verify chain
              </button>
            </div>

            {chain && <ChainBanner result={chain} />}
            {custodyQ.error && <div className="mt-4"><ErrorNote error={custodyQ.error} onRetry={custodyQ.reload} /></div>}

            {custodyQ.loading && !custodyQ.data ? (
              <div className="mt-6 space-y-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-20" />)}</div>
            ) : custodyQ.data && custodyQ.data.events.length > 0 ? (
              <>
                {custodyQ.data.total > custodyQ.data.events.length && (
                  <p className="mt-4 text-[13px] text-ink-soft">Showing the latest {custodyQ.data.events.length} of {custodyQ.data.total} events.</p>
                )}
                <ol className="mt-6" aria-label="Custody events, newest first">
                  {custodyQ.data.events.map((e, i, all) => (
                    <TimelineItem key={e.id} e={e} last={i === all.length - 1} broken={chain?.broken_at_event_id === e.id} />
                  ))}
                </ol>
              </>
            ) : !custodyQ.error ? (
              <EmptyState icon={ScrollText} title="No custody events yet" description="The ledger starts with the first piece of evidence." />
            ) : null}
          </section>
        </>
      )}

      {c && (
        <EvidenceUploadModal
          open={uploadOpen}
          onClose={() => setUploadOpen(false)}
          caseId={caseId}
          caseNumber={c.case_number}
          onUploaded={() => {
            setEvidenceOffset(0)
            refresh()
          }}
        />
      )}

      {c && closeOpen && (
        <CloseCaseDialog
          caseRecord={c}
          onClose={() => setCloseOpen(false)}
          onClosed={() => {
            setCloseOpen(false)
            caseQ.reload()
            refresh()
          }}
        />
      )}

      {pendingDelete && (
        <DeleteDialog
          evidence={pendingDelete}
          onClose={() => setPendingDelete(null)}
          onDeleted={() => {
            setPendingDelete(null)
            refresh()
          }}
        />
      )}
    </div>
  )
}

// ------------------------------------------------------------------------------------------
// Pieces
// ------------------------------------------------------------------------------------------
function BackLink() {
  return (
    <Link to="/cases" className="inline-flex items-center gap-1.5 rounded-full text-sm font-semibold text-ink-soft transition hover:text-ink">
      <ArrowLeft className="h-4 w-4" /> All cases
    </Link>
  )
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-hairline bg-white/70 px-4 py-3">
      <dt className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">{label}</dt>
      <dd className="mt-0.5 truncate text-base font-bold tracking-heading text-ink" title={value}>{value}</dd>
    </div>
  )
}

function integrityBadge(ev: EvidenceRecord) {
  switch (ev.last_verify_result) {
    case 'pass': return <Badge tone="green"><ShieldCheck className="h-3 w-3" /> Verified</Badge>
    case 'fail': return <Badge tone="red"><ShieldAlert className="h-3 w-3" /> Failed</Badge>
    case 'error': return <Badge tone="amber">Unreadable</Badge>
    default: return <Badge>Not verified</Badge>
  }
}

function EvidenceRow({ ev, busy, canDownload, canVerify, canDelete, onDownload, onVerify, onDelete }: {
  ev: EvidenceRecord
  busy: 'download' | 'verify' | undefined
  canDownload: boolean
  canVerify: boolean
  canDelete: boolean
  onDownload: () => void
  onVerify: () => void
  onDelete: () => void
}) {
  return (
    <tr className="align-middle transition-colors hover:bg-white/60">
      <td className="px-6 py-4">
        <p className="max-w-[16rem] truncate font-semibold text-ink" title={ev.original_filename}>{ev.original_filename}</p>
        <p className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[13px] text-ink-soft">
          <span>{formatBytes(ev.size_bytes)}</span><span aria-hidden>·</span><span>{ev.detected_mime}</span>
        </p>
        {ev.tags.length > 0 && (
          <p className="mt-1.5 flex flex-wrap gap-1">{ev.tags.slice(0, 4).map((t) => <Badge key={t} tone="neutral" className="font-medium">{t}</Badge>)}</p>
        )}
      </td>
      <td className="px-4 py-4">
        <button type="button" onClick={() => void copyText(ev.sha256_server, 'SHA-256')} title={`${ev.sha256_server} (click to copy)`}
          className="hash inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[13px] text-ink-soft transition hover:bg-black/[0.05] hover:text-ink">
          {shortHash(ev.sha256_server)} <Copy className="h-3 w-3" />
        </button>
      </td>
      <td className="whitespace-nowrap px-4 py-4 text-ink-soft">{formatDateTime(ev.uploaded_at)}</td>
      <td className="px-4 py-4" title={ev.last_verified_at ? `Last checked ${formatDateTime(ev.last_verified_at)}` : undefined}>{integrityBadge(ev)}</td>
      <td className="px-6 py-4">
        <div className="flex items-center justify-end gap-1.5">
          {canVerify && <IconAction label={`Verify integrity of ${ev.original_filename}`} onClick={onVerify} loading={busy === 'verify'} disabled={!!busy} icon={ShieldCheck} />}
          {canDownload && <IconAction label={`Download ${ev.original_filename}`} onClick={onDownload} loading={busy === 'download'} disabled={!!busy} icon={Download} />}
          {canDelete && <IconAction label={`Delete ${ev.original_filename}`} onClick={onDelete} disabled={!!busy} icon={Trash2} danger />}
        </div>
      </td>
    </tr>
  )
}

function IconAction({ label, icon: Icon, onClick, loading, disabled, danger }: {
  label: string
  icon: LucideIcon
  onClick: () => void
  loading?: boolean
  disabled?: boolean
  danger?: boolean
}) {
  return (
    <button type="button" aria-label={label} title={label} onClick={onClick} disabled={disabled}
      className={cn('inline-flex h-9 w-9 items-center justify-center rounded-full bg-white/80 shadow-glass-sm ring-1 ring-hairline transition hover:bg-white disabled:opacity-50',
        danger ? 'text-apple-red-ink hover:bg-apple-red/10' : 'text-ink')}>
      {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Icon className="h-4 w-4" />}
    </button>
  )
}

function ChainBanner({ result }: { result: ChainVerify }) {
  return result.valid ? (
    <div role="status" className="mt-5 flex items-start gap-3 rounded-2xl border border-apple-green/25 bg-apple-green/10 p-4 text-apple-green-ink">
      <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" />
      <div className="min-w-0 text-sm leading-relaxed">
        <p className="font-bold">Chain intact</p>
        <p>{result.events_checked === 0 ? 'No events to verify yet.' : `${result.events_checked} event${result.events_checked === 1 ? '' : 's'} re-hashed and authenticated. No tampering detected.`}</p>
        {result.head_hash && <p className="hash mt-1 text-[12px] opacity-90" title={result.head_hash}>Head {shortHash(result.head_hash, 16, 8)}</p>}
      </div>
    </div>
  ) : (
    <div role="alert" className="mt-5 flex items-start gap-3 rounded-2xl border border-apple-red/25 bg-apple-red/10 p-4 text-apple-red-ink">
      <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0" />
      <div className="min-w-0 text-sm leading-relaxed">
        <p className="font-bold">Chain broken{result.broken_at_sequence !== null ? ` at event #${result.broken_at_sequence}` : ''}</p>
        <p>{FAILURE_LABELS[result.failure_type ?? ''] ?? 'The ledger failed verification.'}</p>
        <p className="mt-1 text-[13px]">The first failing event is highlighted below. Treat evidence recorded after it as unverified and escalate to an administrator.</p>
      </div>
    </div>
  )
}

function TimelineItem({ e, last, broken }: { e: CustodyEvent; last: boolean; broken: boolean }) {
  const meta = ACTIONS[e.action] ?? { label: humanize(e.action), tone: 'neutral' as Tone, icon: ScrollText }
  const Icon = meta.icon
  const detail = summarize(e)
  const tone: Tone = e.outcome === 'FAILURE' ? 'red' : meta.tone
  return (
    <li className="relative flex gap-4 pb-5 last:pb-0" data-broken={broken || undefined}>
      {!last && <span aria-hidden className="absolute bottom-0 left-[19px] top-10 w-px bg-gradient-to-b from-black/15 to-black/5" />}
      <span className={cn('relative z-10 mt-1 inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-white shadow-glass-sm ring-4 ring-white/80', DOT[tone])}>
        <Icon className="h-[18px] w-[18px]" />
      </span>
      <div className={cn('min-w-0 flex-1 rounded-2xl border bg-white/70 p-4 transition', broken ? 'border-apple-red/60 bg-apple-red/5 ring-2 ring-apple-red/30' : 'border-hairline')}>
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
          <p className="text-[15px] font-bold tracking-heading text-ink">{meta.label}</p>
          {e.outcome !== 'SUCCESS' && <Badge tone={e.outcome === 'FAILURE' ? 'red' : 'amber'}>{humanize(e.outcome)}</Badge>}
          {broken && <Badge tone="red">First broken event</Badge>}
          <span className="ml-auto text-[12px] font-semibold tabular-nums text-ink-soft">#{e.sequence_no}</span>
        </div>
        {detail && <p className="mt-1 break-words text-sm leading-relaxed text-ink-soft">{detail}</p>}
        <p className="mt-1.5 text-[13px] text-ink-soft">
          {formatDateTime(e.occurred_at)} · {formatCustodyActor(e)} · {humanize(e.actor_role)} · <span className="hash">{e.source_ip}</span>
        </p>
        <p className="hash mt-2 flex flex-wrap items-center gap-x-2 text-[12px] text-ink-faint" title={`hash ${e.event_hash}\nprev ${e.prev_event_hash}`}>
          <Link2 className="h-3 w-3" />
          <span>{shortHash(e.event_hash, 10, 6)}</span>
          <span aria-hidden>←</span>
          <span>{shortHash(e.prev_event_hash, 10, 6)}</span>
        </p>
      </div>
    </li>
  )
}

function CloseCaseDialog({ caseRecord, onClose, onClosed }: { caseRecord: CaseRecord; onClose: () => void; onClosed: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const titleId = useId()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && !busy && onClose()
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
    }
  }, [busy, onClose])

  async function confirm() {
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      await casesApi.close(caseRecord.id)
      toast.success(`Case ${caseRecord.case_number} closed and sealed.`)
      onClosed()
    } catch (err) {
      setError(getErrorMessage(err))
      setBusy(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-end justify-center p-3 sm:items-center sm:p-6">
      <button type="button" aria-label="Close dialog" tabIndex={-1} onClick={onClose} disabled={busy} className="absolute inset-0 bg-black/30 backdrop-blur-sm" />
      <div role="alertdialog" aria-modal="true" aria-labelledby={titleId} className="apple-glass-strong relative w-full max-w-md animate-scale-in rounded-4xl p-6 sm:p-8">
        <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-black/5 text-ink"><Lock className="h-5 w-5" /></span>
        <h2 id={titleId} className="mt-4 text-xl font-extrabold tracking-heading text-ink">Close this case?</h2>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">
          <b className="text-ink">{caseRecord.case_number}</b> ({caseRecord.title}) will be permanently locked. A SHA-256 closure manifest will be computed over all active evidence, and no further uploads, edits, or assignment changes will be permitted.
        </p>
        {error && <p role="alert" className="mt-3 rounded-2xl border border-apple-red/20 bg-apple-red/5 px-4 py-3 text-sm text-apple-red-ink">{error}</p>}
        <div className="mt-6 flex justify-end gap-2">
          <button type="button" className="btn-glass" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn-dark" disabled={busy} onClick={() => void confirm()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />} Close case
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

function DeleteDialog({ evidence, onClose, onDeleted }: { evidence: EvidenceRecord; onClose: () => void; onDeleted: () => void }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const titleId = useId()
  const valid = reason.trim().length >= 3

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && !busy && onClose()
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
    }
  }, [busy, onClose])

  async function confirm() {
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      await apiClient.delete(`/evidence/${evidence.id}`, { params: { reason: reason.trim() } })
      toast.success('Evidence removed from the case. The encrypted file and custody history are retained.')
      onDeleted()
    } catch (err) {
      setError(getErrorMessage(err))
      setBusy(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-end justify-center p-3 sm:items-center sm:p-6">
      <button type="button" aria-label="Close dialog" tabIndex={-1} onClick={onClose} disabled={busy} className="absolute inset-0 bg-black/30 backdrop-blur-sm" />
      <div role="alertdialog" aria-modal="true" aria-labelledby={titleId} className="apple-glass-strong relative w-full max-w-md animate-scale-in rounded-4xl p-6 sm:p-8">
        <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-apple-red/10 text-apple-red-ink"><Trash2 className="h-5 w-5" /></span>
        <h2 id={titleId} className="mt-4 text-xl font-extrabold tracking-heading text-ink">Remove this evidence?</h2>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">
          <b className="text-ink">{evidence.original_filename}</b> will be hidden from the case. This is a soft delete: the encrypted file and its custody history are kept, and the removal is recorded in the ledger.
        </p>
        <label htmlFor={`${titleId}-reason`} className="mb-1.5 mt-5 block text-sm font-semibold text-ink">Reason (required)</label>
        <textarea id={`${titleId}-reason`} rows={3} maxLength={500} autoFocus className="field resize-none" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Duplicate of item uploaded on 3 Nov" />
        {error && <p role="alert" className="mt-3 rounded-2xl border border-apple-red/20 bg-apple-red/5 px-4 py-3 text-sm text-apple-red-ink">{error}</p>}
        <div className="mt-6 flex justify-end gap-2">
          <button type="button" className="btn-glass" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="button" className="btn bg-apple-red-ink text-white shadow-glass-sm hover:brightness-110" disabled={!valid || busy} onClick={() => void confirm()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />} Remove evidence
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export default CaseDetail
