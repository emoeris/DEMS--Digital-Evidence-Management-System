import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Fingerprint,
  Loader2,
  ShieldCheck,
  UploadCloud,
  X,
} from 'lucide-react'
import { useCallback, useEffect, useId, useRef, useState, type DragEvent, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { toast } from 'sonner'
import { apiClient, toApiError, type EvidenceRecord } from '@/lib/api'
import { HashAbortedError, hashesEqual, sha256File } from '@/lib/crypto'
import { cn, formatBytes } from '@/lib/utils'

export interface EvidenceUploadModalProps {
  open: boolean
  onClose: () => void
  caseId: string
  /** Shown in the header, e.g. "CASE-2026-014". */
  caseNumber?: string
  /** Called once the server has accepted and sealed the file. */
  onUploaded?: (evidence: EvidenceRecord) => void
}

type Phase = 'select' | 'hashing' | 'ready' | 'uploading' | 'done'

const MAX_TAGS = 20
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

/** Mounts a fresh dialog each time `open` flips to true, so state never leaks between uploads. */
export function EvidenceUploadModal(props: EvidenceUploadModalProps) {
  if (!props.open) return null
  return createPortal(<UploadDialog {...props} />, document.body)
}

function friendlyError(code: string, message: string): string {
  switch (code) {
    case 'hash_mismatch':
      return 'The bytes received by the server did not match the hash computed in your browser, so nothing was stored. Please try again.'
    case 'case_closed':
      return 'This case is closed, so no new evidence can be added.'
    case 'network_error':
      return 'Cannot reach the server. Check your connection and try again.'
    default:
      return message
  }
}

function UploadDialog({ caseId, caseNumber, onClose, onUploaded }: EvidenceUploadModalProps) {
  const [phase, setPhase] = useState<Phase>('select')
  const [file, setFile] = useState<File | null>(null)
  const [digest, setDigest] = useState<string | null>(null)
  const [hashFraction, setHashFraction] = useState(0)
  const [sendFraction, setSendFraction] = useState(0)
  const [description, setDescription] = useState('')
  const [source, setSource] = useState('')
  const [tags, setTags] = useState('')
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<EvidenceRecord | null>(null)

  const abortRef = useRef<AbortController | null>(null)
  const dialogRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const ids = { title: useId(), file: useId(), desc: useId(), src: useId(), tags: useId() }

  const busy = phase === 'uploading'

  const close = useCallback(() => {
    abortRef.current?.abort()
    onClose()
  }, [onClose])

  // Escape, focus trap, scroll lock, focus restore
  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null
    document.body.style.overflow = 'hidden'
    dialogRef.current?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) {
        e.stopPropagation()
        close()
      }
      if (e.key === 'Tab' && dialogRef.current) {
        const items = [...dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)]
        const first = items[0]
        const last = items[items.length - 1]
        if (!first || !last) return
        const active = document.activeElement
        if (e.shiftKey && (active === first || active === dialogRef.current)) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && active === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
      previouslyFocused?.focus?.()
    }
  }, [busy, close])

  useEffect(() => () => abortRef.current?.abort(), [])

  // ---------------------------------------------------------------- hashing
  async function selectFile(picked: File | undefined | null) {
    if (!picked) return
    abortRef.current?.abort()
    setError(null)
    setDigest(null)
    setResult(null)
    if (picked.size === 0) {
      setFile(null)
      setPhase('select')
      setError('That file is empty. Empty files cannot be ingested.')
      return
    }

    const controller = new AbortController()
    abortRef.current = controller
    setFile(picked)
    setHashFraction(0)
    setPhase('hashing')
    try {
      // Computed in the browser with SubtleCrypto (or the streaming fallback for very large files).
      const hex = await sha256File(picked, {
        signal: controller.signal,
        onProgress: (p) => setHashFraction(p.fraction),
      })
      setDigest(hex)
      setPhase('ready')
    } catch (err) {
      if (err instanceof HashAbortedError || controller.signal.aborted) return
      setFile(null)
      setPhase('select')
      setError(`Could not read the file: ${err instanceof Error ? err.message : 'unknown error'}`)
    }
  }

  // ---------------------------------------------------------------- upload
  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!file || !digest || busy) return

    const tagList = tags.split(',').map((t) => t.trim()).filter(Boolean)
    if (tagList.length > MAX_TAGS || tagList.some((t) => t.length > 64)) {
      setError(`Use at most ${MAX_TAGS} tags of 64 characters each.`)
      return
    }

    const form = new FormData()
    form.append('case_id', caseId)
    form.append('client_sha256', digest)
    if (description.trim()) form.append('description', description.trim())
    if (source.trim()) form.append('source', source.trim())
    if (tagList.length) form.append('tags', tagList.join(','))
    form.append('file', file, file.name)

    const controller = new AbortController()
    abortRef.current = controller
    setError(null)
    setSendFraction(0)
    setPhase('uploading')
    try {
      // The digest is sent as a form field (validated by the API) and as the x-client-sha256 header.
      const { data } = await apiClient.post<EvidenceRecord>('/evidence/upload', form, {
        headers: { 'x-client-sha256': digest },
        timeout: 0,
        signal: controller.signal,
        onUploadProgress: (ev) => {
          if (ev.total) setSendFraction(Math.min(ev.loaded / ev.total, 1))
        },
      })
      setResult(data)
      setPhase('done')
      toast.success('Evidence sealed and recorded in the chain of custody')
      onUploaded?.(data)
    } catch (err) {
      const apiError = toApiError(err)
      setPhase('ready')
      if (apiError.code !== 'cancelled') setError(friendlyError(apiError.code, apiError.message))
    }
  }

  function reset() {
    abortRef.current?.abort()
    setFile(null)
    setDigest(null)
    setResult(null)
    setError(null)
    setDescription('')
    setSource('')
    setTags('')
    setPhase('select')
  }

  async function copyDigest() {
    if (!digest) return
    try {
      await navigator.clipboard.writeText(digest)
      toast.success('SHA-256 copied')
    } catch {
      toast.error('Could not access the clipboard')
    }
  }

  // ---------------------------------------------------------------- drag & drop
  const onDrop = (e: DragEvent<HTMLElement>) => {
    e.preventDefault()
    setDragging(false)
    if (phase === 'select') void selectFile(e.dataTransfer.files?.[0])
  }
  const onDragOver = (e: DragEvent<HTMLElement>) => {
    e.preventDefault()
    if (phase === 'select') setDragging(true)
  }

  const pct = (f: number) => `${Math.round(f * 100)}%`

  return (
    <div className="fixed inset-0 z-[70] flex items-end justify-center p-3 sm:items-center sm:p-6">
      <button
        type="button"
        aria-label="Close dialog"
        tabIndex={-1}
        disabled={busy}
        onClick={close}
        className="absolute inset-0 bg-black/30 backdrop-blur-sm"
      />

      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ids.title}
        tabIndex={-1}
        className="apple-glass-strong relative max-h-[92vh] w-full max-w-lg animate-scale-in overflow-y-auto rounded-4xl p-6 outline-none sm:p-8"
      >
        {/* ------------------------------------------------ header */}
        <div className="mb-6 flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-accent-soft via-accent to-accent-strong text-white shadow-glass-sm">
              <UploadCloud className="h-5 w-5" />
            </span>
            <div>
              <h2 id={ids.title} className="text-xl font-extrabold tracking-heading text-ink">Upload evidence</h2>
              {caseNumber && <p className="text-sm text-ink-soft">Case {caseNumber}</p>}
            </div>
          </div>
          <button
            type="button"
            aria-label="Close"
            onClick={close}
            disabled={busy}
            className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-black/[0.05] text-ink transition hover:bg-black/10 disabled:opacity-40"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {error && (
          <p role="alert" className="mb-5 flex items-start gap-2.5 rounded-2xl border border-apple-red/20 bg-apple-red/5 px-4 py-3 text-sm leading-relaxed text-apple-red-ink">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> <span>{error}</span>
          </p>
        )}

        {/* ------------------------------------------------ done */}
        {phase === 'done' && result ? (
          <div>
            <div className="flex flex-col items-center rounded-3xl bg-apple-green/10 px-5 py-7 text-center">
              <CheckCircle2 className="h-10 w-10 text-apple-green-ink" />
              <p className="mt-3 text-lg font-bold tracking-heading text-ink">Evidence sealed</p>
              <p className="mt-1 text-sm leading-relaxed text-ink-soft">Encrypted at rest and appended to the chain of custody.</p>
            </div>

            <dl className="mt-5 space-y-3 text-sm">
              <Row label="File" value={result.original_filename} />
              <Row label="Size" value={formatBytes(result.size_bytes)} />
              <Row label="Detected type" value={result.detected_mime} />
              <Row label="Evidence ID" value={result.id} hash />
            </dl>

            {digest && hashesEqual(digest, result.sha256_server) ? (
              <div className="mt-5 flex items-start gap-2.5 rounded-2xl border border-apple-green/25 bg-apple-green/10 p-4 text-sm text-apple-green-ink">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
                <p className="leading-relaxed">
                  <b>Hashes match.</b> The SHA-256 from your browser equals the server's independent re-hash:
                  <span className="hash mt-1 block text-[13px]">{result.sha256_server}</span>
                </p>
              </div>
            ) : (
              <p role="alert" className="mt-5 rounded-2xl border border-apple-red/20 bg-apple-red/5 p-4 text-sm text-apple-red-ink">
                The server's hash differs from the one computed locally. Do not rely on this upload; contact an administrator.
              </p>
            )}

            <div className="mt-6 flex flex-wrap justify-end gap-2">
              <button type="button" className="btn-glass" onClick={reset}>Upload another</button>
              <button type="button" className="btn-dark" onClick={close}>Done</button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} noValidate>
            {/* ------------------------------------------------ file selection */}
            {phase === 'select' ? (
              <div
                onDragOver={onDragOver}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                className={cn(
                  'flex flex-col items-center rounded-3xl border-2 border-dashed px-6 py-10 text-center transition',
                  dragging ? 'border-apple-blue bg-apple-blue/5' : 'border-black/10 bg-white/50 hover:bg-white/70',
                )}
              >
                <span className="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-black/[0.05] text-ink-soft">
                  <UploadCloud className="h-6 w-6" />
                </span>
                <p className="mt-4 text-base font-semibold text-ink">Drop a file here</p>
                <p className="mt-1 text-sm text-ink-soft">or</p>
                <label htmlFor={ids.file} className="btn-dark mt-3 cursor-pointer">Choose file</label>
                <input
                  ref={inputRef}
                  id={ids.file}
                  type="file"
                  className="sr-only"
                  onChange={(e) => {
                    void selectFile(e.target.files?.[0])
                    e.target.value = ''
                  }}
                />
                <p className="mt-5 max-w-xs text-xs leading-relaxed text-ink-soft">
                  Your browser computes a SHA-256 fingerprint before anything is sent. The server independently re-hashes the file and rejects any mismatch.
                </p>
              </div>
            ) : (
              <>
                {/* ------------------------------------------------ chosen file */}
                {file && (
                  <div className="flex items-center gap-3 rounded-2xl border border-hairline bg-white/70 p-3.5">
                    <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-accent/10 text-accent-strong">
                      <Fingerprint className="h-5 w-5" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold text-ink" title={file.name}>{file.name}</p>
                      <p className="text-[13px] text-ink-soft">{formatBytes(file.size)}{file.type ? ` · ${file.type}` : ''}</p>
                    </div>
                    {!busy && (
                      <button type="button" onClick={reset} className="rounded-full px-3 py-1.5 text-sm font-semibold text-apple-blue-ink transition hover:bg-apple-blue/10">
                        Change
                      </button>
                    )}
                  </div>
                )}

                {/* ------------------------------------------------ fingerprint */}
                <div className="mt-4 rounded-2xl border border-hairline bg-gradient-to-br from-white/90 to-white/60 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">SHA-256 · computed in your browser</p>
                    {digest && (
                      <button type="button" onClick={copyDigest} aria-label="Copy SHA-256" className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold text-ink-soft transition hover:bg-black/[0.05] hover:text-ink">
                        <Copy className="h-3.5 w-3.5" /> Copy
                      </button>
                    )}
                  </div>
                  {phase === 'hashing' ? (
                    <div className="mt-3" aria-live="polite">
                      <ProgressBar fraction={hashFraction} label="Hashing locally" />
                      <p className="mt-2 text-xs text-ink-soft">Hashing {pct(hashFraction)}. Nothing has left your device yet.</p>
                    </div>
                  ) : (
                    <p data-testid="client-digest" className="hash mt-2 text-[13px] font-medium leading-relaxed text-ink">{digest}</p>
                  )}
                </div>

                {/* ------------------------------------------------ metadata */}
                <div className="mt-5 space-y-4">
                  <div>
                    <label htmlFor={ids.desc} className="mb-1.5 block text-sm font-semibold text-ink">Description <span className="font-normal text-ink-soft">(optional)</span></label>
                    <textarea id={ids.desc} rows={3} maxLength={5000} className="field resize-none" disabled={busy || phase === 'hashing'}
                      placeholder="What is this item and how was it obtained?" value={description} onChange={(e) => setDescription(e.target.value)} />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label htmlFor={ids.src} className="mb-1.5 block text-sm font-semibold text-ink">Source <span className="font-normal text-ink-soft">(optional)</span></label>
                      <input id={ids.src} maxLength={255} className="field" disabled={busy || phase === 'hashing'} placeholder="e.g. Seized laptop #3"
                        value={source} onChange={(e) => setSource(e.target.value)} />
                    </div>
                    <div>
                      <label htmlFor={ids.tags} className="mb-1.5 block text-sm font-semibold text-ink">Tags <span className="font-normal text-ink-soft">(comma-separated)</span></label>
                      <input id={ids.tags} className="field" disabled={busy || phase === 'hashing'} placeholder="email, financial"
                        value={tags} onChange={(e) => setTags(e.target.value)} />
                    </div>
                  </div>
                </div>

                {/* ------------------------------------------------ upload progress */}
                {busy && (
                  <div className="mt-5" aria-live="polite">
                    <ProgressBar fraction={sendFraction} label="Uploading" />
                    <p className="mt-2 text-xs text-ink-soft">
                      {sendFraction >= 1
                        ? 'Upload complete. The server is verifying the hash, encrypting and sealing the file…'
                        : `Uploading ${pct(sendFraction)} of ${file ? formatBytes(file.size) : ''}`}
                    </p>
                  </div>
                )}

                {/* ------------------------------------------------ actions */}
                <div className="mt-6 flex flex-wrap justify-end gap-2">
                  {busy ? (
                    <button type="button" className="btn-glass" onClick={() => abortRef.current?.abort()}>Cancel upload</button>
                  ) : (
                    <button type="button" className="btn-glass" onClick={close}>Cancel</button>
                  )}
                  <button type="submit" className="btn-accent" disabled={phase !== 'ready' || !digest}>
                    {busy ? <><Loader2 className="h-4 w-4 animate-spin" /> Uploading…</> : <><UploadCloud className="h-4 w-4" /> Upload evidence</>}
                  </button>
                </div>
              </>
            )}
          </form>
        )}
      </div>
    </div>
  )
}

function ProgressBar({ fraction, label }: { fraction: number; label: string }) {
  const value = Math.round(fraction * 100)
  return (
    <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={value} className="h-2 overflow-hidden rounded-full bg-black/[0.07]">
      <div className="h-full rounded-full bg-gradient-to-r from-apple-blue via-accent to-accent-soft transition-[width] duration-200" style={{ width: `${value}%` }} />
    </div>
  )
}

function Row({ label, value, hash }: { label: string; value: string; hash?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-hairline pb-2.5 last:border-0">
      <dt className="shrink-0 text-ink-soft">{label}</dt>
      <dd className={cn('min-w-0 text-right font-medium text-ink', hash && 'hash text-[13px]')}>{value}</dd>
    </div>
  )
}

export default EvidenceUploadModal
