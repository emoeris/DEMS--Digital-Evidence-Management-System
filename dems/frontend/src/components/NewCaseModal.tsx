import { FolderPlus, Loader2 } from 'lucide-react'
import { useEffect, useId, useState, type FormEvent } from 'react'
import { createPortal } from 'react-dom'
import { apiClient, getErrorMessage, type CaseRecord } from '@/lib/api'

interface NewCaseModalProps {
  open: boolean
  onClose: () => void
  onCreated: (created: CaseRecord) => void
}

const CASE_NUMBER_MAX = 64
const TITLE_MAX = 200

export function NewCaseModal({ open, onClose, onCreated }: NewCaseModalProps) {
  const [caseNumber, setCaseNumber] = useState('')
  const [title, setTitle] = useState('')
  const [touched, setTouched] = useState({ caseNumber: false, title: false })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const ids = { t: useId(), n: useId(), h: useId() }

  const number = caseNumber.trim()
  const name = title.trim()
  const problems = {
    caseNumber: number.length < 3 ? 'At least 3 characters, for example CASE-001.' : number.length > CASE_NUMBER_MAX ? `At most ${CASE_NUMBER_MAX} characters.` : null,
    title: name.length < 3 ? 'At least 3 characters.' : name.length > TITLE_MAX ? `At most ${TITLE_MAX} characters.` : null,
  }
  const valid = !problems.caseNumber && !problems.title

  // Reset the form each time the dialog is opened.
  useEffect(() => {
    if (!open) return
    setCaseNumber('')
    setTitle('')
    setTouched({ caseNumber: false, title: false })
    setError(null)
    setBusy(false)
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && !busy && onClose()
    document.addEventListener('keydown', onKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKey)
      document.body.style.overflow = ''
    }
  }, [open, busy, onClose])

  if (!open) return null

  async function submit(e: FormEvent) {
    e.preventDefault()
    setTouched({ caseNumber: true, title: true })
    if (!valid || busy) return
    setBusy(true)
    setError(null)
    try {
      const { data } = await apiClient.post<CaseRecord>('/cases', { case_number: number, title: name })
      onCreated(data)
    } catch (err) {
      setError(getErrorMessage(err))
      setBusy(false)
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-[70] flex items-end justify-center p-3 sm:items-center sm:p-6">
      <button type="button" aria-label="Close dialog" tabIndex={-1} onClick={onClose} disabled={busy} className="absolute inset-0 bg-black/30 backdrop-blur-sm" />
      <form
        role="dialog"
        aria-modal="true"
        aria-labelledby={ids.h}
        onSubmit={submit}
        noValidate
        className="apple-glass-strong relative w-full max-w-md animate-scale-in rounded-4xl p-6 sm:p-8"
      >
        <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-accent/10 text-accent-strong">
          <FolderPlus className="h-5 w-5" />
        </span>
        <h2 id={ids.h} className="mt-4 text-xl font-extrabold tracking-heading text-ink">New case</h2>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">
          You will become the lead investigator for this case. Evidence can be uploaded as soon as it is created.
        </p>

        {error && (
          <p role="alert" className="mt-5 rounded-2xl border border-apple-red/20 bg-apple-red/5 px-4 py-3 text-sm leading-relaxed text-apple-red-ink">{error}</p>
        )}

        <div className="mt-5 space-y-4">
          <div>
            <label htmlFor={ids.n} className="mb-1.5 block text-sm font-semibold text-ink">Case number</label>
            <input id={ids.n} className="field" autoFocus autoComplete="off" spellCheck={false} maxLength={CASE_NUMBER_MAX + 20}
              value={caseNumber} placeholder="CASE-001" aria-invalid={touched.caseNumber && !!problems.caseNumber}
              onChange={(e) => setCaseNumber(e.target.value)} onBlur={() => setTouched((t) => ({ ...t, caseNumber: true }))} />
            {touched.caseNumber && problems.caseNumber && <p role="alert" className="mt-1.5 text-[13px] text-apple-red-ink">{problems.caseNumber}</p>}
          </div>
          <div>
            <label htmlFor={ids.t} className="mb-1.5 block text-sm font-semibold text-ink">Title</label>
            <input id={ids.t} className="field" autoComplete="off" maxLength={TITLE_MAX + 20}
              value={title} placeholder="Short description of the case" aria-invalid={touched.title && !!problems.title}
              onChange={(e) => setTitle(e.target.value)} onBlur={() => setTouched((t) => ({ ...t, title: true }))} />
            {touched.title && problems.title && <p role="alert" className="mt-1.5 text-[13px] text-apple-red-ink">{problems.title}</p>}
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-2">
          <button type="button" className="btn-glass" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className="btn-accent" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FolderPlus className="h-4 w-4" />} Create case
          </button>
        </div>
      </form>
    </div>,
    document.body,
  )
}

export default NewCaseModal
