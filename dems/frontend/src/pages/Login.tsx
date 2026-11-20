import { ArrowRight, Loader2 } from 'lucide-react'
import { useId, useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { Backdrop } from '@/components/layout/Backdrop'
import { AppMark } from '@/components/ui/primitives'
import { getErrorMessage, toApiError } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

type Step = 'credentials' | 'mfa' | 'password'

export function Login() {
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? '/'
  const { login, changePassword, status, mustChangePassword } = useAuthStore()

  const [step, setStep] = useState<Step>('credentials')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [useBackup, setUseBackup] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  // After a page reload mid-onboarding we no longer know the temporary password, so ask for it.
  const [askCurrent] = useState(() => status === 'authenticated' && mustChangePassword)
  const [error, setError] = useState<string | null>(null)
  const ids = { u: useId(), p: useId(), c: useId(), n: useId(), v: useId() }

  if (status === 'authenticated' && !mustChangePassword && step !== 'password') return <Navigate to={from} replace />

  const effectiveStep: Step = status === 'authenticated' && mustChangePassword ? 'password' : step

  const finish = () => {
    toast.success('Welcome back')
    navigate(from, { replace: true })
  }

  async function submitCredentials(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login({
        username: username.trim(),
        password,
        ...(effectiveStep === 'mfa' ? (useBackup ? { backupCode: code.trim() } : { totpCode: code.trim() }) : {}),
      })
      if (useAuthStore.getState().mustChangePassword) setStep('password')
      else finish()
    } catch (err) {
      const apiError = toApiError(err)
      if (apiError.code === 'mfa_required') {
        setStep('mfa')
        setCode('')
      } else {
        setError(apiError.message)
        if (effectiveStep === 'mfa') setCode('')
      }
    } finally {
      setBusy(false)
    }
  }

  async function submitPassword(e: FormEvent) {
    e.preventDefault()
    if (newPassword !== confirm) return setError('The new passwords do not match.')
    setBusy(true)
    setError(null)
    try {
      await changePassword(password, newPassword)
      finish()
    } catch (err) {
      setError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const heading = effectiveStep === 'mfa' ? 'Two-step verification' : effectiveStep === 'password' ? 'Choose a new password' : 'Sign in'
  const subtitle =
    effectiveStep === 'mfa'
      ? useBackup ? 'Enter one of your single-use backup codes.' : 'Enter the 6-digit code from your authenticator app.'
      : effectiveStep === 'password'
        ? 'Your account uses a temporary password. Set a new one (12+ characters) to continue.'
        : 'Secure Digital Evidence Management System'

  return (
    <div className="relative isolate flex min-h-screen items-center justify-center px-4 py-10">
      <Backdrop />
      <div className="apple-glass-strong w-full max-w-[26rem] animate-fade-up rounded-4xl p-8 sm:p-10">
        <div className="flex flex-col items-center text-center">
          <AppMark size="lg" variant="dark" />
          <h1 className="mt-6 text-3xl font-extrabold tracking-display text-ink">{heading}</h1>
          <p className="mt-2 text-[15px] leading-relaxed text-ink-soft">{subtitle}</p>
        </div>

        {error && (
          <p role="alert" className="mt-6 rounded-2xl border border-apple-red/20 bg-apple-red/5 px-4 py-3 text-sm text-apple-red-ink">
            {error}
          </p>
        )}

        {effectiveStep !== 'password' ? (
          <form onSubmit={submitCredentials} className="mt-6 space-y-4" noValidate>
            {effectiveStep === 'credentials' ? (
              <>
                <div>
                  <label htmlFor={ids.u} className="mb-1.5 block text-sm font-semibold text-ink">Username</label>
                  <input id={ids.u} className="field" autoComplete="username" autoFocus required value={username}
                    onChange={(e) => setUsername(e.target.value)} />
                </div>
                <div>
                  <label htmlFor={ids.p} className="mb-1.5 block text-sm font-semibold text-ink">Password</label>
                  <input id={ids.p} className="field" type="password" autoComplete="current-password" required value={password}
                    onChange={(e) => setPassword(e.target.value)} />
                </div>
              </>
            ) : (
              <div>
                <label htmlFor={ids.c} className="mb-1.5 block text-sm font-semibold text-ink">{useBackup ? 'Backup code' : 'Verification code'}</label>
                <input id={ids.c} className="field text-center text-xl font-semibold tracking-[0.3em] tabular-nums"
                  inputMode={useBackup ? 'text' : 'numeric'} autoComplete="one-time-code" autoFocus required
                  maxLength={useBackup ? 11 : 6} value={code}
                  onChange={(e) => setCode(useBackup ? e.target.value.toUpperCase() : e.target.value.replace(/\D/g, ''))} />
                <button type="button" className="mt-3 text-sm font-semibold text-apple-blue-ink hover:underline"
                  onClick={() => { setUseBackup((v) => !v); setCode('') }}>
                  {useBackup ? 'Use authenticator code instead' : 'Use a backup code instead'}
                </button>
              </div>
            )}
            <button type="submit" disabled={busy || (effectiveStep === 'credentials' ? !username || !password : code.length < 6)} className="btn-accent w-full py-3">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <>{effectiveStep === 'mfa' ? 'Verify' : 'Continue'} <ArrowRight className="h-4 w-4" /></>}
            </button>
            {effectiveStep === 'mfa' && (
              <button type="button" className="w-full text-center text-sm font-medium text-ink-soft hover:text-ink"
                onClick={() => { setStep('credentials'); setError(null); setCode('') }}>
                Back
              </button>
            )}
          </form>
        ) : (
          <form onSubmit={submitPassword} className="mt-6 space-y-4" noValidate>
            {askCurrent && (
              <div>
                <label htmlFor={ids.p} className="mb-1.5 block text-sm font-semibold text-ink">Current (temporary) password</label>
                <input id={ids.p} className="field" type="password" autoComplete="current-password" required value={password}
                  onChange={(e) => setPassword(e.target.value)} />
              </div>
            )}
            <div>
              <label htmlFor={ids.n} className="mb-1.5 block text-sm font-semibold text-ink">New password</label>
              <input id={ids.n} className="field" type="password" autoComplete="new-password" autoFocus required minLength={12}
                value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            </div>
            <div>
              <label htmlFor={ids.v} className="mb-1.5 block text-sm font-semibold text-ink">Confirm new password</label>
              <input id={ids.v} className="field" type="password" autoComplete="new-password" required value={confirm}
                onChange={(e) => setConfirm(e.target.value)} />
            </div>
            <button type="submit" disabled={busy || newPassword.length < 12 || !password} className="btn-accent w-full py-3">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <>Save and continue <ArrowRight className="h-4 w-4" /></>}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}

export default Login
