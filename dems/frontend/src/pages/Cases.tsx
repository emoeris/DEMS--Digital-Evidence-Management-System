import { FolderOpen, FolderPlus, Lock } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { NewCaseModal } from '@/components/NewCaseModal'
import { Badge, EmptyState, ErrorNote, PageHeader, Pager, Segmented, Skeleton } from '@/components/ui/primitives'
import { casesApi, getErrorMessage, type CaseStatus } from '@/lib/api'
import { useAsync } from '@/lib/useAsync'
import { formatDate, shortHash } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'

const PAGE_SIZE = 15
type Filter = 'all' | CaseStatus

export function Cases() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const canCreate = useAuthStore((s) => s.can('case:create'))
  const canManage = useAuthStore((s) => s.can('case:manage'))
  const [filter, setFilter] = useState<Filter>('all')
  const [offset, setOffset] = useState(0)
  const [newCaseOpen, setNewCaseOpen] = useState(false)
  const [closingId, setClosingId] = useState<string | null>(null)
  const { data, error, loading, reload } = useAsync(
    (signal) => casesApi.list({ limit: PAGE_SIZE, offset, ...(filter === 'all' ? {} : { status: filter }) }, signal),
    [filter, offset],
  )

  async function handleCloseCase(caseId: string, caseNumber: string) {
    setClosingId(caseId)
    try {
      await casesApi.close(caseId)
      toast.success(`Case ${caseNumber} closed and sealed`)
      reload()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setClosingId(null)
    }
  }

  return (
    <>
      <PageHeader
        title="Cases"
        description="Every case you are permitted to see. Closed cases are locked and sealed with a manifest hash."
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <Segmented<Filter> label="Filter by status" value={filter} onChange={(v) => { setFilter(v); setOffset(0) }}
              options={[{ value: 'all', label: 'All' }, { value: 'open', label: 'Open' }, { value: 'closed', label: 'Closed' }]} />
            {canCreate && (
              <button type="button" className="btn-accent" onClick={() => setNewCaseOpen(true)}>
                <FolderPlus className="h-4 w-4" /> New case
              </button>
            )}
          </div>
        }
      />

      {error && <ErrorNote error={error} onRetry={reload} />}

      <div className="apple-glass overflow-hidden rounded-4xl">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr className="border-b border-hairline text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">
                <th className="px-6 py-4">Case</th>
                <th className="px-4 py-4">Status</th>
                <th className="px-4 py-4">Opened</th>
                <th className="px-4 py-4">Closed</th>
                <th className="px-4 py-4">Manifest</th>
                <th className="px-6 py-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading && !data
                ? [0, 1, 2, 3].map((i) => (
                    <tr key={i}><td colSpan={6} className="px-6 py-3"><Skeleton className="h-10" /></td></tr>
                  ))
                : data?.items.map((c) => {
                    const canClose =
                      c.status === 'open' &&
                      canManage &&
                      (user?.role === 'admin' || c.lead_investigator_id === user?.id)

                    return (
                      <tr key={c.id} className="transition-colors hover:bg-white/60">
                        <td className="px-6 py-4">
                          <Link to={`/cases/${c.id}`} className="font-semibold text-ink hover:text-accent-strong hover:underline">{c.title}</Link>
                          <p className="text-[13px] text-ink-soft">{c.case_number}</p>
                        </td>
                        <td className="px-4 py-4"><Badge tone={c.status === 'open' ? 'green' : 'neutral'}>{c.status === 'open' ? 'Open' : 'Closed'}</Badge></td>
                        <td className="px-4 py-4 text-ink-soft">{formatDate(c.created_at)}</td>
                        <td className="px-4 py-4 text-ink-soft">{formatDate(c.closed_at)}</td>
                        <td className="hash px-4 py-4 text-[13px] text-ink-soft" title={c.closure_manifest_hash ?? undefined}>{shortHash(c.closure_manifest_hash)}</td>
                        <td className="px-6 py-4 text-right">
                          {canClose ? (
                            <button
                              type="button"
                              className="btn-glass inline-flex items-center gap-1.5 px-3 py-1.5 text-xs"
                              disabled={closingId === c.id}
                              onClick={() => void handleCloseCase(c.id, c.case_number)}
                            >
                              <Lock className="h-3.5 w-3.5" />
                              {closingId === c.id ? 'Closing…' : 'Close case'}
                            </button>
                          ) : (
                            <span className="text-xs text-ink-soft">{c.status === 'closed' ? 'Sealed' : '—'}</span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
            </tbody>
          </table>
        </div>
        {data && data.items.length === 0 && !error && (
          <EmptyState
            icon={FolderOpen}
            title="No cases found"
            description={filter === 'all' ? (canCreate ? 'Use New case to create your first one.' : 'Cases you can access will appear here.') : `There are no ${filter} cases.`}
          />
        )}
        {data && <Pager offset={offset} limit={PAGE_SIZE} total={data.total} onChange={setOffset} />}
      </div>

      <NewCaseModal
        open={newCaseOpen}
        onClose={() => setNewCaseOpen(false)}
        onCreated={(created) => {
          setNewCaseOpen(false)
          toast.success(`Case ${created.case_number} created`)
          navigate(`/cases/${created.id}`)
        }}
      />
    </>
  )
}

export default Cases
