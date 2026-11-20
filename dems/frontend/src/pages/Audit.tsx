import { ScrollText } from 'lucide-react'
import { useState } from 'react'
import { Badge, EmptyState, ErrorNote, PageHeader, Pager, Segmented, Skeleton, type Tone } from '@/components/ui/primitives'
import { auditApi, type AuditEntry, type Outcome } from '@/lib/api'
import { useAsync } from '@/lib/useAsync'
import { formatDateTime, shortHash } from '@/lib/utils'

const PAGE_SIZE = 25
type Filter = 'all' | Outcome
const OUTCOME_TONE: Record<Outcome, Tone> = { SUCCESS: 'green', DENIED: 'amber', FAILURE: 'red' }

function formatActor(entry: AuditEntry): string {
  const username = entry.actor_username ?? entry.actor_username_attempted
  if (username && entry.actor_id) return `${username} (${entry.actor_id})`
  if (username) return username
  if (entry.actor_id) return entry.actor_id
  return 'System'
}

export function Audit() {
  const [filter, setFilter] = useState<Filter>('all')
  const [offset, setOffset] = useState(0)
  const { data, error, loading, reload } = useAsync(
    (signal) => auditApi.list({ limit: PAGE_SIZE, offset, ...(filter === 'all' ? {} : { outcome: filter }) }, signal),
    [filter, offset],
  )

  return (
    <>
      <PageHeader
        title="Audit log"
        description="An append-only, hash-chained record of every sensitive action. Opening this page is itself recorded."
        actions={
          <Segmented<Filter> label="Filter by outcome" value={filter} onChange={(v) => { setFilter(v); setOffset(0) }}
            options={[{ value: 'all', label: 'All' }, { value: 'SUCCESS', label: 'Success' }, { value: 'DENIED', label: 'Denied' }, { value: 'FAILURE', label: 'Failure' }]} />
        }
      />

      {error && <ErrorNote error={error} onRetry={reload} />}

      <div className="apple-glass overflow-hidden rounded-4xl">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead>
              <tr className="border-b border-hairline text-[11px] font-semibold uppercase tracking-[0.1em] text-ink-soft">
                <th className="px-6 py-4">#</th>
                <th className="px-4 py-4">When</th>
                <th className="px-4 py-4">Action</th>
                <th className="px-4 py-4">Outcome</th>
                <th className="px-4 py-4">Actor</th>
                <th className="px-4 py-4">Source</th>
                <th className="px-6 py-4">Entry hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading && !data
                ? [0, 1, 2, 3, 4].map((i) => (
                    <tr key={i}><td colSpan={7} className="px-6 py-3"><Skeleton className="h-9" /></td></tr>
                  ))
                : data?.items.map((e) => (
                    <tr key={e.id} className="transition-colors hover:bg-white/60">
                      <td className="px-6 py-3.5 tabular-nums text-ink-soft">{e.sequence_no}</td>
                      <td className="whitespace-nowrap px-4 py-3.5 text-ink-soft">{formatDateTime(e.occurred_at)}</td>
                      <td className="px-4 py-3.5 font-semibold text-ink">{e.action.replaceAll('_', ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())}</td>
                      <td className="px-4 py-3.5"><Badge tone={OUTCOME_TONE[e.outcome]}>{e.outcome.charAt(0) + e.outcome.slice(1).toLowerCase()}</Badge></td>
                      <td className="px-4 py-3.5 text-ink-soft" title={formatActor(e)}>{formatActor(e)}</td>
                      <td className="hash px-4 py-3.5 text-ink-soft">{e.source_ip}</td>
                      <td className="hash px-6 py-3.5 text-[13px] text-ink-soft" title={e.entry_hash}>{shortHash(e.entry_hash)}</td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
        {data && data.items.length === 0 && !error && <EmptyState icon={ScrollText} title="No matching entries" />}
        {data && <Pager offset={offset} limit={PAGE_SIZE} total={data.total} onChange={setOffset} />}
      </div>
    </>
  )
}

export default Audit
