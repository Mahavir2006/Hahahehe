import { api } from './api'
import { ErrorBox, useLoad } from './common'

interface LiveEvent {
  block: number
  tx: string
  contract: string
  event: string
  org: string | null
}

interface Live {
  block: number
  chain_id: number
  events_indexed: number
  events: LiveEvent[]
  sim_day: number
  auto_advance_seconds: number | null
  reassessments: number | null
}

// Real activity on the local chain, polled every 2 s: block height, transaction hashes, contract events.
export function LiveChainView({ d }: { d: Live }) {
  return (
    <section className="panel">
      <h3>
        Live chain <span className="live-dot" aria-hidden="true" /> block {d.block}
      </h3>
      <p className="muted">
        chain id {d.chain_id} · {d.events_indexed} events indexed · simulated day {d.sim_day} ·{' '}
        {d.auto_advance_seconds ? `auto-advancing one simulated day every ${d.auto_advance_seconds} s` : 'auto-advance off'}
      </p>
      <table className="ps03-table">
        <thead>
          <tr>
            <th>Block</th>
            <th>Transaction hash</th>
            <th>Contract.event</th>
            <th>Org</th>
          </tr>
        </thead>
        <tbody>
          {d.events.map((e) => (
            <tr key={`${e.tx}-${e.event}`}>
              <td>{e.block}</td>
              <td>
                <code className="hash">{e.tx}</code>
              </td>
              <td>
                {e.contract}.{e.event}
              </td>
              <td>{e.org ?? '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}

export default function LiveChain({ limit = 15 }: { limit?: number }) {
  const [d, err] = useLoad(() => api<Live>(`/api/ps03/chain/live?limit=${limit}`), [limit], 2000)
  return (
    <>
      <ErrorBox error={err} />
      {d && <LiveChainView d={d} />}
    </>
  )
}
