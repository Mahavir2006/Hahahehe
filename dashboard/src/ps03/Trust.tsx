import { api } from './api'
import { ErrorBox, useLoad } from './common'

export default function Trust({ org }: { org: string }) {
  const [chain, e1] = useLoad(() => api<any>('/api/chain/status'), [])
  const [audit, e2] = useLoad(() => api<any>(`/api/audit/verify?org=${org}`), [org])
  const [att, e3] = useLoad(() => api<any>('/api/chain/attestations'), [])
  const [model] = useLoad(() => api<any>('/api/ps03/model/info'), [])
  return (
    <div>
      <ErrorBox error={e1 || e2 || e3} />
      <section className="panel">
        <h3>Chain</h3>
        {chain && (
          <p>
            connected {String(chain.connected)} · chain id {chain.chain_id} · block {chain.block} · pending writes {chain.pending_writes} · paused {String(chain.paused)}
          </p>
        )}
        {model && (
          <p>
            Model {model.source} <code>{model.model_version}</code>. Service risk bands are attested on-chain as commitments with the model version hash; per-asset
            data stays private (SEC-PRIV).
          </p>
        )}
      </section>
      <section className="panel">
        <h3>Audit verify ({org})</h3>
        <pre className="pre">{audit ? JSON.stringify(audit, null, 1) : '...'}</pre>
      </section>
      <section className="panel">
        <h3>Recent risk attestations</h3>
        <table className="ps03-table">
          <tbody>
            {(att?.risk || [])
              .slice(-15)
              .reverse()
              .map((e: any, i: number) => (
                <tr key={i}>
                  <td>block {e.block ?? e.blockNumber}</td>
                  <td>
                    <code>{JSON.stringify(e.args ?? e).slice(0, 160)}</code>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
