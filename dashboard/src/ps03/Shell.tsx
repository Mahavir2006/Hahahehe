import React from 'react'
import { ORGS } from './api'
import { SimBanner } from './common'
import Overview from './Overview'
import AssetDetail from './AssetDetail'
import Detections from './Detections'
import Plans from './Plans'
import Trust from './Trust'
import ModelCard from './ModelCard'
import './ps03.css'

export const TABS = ['Overview', 'Asset detail', 'Detections', 'Plans and approvals', 'Trust', 'Model card', 'Team dashboard'] as const
export type Tab = (typeof TABS)[number]

export default function Shell({ pipeline }: { pipeline: React.ReactNode }) {
  const [tab, setTab] = React.useState<Tab>('Overview')
  const [org, setOrg] = React.useState('power')
  const [asset, setAsset] = React.useState<string | null>(null)
  return (
    <div className="ps03">
      <header className="ps03-header">
        <h1>CascadeShield</h1>
        <label>
          Organisation{' '}
          <select
            value={org}
            onChange={(e) => {
              setOrg(e.target.value)
              setAsset(null)
            }}
          >
            {ORGS.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
        </label>
      </header>
      <SimBanner />
      <nav className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'tab active' : 'tab'} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </nav>
      <main className="ps03-main">
        <div className={tab === 'Team dashboard' ? 'team-view' : 'ps03-view'}>
        {tab === 'Overview' && (
          <Overview
            org={org}
            onSelect={(id) => {
              setAsset(id)
              setTab('Asset detail')
            }}
          />
        )}
        {tab === 'Asset detail' && <AssetDetail org={org} assetId={asset} />}
        {tab === 'Detections' && <Detections org={org} />}
        {tab === 'Plans and approvals' && <Plans org={org} />}
        {tab === 'Trust' && <Trust org={org} />}
        {tab === 'Model card' && <ModelCard />}
        {tab === 'Team dashboard' && pipeline}
        </div>
      </main>
    </div>
  )
}
