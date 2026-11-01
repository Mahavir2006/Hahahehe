# Digital twin built from the blockchain

The digital twin is a live copy of the consortium (organisations, their services, the dependencies between them,
cascade alerts, human approvals, firmware trust and audit anchors) that is **rebuilt automatically from contract
events**. Nothing in it is configured or hardcoded: if a contract emitted it, it is in the twin; if not, it is not.

Code: `backend/twin/` (model, sources, service), API `backend/api/twin.py`, UI `cascade_ui/src/pages/Twin.tsx`,
tests `backend/tests/test_twin.py`.

## How it stays live

The running backend (`python -m backend.ps03_serve --live-interval 20`) advances a simulated day every 20 seconds;
the agents write risk attestations and audit anchors to the chain as risk changes. The event indexer picks up every
new block, the twin is rebuilt from the events, and the UI receives one server-sent event per block that changed it.

## What it does

| Capability | How | Endpoint |
|---|---|---|
| Self-assembly | Pure replay of contract events, in block order. Starts with no organisations and grows one registration at a time. | `GET /api/twin/timeline` |
| Fingerprint | One keccak hash per section of the twin (canonical JSON), Merkle root over the sections. | in every `/api/twin` response |
| Time travel | Rebuild the twin up to any block. | `GET /api/twin?block=N` |
| Shared verification | Each organisation replays the raw chain over its own RPC connection and decodes every log itself; all must reach the twin's fingerprint. The twin is also cross-checked against the contracts' own view functions (org status, edge state, approval status, firmware verification). | `GET /api/twin/verify` |
| Private overlay | The shared twin holds hashes and commitments only. Each organisation opens its own sealed risk bands and dependency terms, checks them against the on-chain commitments, and names its own services. | `GET /api/twin/overlay/{org}` |
| Drift | Where live reality and the chain disagree: a service's live risk band differs from its last attested band, an asset runs firmware the registry does not vouch for, an alert is unacknowledged, a dependency is one-sided, an approval expired while pending, a confirmed link involves a deactivated organisation. | `GET /api/twin/drift` |
| What-if on a fork | Snapshot the chain (`evm_snapshot`), send one real transaction (revoke a dependency, revoke a firmware release, deactivate an organisation), rebuild the twin from the forked chain, then `evm_revert`. Real writes and indexing are held off while the fork is open (`Chain.gate`), so nothing real is lost. | `POST /api/twin/fork` |

## Evidence (`backend/tests/test_twin.py`)

1. An independent decode of the raw chain reproduces the twin exactly, and it matches what was written (3 members,
   every declared bilateral edge, the full firmware catalogue, the one-sided edge left pending).
2. The twin starts with no organisations and gains them one at a time; rebuilding at sampled blocks from the raw
   chain lands on the timeline's fingerprints.
3. Every organisation's replay agrees, and every contract view agrees with the twin.
4. Editing one event in the local copy is detected, and the disagreement names the edited section.
5. Each what-if mines a real transaction on the fork, changes the twin as expected, and afterwards the chain head,
   the fingerprint and the indexer are exactly as before. Links are offered most-impactful first, and the predicted
   cut equals what the forked chain shows.
6. The shared layer contains no service names and no bands; overlays open only the organisation's own data.
7. Firmware drift equals the contract's own `verifyFirmware` result for every asset.
8. The API enforces roles (overlay and drift per organisation, what-ifs admin only).

## Limits

This is a twin of the consortium's cyber and dependency state as recorded on chain, not a physical model of a plant.
The live data comes from the simulated organisations. A what-if pauses real writes for the few seconds it runs.
