"""
Local PS-03 demo backend, live: (re)use a Hardhat node, deploy the contracts if the node does not have them,
bootstrap the system, serve the API with the PS-03 flags on, and keep it moving:

  * every --live-interval seconds the simulated clock advances one day (the scripted demo week first, plain days
    after it); each day reassesses every asset and writes the existing hashed snapshot and any band change to the
    chain through the normal agent path;
  * every on-chain event is printed as it lands: block, transaction hash, contract.event, org.

SIMULATION ONLY, local laptop only. Start the chain in its own terminal to watch it (`npx hardhat node` in chain/);
if no node is running on --chain-port this script starts one in the background.

  python -m backend.ps03_serve [--port 8000] [--chain-port 8545] [--live-interval 20]   (0 = no auto-advance)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def has_code(url: str, address: str) -> bool:
    r = requests.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]}, timeout=5)
    return r.json().get("result", "0x") not in ("0x", "0x0", None)


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def chain_feed(system, stop: threading.Event) -> None:
    from backend.common.chain import ORGS, org_id

    names = {"0x" + bytes(org_id(o)).hex(): o for o in ORGS}
    seen = 0
    while not stop.is_set():
        try:
            system.indexer.sync()
            evs = [e for e in system.indexer.query(None, None, 500) if e["block"] > seen]
            for e in sorted(evs, key=lambda x: (x["block"], x["log_index"])):
                a = e.get("args") or {}
                org = next((names[str(a[k]).lower()] for k in ("orgId", "consumerOrg", "providerOrg") if a.get(k) is not None and str(a[k]).lower() in names), "-")
                log(f"[chain] block {e['block']:>5}  tx {e['tx']}  {e['contract']}.{e['name']}  org={org}")
            if evs:
                seen = max(e["block"] for e in evs)
        except Exception as ex:  # noqa: BLE001
            log(f"[chain] feed error: {ex}")
        stop.wait(2.0)


def auto_advance(app, interval: float, stop: threading.Event) -> None:
    from backend import simclock

    from backend.attack_demo import LIVE_HOLD

    while not stop.wait(interval):
        if LIVE_HOLD.is_set():
            log("[sim] holding: an attack demo is running")
            continue
        try:
            P = app.state.ps03
            day = simclock.now_day() + 1
            out = P.ensure().advance(1, "demo_week" if day <= 7 else None)
            ev = "; ".join(e["text"] for e in out["events_applied"]) or "no scripted event"
            changed = [f"{c['org']}/{c['asset_id']} {c['from_band']}->{c['to_band']}" for c in out["changes"] if c["from_band"] != c["to_band"]]
            log(f"[sim] day {out['to_day']}: {ev}; {len(out['changes'])} risk changes; band moves: {', '.join(changed) or 'none'}")
        except Exception as ex:  # noqa: BLE001
            log(f"[sim] advance skipped: {ex}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--chain-port", type=int, default=8545)
    ap.add_argument("--live-interval", type=float, default=20.0, help="seconds per simulated day; 0 disables auto-advance")
    a = ap.parse_args()
    for k in ("PS03_ENABLE", "PS03_SEED_REAL"):
        os.environ.setdefault(k, "1")

    import uvicorn

    from backend.api.main import create_app
    from backend.devchain import DevChain, rpc_alive
    from backend.system import CascadeShieldSystem

    dep = ROOT / "chain" / "deployments" / "local.json"
    state = ROOT / "state" / "ps03"
    dc = DevChain(port=a.chain_port, deployment_file=dep)
    started = False
    if not rpc_alive(dc.url):
        log(f"no chain on {dc.url}: starting a Hardhat node in the background")
        dc.start(deploy=False)
        started = True
    # Every backend start deploys a fresh contract set on the running chain (the node and its block history keep
    # running): bootstrap writes one-time records (bilateral dependency edges) that a second bootstrap against the
    # same contracts would correctly be refused for (EdgeAlreadyExists).
    reused = dep.exists() and has_code(dc.url, json.loads(dep.read_text(encoding="utf-8"))["contracts"]["OrgRegistry"])
    log(f"deploying a fresh contract set on {dc.url}" + (" (replacing the previous run's contracts)" if reused else ""))
    if state.exists():
        shutil.rmtree(state)  # writer/indexer state belongs to the previous contract set
    dc.deploy()
    system = CascadeShieldSystem(dc.url, str(dep), state)
    boot = system.bootstrap()
    log(f"bootstrap: {json.dumps({k: v for k, v in boot.items() if k not in ('supply_chain', 'edges')})}")
    app = create_app(system)
    app.state.ps03_live_interval = a.live_interval or None
    stop = threading.Event()
    threading.Thread(target=chain_feed, args=(system, stop), daemon=True).start()
    if a.live_interval > 0:
        app.state.ps03.ensure()
        log(f"[sim] auto-advance: one simulated day every {a.live_interval:g} s (demo week first)")
        threading.Thread(target=auto_advance, args=(app, a.live_interval, stop), daemon=True).start()
    log(f"API on http://127.0.0.1:{a.port}  (UI: npm --prefix cascade_ui run dev -> http://localhost:8443)")
    try:
        uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
    finally:
        stop.set()
        if started:
            dc.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
