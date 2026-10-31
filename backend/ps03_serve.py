"""
Local PS-03 demo backend: start (or reuse) a Hardhat node, deploy + seed the contracts, bootstrap the system,
then serve the API with the PS-03 flags on. SIMULATION ONLY, local laptop only.

  python -m backend.ps03_serve [--port 8000] [--chain-port 8545]

Equivalent manual steps: `make chain`, `make deploy`, then a bootstrapped CascadeShieldSystem behind
`uvicorn`; the plain `uvicorn backend.api.main:app` path never calls bootstrap().
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--chain-port", type=int, default=8545)
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
        if state.exists():
            shutil.rmtree(state)  # a new chain: old writer/indexer state would not match it
        dc.start(deploy=True)
        started = True
    elif not dep.exists():
        dc.deploy()
    system = CascadeShieldSystem(dc.url, str(dep), state)
    boot = system.bootstrap()
    print("bootstrap:", {k: v for k, v in boot.items() if k != "supply_chain"}, flush=True)
    try:
        uvicorn.run(create_app(system), host="127.0.0.1", port=a.port, log_level="warning")
    finally:
        if started:
            dc.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
