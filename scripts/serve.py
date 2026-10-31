#!/usr/bin/env python3
"""
Run the whole stack locally for the dashboard: a local Hardhat chain (deployed + seeded), the three org nodes
(bootstrapped) and the FastAPI server on http://127.0.0.1:8000. Then `cd dashboard && npm run dev`.

    python scripts/serve.py [--port 8000] [--headline]     # --headline also ingests the demo advisory
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from backend.api.main import create_app  # noqa: E402
from backend.devchain import DevChain  # noqa: E402
from backend.system import CascadeShieldSystem  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--headline", action="store_true", help="ingest the headline advisory after bootstrap")
    args = ap.parse_args()
    dc = DevChain().start()
    try:
        s = CascadeShieldSystem(dc.url, str(dc.deployment_file), Path(tempfile.mkdtemp(prefix="cascadeshield-")), llm_provider="offline")
        s.bootstrap()
        if args.headline:
            s.ingest((ROOT / "data" / "advisories" / "ADV-2023-0001.txt").read_text(encoding="utf-8"), source="CERT-In")
        print(f"chain {dc.url}  API http://127.0.0.1:{args.port}  (Ctrl+C to stop)", flush=True)
        uvicorn.run(create_app(s), host="127.0.0.1", port=args.port, log_level="warning")
    finally:
        dc.stop()


if __name__ == "__main__":
    main()
