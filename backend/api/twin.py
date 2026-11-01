"""
Digital twin API. The shared twin (public layer) is open to every role; an organisation's private overlay and
drift are visible to that organisation and the consortium admin only. What-if forks are admin only.

  GET  /api/twin                 live twin (+ the caller's private overlay when the role is an organisation)
  GET  /api/twin?block=N         time travel: the twin exactly as it was after block N
  GET  /api/twin/timeline        fingerprint after every block, for replaying how the twin assembled itself
  GET  /api/twin/verify          every organisation replays the chain independently; contract cross-checks
  GET  /api/twin/drift           where live reality and the twin disagree
  GET  /api/twin/scenarios       what-ifs that can be run on a fork
  POST /api/twin/fork            run one what-if on a chain snapshot, then roll back
  GET  /api/twin/stream          server-sent events: one message per new block that changed the twin
"""

from __future__ import annotations

import asyncio
import json
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.twin import model as M
from backend.twin.service import TwinService


class ForkIn(BaseModel):
    kind: str
    target: str


def register(app: FastAPI, S: Callable, role: Callable, need_org: Callable, need_admin: Callable) -> None:
    holder = {"svc": None}

    def T() -> TwinService:
        if holder["svc"] is None or holder["svc"].S is not S():
            holder["svc"] = TwinService(S())
        return holder["svc"]

    def org_of(r: str) -> Optional[str]:
        return r[4:] if r.startswith("org:") else None

    @app.get("/api/twin")
    def twin(block: Optional[int] = Query(default=None, ge=0), r: str = Depends(role)):
        t = T()
        live = t.live()
        if block is not None and block > live["state"]["block"]:
            raise HTTPException(400, f"block {block} is beyond the chain head {live['state']['block']}")
        snap = live if block is None else t.at(block)
        out = t.public(snap)
        out["head"] = live["state"]["block"]
        if (org := org_of(r)) is not None:
            out["overlay"] = t.overlay(org, snap)
        return out

    @app.get("/api/twin/overlay/{org}")
    def overlay(org: str, r: str = Depends(role)):
        need_org(org, r)
        t = T()
        return t.overlay(org, t.live())

    @app.get("/api/twin/timeline")
    def timeline(points: int = Query(default=300, ge=2, le=2000), r: str = Depends(role)):
        return T().timeline(max_points=points)

    @app.get("/api/twin/verify")
    def verify(r: str = Depends(role)):
        return T().verify()

    @app.get("/api/twin/drift")
    def drift(r: str = Depends(role)):
        t = T()
        return t.drift(t.live(), org=org_of(r))

    @app.get("/api/twin/scenarios")
    def scenarios(r: str = Depends(role)):
        need_admin(r)
        return T().scenarios()

    @app.post("/api/twin/fork")
    def fork(body: ForkIn, r: str = Depends(role)):
        need_admin(r)
        try:
            return T().fork(body.kind, body.target)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/api/twin/stream")
    async def stream():
        """Public layer only (EventSource cannot send role headers): block, fingerprint and what changed."""

        async def gen():
            last = None
            yield "retry: 3000\n\n"
            while True:
                snap = await asyncio.to_thread(T().live)
                st = snap["state"]
                if snap["fp"]["root"] != last:
                    last = snap["fp"]["root"]
                    yield "data: " + json.dumps({"block": st["block"], "root": last, "events": st["events"], "summary": M.summary(st)}) + "\n\n"
                else:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(2)

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
