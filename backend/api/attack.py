"""Firmware attack demo API (admin only to launch or reset; anyone can watch).

  POST /api/attack/firmware/launch   start the end-to-end demo (runs in the background)
  GET  /api/attack/firmware          live status: every stage, what each actor did, chain records, twin
  POST /api/attack/firmware/reset    put the device back on vendor firmware (chain history stays)
  GET  /api/attack/firmware/image    the vendor and tampered firmware sources, the diff and the hashes compared
"""

from __future__ import annotations

from typing import Callable

from fastapi import Depends, FastAPI

from backend.attack_demo import FirmwareAttackDemo, firmware_image
from backend.twin.service import TwinService


def register(app: FastAPI, S: Callable, role: Callable, need_org: Callable, need_admin: Callable) -> None:
    holder = {"demo": None}

    def D() -> FirmwareAttackDemo:
        if holder["demo"] is None or holder["demo"].S is not S():
            ps03 = getattr(app.state, "ps03", None)
            holder["demo"] = FirmwareAttackDemo(S(), lambda: TwinService(S()), prepare=(lambda: ps03.ensure().reset()) if ps03 else None)
        return holder["demo"]

    @app.get("/api/attack/firmware")
    def status(r: str = Depends(role)):
        return D().snapshot()

    @app.get("/api/attack/firmware/image")
    def image(r: str = Depends(role)):
        return firmware_image()

    @app.post("/api/attack/firmware/launch")
    def launch(r: str = Depends(role)):
        need_admin(r)
        return D().launch()

    @app.post("/api/attack/firmware/reset")
    def reset(r: str = Depends(role)):
        need_admin(r)
        return D().reset()
