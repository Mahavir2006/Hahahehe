# Firmware attack demo (end to end)

**UI:** ☰ → Attack Demo. **API:** `POST /api/attack/firmware/launch`, `GET /api/attack/firmware`, `POST /api/attack/firmware/reset`.
**Code:** `backend/attack_demo.py`, `backend/api/attack.py`, `cascade_ui/src/pages/AttackDemo.tsx`. **Test:** `backend/tests/test_attack_demo.py`.

A trojanised SICAM PAS 8.2.1 firmware image lands on Power's substation gateway (`power-asset-001`). The implant
itself is simulated (the device's firmware hash changes and its network behaviour shows up in telemetry); every step
after that runs on the live system.

| Stage | What happens | Real system part |
|---|---|---|
| 1 Implant | Device reports a firmware hash the vendor never published; implant opens a remote session and beacons out | simulated |
| 2 Detect | `FirmwareRegistry.verifyFirmware` returns **Mismatch**; detection rules fire | contract call, rules D |
| 3 Predict | M1 re-scores the gateway; SHAP compares before/after with only the implant's inputs changed | risk model M1 + SHAP |
| 4 Agents | Bulletin runs the agent pipeline: intake, risk attestation, cascade prediction (water ~35 min, hospital ~70 min) with sealed AlertBus alerts, planner, critic verdict anchored on AuditLog, ApprovalGate request | all agents, 4 contracts |
| 5 Approve | Human approvers sign on ApprovalGate (the AI cannot vote) | ApprovalGate |
| 6 Contain | Executor reads the approval from chain, applies the plan, re-scores (predicted = actual reduction) | executor |
| 7 Record | Every contract event since the attack started; digital twin fingerprint before/after and the drift it flags | chain + twin |

At launch the simulation goes back to day 0 and the live clock holds while the attack runs, so the implant's effect
is not mixed with scripted live events. **Restore device** puts the gateway back on vendor firmware; the chain keeps
the history (append-only).

Example live run: gateway risk 20.2 (high) → 71.7 (critical); the implant alone takes the likelihood of compromise from
24% to 87% (SHAP: detection-rule hits +2.33, high-severity detection +0.85 log-odds, plus the firmware inputs); after
containment 12.2 (medium), predicted reduction = actual; 18 contract events across AttestationRegistry, AlertBus,
ApprovalGate and AuditLog.
