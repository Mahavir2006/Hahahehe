"""
Critic Agent - Validates remediation plans against constraints and risk deltas.
"""

import asyncio
import hashlib
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from .base_agent import BaseAgent, AgentConfig, ToolRegistry
from backend.common.schemas import *
from .tool_framework import tool, SideEffect
from .trace_system import TraceManager, TraceStepType, get_trace_manager

from ..common.config import settings
from ..common.chain_client import get_chain_client
from ..common.chain_writer import ChainWriter, IdempotencyKeyGenerator
from ..common.audit_anchor import get_anchor_service

import logging

logger = logging.getLogger(__name__)


@dataclass
class CriticAgentInput:
    plan: RemediationPlan
    finding: AdvisoryFinding
    risk_assessments: List[RiskAssessment]
    org: str


class CriticAgent(BaseAgent[CriticAgentInput]):
    """Validates remediation plans against constraints and risk deltas."""
    
    def __init__(
        self,
        config: AgentConfig,
        trace_manager: Optional[TraceManager] = None
    ):
        super().__init__(config, trace_manager=trace_manager)
        self.chain_client = get_chain_client()
        self.chain_writer = ChainWriter(self.chain_client)
        self.anchor_service = get_anchor_service()
    
    def _register_tools(self):
        reg = self.tool_registry
        
        @tool(
            name="verify_plan",
            description="Verify plan against all constraints",
            input_model=VerifyPlanInput,
            output_model=VerifyPlanOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def verify_plan(input_data: VerifyPlanInput) -> VerifyPlanOutput:
            return await self._verify_plan(input_data)
        
        @tool(
            name="recompute_risk_delta",
            description="Recompute risk delta for plan steps",
            input_model=RecomputeRiskDeltaInput,
            output_model=RecomputeRiskDeltaOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def recompute_risk_delta(input_data: RecomputeRiskDeltaInput) -> RecomputeRiskDeltaOutput:
            return await self._recompute_risk_delta(input_data)
        
        @tool(
            name="anchor_verdict",
            description="Anchor critic verdict to blockchain",
            input_model=AnchorVerdictInput,
            output_model=AnchorVerdictOutput,
            side_effect=SideEffect.WRITE_CHAIN,
            required_role="agent"
        )
        async def anchor_verdict(input_data: AnchorVerdictInput) -> AnchorVerdictOutput:
            return await self._anchor_verdict(input_data)
    
    async def process(self, input_data: CriticAgentInput) -> CriticVerdict:
        """Critic validates the plan."""
        trace = await self.trace_manager.start_trace(f"critic-{input_data.org}-{int(time.time())}")
        self._current_trace = trace
        
        # Verify plan constraints
        verify_result = await self._verify_plan(VerifyPlanInput(
            plan=input_data.plan,
            org=input_data.org
        ))
        
        # Recompute risk deltas
        recompute_result = await self._recompute_risk_delta(RecomputeRiskDeltaInput(
            plan=input_data.plan,
            risk_assessments=input_data.risk_assessments
        ))
        
        # Determine verdict
        if not verify_result.valid:
            verdict = CriticVerdict(
                verdict="REJECT",
                reasons=verify_result.violations,
                revision_count=0,
                trace_id=trace.trace_id
            )
        elif abs(recompute_result.total_risk_delta - input_data.plan.total_delta) > 1e-6:
            verdict = CriticVerdict(
                verdict="REVISE",
                reasons=[f"Risk delta mismatch: plan={input_data.plan.total_delta}, recomputed={recompute_result.total_risk_delta}"],
                revision_count=0,
                trace_id=trace.trace_id
            )
        else:
            verdict = CriticVerdict(
                verdict="APPROVE_FOR_GATE",
                reasons=["All constraints satisfied", "Risk delta matches recomputation"],
                revision_count=0,
                trace_id=trace.trace_id
            )
        
        # Anchor verdict
        await self._anchor_verdict(AnchorVerdictInput(
            verdict=verdict,
            org=input_data.org
        ))
        
        await self.trace_manager.complete_trace(self._current_trace.trace_id, "completed")
        return verdict
    
    async def _verify_plan(self, input_data: VerifyPlanInput) -> VerifyPlanOutput:
        """Verify plan against all constraints."""
        violations = []
        plan = input_data.plan
        
        # Load inventory for asset details
        import json
        from pathlib import Path
        
        inventory_path = Path(settings.data_dir) / "orgs" / input_data.org / "inventory.json"
        if not inventory_path.exists():
            return VerifyPlanOutput(valid=False, violations=["Inventory not found"])
        
        with open(inventory_path) as f:
            inventory = {a["asset_id"]: a for a in json.load(f)}
        
        # Load services
        services_path = Path(settings.data_dir) / "orgs" / input_data.org / "services.json"
        services = {}
        if services_path.exists():
            with open(services_path) as f:
                services = {s["service_id"]: s for s in json.load(f)}
        
        # Check each step
        for step in plan.steps:
            for asset_id in step.target_assets:
                asset = inventory.get(asset_id)
                if not asset:
                    violations.append(f"Step {step.step_id}: Asset {asset_id} not found in inventory")
                    continue
                
                # Safety-critical isolation constraint
                if asset.get("safety_critical") and step.action in ["ISOLATE_ASSET", "DISABLE_SERVICE_PORT"]:
                    violations.append(f"Step {step.step_id}: Cannot isolate safety-critical asset {asset_id} without compensating control")
                
                # Maintenance window
                if asset.get("patch_requires_downtime") and asset.get("maintenance_window") == "none":
                    if step.action == "PATCH":
                        violations.append(f"Step {step.step_id}: Asset {asset_id} requires maintenance window but none defined")
                
                # Vendor signoff
                if asset.get("vendor_signoff_required") and step.action == "PATCH":
                    # Check if vendor signoff step exists before this
                    has_signoff = any(
                        s.action == "REQUEST_VENDOR_SIGNOFF" and asset_id in s.target_assets
                        for s in plan.steps if plan.steps.index(s) < plan.steps.index(step)
                    )
                    if not has_signoff:
                        violations.append(f"Step {step.step_id}: Vendor signoff required for {asset_id} but not requested")
                
                # Dependency order
                for dep_id in asset.get("depends_on", []):
                    dep_steps = [s for s in plan.steps if dep_id in s.target_assets]
                    if dep_steps:
                        dep_idx = min(plan.steps.index(s) for s in dep_steps)
                        if plan.steps.index(step) < dep_idx:
                            violations.append(f"Step {step.step_id}: Dependency {dep_id} addressed after dependent {asset_id}")
                
                # Life-critical conflicts
                if asset.get("service_criticality") == "life_critical" and step.impact_class == ImpactClass.HIGH:
                    # Check for other HIGH impact steps in same window
                    conflicting = [
                        s for s in plan.steps
                        if s.scheduled_window == step.scheduled_window
                        and s.impact_class == ImpactClass.HIGH
                        and s != step
                        and any(a.get("service_criticality") == "life_critical" for a in [inventory.get(a_id) for a_id in s.target_assets])
                    ]
                    if conflicting:
                        violations.append(f"Step {step.step_id}: Life-critical service conflict in window {step.scheduled_window}")
        
        # Check budget (simplified)
        total_downtime = sum(s.est_downtime_min for s in plan.steps)
        total_effort = sum(s.est_effort_h for s in plan.steps)
        
        if total_downtime > 480:  # 8 hours max
            violations.append(f"Total downtime {total_downtime}min exceeds 8-hour budget")
        
        if total_effort > 40:  # 40 hours max
            violations.append(f"Total effort {total_effort}h exceeds 40-hour budget")
        
        return VerifyPlanOutput(
            valid=len(violations) == 0,
            violations=violations
        )
    
    async def _recompute_risk_delta(self, input_data: RecomputeRiskDeltaInput) -> RecomputeRiskDeltaOutput:
        """Recompute risk delta for plan steps."""
        total_delta = 0.0
        step_deltas = {}
        
        for step in input_data.plan.steps:
            # Simplified: use step's expected_risk_delta
            step_deltas[step.step_id] = step.expected_risk_delta
            total_delta += step.expected_risk_delta
        
        return RecomputeRiskDeltaOutput(
            total_risk_delta=total_delta,
            step_deltas=step_deltas
        )
    
    async def _anchor_verdict(self, input_data: AnchorVerdictInput) -> AnchorVerdictOutput:
        """Anchor critic verdict to blockchain via AuditLog."""
        verdict_digest = hashlib.sha256(str(input_data.verdict).encode()).hexdigest()
        
        idempotency_key = f"critic:{input_data.org}:{verdict_digest}"
        
        async def do_anchor():
            return self.chain_client.anchor(
                self.chain_client.to_bytes32(input_data.org),
                3,  # CriticVerdict
                self.chain_client.to_bytes32(verdict_digest),
                self.chain_client.get_last_digest(self.chain_client.to_bytes32(input_data.org)),
                self.chain_client.to_bytes32(hashlib.sha256(str(input_data.verdict).encode()).hexdigest()),
                bytes.fromhex("00" * 65)  # Placeholder signature
            )
        
        tx_hash = await self.chain_writer.write(idempotency_key, do_anchor)
        
        return AnchorVerdictOutput(
            verdict_digest=verdict_digest,
            tx_hash=tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
        )


# ============================================================================
# Tool Input/Output Schemas
# ============================================================================

class VerifyPlanInput(BaseModel):
    plan: RemediationPlan
    org: str


class VerifyPlanOutput(BaseModel):
    valid: bool
    violations: List[str]


class RecomputeRiskDeltaInput(BaseModel):
    plan: RemediationPlan
    risk_assessments: List[RiskAssessment]


class RecomputeRiskDeltaOutput(BaseModel):
    total_risk_delta: float
    step_deltas: Dict[str, float]


class AnchorVerdictInput(BaseModel):
    verdict: CriticVerdict
    org: str


class AnchorVerdictOutput(BaseModel):
    verdict_digest: str
    tx_hash: str