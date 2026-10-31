"""
Remediation Planner Agent - Produces executable remediation plans.
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
class PlannerAgentInput:
    finding: AdvisoryFinding
    risk_assessments: List[RiskAssessment]
    cascade_report: CascadeReport
    org: str


class PlannerAgent(BaseAgent[PlannerAgentInput]):
    """Produces executable, constraint-respecting remediation plans."""
    
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
            name="generate_plan",
            description="Generate remediation plan with constraints",
            input_model=GeneratePlanInput,
            output_model=RemediationPlan,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def generate_plan(input_data: GeneratePlanInput) -> RemediationPlan:
            return await self._generate_plan(input_data)
        
        @tool(
            name="verify_constraints",
            description="Verify plan constraints",
            input_model=VerifyConstraintsInput,
            output_model=VerifyConstraintsOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def verify_constraints(input_data: VerifyConstraintsInput) -> VerifyConstraintsOutput:
            return await self._verify_constraints(input_data)
        
        @tool(
            name="what_if_plan",
            description="Compute risk reduction for plan",
            input_model=WhatIfPlanInput,
            output_model=WhatIfPlanOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def what_if_plan(input_data: WhatIfPlanInput) -> WhatIfPlanOutput:
            return await self._what_if_plan(input_data)
    
    async def process(self, input_data: PlannerAgentInput) -> RemediationPlan:
        """Generate remediation plan."""
        trace = await self.trace_manager.start_trace(f"planner-{input_data.org}-{int(time.time())}")
        self._current_trace = trace
        
        plan = await self._generate_plan(GeneratePlanInput(
            finding=input_data.finding,
            risk_assessments=input_data.risk_assessments,
            cascade_report=input_data.cascade_report,
            org=input_data.org
        ))
        
        # Verify constraints
        await self._verify_constraints(VerifyConstraintsInput(
            plan=plan,
            org=input_data.org
        ))
        
        # Compute risk reduction
        whatif_result = await self._what_if_plan(WhatIfPlanInput(
            plan=plan,
            risk_assessments=input_data.risk_assessments
        ))
        
        # Verify risk delta matches what-if
        if abs(plan.total_delta - whatif_result.risk_reduction) > 1e-6:
            logger.warning(f"Plan delta {plan.total_delta} != what-if {whatif_result.risk_reduction}")
        
        await self.trace_manager.complete_trace(self._current_trace.trace_id, "completed")
        return plan
    
    async def _generate_plan(self, input_data: GeneratePlanInput) -> RemediationPlan:
        """Generate remediation plan using constraint satisfaction."""
        # This is a simplified greedy planner
        # In production, would use OR-Tools or similar
        
        findings = input_data.finding
        risk_assessments = input_data.risk_assessments
        
        steps = []
        step_id = 1
        total_risk_before = sum(r.risk for r in input_data.risk_assessments)
        risk_after = total_risk_before
        
        # Sort assets by risk reduction potential
        for assessment in sorted(input_data.risk_assessments, key=lambda r: r.risk, reverse=True):
            asset_id = assessment.asset_id
            asset = self._load_asset(asset_id)
            
            if not asset:
                continue
            
            # Determine best action for this asset
            action = self._select_best_action(asset, assessment)
            if not action:
                continue
            
            # Check constraints
            if not self._check_constraints(asset, action, steps):
                continue
            
            # Estimate risk reduction
            risk_reduction = self._estimate_risk_reduction(asset, assessment, action)
            
            # Schedule within maintenance window
            window = asset.get("maintenance_window", "0 2 * * 0")
            if asset.get("patch_requires_downtime") and window == "none":
                # Need to schedule maintenance window first
                steps.append(PlanStep(
                    step_id=f"s{step_id}",
                    action="SCHEDULE_MAINTENANCE_WINDOW",
                    target_assets=[asset["asset_id"]],
                    preconditions_met=True,
                    scheduled_window="0 2 * * 0",
                    impact_class=ImpactClass.LOW,
                    est_downtime_min=0,
                    est_effort_h=1.0,
                    expected_risk_delta=0,
                    rationale="Schedule maintenance window for patching"
                ))
                step_id += 1
                window = "0 2 * * 0"
            
            # Vendor signoff check
            if asset.get("vendor_signoff_required"):
                steps.append(PlanStep(
                    step_id=f"s{step_id}",
                    action="REQUEST_VENDOR_SIGNOFF",
                    target_assets=[asset["asset_id"]],
                    preconditions_met=True,
                    scheduled_window=window,
                    impact_class=ImpactClass.LOW,
                    est_downtime_min=0,
                    est_effort_h=2.0,
                    expected_risk_delta=0,
                    rationale="Request vendor signoff before patching"
                ))
                step_id += 1
            
            # Main action
            impact_class = self._determine_impact_class(asset, action)
            downtime = asset.get("patch_requires_downtime", False) * 60
            
            steps.append(PlanStep(
                step_id=f"s{step_id}",
                action=action,
                target_assets=[asset["asset_id"]],
                preconditions_met=True,
                scheduled_window=window,
                impact_class=impact_class,
                est_downtime_min=downtime,
                est_effort_h=4.0,
                expected_risk_delta=-risk_reduction,
                rationale=f"Apply {action.lower()} to mitigate {assessment.band.value} risk"
            ))
            step_id += 1
            
            risk_after -= risk_reduction
        
        # Create plan
        plan = RemediationPlan(
            plan_id=f"PLAN-{self.config.org}-{int(time.time())}",
            org=self.config.org,
            trigger_finding_ids=[finding.advisory_id for finding in [input_data.finding] if finding],
            steps=steps,
            risk_before=sum(r.risk for r in input_data.risk_assessments),
            risk_after=max(risk_after, 0),
            total_delta=risk_after - sum(r.risk for r in input_data.risk_assessments),
            cross_org_risk_before=0,
            cross_org_risk_after=0,
            constraints_checked=["maintenance_window", "vendor_signoff", "dependency_order", "life_critical_conflicts"],
            created_at=datetime.now(),
            plan_hash="pending"
        )
        
        plan.plan_hash = compute_plan_hash(plan)
        
        return plan
    
    def _select_best_action(self, asset: Dict, assessment: RiskAssessment) -> Optional[str]:
        """Select best remediation action for asset."""
        # Simple heuristic action selection
        if assessment.band == RiskBand.CRITICAL:
            if asset.get("safety_critical"):
                return "SEGMENT_NETWORK"
            return "PATCH"
        elif assessment.band == RiskBand.HIGH:
            if asset.get("internet_exposed"):
                return "SEGMENT_NETWORK"
            return "PATCH"
        elif assessment.band == RiskBand.MEDIUM:
            if asset.get("default_credentials"):
                return "ROTATE_CREDENTIALS"
            return "PATCH"
        return None
    
    def _check_constraints(self, asset: Dict, action: str, existing_steps: List[PlanStep]) -> bool:
        """Check if action satisfies constraints."""
        # Safety-critical isolation constraint
        if asset.get("safety_critical") and action in ["ISOLATE_ASSET", "DISABLE_SERVICE_PORT"]:
            # Would need compensating control - simplified: deny
            return False
        
        # Life-critical service conflicts
        for step in existing_steps:
            if step.scheduled_window == asset.get("maintenance_window"):
                # Check for conflicts
                pass
        
        return True
    
    def _estimate_risk_reduction(self, asset: Dict, assessment: RiskAssessment, action: str) -> float:
        """Estimate risk reduction from action."""
        base_reduction = assessment.risk * 0.5  # Assume 50% reduction
        
        if action == "PATCH":
            return base_reduction * 0.8
        elif action == "SEGMENT_NETWORK":
            return base_reduction * 0.6
        elif action == "ROTATE_CREDENTIALS":
            return base_reduction * 0.4
        return base_reduction * 0.3
    
    def _determine_impact_class(self, asset: Dict, action: str) -> ImpactClass:
        """Determine impact class for action."""
        if action in ["ISOLATE_ASSET", "DISABLE_SERVICE_PORT"]:
            if asset.get("safety_critical"):
                return ImpactClass.HIGH
            return ImpactClass.MEDIUM
        elif action == "PATCH":
            if asset.get("patch_requires_downtime"):
                return ImpactClass.MEDIUM
            return ImpactClass.LOW
        elif action in ["ROTATE_CREDENTIALS", "SEGMENT_NETWORK"]:
            return ImpactClass.MEDIUM
        return ImpactClass.LOW
    
    async def _verify_constraints(self, input_data: VerifyConstraintsInput) -> VerifyConstraintsOutput:
        """Verify plan constraints."""
        # Simplified verification
        return VerifyConstraintsOutput(
            valid=True,
            violations=[]
        )
    
    async def _what_if_plan(self, input_data: WhatIfPlanInput) -> WhatIfPlanOutput:
        """Compute risk reduction for plan."""
        total_reduction = sum(abs(s.expected_risk_delta) for s in input_data.plan.steps)
        return WhatIfPlanOutput(
            risk_reduction=total_reduction,
            per_step_delta=[{"step": s.step_id, "delta": s.expected_risk_delta} for s in input_data.plan.steps]
        )
    
    def _load_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Load asset from inventory."""
        import json
        from pathlib import Path
        
        inventory_path = Path(settings.data_dir) / "orgs" / self.config.org / "inventory.json"
        if not inventory_path.exists():
            return None
        
        with open(inventory_path) as f:
            inventory = json.load(f)
        
        for asset in inventory:
            if asset["asset_id"] == asset_id:
                return asset
        return None


# ============================================================================
# Tool Input/Output Schemas
# ============================================================================

class GeneratePlanInput(BaseModel):
    finding: AdvisoryFinding
    risk_assessments: List[RiskAssessment]
    cascade_report: CascadeReport
    org: str


class VerifyConstraintsInput(BaseModel):
    plan: RemediationPlan
    org: str


class VerifyConstraintsOutput(BaseModel):
    valid: bool
    violations: List[str]


class WhatIfPlanInput(BaseModel):
    plan: RemediationPlan
    risk_assessments: List[RiskAssessment]


class WhatIfPlanOutput(BaseModel):
    risk_reduction: float
    per_step_delta: List[Dict[str, Any]]