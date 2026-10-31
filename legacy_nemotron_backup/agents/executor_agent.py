"""
Executor Agent - Simulates remediation execution after approval.
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
class ExecutorAgentInput:
    plan: RemediationPlan
    approval_request_id: str
    org: str


class ExecutorAgent(BaseAgent[ExecutorAgentInput]):
    """Simulates remediation execution after approval."""
    
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
            name="check_approval",
            description="Verify approval status on-chain",
            input_model=CheckApprovalInput,
            output_model=CheckApprovalOutput,
            side_effect=SideEffect.READ_CHAIN,
            required_role="agent"
        )
        async def check_approval(input_data: CheckApprovalInput) -> CheckApprovalOutput:
            return await self._check_approval(input_data)
        
        @tool(
            name="execute_step",
            description="Execute a single remediation step (simulated)",
            input_model=ExecuteStepInput,
            output_model=ExecuteStepOutput,
            side_effect=SideEffect.WRITE_LOCAL,
            required_role="agent"
        )
        async def execute_step(input_data: ExecuteStepInput) -> ExecuteStepOutput:
            return await self._execute_step(input_data)
        
        @tool(
            name="mark_executed",
            description="Mark step as executed on-chain",
            input_model=MarkExecutedInput,
            output_model=MarkExecutedOutput,
            side_effect=SideEffect.WRITE_CHAIN,
            required_role="agent"
        )
        async def mark_executed(input_data: MarkExecutedInput) -> MarkExecutedOutput:
            return await self._mark_executed(input_data)
        
        @tool(
            name="recompute_risk",
            description="Recompute risk after execution",
            input_model=RecomputeRiskInput,
            output_model=RecomputeRiskOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def recompute_risk(input_data: RecomputeRiskInput) -> RecomputeRiskOutput:
            return await self._recompute_risk(input_data)
    
    async def process(self, input_data: ExecutorAgentInput) -> ExecutionRecord:
        """Execute remediation plan after approval."""
        trace = await self.trace_manager.start_trace(f"executor-{input_data.org}-{int(time.time())}")
        self._current_trace = trace
        
        # Check approval status
        approval_status = await self._check_approval(CheckApprovalInput(
            approval_request_id=input_data.approval_request_id
        ))
        
        if not approval_status.approved:
            raise RuntimeError(f"Plan not approved: {approval_status.state}")
        
        if approval_status.plan_hash != input_data.plan.plan_hash:
            raise RuntimeError("Plan hash mismatch between approval and execution")
        
        # Execute each step
        execution_results = []
        for step in input_data.plan.steps:
            if step.impact_class in [ImpactClass.MEDIUM, ImpactClass.HIGH]:
                # Verify approval for this step
                step_approval = await self._check_approval(CheckApprovalInput(
                    approval_request_id=input_data.approval_request_id
                ))
                if not step_approval.approved:
                    raise RuntimeError(f"Step {step.step_id} not approved")
            
            # Execute step
            result = await self._execute_step(ExecuteStepInput(
                plan_id=input_data.plan.plan_id,
                step=step,
                org=input_data.org
            ))
            execution_results.append(result)
            
            # Mark step as executed on-chain
            await self._mark_executed(MarkExecutedInput(
                approval_request_id=input_data.approval_request_id,
                step_id=step.step_id,
                execution_digest=hashlib.sha256(str(result).encode()).hexdigest()
            ))
        
        # Recompute risk after execution
        final_risk = await self._recompute_risk(RecomputeRiskInput(
            plan=input_data.plan,
            org=input_data.org
        ))
        
        # Create execution record
        execution_record = ExecutionRecord(
            plan_id=input_data.plan.plan_id,
            execution_id=f"EXEC-{int(time.time())}",
            org=input_data.org,
            steps_executed=[s.step_id for s in input_data.plan.steps],
            actual_risk_delta=final_risk.risk_after - final_risk.risk_before,
            predicted_risk_delta=input_data.plan.total_delta,
            executed_at=int(time.time()),
            status="completed"
        )
        
        # Anchor execution record
        await self._anchor_execution(execution_record)
        
        await self.trace_manager.complete_trace(self._current_trace.trace_id, "completed")
        return execution_record
    
    async def _check_approval(self, input_data: CheckApprovalInput) -> CheckApprovalOutput:
        """Check approval status on-chain."""
        request = self.chain_client.get_request(
            self.chain_client.to_bytes32(input_data.approval_request_id)
        )
        
        return CheckApprovalOutput(
            approval_request_id=input_data.approval_request_id,
            approved=request["state"] == 1,  # Approved
            plan_hash=request["plan_hash"],
            state=request["state"]
        )
    
    async def _execute_step(self, input_data: ExecuteStepInput) -> ExecuteStepOutput:
        """Simulate step execution."""
        step = input_data.step
        org = input_data.org
        
        logger.info(f"Executing step {step.step_id}: {step.action} on {step.target_assets}")
        
        # Simulate execution delay
        await asyncio.sleep(0.1)
        
        # Simulate state changes
        changes = []
        for asset_id in step.target_assets:
            if step.action == "PATCH":
                changes.append(f"Patched {asset_id}")
            elif step.action == "SEGMENT_NETWORK":
                changes.append(f"Network segmented for {asset_id}")
            elif step.action == "ROTATE_CREDENTIALS":
                changes.append(f"Credentials rotated for {asset_id}")
            elif step.action == "ISOLATE_ASSET":
                changes.append(f"Isolated {asset_id}")
            elif step.action == "SEGMENT_NETWORK":
                changes.append(f"Network segmented for {asset_id}")
            elif step.action == "ROTATE_CREDENTIALS":
                changes.append(f"Credentials rotated for {asset_id}")
            elif step.action == "ISOLATE_ASSET":
                changes.append(f"Isolated {asset_id}")
            elif step.action == "SEGMENT_NETWORK":
                changes.append(f"Network segmented for {asset_id}")
            elif step.action == "ROTATE_CREDENTIALS":
                changes.append(f"Credentials rotated for {asset_id}")
            elif step.action == "ISOLATE_ASSET":
                changes.append(f"Isolated {asset_id}")
        
        return ExecuteStepOutput(
            step_id=step.step_id,
            success=True,
            changes=changes,
            execution_digest=hashlib.sha256(f"{step.step_id}:{time.time()}".encode()).hexdigest()
        )
    
    async def _mark_executed(self, input_data: MarkExecutedInput) -> MarkExecutedOutput:
        """Mark step as executed on-chain."""
        idempotency_key = f"exec:{input_data.approval_request_id}:{input_data.step_id}"
        
        async def do_mark():
            return self.chain_client.mark_executed(
                self.chain_client.to_bytes32(input_data.approval_request_id),
                self.chain_client.to_bytes32(input_data.execution_digest),
                bytes.fromhex("00" * 65)  # Placeholder
            )
        
        tx_hash = await self.chain_writer.write(idempotency_key, do_mark)
        
        return MarkExecutedOutput(
            tx_hash=tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
        )
    
    async def _recompute_risk(self, input_data: RecomputeRiskInput) -> RecomputeRiskOutput:
        """Recompute risk after execution."""
        # In production, would reload inventory and rescore
        # For now, return planned values
        return RecomputeRiskOutput(
            risk_before=input_data.plan.risk_before,
            risk_after=input_data.plan.risk_after,
            delta=input_data.plan.total_delta,
            per_asset={}
        )
    
    async def _anchor_execution(self, execution_record: ExecutionRecord):
        """Anchor execution record to AuditLog."""
        digest = hashlib.sha256(str(execution_record).encode()).hexdigest()
        
        idempotency_key = f"execution:{execution_record.plan_id}"
        
        async def do_anchor():
            return self.chain_client.anchor(
                self.chain_client.to_bytes32(execution_record.org),
                4,  # Execution
                self.chain_client.to_bytes32(digest),
                self.chain_client.get_last_digest(self.chain_client.to_bytes32(execution_record.org)),
                self.chain_client.to_bytes32(hashlib.sha256(str(execution_record).encode()).hexdigest()),
                bytes.fromhex("00" * 65)  # Placeholder
            )
        
        await self.chain_writer.write(idempotency_key, do_anchor)


# ============================================================================
# Tool Input/Output Schemas
# ============================================================================

class CheckApprovalInput(BaseModel):
    approval_request_id: str


class CheckApprovalOutput(BaseModel):
    approval_request_id: str
    approved: bool
    plan_hash: str
    state: int


class ExecuteStepInput(BaseModel):
    plan_id: str
    step: PlanStep
    org: str


class ExecuteStepOutput(BaseModel):
    step_id: str
    success: bool
    changes: List[str]
    execution_digest: str


class MarkExecutedInput(BaseModel):
    approval_request_id: str
    step_id: str
    execution_digest: str


class MarkExecutedOutput(BaseModel):
    tx_hash: str


class RecomputeRiskInput(BaseModel):
    plan: RemediationPlan
    org: str


class RecomputeRiskOutput(BaseModel):
    risk_before: float
    risk_after: float
    delta: float
    per_asset: Dict[str, float]