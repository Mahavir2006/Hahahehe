"""
Trace system for agent observability and audit anchoring.
"""

import asyncio
import hashlib
import json
import time
import uuid
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager
import logging

from backend.common.schemas import *
from .llm_client import get_llm_client
from .tool_framework import ToolRegistry
from ..common.config import settings
from ..common.chain_client import get_chain_client
from ..common.chain_writer import ChainWriter, IdempotencyKeyGenerator
from ..common.audit_anchor import AuditAnchorService, get_anchor_service

logger = logging.getLogger(__name__)


@dataclass
class TraceContext:
    """Context for a trace."""
    trace_id: str
    advisory_id: str
    org: str
    parent_trace_id: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


class TraceWriter:
    """Writes trace steps to local storage and anchors to chain."""
    
    def __init__(
        self,
        trace_dir: str = "backend/traces",
        anchor_service: Optional[AuditAnchorService] = None
    ):
        self.trace_dir = Path(trace_dir)
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.anchor_service = anchor_service
        self._current_trace: Optional[AgentTrace] = None
    
    def start_trace(self, trace_id: str, advisory_id: str, org: str) -> AgentTrace:
        """Start a new trace."""
        trace = AgentTrace(
            trace_id=trace_id,
            advisory_id=advisory_id,
            org=org,
            started_at=datetime.now(),
            stages_completed=[],
            current_stage=None,
            steps=[],
            status="running"
        )
        self._current_trace = trace
        return trace
    
    def add_step(
        self,
        trace: AgentTrace,
        step_type: TraceStepType,
        agent: str,
        content: Dict[str, Any],
        duration_ms: Optional[int] = None,
        tool_name: Optional[str] = None,
        tool_input: Optional[Dict[str, Any]] = None,
        tool_output: Optional[Dict[str, Any]] = None,
        llm_fallback: bool = False
    ) -> TraceStep:
        """Add a step to the trace."""
        step = TraceStep(
            step_id=str(uuid.uuid4()),
            trace_id=trace.trace_id,
            timestamp=datetime.now(),
            step_type=step_type,
            agent=agent,
            content=content,
            duration_ms=duration_ms,
            tool_name=tool_name,
            tool_input=tool_input,
            tool_output=tool_output,
            llm_fallback=llm_fallback
        )
        trace.steps.append(step)
        return step
    
    def complete_trace(self, trace: AgentTrace, status: str = "completed") -> AgentTrace:
        """Complete a trace and compute digest."""
        trace.completed_at = datetime.now()
        trace.status = status
        trace.trace_digest = compute_trace_digest(trace)
        
        # Persist to file
        self._persist_trace(trace)
        
        return trace
    
    def _persist_trace(self, trace: AgentTrace):
        """Persist trace to JSONL file."""
        trace_file = self.trace_dir / f"{trace.org}_{trace.trace_id}.jsonl"
        with open(trace_file, "w") as f:
            f.write(trace.model_dump_json() + "\n")
    
    async def anchor_trace(self, trace: AgentTrace):
        """Anchor trace digest to chain via AuditAnchorService."""
        if self.anchor_service:
            await self.anchor_service.add_item(
                org_id=trace.org,
                kind="AgentTrace",
                digest=trace.trace_digest or "",
                meta={
                    "advisory_id": trace.advisory_id,
                    "stages": [s.value for s in trace.stages_completed],
                    "status": trace.status,
                    "step_count": len(trace.steps)
                }
            )


class TraceManager:
    """Manages traces for an organization."""
    
    def __init__(self, org: str, trace_dir: str = "backend/traces"):
        self.org = org
        self.trace_dir = Path(trace_dir) / org
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self._traces: Dict[str, AgentTrace] = {}
        self._lock = asyncio.Lock()
    
    async def start_trace(self, advisory_id: str) -> AgentTrace:
        """Start a new trace."""
        trace_id = f"tr_{uuid.uuid4().hex[:16]}"
        trace = AgentTrace(
            trace_id=trace_id,
            advisory_id=advisory_id,
            org=self.org,
            started_at=datetime.now(),
            stages_completed=[],
            current_stage=None,
            steps=[],
            status="running"
        )
        
        async with self._lock:
            self._traces[trace_id] = trace
        
        # Persist initial trace
        self._persist_trace(trace)
        
        return trace
    
    def add_step(
        self,
        trace_id: str,
        step_type: TraceStepType,
        agent: str,
        content: Dict[str, Any],
        **kwargs
    ) -> Optional[TraceStep]:
        """Add step to trace."""
        trace = self._traces.get(trace_id)
        if not trace:
            return None
        
        step = TraceStep(
            step_id=str(uuid.uuid4()),
            trace_id=trace_id,
            timestamp=datetime.now(),
            step_type=step_type,
            agent=agent,
            content=content,
            **kwargs
        )
        trace.steps.append(step)
        self._persist_trace(trace)
        return step
    
    async def complete_trace(self, trace_id: str, status: str = "completed") -> Optional[AgentTrace]:
        """Complete trace and anchor to chain."""
        async with self._lock:
            trace = self._traces.get(trace_id)
            if not trace:
                return None
            
            trace.completed_at = datetime.now()
            trace.status = status
            trace.trace_digest = compute_trace_digest(trace)
            
            self._persist_trace(trace)
            return trace
    
    def _persist_trace(self, trace: AgentTrace):
        """Persist trace to JSONL file."""
        trace_file = self.trace_dir / f"{trace.trace_id}.jsonl"
        with open(trace_file, "w") as f:
            f.write(trace.model_dump_json() + "\n")
    
    def get_trace(self, trace_id: str) -> Optional[AgentTrace]:
        return self._traces.get(trace_id)
    
    def list_traces(self, limit: int = 100) -> List[AgentTrace]:
        return list(self._traces.values())[-limit:]


# Global trace managers per org
_trace_managers: Dict[str, TraceManager] = {}


def get_trace_manager(org: str) -> TraceManager:
    """Get or create trace manager for org."""
    if org not in _trace_managers:
        _trace_managers[org] = TraceManager(org)
    return _trace_managers[org]


@asynccontextmanager
async def trace_stage(
    trace: AgentTrace,
    stage: AgentStage,
    agent_name: str,
    trace_manager: TraceManager
):
    """Context manager for tracing a stage."""
    trace.current_stage = stage
    trace.stages_completed.append(stage)
    
    start_time = time.time()
    try:
        yield
    finally:
        duration_ms = int((time.time() - start_time) * 1000)
        trace_manager.add_step(
            trace_id=trace.trace_id,
            step_type=TraceStepType.DECISION,
            agent=agent_name,
            content={"stage": stage.value, "duration_ms": duration_ms}
        )


# ============================================================================
# Utility Functions
# ============================================================================

def compute_trace_digest(trace: AgentTrace) -> str:
    """Compute canonical hash of a trace."""
    data = trace.model_dump(exclude={"trace_digest", "on_chain_anchor_tx"})
    canon = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def compute_plan_hash(plan: 'RemediationPlan') -> str:
    """Compute canonical hash of a plan."""
    from backend.common.schemas import RemediationPlan
    data = plan.model_dump(exclude={"plan_hash", "alternatives"})
    canon = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()