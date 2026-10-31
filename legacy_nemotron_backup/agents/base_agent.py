"""
Base agent class and state machine for agent orchestration.
"""

import asyncio
import hashlib
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Type, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
import logging

from backend.common.schemas import *
from .llm_client import get_llm_client, LLMClient
from .tool_framework import ToolRegistry, ToolNotAllowed
from .trace_system import TraceManager, TraceStepType, get_trace_manager, trace_stage
from ..common.config import settings
from ..common.chain_client import get_chain_client
from ..common.chain_writer import ChainWriter, IdempotencyKeyGenerator
from ..common.audit_anchor import get_anchor_service
from ..common.event_indexer import EventIndexer

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=BaseModel)


class AgentState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    WAITING_APPROVAL = "waiting_approval"


@dataclass
class AgentConfig:
    """Agent configuration."""
    org: str
    agent_id: str
    max_retries: int = 3
    timeout_seconds: int = 300
    llm_budget_tokens: int = 50000
    llm_budget_calls: int = 20


class BaseAgent(ABC, Generic[T]):
    """Base class for all agents."""
    
    def __init__(
        self,
        config: AgentConfig,
        tool_registry: Optional[ToolRegistry] = None,
        trace_manager: Optional['TraceManager'] = None
    ):
        self.config = config
        self.tool_registry = tool_registry or ToolRegistry()
        self.trace_manager = trace_manager or get_trace_manager(config.org)
        self.llm_client = get_llm_client()
        self.chain_client = get_chain_client()
        self.chain_writer = ChainWriter(self.chain_client)
        self.anchor_service = get_anchor_service(self.chain_client, self.chain_writer)
        
        self.state = AgentState.IDLE
        self._current_trace: Optional[AgentTrace] = None
        self._llm_tokens_used = 0
        self._llm_calls_made = 0
        
        # Register agent-specific tools
        self._register_tools()
    
    @abstractmethod
    def _register_tools(self):
        """Register agent-specific tools."""
        pass
    
    @abstractmethod
    async def process(self, input_data: T) -> BaseModel:
        """Process input and return output."""
        pass
    
    def _call_tool(self, name: str, input_data: BaseModel) -> BaseModel:
        """Call a registered tool with validation."""
        tool = self.tool_registry.get_tool(name)
        if not tool:
            raise ToolNotAllowed(f"Tool '{name}' not registered for this agent")
        
        # Validate input
        if not isinstance(input_data, tool.input_model):
            raise ValueError(f"Invalid input type for tool {name}")
        
        # Execute tool
        start = time.time()
        try:
            # This would be async in real implementation
            result = tool.handler(input_data)
            duration_ms = int((time.time() - start) * 1000)
            
            # Log tool call in trace
            if self._current_trace:
                self.trace_manager.add_step(
                    trace_id=self._current_trace.trace_id,
                    step_type=TraceStepType.TOOL_CALL,
                    agent=self.config.agent_id,
                    content={"tool": name, "input_hash": hashlib.sha256(str(input_data).encode()).hexdigest()[:16]},
                    duration_ms=duration_ms,
                    tool_name=name,
                    tool_input=input_data.model_dump(),
                    tool_output=result.model_dump() if hasattr(result, 'model_dump') else str(result)
                )
            
            return result
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            raise
    
    async def _call_llm(
        self,
        messages: List[Dict[str, str]],
        schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.0
    ) -> Any:
        """Call LLM with budget tracking."""
        if self._llm_calls_made >= self.config.llm_budget_calls:
            raise RuntimeError("LLM call budget exceeded")
        
        if self._llm_tokens_used >= self.config.llm_budget_tokens:
            raise RuntimeError("LLM token budget exceeded")
        
        self._llm_calls_made += 1
        
        # Estimate tokens (rough approximation)
        prompt_tokens = sum(len(m.get("content", "")) for m in messages) // 4
        if self._llm_tokens_used + prompt_tokens > self.config.llm_budget_tokens:
            raise RuntimeError("LLM token budget would be exceeded")
        
        self._llm_tokens_used += prompt_tokens
        
        try:
            result = await self.llm_client.complete(messages, schema, temperature)
            return result
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            raise
    
    def _check_injection(self, text: str) -> bool:
        """Check for prompt injection patterns."""
        injection_patterns = [
            r'ignore previous instructions',
            r'system:.*approve',
            r'call approve',
            r'maintenance mode',
            r'base64.*payload',
            r'you are now',
            r'forget previous',
            r'new instructions',
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in injection_patterns)
    
    def _sanitize_input(self, text: str) -> str:
        """Sanitize input text."""
        # Remove potential injection markers
        sanitized = text
        # Remove zero-width characters
        sanitized = re.sub(r'[\u200b-\u200f\ufeff]', '', sanitized)
        # Limit length
        if len(sanitized) > 200000:
            sanitized = sanitized[:200000] + "... [TRUNCATED]"
        return sanitized
    
    async def run_with_trace(
        self,
        advisory_id: str,
        process_fn: Callable[[], Awaitable[Any]]
    ) -> Any:
        """Run agent processing with full trace."""
        trace = await self.trace_manager.start_trace(advisory_id)
        self._current_trace = trace
        
        try:
            result = await process_fn()
            await self.trace_manager.complete_trace(trace.trace_id, "completed")
            return result
        except Exception as e:
            await self.trace_manager.complete_trace(trace.trace_id, "failed")
            raise


# ============================================================================
# Orchestrator State Machine
# ============================================================================

class PipelineStage(str, Enum):
    INTAKE = "intake"
    RISK = "risk"
    CASCADE = "cascade"
    PLANNER = "planner"
    CRITIC = "critic"
    GATE = "gate"
    EXECUTOR = "executor"


@dataclass
class PipelineState:
    """State of the advisory processing pipeline."""
    advisory_id: str
    current_stage: PipelineStage = PipelineStage.INTAKE
    stages_completed: List[PipelineStage] = field(default_factory=list)
    trace_id: Optional[str] = None
    finding: Optional[Any] = None
    risk_assessments: List[Any] = field(default_factory=list)
    cascade_report: Optional[Any] = None
    plan: Optional[Any] = None
    critic_verdict: Optional[Any] = None
    approval_request_id: Optional[str] = None
    execution_record: Optional[Any] = None
    status: str = "running"
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class Orchestrator:
    """Orchestrates the agent pipeline for an advisory."""
    
    def __init__(self, org: str, agents: Dict[str, BaseAgent]):
        self.org = org
        self.agents = agents
        self.chain_client = get_chain_client()
        self.chain_writer = ChainWriter(self.chain_client)
        self.trace_manager = get_trace_manager(org)
        self.event_indexer = EventIndexer(get_chain_client())
        
        self._pipelines: Dict[str, PipelineState] = {}
        self._lock = asyncio.Lock()
        self._max_concurrent = settings.agent_max_concurrent_advisories
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        
        # Progress event handlers
        self._progress_handlers: List[Callable] = []
    
    def add_progress_handler(self, handler: Callable):
        self._progress_handlers.append(handler)
    
    async def _emit_progress(self, state: PipelineStage, advisory_id: str, status: str, data: Dict = None):
        """Emit progress event."""
        event = {
            "advisory_id": advisory_id,
            "stage": state.value,
            "status": status,
            "timestamp": time.time(),
            "data": data or {}
        }
        for handler in self._progress_handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Progress handler failed: {e}")
    
    async def process_advisory(self, advisory_id: str, advisory_text: str) -> Dict[str, Any]:
        """Process an advisory through the full pipeline."""
        async with self._semaphore:
            state = PipelineState(advisory_id=advisory_id)
            
            async with self._lock:
                self._pipelines[advisory_id] = state
            
            trace = await self.trace_manager.start_trace(advisory_id)
            state.trace_id = trace.trace_id
            
            try:
                # Stage 1: Intake
                await self._emit_progress(PipelineStage.INTAKE, advisory_id, "started")
                intake_agent = self.agents.get("intake")
                if not intake_agent:
                    raise RuntimeError("Intake agent not configured")
                
                finding = await self._run_agent(intake_agent, advisory_text, trace)
                state.finding = finding
                state.stages_completed.append(PipelineStage.INTAKE)
                await self._emit_progress(PipelineStage.INTAKE, advisory_id, "completed", {"finding_id": finding.advisory_id if hasattr(finding, 'advisory_id') else None})
                
                # Stage 2: Risk
                await self._emit_progress(PipelineStage.RISK, advisory_id, "started")
                risk_agent = self.agents.get("risk")
                if risk_agent:
                    risk_assessments = await self._run_agent(risk_agent, finding, trace)
                    state.risk_assessments = risk_assessments
                    state.stages_completed.append(PipelineStage.RISK)
                    await self._emit_progress(PipelineStage.RISK, advisory_id, "completed")
                
                # Stage 3: Cascade
                await self._emit_progress(PipelineStage.CASCADE, advisory_id, "started")
                cascade_agent = self.agents.get("cascade")
                if cascade_agent:
                    cascade_report = await self._run_agent(cascade_agent, state.risk_assessments, trace)
                    state.cascade_report = cascade_report
                    state.stages_completed.append(PipelineStage.CASCADE)
                    await self._emit_progress(PipelineStage.CASCADE, advisory_id, "completed")
                
                # Stage 4: Planner
                await self._emit_progress(PipelineStage.PLANNER, advisory_id, "started")
                planner_agent = self.agents.get("planner")
                if planner_agent:
                    plan = await self._run_agent(planner_agent, {
                        "finding": finding,
                        "risk_assessments": state.risk_assessments,
                        "cascade_report": state.cascade_report
                    }, trace)
                    state.plan = plan
                    state.stages_completed.append(PipelineStage.PLANNER)
                    await self._emit_progress(PipelineStage.PLANNER, advisory_id, "completed")
                
                # Stage 5: Critic
                await self._emit_progress(PipelineStage.CRITIC, advisory_id, "started")
                critic_agent = self.agents.get("critic")
                if critic_agent:
                    critic_verdict = await self._run_agent(critic_agent, {
                        "plan": state.plan,
                        "finding": finding,
                        "risk_assessments": state.risk_assessments
                    }, trace)
                    state.critic_verdict = critic_verdict
                    state.stages_completed.append(PipelineStage.CRITIC)
                    await self._emit_progress(PipelineStage.CRITIC, advisory_id, "completed")
                
                # Stage 6: Gate (Approval)
                if state.plan and hasattr(state.plan, 'steps'):
                    high_impact_steps = [s for s in state.plan.steps if s.impact_class in (ImpactClass.MEDIUM, ImpactClass.HIGH)]
                    if high_impact_steps:
                        await self._emit_progress(PipelineStage.GATE, advisory_id, "started")
                        # Request approval
                        await self._request_approval(state, trace)
                        state.stages_completed.append(PipelineStage.GATE)
                        await self._emit_progress(PipelineStage.GATE, advisory_id, "completed")
                
                # Stage 7: Executor
                if state.plan and state.approval_request_id:
                    await self._emit_progress(PipelineStage.EXECUTOR, advisory_id, "started")
                    executor_agent = self.agents.get("executor")
                    if executor_agent:
                        execution_record = await self._run_agent(executor_agent, {
                            "plan": state.plan,
                            "approval_request_id": state.approval_request_id
                        }, trace)
                        state.execution_record = execution_record
                        state.stages_completed.append(PipelineStage.EXECUTOR)
                        await self._emit_progress(PipelineStage.EXECUTOR, advisory_id, "completed")
                
                state.status = "completed"
                return {
                    "status": "completed",
                    "advisory_id": advisory_id,
                    "finding": state.finding,
                    "plan": state.plan,
                    "execution": state.execution_record
                }
                
            except Exception as e:
                logger.error(f"Pipeline failed for {advisory_id}: {e}")
                state.status = "failed"
                state.error = str(e)
                await self._emit_progress(PipelineStage.EXECUTOR, advisory_id, "failed", {"error": str(e)})
                raise
            finally:
                await self.trace_manager.complete_trace(trace.trace_id, state.status)
    
    async def _run_agent(self, agent: BaseAgent, input_data: Any, trace: AgentTrace) -> Any:
        """Run an agent with trace context."""
        # This is a simplified version - real implementation would use the agent's process method
        return await agent.process(input_data)
    
    async def _request_approval(self, state: PipelineState, trace: AgentTrace):
        """Request approval for plan."""
        # Implementation would call ApprovalGate contract
        pass
    
    def get_pipeline_state(self, advisory_id: str) -> Optional[PipelineState]:
        return self._pipelines.get(advisory_id)
    
    def list_pipelines(self) -> List[PipelineState]:
        return list(self._pipelines.values())


# ============================================================================
# OrgNodeRuntime - Isolated per-org runtime
# ============================================================================

class OrgNodeRuntime:
    """Runtime for a single organization's agent node."""
    
    def __init__(self, org: str, private_key: str):
        self.org = org
        self.private_key = private_key
        
        # Initialize chain client with org's keys
        self.chain_client = get_chain_client()
        self.chain_client.set_account(private_key)
        self.chain_writer = ChainWriter(self.chain_client)
        
        # Trace manager
        self.trace_manager = get_trace_manager(org)
        
        # Agent registry
        self.agents: Dict[str, BaseAgent] = {}
        
        # Orchestrator
        self.orchestrator = Orchestrator(org, {})
        
        # Event indexer
        self.event_indexer = EventIndexer(self.chain_client)
        
        # Anchor service
        self.anchor_service = get_anchor_service()
        
        # Isolation enforcement
        self._allowed_paths = [
            f"data/orgs/{org}/",
            "data/advisories/",
            "backend/traces/",
            "backend/risk/artifacts/"
        ]
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with this runtime."""
        self.agents[agent.config.agent_id] = agent
        self.orchestrator.agents[agent.config.agent_id] = agent
    
    def _check_path_access(self, path: str) -> bool:
        """Enforce org data isolation."""
        for allowed in self._allowed_paths:
            if path.startswith(allowed):
                return True
        return False
    
    async def process_advisory(self, advisory_id: str, advisory_text: str) -> Dict[str, Any]:
        """Process advisory through full pipeline."""
        return await self.orchestrator.process_advisory(advisory_id, advisory_text)
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        return self.agents.get(agent_id)
    
    async def start(self):
        """Start the org node."""
        self.event_indexer.start()
        self.orchestrator.add_progress_handler(self._handle_progress)
    
    async def stop(self):
        """Stop the org node."""
        self.event_indexer.stop()
        await self.orchestrator.chain_writer.flush()
        await self.anchor_service.flush_all()
    
    async def _handle_progress(self, event: Dict[str, Any]):
        """Handle progress events."""
        # Could emit to SSE, log, etc.
        pass


# ============================================================================
# Utility
# ============================================================================

import re
from datetime import datetime