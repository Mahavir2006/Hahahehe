"""
Pydantic schemas for CascadeShield backend.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum
import hashlib
import json


class Sector(str, Enum):
    ENERGY = "energy"
    WATER = "water"
    HEALTHCARE = "healthcare"
    OTHER = "other"


class Zone(str, Enum):
    IT = "IT"
    DMZ = "DMZ"
    OT = "OT"
    SAFETY = "SAFETY"


class ServiceCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    LIFE_CRITICAL = "life_critical"


class DependencyStrength(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToleranceBucket(str, Enum):
    UNDER_15M = "under_15m"
    MIN_15_TO_60 = "min_15_to_60"
    HOURS_1_TO_4 = "hours_1_to_4"
    OVER_4H = "over_4h"


class RiskBand(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CriticalityBucket(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    LIFE_CRITICAL = "life_critical"


class ImpactClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    EXPIRED = "expired"
    UNRELATED = "unrelated"


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    CANCELLED = "cancelled"


class VerificationResult(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"
    REVOKED = "revoked"


class AgentStage(str, Enum):
    INTAKE = "intake"
    RISK = "risk"
    CASCADE = "cascade"
    PLANNER = "planner"
    CRITIC = "critic"
    GATE = "gate"
    EXECUTOR = "executor"


class TraceStepType(str, Enum):
    OBSERVATION = "observation"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    LLM_CALL = "llm_call"
    DECISION = "decision"


# ============================================================================
# Data Schemas
# ============================================================================

class Asset(BaseModel):
    asset_id: str
    org: str
    name: str
    type: str
    vendor: str
    model: str
    firmware_version: str
    os: str
    zone: Zone
    internet_exposed: bool
    open_ports: List[int]
    default_credentials: bool
    last_patched: str
    criticality: int = Field(ge=1, le=5)
    safety_critical: bool
    maintenance_window: str
    patch_requires_downtime: bool
    vendor_signoff_required: bool
    service_supported: str
    depends_on: List[str]
    sbom_hash: str


class Service(BaseModel):
    service_id: str
    org: str
    name: str
    required_assets: List[str]
    criticality: ServiceCriticality


class CrossOrgDependency(BaseModel):
    consumer_org: str
    consumer_service: str
    provider_org: str
    provider_service: str
    dependency_strength: DependencyStrength
    tolerance_minutes: int


class FirmwareEntry(BaseModel):
    vendor: str
    model: str
    version: str
    firmware_sha256: str
    sbom_hash: str
    release_date: str


# ============================================================================
# Advisory & Finding Schemas
# ============================================================================

class AdvisoryFinding(BaseModel):
    advisory_id: str
    source: str
    cve_ids: List[str]
    title: str
    vendor: str
    products: List[str]
    affected_version_ranges: List[str]
    cvss_base: Optional[float] = None
    exploited_in_wild: Optional[bool] = None
    epss_like: Optional[float] = None
    summary: str
    mitigations_text: str
    extraction_confidence: float = Field(ge=0, le=1)
    llm_fallback: bool = False
    injection_suspected: bool = False
    match_confidence: Optional[float] = None
    match_reason: Optional[str] = None
    matched_assets: List[str] = []


class FindingAttestation(BaseModel):
    org_id: str
    advisory_content_hash: str
    cve_set_hash: str
    processed_at: int
    matched: bool
    attestation_id: Optional[str] = None


# ============================================================================
# Risk Schemas
# ============================================================================

class SHAPFactor(BaseModel):
    factor: str
    value: float
    contribution: float


class RiskAssessment(BaseModel):
    asset_id: str
    risk: float = Field(ge=0, le=100)
    band: RiskBand
    likelihood: float = Field(ge=0, le=1)
    impact: float = Field(ge=0, le=1)
    top_factors: List[SHAPFactor]
    model_version: str
    narrative: str


class OrgRiskAggregate(BaseModel):
    org: str
    risk_before: float
    risk_after: Optional[float] = None
    risk_delta: Optional[float] = None
    service_risks: Dict[str, RiskBand]


class WhatIfResult(BaseModel):
    risk_before: float
    risk_after: float
    delta: float
    per_asset_delta: List[Dict[str, Any]]
    org_risk_before: float
    org_risk_after: float
    cross_org_risk_before: Optional[float] = None
    cross_org_risk_after: Optional[float] = None


# ============================================================================
# Cascade Schemas
# ============================================================================

class CascadeNode(BaseModel):
    org: str
    service: str
    p_degraded: float
    time_to_impact_minutes: int
    criticality_bucket: CriticalityBucket


class CascadeEdge(BaseModel):
    source: str
    target: str
    strength: DependencyStrength
    tolerance_minutes: int


class CascadeReport(BaseModel):
    impact_chain: List[CascadeNode]
    graph: Dict[str, Any]
    unconfirmed_edges: List[CascadeEdge] = []


# ============================================================================
# Agent Trace Schemas
# ============================================================================

class TraceStep(BaseModel):
    step_id: str
    trace_id: str
    timestamp: datetime
    step_type: TraceStepType
    agent: str
    content: Dict[str, Any]
    duration_ms: Optional[int] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[Dict[str, Any]] = None
    llm_prompt_hash: Optional[str] = None
    llm_response_hash: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_latency_ms: Optional[int] = None
    llm_fallback: bool = False


class AgentTrace(BaseModel):
    trace_id: str
    advisory_id: str
    org: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    stages_completed: List[AgentStage]
    current_stage: Optional[AgentStage] = None
    steps: List[TraceStep]
    status: str
    error: Optional[str] = None
    on_chain_anchor_tx: Optional[str] = None
    trace_digest: Optional[str] = None


# ============================================================================
# Plan Schemas
# ============================================================================

class PlanStep(BaseModel):
    step_id: str
    action: str
    target_assets: List[str]
    preconditions_met: bool
    scheduled_window: Optional[str] = None
    impact_class: ImpactClass
    est_downtime_min: int
    est_effort_h: float
    expected_risk_delta: float
    rationale: str


class RemediationPlan(BaseModel):
    plan_id: str
    org: str
    trigger_finding_ids: List[str]
    steps: List[PlanStep]
    risk_before: float
    risk_after: float
    total_delta: float
    cross_org_risk_before: float
    cross_org_risk_after: float
    constraints_checked: List[str]
    created_at: datetime
    alternatives: List[Any] = Field(default_factory=list)
    plan_hash: str


class CriticVerdict(BaseModel):
    verdict: Literal["APPROVE_FOR_GATE", "REVISE", "REJECT"]
    reasons: List[str]
    revision_count: int = 0
    trace_id: str


# ============================================================================
# Approval Schemas
# ============================================================================

class ApprovalRequest(BaseModel):
    request_id: str
    org_id: str
    plan_hash: str
    step_ids: List[int]
    impact_class: ImpactClass
    expiry: int
    critic_verdict_digest: str
    state: ApprovalState
    created_at: int
    snapshot_approvers: List[str]
    snapshot_threshold: int
    snapshot_has_safety_officer: bool
    approvals: List[str] = []
    rejections: List[str] = []


class ApprovalVote(BaseModel):
    request_id: str
    approver: str
    approve: bool
    signature: str


# ============================================================================
# Execution Schemas
# ============================================================================

class ExecutionRecord(BaseModel):
    request_id: str
    plan_hash: str
    step_id: str
    result_hash: str
    executed_at: int
    actual_risk_delta: float
    predicted_risk_delta: float


# ============================================================================
# Audit Schemas
# ============================================================================

class AuditAnchor(BaseModel):
    org_id: str
    kind: str
    digest: str
    prev_digest: str
    meta_hash: str
    index: int
    timestamp: int
    signer: str


class MerkleProof(BaseModel):
    leaf: str
    proof: List[str]
    root: str
    index: int


# ============================================================================
# API Request/Response Schemas
# ============================================================================

class IngestAdvisoryRequest(BaseModel):
    text: str
    source: Optional[str] = None


class IngestAdvisoryResponse(BaseModel):
    advisory_id: str
    finding: AdvisoryFinding
    trace_id: str


class SubmitForApprovalRequest(BaseModel):
    plan_id: str


class ExecutePlanRequest(BaseModel):
    plan_id: str


class ApproveRequest(BaseModel):
    request_id: str
    approver: str
    signature: str


class ChainStatusResponse(BaseModel):
    connected: bool
    block_height: int
    pending_writes: int
    kill_switch_active: bool
    last_digest: Optional[str] = None


# ============================================================================
# Utility Functions
# ============================================================================

def compute_plan_hash(plan: RemediationPlan) -> str:
    """Compute canonical hash of a plan."""
    data = plan.model_dump(exclude={"plan_hash", "alternatives"})
    canon = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def compute_trace_digest(trace: AgentTrace) -> str:
    """Compute canonical hash of a trace."""
    data = trace.model_dump(exclude={"trace_digest", "on_chain_anchor_tx"})
    canon = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()