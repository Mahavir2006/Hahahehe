"""
Cascade Agent - Computes cascade risk propagation.
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
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class CascadeAgentInput:
    risk_assessments: List[RiskAssessment]
    org: str


class CascadeAgent(BaseAgent[CascadeAgentInput]):
    """Computes cascade risk propagation within and across organizations."""
    
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
            name="intra_org_cascade",
            description="Compute intra-organization cascade propagation",
            input_model=IntraOrgCascadeInput,
            output_model=IntraOrgCascadeOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def intra_org_cascade(input_data: IntraOrgCascadeInput) -> IntraOrgCascadeOutput:
            return await self._intra_org_cascade(input_data)
        
        @tool(
            name="cross_org_cascade",
            description="Compute cross-organization cascade using on-chain attestations",
            input_model=CrossOrgCascadeInput,
            output_model=CrossOrgCascadeOutput,
            side_effect=SideEffect.READ_CHAIN,
            required_role="agent"
        )
        async def cross_org_cascade(input_data: CrossOrgCascadeInput) -> CrossOrgCascadeOutput:
            return await self._cross_org_cascade(input_data)
        
        @tool(
            name="publish_alert",
            description="Publish cascade alert to AlertBus",
            input_model=PublishAlertInput,
            output_model=PublishAlertOutput,
            side_effect=SideEffect.WRITE_CHAIN,
            required_role="agent"
        )
        async def publish_alert(input_data: PublishAlertInput) -> PublishAlertOutput:
            return await self._publish_alert(input_data)
        
        @tool(
            name="acknowledge_alert",
            description="Acknowledge received cascade alert",
            input_model=AcknowledgeAlertInput,
            output_model=AcknowledgeAlertOutput,
            side_effect=SideEffect.WRITE_CHAIN,
            required_role="agent"
        )
        async def acknowledge_alert(input_data: AcknowledgeAlertInput) -> AcknowledgeAlertOutput:
            return await self._acknowledge_alert(input_data)
    
    async def process(self, input_data: CascadeAgentInput) -> CascadeReport:
        """Process risk assessments and compute cascade."""
        trace = await self.trace_manager.start_trace(f"cascade-{input_data.org}-{int(time.time())}")
        self._current_trace = trace
        
        # Intra-org cascade
        intra_result = await self._intra_org_cascade(IntraOrgCascadeInput(
            risk_assessments=input_data.risk_assessments,
            org=self.config.org
        ))
        
        # Cross-org cascade (using on-chain attestations)
        cross_result = await self._cross_org_cascade(CrossOrgCascadeInput(
            intra_result=intra_result,
            org=self.config.org
        ))
        
        # Publish alerts if threshold exceeded
        for node in cross_result.impact_chain:
            if node.p_degraded >= settings.cascade_alert_threshold:
                await self._publish_alert(PublishAlertInput(
                    provider_org=node.org,
                    provider_service_hash=hashlib.sha256(node.service.encode()).hexdigest()[:32],
                    severity=self._p_to_severity(node.p_degraded),
                    tti_bucket=self._tti_to_bucket(node.time_to_impact_minutes),
                    evidence_commitment=hashlib.sha256(str(node).encode()).hexdigest(),
                    expiry=int(time.time()) + 3600
                ))
        
        # Combine results
        report = CascadeReport(
            impact_chain=cross_result.impact_chain,
            graph=cross_result.graph,
            unconfirmed_edges=cross_result.unconfirmed_edges
        )
        
        await self.trace_manager.complete_trace(self._current_trace.trace_id, "completed")
        return report
    
    async def _intra_org_cascade(self, input_data: IntraOrgCascadeInput) -> IntraOrgCascadeOutput:
        """Compute intra-organization cascade propagation."""
        # Load org dependency graph
        import json
        from pathlib import Path
        
        graph_path = Path(settings.data_dir) / "orgs" / self.config.org / "graph.json"
        if not graph_path.exists():
            return IntraOrgCascadeOutput(
                affected_services={},
                affected_assets=[],
                graph={}
            )
        
        with open(graph_path) as f:
            graph_data = json.load(f)
        
        # Build NetworkX graph
        G = nx.DiGraph()
        for asset, deps in graph_data.items():
            G.add_node(asset)
            for dep in deps:
                G.add_edge(dep, asset)  # dep -> asset (asset depends on dep)
        
        # Find high/critical risk assets
        high_risk_assets = []
        for assessment in input_data.risk_assessments:
            if assessment.band in [RiskBand.HIGH, RiskBand.CRITICAL]:
                high_risk_assets.append(assessment.asset_id)
        
        # Propagate through graph
        affected_assets = set(high_risk_assets)
        affected_services = {}
        
        for asset in high_risk_assets:
            # Find all downstream nodes
            try:
                descendants = nx.descendants(G, asset)
                affected_assets.update(descendants)
            except nx.NetworkXError:
                pass
        
        # Load services
        services_path = Path(settings.data_dir) / "orgs" / self.config.org / "services.json"
        if services_path.exists():
            with open(services_path) as f:
                services = json.load(f)
            
            for service in services:
                required = set(service["required_assets"])
                affected = required & affected_assets
                if affected:
                    p_degraded = len(affected) / len(required)
                    affected_services[service["service_id"]] = p_degraded
        
        return IntraOrgCascadeOutput(
            affected_services=affected_services,
            affected_assets=list(affected_assets),
            graph=graph_data
        )
    
    async def _cross_org_cascade(self, input_data: CrossOrgCascadeInput) -> CrossOrgCascadeOutput:
        """Compute cross-organization cascade using on-chain attestations."""
        # Get confirmed dependency edges from AttestationRegistry
        # For now, use static data from cross_org_dependencies.json
        import json
        from pathlib import Path
        
        cross_path = Path(settings.data_dir) / "cross_org_dependencies.json"
        if not cross_path.exists():
            return CrossOrgCascadeOutput(
                impact_chain=[],
                graph={},
                unconfirmed_edges=[]
            )
        
        with open(cross_path) as f:
            cross_deps = json.load(f)
        
        # Get risk attestations from chain (simplified - use static for now)
        # In production, would query AttestationRegistry contract
        
        # Build cascade chain
        impact_chain = []
        unconfirmed_edges = []
        
        # Start with this org's affected services
        for service_id, p_degraded in input_data.intra_result.affected_services.items():
            if p_degraded >= 0.3:  # Only propagate significant risks
                # Find cross-org dependencies
                for dep in cross_deps:
                    if dep["provider_service"] == service_id:
                        # Check if edge is confirmed (both sides attested)
                        # For demo, assume confirmed
                        consumer_org = dep["consumer_org"]
                        consumer_service = dep["consumer_service"]
                        p_consumer = p_degraded * (1.0 if dep["dependency_strength"] == "high" else 0.7)
                        
                        impact_chain.append(CascadeNode(
                            org=consumer_org,
                            service=consumer_service,
                            p_degraded=min(p_consumer, 1.0),
                            time_to_impact_minutes=dep["tolerance_minutes"],
                            criticality_bucket=CriticalityBucket.HIGH
                        ))
        
        # Sort by time to impact
        impact_chain.sort(key=lambda n: n.time_to_impact_minutes)
        
        return CrossOrgCascadeOutput(
            impact_chain=impact_chain,
            graph={"nodes": [], "edges": []},
            unconfirmed_edges=[]
        )
    
    async def _publish_alert(self, input_data: PublishAlertInput) -> PublishAlertOutput:
        """Publish cascade alert to AlertBus."""
        idempotency_key = IdempotencyKeyGenerator.alert_publish(
            input_data.provider_org,
            input_data.provider_service_hash,
            input_data.severity
        )
        
        async def do_publish():
            return self.chain_client.publish_alert(
                self.chain_client.to_bytes32(input_data.provider_org),
                self.chain_client.to_bytes32(input_data.provider_service_hash),
                input_data.severity,
                input_data.tti_bucket,
                self.chain_client.to_bytes32(input_data.evidence_commitment),
                input_data.expiry,
                bytes.fromhex("00" * 65)  # Placeholder
            )
        
        tx_hash = await self.chain_writer.write(idempotency_key, do_publish)
        
        return PublishAlertOutput(
            alert_id=hashlib.sha256(f"{input_data.provider_org}:{input_data.provider_service_hash}".encode()).hexdigest()[:32],
            tx_hash=tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
        )
    
    async def _acknowledge_alert(self, input_data: AcknowledgeAlertInput) -> AcknowledgeAlertOutput:
        """Acknowledge received cascade alert."""
        idempotency_key = f"ack:{input_data.alert_id}:{self.config.org}"
        
        async def do_ack():
            return self.chain_client.acknowledge_alert(
                self.chain_client.to_bytes32(input_data.alert_id),
                bytes.fromhex("00" * 65)  # Placeholder
            )
        
        tx_hash = await self.chain_writer.write(idempotency_key, do_ack)
        
        return AcknowledgeAlertOutput(
            tx_hash=tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
        )
    
    def _p_to_severity(self, p: float) -> int:
        if p >= 0.8: return 3  # Critical
        elif p >= 0.6: return 2  # High
        elif p >= 0.4: return 1  # Medium
        else: return 0  # Low
    
    def _tti_to_bucket(self, tti: int) -> int:
        if tti <= 15: return 0  # Under15m
        elif tti <= 60: return 1  # Min15To60
        elif tti <= 240: return 2  # Hours1To4
        else: return 3  # Over4h


# ============================================================================
# Tool Input/Output Schemas
# ============================================================================

class IntraOrgCascadeInput(BaseModel):
    risk_assessments: List[RiskAssessment]
    org: str


class IntraOrgCascadeOutput(BaseModel):
    affected_services: Dict[str, float]  # service_id -> p_degraded
    affected_assets: List[str]
    graph: Dict[str, List[str]]


class CrossOrgCascadeInput(BaseModel):
    intra_result: IntraOrgCascadeOutput
    org: str


class CrossOrgCascadeOutput(BaseModel):
    impact_chain: List[CascadeNode]
    graph: Dict[str, Any]
    unconfirmed_edges: List[CascadeEdge]


class PublishAlertInput(BaseModel):
    provider_org: str
    provider_service_hash: str
    severity: int
    tti_bucket: int
    evidence_commitment: str
    expiry: int


class PublishAlertOutput(BaseModel):
    alert_id: str
    tx_hash: str


class AcknowledgeAlertInput(BaseModel):
    alert_id: str


class AcknowledgeAlertOutput(BaseModel):
    tx_hash: str