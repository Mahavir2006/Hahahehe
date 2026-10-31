"""
Risk Agent - Scores assets and produces risk assessments.
"""

import asyncio
import hashlib
import joblib
import numpy as np
import pandas as pd
import shap
from pathlib import Path
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
import re
import time

logger = logging.getLogger(__name__)


@dataclass
class RiskAgentInput:
    findings: List[AdvisoryFinding]
    org: str


class RiskAgent(BaseAgent[RiskAgentInput]):
    """Scores assets and produces risk assessments."""
    
    def __init__(
        self,
        config: AgentConfig,
        trace_manager: Optional[TraceManager] = None
    ):
        super().__init__(config, trace_manager=trace_manager)
        self.chain_client = get_chain_client()
        self.chain_writer = ChainWriter(self.chain_client)
        self.anchor_service = get_anchor_service()
        
        # Load risk model
        self._model = None
        self._model_version = "unknown"
        self._load_model()
    
    def _load_model(self):
        """Load trained risk model."""
        model_path = Path(settings.data_dir).parent / "backend" / "risk" / "artifacts" / "model.joblib"
        if model_path.exists():
            self._model = joblib.load(model_path)
            self._model_version = hashlib.sha256(joblib.dumps(self._model)).hexdigest()[:16]
            logger.info(f"Loaded risk model version {self._model_version}")
        else:
            logger.warning("No trained model found, using heuristic scoring")
    
    def _register_tools(self):
        reg = self.tool_registry
        
        @tool(
            name="score_asset",
            description="Score a single asset's risk",
            input_model=ScoreAssetInput,
            output_model=RiskAssessment,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def score_asset(input_data: ScoreAssetInput) -> RiskAssessment:
            return await self._score_asset(input_data)
        
        @tool(
            name="what_if",
            description="Compute risk reduction for remediation actions",
            input_model=WhatIfInput,
            output_model=WhatIfOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def what_if(input_data: WhatIfInput) -> WhatIfOutput:
            return await self._what_if(input_data)
        
        @tool(
            name="generate_narrative",
            description="Generate human-readable risk narrative",
            input_model=GenerateNarrativeInput,
            output_model=GenerateNarrativeOutput,
            side_effect=SideEffect.NONE,
            required_role="agent"
        )
        async def generate_narrative(input_data: GenerateNarrativeInput) -> GenerateNarrativeOutput:
            return await self._generate_narrative(input_data)
        
        @tool(
            name="attest_risk",
            description="Submit risk attestation to blockchain",
            input_model=AttestRiskInput,
            output_model=AttestRiskOutput,
            side_effect=SideEffect.WRITE_CHAIN,
            required_role="agent"
        )
        async def attest_risk(input_data: AttestRiskInput) -> AttestRiskOutput:
            return await self._attest_risk(input_data)
    
    async def process(self, input_data: RiskAgentInput) -> List[RiskAssessment]:
        """Process findings and produce risk assessments."""
        trace = await self.trace_manager.start_trace(f"risk-{input_data.org}-{int(time.time())}")
        self._current_trace = trace
        
        assessments = []
        
        for finding in input_data.findings:
            for asset_id in finding.matched_assets:
                asset = self._load_asset(asset_id)
                if asset:
                    assessment = await self._score_asset(ScoreAssetInput(
                        asset=asset,
                        finding=finding
                    ))
                    
                    # Generate narrative
                    narrative_result = await self._generate_narrative(GenerateNarrativeInput(
                        assessment=assessment
                    ))
                    assessment.narrative = narrative_result.narrative
                    
                    assessments.append(assessment)
                    
                    # Attest risk on-chain
                    await self._attest_risk(AttestRiskInput(
                        org=input_data.org,
                        service_hash=hashlib.sha256(asset["service_supported"].encode()).hexdigest()[:32],
                        risk_band=self._band_to_int(assessment.band),
                        criticality_bucket=self._criticality_to_int(asset.get("criticality_bucket", "medium")),
                        model_version_hash=self._model_version,
                        evidence_commitment=hashlib.sha256(str(assessment).encode()).hexdigest(),
                        valid_until=int(time.time()) + 3600
                    ))
        
        await self.trace_manager.complete_trace(self._current_trace.trace_id, "completed")
        return assessments
    
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
    
    async def _score_asset(self, input_data: ScoreAssetInput) -> RiskAssessment:
        """Score a single asset's risk."""
        asset = input_data.asset
        finding = input_data.finding
        
        if self._model:
            # Use ML model
            features = self._extract_features(asset, finding)
            likelihood = float(self._model.predict_proba([features])[0][1])
        else:
            # Heuristic scoring
            likelihood = self._heuristic_likelihood(asset, finding)
        
        # Impact calculation
        impact = self._calculate_impact(asset)
        
        # Risk score
        risk = 100 * likelihood * impact
        
        # Band
        band = self._score_to_band(risk)
        
        # SHAP factors
        top_factors = self._get_shap_factors(asset, finding, likelihood)
        
        return RiskAssessment(
            asset_id=asset["asset_id"],
            risk=risk,
            band=band,
            likelihood=likelihood,
            impact=impact,
            top_factors=top_factors,
            model_version=self._model_version,
            narrative=""  # Will be filled by generate_narrative
        )
    
    def _extract_features(self, asset: Dict, finding: AdvisoryFinding) -> np.ndarray:
        """Extract features for ML model."""
        features = [
            1.0 if asset.get("internet_exposed") else 0.0,
            finding.cvss_base or 0.0,
            finding.epss_like or 0.0,
            1.0 if asset.get("default_credentials") else 0.0,
            {"IT": 0, "DMZ": 1, "OT": 2, "SAFETY": 3}.get(asset.get("zone", "IT"), 0),
            (time.time() - pd.Timestamp(asset.get("last_patched", "2020-01-01")).timestamp()) / (365 * 24 * 3600),
            asset.get("criticality", 1),
            len(asset.get("depends_on", [])),
            1.0 if asset.get("safety_critical") else 0.0,
            1.0 if asset.get("supply_chain_flag") else 0.0,
        ]
        return np.array(features).reshape(1, -1)
    
    def _heuristic_likelihood(self, asset: Dict, finding: AdvisoryFinding) -> float:
        """Heuristic likelihood calculation."""
        base = 0.01
        
        if asset.get("internet_exposed"):
            base += 0.15
        if finding.cvss_base:
            base += (finding.cvss_base / 10) * 0.2
        if finding.epss_like:
            base += finding.epss_like * 0.2
        if asset.get("default_credentials"):
            base += 0.1
        if asset.get("zone") in ["OT", "SAFETY"]:
            base += 0.05
        
        days_since_patch = (time.time() - pd.Timestamp(asset.get("last_patched", "2020-01-01")).timestamp()) / (24 * 3600)
        base += min(days_since_patch / 3650, 0.1)
        
        base += asset.get("criticality", 1) * 0.02
        base += len(asset.get("depends_on", [])) * 0.01
        
        if asset.get("safety_critical"):
            base += 0.1
        if asset.get("supply_chain_flag"):
            base += 0.15
        
        return min(base, 0.95)
    
    def _calculate_impact(self, asset: Dict) -> float:
        """Calculate asset impact."""
        impact = 0.0
        impact += asset.get("criticality", 1) * 0.15
        if asset.get("safety_critical"):
            impact += 0.3
        impact += min(len(asset.get("depends_on", [])) * 0.05, 0.2)
        
        # Service criticality
        service_criticality = asset.get("service_criticality", "medium")
        impact += {"low": 0.05, "medium": 0.1, "high": 0.2, "life_critical": 0.3}.get(service_criticality, 0.1)
        
        return min(impact, 1.0)
    
    def _score_to_band(self, risk: float) -> RiskBand:
        if risk < settings.risk_band_low_max:
            return RiskBand.LOW
        elif risk < settings.risk_band_medium_max:
            return RiskBand.MEDIUM
        elif risk < settings.risk_band_high_max:
            return RiskBand.HIGH
        else:
            return RiskBand.CRITICAL
    
    def _band_to_int(self, band: RiskBand) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[band.value]
    
    def _criticality_to_int(self, bucket: str) -> int:
        return {"low": 0, "medium": 1, "high": 2, "life_critical": 3}[bucket]
    
    def _get_shap_factors(self, asset: Dict, finding: AdvisoryFinding, likelihood: float) -> List[SHAPFactor]:
        """Get SHAP-like factors for explanation."""
        factors = []
        
        if asset.get("internet_exposed"):
            factors.append(SHAPFactor(factor="Internet-exposed", value=1.0, contribution=18.0))
        if finding.cvss_base:
            factors.append(SHAPFactor(factor=f"CVSS {finding.cvss_base}", value=finding.cvss_base, contribution=finding.cvss_base * 1.5))
        if asset.get("default_credentials"):
            factors.append(SHAPFactor(factor="Default credentials", value=1.0, contribution=12.0))
        if asset.get("safety_critical"):
            factors.append(SHAPFactor(factor="Safety-critical asset", value=1.0, contribution=15.0))
        
        # Sort by contribution
        factors.sort(key=lambda f: f.contribution, reverse=True)
        return factors[:5]
    
    async def _what_if(self, input_data: WhatIfInput) -> WhatIfOutput:
        """Compute risk reduction for remediation actions."""
        # Implementation would recompute scores with actions applied
        return WhatIfOutput(
            risk_before=input_data.risk_before,
            risk_after=input_data.risk_after,
            delta=input_data.risk_before - input_data.risk_after,
            per_asset_delta=[]
        )
    
    async def _generate_narrative(self, input_data: GenerateNarrativeInput) -> GenerateNarrativeOutput:
        """Generate human-readable risk narrative."""
        assessment = input_data.assessment
        
        # Use template-based narrative (offline mode)
        factors_text = ", ".join([f"{f.factor}: +{f.contribution:.1f}" for f in assessment.top_factors])
        
        narrative = (
            f"Asset {assessment.asset_id} has {assessment.band.value} risk ({assessment.risk:.1f}/100). "
            f"Key factors: {factors_text}. "
            f"Likelihood: {assessment.likelihood:.2f}, Impact: {assessment.impact:.2f}. "
            f"Model version: {assessment.model_version}."
        )
        
        return GenerateNarrativeOutput(narrative=narrative)
    
    async def _attest_risk(self, input_data: AttestRiskInput) -> AttestRiskOutput:
        """Submit risk attestation to blockchain."""
        # Create idempotency key
        idempotency_key = IdempotencyKeyGenerator.risk_attestation(
            input_data.org,
            input_data.service_hash,
            input_data.nonce
        )
        
        async def do_attest():
            return self.chain_client.submit_risk_attestation(
                self.chain_client.to_bytes32(input_data.org),
                self.chain_client.to_bytes32(input_data.service_hash),
                input_data.risk_band,
                input_data.criticality_bucket,
                self.chain_client.to_bytes32(input_data.model_version_hash),
                self.chain_client.to_bytes32(input_data.evidence_commitment),
                input_data.valid_until,
                input_data.nonce,
                bytes.fromhex("00" * 65)  # Placeholder signature
            )
        
        tx_hash = await self.chain_writer.write(idempotency_key, do_attest)
        
        return AttestRiskOutput(
            attestation_id=hashlib.sha256(f"{input_data.org}:{input_data.service_hash}".encode()).hexdigest()[:32],
            tx_hash=tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
        )


# ============================================================================
# Tool Input/Output Schemas
# ============================================================================

class ScoreAssetInput(BaseModel):
    asset: Dict[str, Any]
    finding: AdvisoryFinding


class WhatIfInput(BaseModel):
    remediation_actions: List[Dict[str, Any]]
    current_assessments: List[RiskAssessment]
    risk_before: float


class WhatIfOutput(BaseModel):
    risk_before: float
    risk_after: float
    delta: float
    per_asset_delta: List[Dict[str, Any]]


class GenerateNarrativeInput(BaseModel):
    assessment: RiskAssessment


class GenerateNarrativeOutput(BaseModel):
    narrative: str


class AttestRiskInput(BaseModel):
    org: str
    service_hash: str
    risk_band: int
    criticality_bucket: int
    model_version_hash: str
    evidence_commitment: str
    valid_until: int
    nonce: int = 1


class AttestRiskOutput(BaseModel):
    attestation_id: str
    tx_hash: str