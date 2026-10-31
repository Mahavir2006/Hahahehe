"""
LLM Client abstraction with offline deterministic provider.
"""

import asyncio
import hashlib
import json
import re
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Type, TypeVar
from dataclasses import dataclass
from pydantic import BaseModel, ValidationError
import logging

from backend.common.config import settings

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=BaseModel)


@dataclass
class LLMCallRecord:
    """Record of an LLM call for tracing."""
    prompt_hash: str
    response_hash: str
    provider: str
    model: str
    latency_ms: int
    timestamp: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    fallback: bool = False
    validation_errors: List[str] = None


class LLMClient(ABC):
    """Abstract LLM client interface."""
    
    @abstractmethod
    async def complete(
        self,
        messages: List[Dict[str, str]],
        schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None
    ) -> Any:
        """Complete a chat conversation, optionally validating against schema."""
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Return provider identifier."""
        pass
    
    def _validate_against_schema(self, response: str, schema: Type[BaseModel]) -> Any:
        """Validate response against Pydantic schema."""
        try:
            data = json.loads(response)
            return schema(**data)
        except (json.JSONDecodeError, ValidationError) as e:
            raise ValueError(f"Schema validation failed: {e}")


class OfflineDeterministicProvider(LLMClient):
    """
    Deterministic offline LLM provider for testing and air-gapped environments.
    Implements all LLM uses via rules/heuristics/templates.
    """
    
    def __init__(self):
        self.call_count = 0
        self.call_records: List[LLMCallRecord] = []
    
    def get_provider_name(self) -> str:
        return "offline"
    
    async def complete(
        self,
        messages: List[Dict[str, str]],
        schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None
    ) -> Any:
        """Generate deterministic response based on message content."""
        self.call_count += 1
        start_time = time.time()
        
        # Extract the last user message for processing
        user_content = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_content = msg.get("content", "")
                break
        
        # Determine response type based on schema or content
        if schema:
            response = await self._generate_structured(user_content, schema)
        else:
            response = await self._generate_text(user_content)
        
        # Record call
        prompt_hash = hashlib.sha256(user_content.encode()).hexdigest()[:16]
        response_str = json.dumps(response.model_dump() if isinstance(response, BaseModel) else str(response))
        response_hash = hashlib.sha256(response_str.encode()).hexdigest()[:16]
        latency_ms = int((time.time() - start_time) * 1000)
        
        self.call_records.append(LLMCallRecord(
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            provider="offline",
            model="deterministic-v1",
            latency_ms=latency_ms,
            timestamp=time.time(),
            fallback=False
        ))
        
        return response
    
    async def _generate_structured(self, content: str, schema: Type[BaseModel]) -> BaseModel:
        """Generate structured output matching schema."""
        schema_name = schema.__name__
        
        if schema_name == "AdvisoryFinding":
            return self._parse_advisory(content)
        elif schema_name == "RiskAssessment":
            return self._generate_risk_narrative(content)
        elif schema_name == "RemediationPlan":
            return self._generate_plan(content)
        elif schema_name == "CriticVerdict":
            return self._generate_critic_verdict(content)
        elif schema_name == "CascadeReport":
            return self._generate_cascade_report(content)
        else:
            # Generic: return empty schema instance
            return schema()
    
    async def _generate_text(self, content: str) -> str:
        """Generate plain text response."""
        return "Deterministic response for: " + content[:100]
    
    def _parse_advisory(self, content: str) -> 'AdvisoryFinding':
        """Parse advisory text into structured finding using heuristics."""
        from backend.common.schemas import AdvisoryFinding
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_ids = list(set(re.findall(cve_pattern, content, re.IGNORECASE)))
        
        # Extract vendor/product using heuristics
        vendor = "Unknown"
        products = []
        version_ranges = []
        
        # Common vendor patterns
        vendor_patterns = {
            r'\bSiemens\b': ("Siemens", ["SICAM PAS", "S7-1500", "S7-1200"]),
            r'\bABB\b': ("ABB", ["RTU560", "RTU570"]),
            r'\bSchneider Electric\b': ("Schneider Electric", ["EcoStruxure", "SCADAPack"]),
            r'\bRockwell Automation\b': ("Rockwell Automation", ["PowerFlex", "ControlLogix"]),
            r'\bEmerson\b': ("Emerson", ["Rosemount", "DeltaV"]),
            r'\bHoneywell\b': ("Honeywell", ["Experion", "Niagara"]),
            r'\bCisco\b': ("Cisco", ["Catalyst", "Firepower"]),
            r'\bPalo Alto Networks\b': ("Palo Alto Networks", ["PA-5220", "PA-3220"]),
            r'\bPhilips Healthcare\b': ("Philips Healthcare", ["IntelliVue"]),
            r'\bGE Healthcare\b': ("GE Healthcare", ["Centricity"]),
            r'\bBaxter\b': ("Baxter", ["Sigma Spectrum"]),
        }
        
        for pattern, (v, prods) in vendor_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                vendor = v
                products = prods
                break
        
        # Extract version ranges
        version_patterns = [
            r'version[s]?\s+(?:before|prior to|through|below)\s+([\d\.\-_a-zA-Z]+)',
            r'versions?\s+([\d\.\-_a-zA-Z]+\s+(?:through|to|and)\s+[\d\.\-_a-zA-Z]+)',
            r'all versions?',
            r'(\d+\.\d+\.\d+(?:-[\w\d]+)?)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            version_ranges.extend(matches if isinstance(matches[0], str) else [m[0] for m in matches])
        
        version_ranges = list(set(version_ranges))[:5] or ["unknown"]
        
        # Extract CVSS
        cvss_match = re.search(r'CVSS\s*(?:v3\.1\s*)?(?:Base\s*Score\s*)?[:=]\s*([\d\.]+)', content, re.IGNORECASE)
        cvss_base = float(cvss_match.group(1)) if cvss_match else 5.0
        
        # Exploited in wild
        exploited = bool(re.search(r'(exploited|active exploitation|in the wild)', content, re.IGNORECASE))
        
        # EPSS
        epss_match = re.search(r'EPSS\s*[:=]\s*([\d\.]+)', content, re.IGNORECASE)
        epss = float(epss_match.group(1)) if epss_match else 0.1
        
        # Check for injection
        injection_patterns = [
            r'ignore previous instructions',
            r'system:.*approve',
            r'call approve',
            r'maintenance mode',
            r'base64.*payload',
        ]
        injection_suspected = any(re.search(p, content, re.IGNORECASE) for p in injection_patterns)
        
        # Extract title
        title_match = re.search(r'(?:Title|Subject):\s*(.+)', content)
        title = title_match.group(1).strip() if title_match else "Security Advisory"
        
        # Summary - first few sentences
        sentences = re.split(r'[.!?]+', content)
        summary = ' '.join(sentences[:3]).strip() + '.'
        
        return AdvisoryFinding(
            advisory_id=f"ADV-OFFLINE-{hash(content) % 10000:04d}",
            source="offline-parser",
            cve_ids=cve_ids,
            title=title,
            vendor=vendor,
            products=products,
            affected_version_ranges=version_ranges,
            cvss_base=cvss_base,
            exploited_in_wild=exploited,
            epss_like=epss,
            summary=summary,
            mitigations_text="Apply vendor patches. Implement network segmentation.",
            extraction_confidence=0.85 if not injection_suspected else 0.3,
            llm_fallback=True,
            injection_suspected=injection_suspected
        )
    
    def _generate_risk_narrative(self, content: str) -> 'RiskAssessment':
        from backend.common.schemas import RiskAssessment, SHAPFactor
        return RiskAssessment(
            asset_id=content.split(':')[0] if ':' in content else "unknown-asset",
            risk=50.0,
            band=RiskBand.MEDIUM,
            likelihood=0.5,
            impact=0.5,
            top_factors=[
                SHAPFactor(factor="Internet-exposed", value=1.0, contribution=18.0),
                SHAPFactor(factor="Default credentials", value=1.0, contribution=12.0),
            ],
            model_version="offline-v1",
            narrative="This asset has moderate risk due to internet exposure and default credentials."
        )
    
    def _generate_plan(self, content: str) -> 'RemediationPlan':
        from backend.common.schemas import RemediationPlan, PlanStep, ImpactClass
        return RemediationPlan(
            plan_id=f"PLAN-OFFLINE-{int(time.time())}",
            org="power",
            trigger_finding_ids=["ADV-001"],
            steps=[
                PlanStep(
                    step_id="1",
                    action="PATCH",
                    target_assets=["power-asset-001"],
                    preconditions_met=True,
                    scheduled_window="0 2 * * 0",
                    impact_class=ImpactClass.MEDIUM,
                    est_downtime_min=60,
                    est_effort_h=4.0,
                    expected_risk_delta=-25.0,
                    rationale="Patch removes vulnerability"
                )
            ],
            risk_before=75.0,
            risk_after=50.0,
            total_delta=-25.0,
            cross_org_risk_before=60.0,
            cross_org_risk_after=45.0,
            constraints_checked=["maintenance_window", "vendor_signoff"],
            created_at=datetime.now(),
            plan_hash="offline-plan-hash"
        )
    
    def _generate_critic_verdict(self, content: str) -> 'CriticVerdict':
        from backend.common.schemas import CriticVerdict
        return CriticVerdict(
            verdict="APPROVE_FOR_GATE",
            reasons=["All constraints satisfied", "Risk delta matches what-if"],
            revision_count=0,
            trace_id=content.split(':')[0] if ':' in content else "unknown"
        )
    
    def _generate_cascade_report(self, content: str) -> 'CascadeReport':
        from backend.common.schemas import CascadeReport, CascadeNode, CascadeEdge, DependencyStrength, CriticalityBucket
        return CascadeReport(
            impact_chain=[
                CascadeNode(
                    org="power",
                    service="Substation-7 Power Delivery",
                    p_degraded=0.8,
                    time_to_impact_minutes=15,
                    criticality_bucket=CriticalityBucket.HIGH
                ),
                CascadeNode(
                    org="water",
                    service="Treatment Plant Pumping",
                    p_degraded=0.6,
                    time_to_impact_minutes=30,
                    criticality_bucket=CriticalityBucket.HIGH
                ),
                CascadeNode(
                    org="hospital",
                    service="Building Environmental Control",
                    p_degraded=0.4,
                    time_to_impact_minutes=60,
                    criticality_bucket=CriticalityBucket.MEDIUM
                ),
            ],
            graph={},
            unconfirmed_edges=[]
        )


class AnthropicProvider(LLMClient):
    """Anthropic API provider (for production use)."""
    
    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307"):
        self.api_key = api_key
        self.model = model
        # In production, would import anthropic SDK
        # import anthropic
        # self.client = anthropic.Anthropic(api_key=api_key)
    
    def get_provider_name(self) -> str:
        return "anthropic"
    
    async def complete(
        self,
        messages: List[Dict[str, str]],
        schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None
    ) -> Any:
        """Call Anthropic API."""
        # Placeholder - would use actual Anthropic SDK in production
        # For now, fallback to offline provider
        offline = OfflineDeterministicProvider()
        return await offline.complete(messages, schema, temperature, max_tokens)


class LLMClientFactory:
    """Factory for creating LLM clients."""
    
    @staticmethod
    def create() -> LLMClient:
        """Create LLM client based on configuration."""
        if settings.llm_provider == "offline" or not settings.anthropic_api_key:
            return OfflineDeterministicProvider()
        elif settings.llm_provider == "anthropic":
            return AnthropicProvider(settings.anthropic_api_key, settings.llm_model)
        else:
            raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")


# Global client instance
_llm_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    """Get or create global LLM client."""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClientFactory.create()
    return _llm_client