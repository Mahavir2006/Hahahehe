"""
Agent framework: typed tools with allow-lists, traces, message bus (AG-TOP-*, AG-TOOL-*, AG-SAF-02).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

from pydantic import BaseModel, Field


class ToolNotAllowed(Exception):
    """AG-TOOL-02: the agent does not own this tool."""


class GateViolation(Exception):
    """AG-ACT-02: an action was attempted without a valid on-chain approval."""


class IsolationError(PermissionError):
    """AG-TOP-05: an org node tried to reach another org's private data."""


class SideEffect(str, Enum):
    none = "none"
    read_chain = "read_chain"
    write_chain = "write_chain"
    write_local = "write_local"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_model: Type[BaseModel]
    output_model: Type[BaseModel]
    side_effect: SideEffect
    required_role: str
    description: str = ""


def agent_tool(name: str, input_model: Type[BaseModel], output_model: Type[BaseModel], side_effect: SideEffect = SideEffect.none, role: str = "agent", description: str = ""):
    def deco(fn: Callable) -> Callable:
        fn._tool_spec = ToolSpec(name, input_model, output_model, side_effect, role, description or (fn.__doc__ or "").strip())
        return fn

    return deco


_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token|private[_-]?key|mnemonic)\b\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


def scrub(obj: Any) -> Any:
    """AG-SAF-02: remove secrets from anything that gets persisted in a trace."""
    if isinstance(obj, str):
        for p in _SECRET_PATTERNS:
            obj = p.sub("[REDACTED]", obj)
        return obj
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub(v) for v in obj]
    return obj


def ihash(x: Any) -> str:
    if isinstance(x, BaseModel):
        x = x.model_dump()
    return hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()[:16]


class Trace:
    """Ordered steps of one pipeline run (observation / tool_call / tool_result / llm_call / decision)."""

    def __init__(self, org: str, label: str, trace_id: Optional[str] = None):
        self.trace_id = trace_id or f"tr-{uuid.uuid4().hex[:12]}"
        self.org, self.label = org, label
        self.started = time.time()
        self.steps: List[Dict[str, Any]] = []
        self.status = "running"
        self.flags: Dict[str, Any] = {}

    def add(self, type_: str, agent: str, **data: Any) -> None:
        self.steps.append({"i": len(self.steps), "ts": round(time.time(), 3), "type": type_, "agent": agent, **scrub(data)})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id, "org": self.org, "label": self.label, "started": round(self.started, 3),
            "status": self.status, "flags": scrub(self.flags), "steps": self.steps,
        }


class Message(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = Field(default_factory=time.time)
    sender: str
    recipient: str
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    trace_id: str = ""
    parent_id: Optional[str] = None


class MessageBus:
    """In-process typed message bus (AG-TOP-03). Cross-org coordination never goes through here, only through the chain."""

    def __init__(self) -> None:
        self.log: List[Message] = []
        self._queues: Dict[str, asyncio.Queue] = {}

    def send(self, m: Message) -> None:
        self.log.append(m)
        self._queues.setdefault(m.recipient, asyncio.Queue()).put_nowait(m)

    async def receive(self, recipient: str, timeout: float = 5.0) -> Message:
        q = self._queues.setdefault(recipient, asyncio.Queue())
        return await asyncio.wait_for(q.get(), timeout)


class BaseAgent:
    NAME = "agent"
    ROLE = "agent"
    TOOLS: Dict[str, ToolSpec] = {}

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        cls.TOOLS = {}
        for attr in dir(cls):
            fn = getattr(cls, attr, None)
            spec = getattr(fn, "_tool_spec", None)
            if spec:
                cls.TOOLS[spec.name] = spec
        cls._tool_fns = {spec.name: attr for attr in dir(cls) if (spec := getattr(getattr(cls, attr, None), "_tool_spec", None))}

    def __init__(self, node: "Any") -> None:
        self.node = node
        self.trace: Optional[Trace] = None

    def bind(self, trace: Optional[Trace]) -> "BaseAgent":
        self.trace = trace
        return self

    def log(self, type_: str, **data: Any) -> None:
        if self.trace:
            self.trace.add(type_, self.NAME, **data)

    def call(self, tool_name: str, **inputs: Any) -> BaseModel:
        """Validated, traced, allow-listed tool call."""
        spec = self.TOOLS.get(tool_name)
        if spec is None:
            self.log("tool_denied", tool=tool_name)
            raise ToolNotAllowed(f"{self.NAME} may not call tool '{tool_name}'")
        if spec.side_effect == SideEffect.write_chain and getattr(self.node.writer, "paused", False):
            from backend.common.chain import ChainPaused

            raise ChainPaused("writes paused")
        model_in = spec.input_model(**inputs)  # AG-TOOL-03: invalid input is rejected before execution
        fn = getattr(self, self._tool_fns[tool_name])
        t0 = time.time()
        out = fn(model_in)
        if not isinstance(out, spec.output_model):
            out = spec.output_model(**(out if isinstance(out, dict) else out.model_dump()))
        self.log("tool_call", tool=tool_name, side_effect=spec.side_effect.value, input_hash=ihash(model_in), output_hash=ihash(out), ms=int((time.time() - t0) * 1000))
        return out
