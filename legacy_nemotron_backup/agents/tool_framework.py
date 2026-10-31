"""
Tool framework for agent tool registry and execution.
"""

import asyncio
import hashlib
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Callable, Awaitable, List, Type, TypeVar
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import logging
from pydantic import BaseModel, ValidationError

from backend.common.schemas import *

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=BaseModel)
U = TypeVar('U', bound=BaseModel)


class SideEffect(str, Enum):
    NONE = "none"
    READ_CHAIN = "read_chain"
    WRITE_CHAIN = "write_chain"
    WRITE_LOCAL = "write_local"


class ToolNotAllowed(Exception):
    """Raised when agent tries to call unauthorized tool."""
    pass


class ToolValidationError(Exception):
    """Raised when tool input/output validation fails."""
    pass


@dataclass
class ToolDefinition:
    """Tool metadata and schema."""
    name: str
    description: str
    input_model: Type[BaseModel]
    output_model: Type[BaseModel]
    side_effect: SideEffect
    required_role: str
    handler: Callable[[BaseModel], Awaitable[BaseModel]]


class ToolRegistry:
    """Registry of allowed tools for an agent."""
    
    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
    
    def register(
        self,
        name: str,
        description: str,
        input_model: Type[BaseModel],
        output_model: Type[BaseModel],
        side_effect: SideEffect,
        required_role: str
    ) -> Callable:
        """Decorator to register a tool."""
        def decorator(func: Callable[[BaseModel], Awaitable[BaseModel]]):
            self._tools[name] = ToolDefinition(
                name=name,
                description=description,
                input_model=input_model,
                output_model=output_model,
                side_effect=side_effect,
                required_role=required_role,
                handler=func
            )
            return func
        return decorator
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)
    
    def list_tools(self) -> List[str]:
        return list(self._tools.keys())
    
    def is_allowed(self, name: str, agent_role: str) -> bool:
        tool = self._tools.get(name)
        if not tool:
            return False
        # Simple role check - in production would be more sophisticated
        return True  # Agent can call any of its registered tools


# ============================================================================
# Base Tool Classes
# ============================================================================

class BaseTool(ABC):
    """Base class for agent tools."""
    
    def __init__(self, registry: ToolRegistry):
        self.registry = registry
    
    @abstractmethod
    async def execute(self, input_data: BaseModel) -> BaseModel:
        pass


class ChainReadTool(BaseTool):
    """Base tool for reading from blockchain."""
    
    def __init__(self, registry: ToolRegistry, client):
        super().__init__(registry)
        self.client = client
    
    @property
    def side_effect(self) -> SideEffect:
        return SideEffect.READ_CHAIN


class ChainWriteTool(BaseTool):
    """Base tool for writing to blockchain."""
    
    def __init__(self, registry: ToolRegistry, writer):
        super().__init__(registry)
        self.writer = writer
    
    @property
    def side_effect(self) -> SideEffect:
        return SideEffect.WRITE_CHAIN


class LocalWriteTool(BaseTool):
    """Base tool for local writes."""
    
    @property
    def side_effect(self) -> SideEffect:
        return SideEffect.WRITE_LOCAL


# ============================================================================
# Tool Decorator
# ============================================================================

def tool(
    name: str,
    description: str,
    input_model: Type[T],
    output_model: Type[U],
    side_effect: SideEffect = SideEffect.NONE,
    required_role: str = "agent"
):
    """Decorator to define a tool with automatic validation and tracing."""
    
    def decorator(func: Callable[[T], Awaitable[U]]) -> Callable[[T], Awaitable[U]]:
        @wraps(func)
        async def wrapper(input_data: T) -> U:
            start_time = time.time()
            input_hash = hashlib.sha256(
                input_data.model_dump_json().encode()
            ).hexdigest()[:16]
            
            # Validate input
            if not isinstance(input_data, input_model):
                try:
                    input_data = input_model(**input_data)
                except ValidationError as e:
                    raise ToolValidationError(f"Input validation failed: {e}")
            
            logger.info(f"Tool call: {name} (input_hash={input_hash[:8]})")
            
            try:
                result = await func(input_data)
                
                # Validate output
                if not isinstance(result, output_model):
                    try:
                        result = output_model(**result)
                    except ValidationError as e:
                        raise ToolValidationError(f"Output validation failed: {e}")
                
                output_hash = hashlib.sha256(
                    result.model_dump_json().encode()
                ).hexdigest()[:16]
                
                duration_ms = int((time.time() - start_time) * 1000)
                logger.info(f"Tool completed: {name} (duration={duration_ms}ms, output_hash={output_hash[:8]})")
                
                return result
                
            except Exception as e:
                logger.error(f"Tool {name} failed: {e}")
                raise
        
        return wrapper
    return decorator


# ============================================================================
# Agent Message Bus
# ============================================================================

class AgentMessage(BaseModel):
    """Message between agents."""
    id: str
    timestamp: float
    sender: str
    recipient: str
    message_type: str
    payload: Dict[str, Any]
    trace_id: str
    parent_id: Optional[str] = None


class MessageBus:
    """In-process message bus for agent communication."""
    
    def __init__(self):
        self._queues: Dict[str, asyncio.Queue] = {}
        self._subscriptions: Dict[str, List[str]] = {}  # topic -> agent_ids
        self._running = False
    
    def register_agent(self, agent_id: str):
        """Register an agent with the bus."""
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.Queue()
    
    def subscribe(self, agent_id: str, topic: str):
        """Subscribe agent to a topic."""
        if topic not in self._subscriptions:
            self._subscriptions[topic] = []
        if agent_id not in self._subscriptions[topic]:
            self._subscriptions[topic].append(agent_id)
    
    async def send(self, message: AgentMessage):
        """Send message to recipient."""
        if message.recipient in self._queues:
            await self._queues[message.recipient].put(message)
        else:
            logger.warning(f"Recipient {message.recipient} not registered")
    
    async def publish(self, topic: str, message: AgentMessage):
        """Publish message to all subscribers of a topic."""
        for agent_id in self._subscriptions.get(topic, []):
            if agent_id in self._queues:
                await self._queues[agent_id].put(message)
    
    async def receive(self, agent_id: str, timeout: Optional[float] = None) -> Optional[AgentMessage]:
        """Receive message for agent."""
        if agent_id not in self._queues:
            return None
        
        try:
            if timeout:
                return await asyncio.wait_for(
                    self._queues[agent_id].get(), timeout=timeout
                )
            else:
                return await self._queues[agent_id].get()
        except asyncio.TimeoutError:
            return None
    
    def start(self):
        self._running = True
    
    def stop(self):
        self._running = False


# Global message bus
_message_bus: Optional[MessageBus] = None


def get_message_bus() -> MessageBus:
    global _message_bus
    if _message_bus is None:
        _message_bus = MessageBus()
    return _message_bus