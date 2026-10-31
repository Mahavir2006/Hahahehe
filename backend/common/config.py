"""
Configuration management for CascadeShield backend.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List
import json


class Settings(BaseSettings):
    # LLM Configuration
    llm_provider: str = Field(default="offline", alias="LLM_PROVIDER")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    llm_model: str = Field(default="claude-3-haiku-20240307", alias="LLM_MODEL")
    llm_max_tokens: int = Field(default=4096, alias="LLM_MAX_TOKENS")
    llm_timeout_seconds: int = Field(default=30, alias="LLM_TIMEOUT_SECONDS")
    llm_max_retries: int = Field(default=3, alias="LLM_MAX_RETRIES")
    llm_budget_tokens_per_advisory: int = Field(default=50000, alias="LLM_BUDGET_TOKENS_PER_ADVISORY")
    llm_budget_calls_per_advisory: int = Field(default=20, alias="LLM_BUDGET_CALLS_PER_ADVISORY")
    trace_raw: bool = Field(default=False, alias="TRACE_RAW")
    
    # Chain Configuration
    chain_rpc_url: str = Field(default="http://localhost:8545", alias="CHAIN_RPC_URL")
    chain_id: int = Field(default=31337, alias="CHAIN_ID")
    deployment_file: str = Field(default="chain/deployments/local.json", alias="DEPLOYMENT_FILE")
    chain_connect_timeout: int = Field(default=10, alias="CHAIN_CONNECT_TIMEOUT")
    chain_request_timeout: int = Field(default=60, alias="CHAIN_REQUEST_TIMEOUT")
    chain_max_retries: int = Field(default=5, alias="CHAIN_MAX_RETRIES")
    chain_retry_backoff_base: float = Field(default=1.5, alias="CHAIN_RETRY_BACKOFF_BASE")
    gas_price_multiplier: float = Field(default=1.2, alias="GAS_PRICE_MULTIPLIER")
    gas_limit_multiplier: float = Field(default=1.3, alias="GAS_LIMIT_MULTIPLIER")
    max_gas_per_tx: int = Field(default=500000, alias="MAX_GAS_PER_TX")
    
    # Data Configuration
    data_seed: int = Field(default=42, alias="DATA_SEED")
    data_dir: str = Field(default="data", alias="DATA_DIR")
    data_orgs: List[str] = Field(default=["power", "water", "hospital"], alias="DATA_ORGS")
    
    # Agent Configuration
    agent_max_concurrent_advisories: int = Field(default=20, alias="AGENT_MAX_CONCURRENT_ADVISORIES")
    approval_ttl_seconds: int = Field(default=3600, alias="APPROVAL_TTL_SECONDS")
    critic_max_iterations: int = Field(default=3, alias="CRITIC_MAX_ITERATIONS")
    
    # Risk Band Thresholds
    risk_band_low_max: int = Field(default=25, alias="RISK_BAND_LOW_MAX")
    risk_band_medium_max: int = Field(default=50, alias="RISK_BAND_MEDIUM_MAX")
    risk_band_high_max: int = Field(default=75, alias="RISK_BAND_HIGH_MAX")
    
    # Cascade Alert Threshold
    cascade_alert_threshold: float = Field(default=0.5, alias="CASCADE_ALERT_THRESHOLD")
    
    # Supply Chain Check Interval
    supply_chain_check_interval: int = Field(default=300, alias="SUPPLY_CHAIN_CHECK_INTERVAL")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=1, alias="API_WORKERS")
    
    # Dashboard Configuration
    dashboard_port: int = Field(default=5173, alias="DASHBOARD_PORT")
    vite_api_url: str = Field(default="http://localhost:8000", alias="VITE_API_URL")
    vite_chain_rpc_url: str = Field(default="http://localhost:8545", alias="VITE_CHAIN_RPC_URL")
    
    # Safety / Kill Switch
    admin_pause_token: str = Field(default="dev-pause-token-change-in-prod", alias="ADMIN_PAUSE_TOKEN")
    
    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"


settings = Settings()


def load_deployment_addresses() -> dict:
    """Load contract deployment addresses from file."""
    import os
    if os.path.exists(settings.deployment_file):
        with open(settings.deployment_file, "r") as f:
            return json.load(f)
    return {}