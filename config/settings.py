import os
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # OpenAI
    openai_api_key: str = Field(default="", env="OPENAI_API_KEY")
    llm_model: str = Field(default="gpt-4o-mini", env="LLM_MODEL")

    # Redis
    redis_host: str = Field(default="localhost", env="REDIS_HOST")
    redis_port: int = Field(default=6379, env="REDIS_PORT")
    redis_db: int = Field(default=0, env="REDIS_DB")

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./immune_memory.db",
        env="DATABASE_URL",
    )

    # Detection thresholds
    anomaly_threshold: float = Field(default=2.5, env="ANOMALY_THRESHOLD")
    brute_force_threshold: int = Field(default=10, env="BRUTE_FORCE_THRESHOLD")
    port_scan_threshold: int = Field(default=20, env="PORT_SCAN_THRESHOLD")
    rate_limit_threshold: int = Field(default=100, env="RATE_LIMIT_THRESHOLD")

    # Agent behavior
    sentinel_block_duration: int = Field(default=3600, env="SENTINEL_BLOCK_DURATION")
    simulate_actions: bool = Field(default=True, env="SIMULATE_ACTIONS")

    # Simulation
    simulation_target_port: int = Field(default=8001, env="SIMULATION_TARGET_PORT")
    simulation_target_host: str = Field(default="127.0.0.1", env="SIMULATION_TARGET_HOST")
    simulation_attack_interval: int = Field(default=15, env="SIMULATION_ATTACK_INTERVAL")

    # API
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="logs/immune_system.log", env="LOG_FILE")

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def simulation_target_url(self) -> str:
        return f"http://{self.simulation_target_host}:{self.simulation_target_port}"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
