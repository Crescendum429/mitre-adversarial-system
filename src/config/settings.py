"""
Configuracion central del sistema. Todas las variables de entorno se cargan
desde un archivo .env en la raiz del proyecto y se validan con Pydantic.
Esto centraliza la configuracion y evita strings magicos dispersos en el codigo.
"""

from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM
    llm_provider: LLMProvider = LLMProvider.OPENAI
    openai_api_key: str = ""
    openai_model: str = "gpt-4-turbo"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5-20250929"
    llm_temperature: float = 0.3
    llm_max_tokens: int = 4096

    # Docker
    attacker_container: str = "attacker"
    target_ip: str = "10.10.0.10"
    attacker_ip: str = "10.10.0.5"
    docker_compose_file: str = "docker/docker-compose.yml"

    # Loki
    loki_url: str = "http://localhost:3100"

    # Ejecucion
    tool_timeout: int = 120
    observer_poll_interval: int = 15
    max_actions_per_tactic: int = 10


settings = Settings()
