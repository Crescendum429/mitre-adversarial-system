"""
Configuracion central del sistema. Todas las variables de entorno se cargan
desde un archivo .env en la raiz del proyecto y se validan con Pydantic.
Esto centraliza la configuracion y evita strings magicos dispersos en el codigo.

Reproducibilidad (ref. Bender & Friedman 2018 "Data Statements for NLP"):
  - llm_seed fijo para determinismo a nivel API (OpenAI, Gemini, Groq soportan
    seed nativo; Anthropic lo ignora).
  - attacker_temperature y observer_temperature separados: el atacante necesita
    algo de exploracion (0.2-0.3) para evadir loops; el observador requiere
    determinismo (0.0) para clasificacion consistente.
"""

from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    GROQ = "groq"
    OPENROUTER = "openrouter"
    CEREBRAS = "cerebras"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # LLM
    llm_provider: LLMProvider = LLMProvider.OPENAI
    openai_api_key: str = ""
    openai_model: str = "gpt-4.1"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5-20250929"
    google_api_key: str = ""
    google_model: str = "gemini-2.5-flash"
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    openrouter_api_key: str = ""
    openrouter_model: str = "nvidia/nemotron-3-super-120b-a12b:free"
    cerebras_api_key: str = ""
    cerebras_model: str = "qwen-3-235b-a22b-instruct-2507"
    # Observer puede usar un proveedor y modelo distintos al agente principal
    # (p.ej. atacante=openai/gpt-4.1, observer=anthropic/claude-sonnet)
    observer_provider: LLMProvider | None = None
    observer_model: str = "claude-sonnet-4-5-20250929"

    # Reproducibilidad
    llm_seed: int = 42
    # Temperatura separada por rol: atacante permite exploracion ligera;
    # observador requiere determinismo maximo para clasificacion consistente.
    attacker_temperature: float = 0.2
    observer_temperature: float = 0.0
    # Deprecated pero mantenido por compatibilidad con .env existentes.
    # Si attacker_temperature/observer_temperature no vienen en .env, se usa este.
    llm_temperature: float = 0.2
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
    # Ventana del observador. 5s default tras calibracion empirica:
    # tacticas rapidas (RCE = 1-3s, login_success = <1s, discovery webshell
    # call = <1s) quedaban enmascaradas en ventanas de 10s+ por el volumen
    # de scanner (gobuster 200+ req en la misma ventana). 5s reduce el
    # mixing manteniendo recall (Bhuyan et al. 2014, NIST SP 800-94).
    observer_poll_interval: int = 5
    max_actions_per_tactic: int = 10

    def validate_credentials(self) -> list[str]:
        """
        Chequea que las API keys requeridas esten presentes. Devuelve la lista
        de providers sin credencial para que el caller decida si es fatal.
        """
        missing: list[str] = []
        providers = {self.llm_provider}
        if self.observer_provider:
            providers.add(self.observer_provider)
        if LLMProvider.OPENAI in providers and not self.openai_api_key:
            missing.append("OPENAI_API_KEY")
        if LLMProvider.ANTHROPIC in providers and not self.anthropic_api_key:
            missing.append("ANTHROPIC_API_KEY")
        if LLMProvider.GOOGLE in providers and not self.google_api_key:
            missing.append("GOOGLE_API_KEY")
        if LLMProvider.GROQ in providers and not self.groq_api_key:
            missing.append("GROQ_API_KEY")
        if LLMProvider.OPENROUTER in providers and not self.openrouter_api_key:
            missing.append("OPENROUTER_API_KEY")
        if LLMProvider.CEREBRAS in providers and not self.cerebras_api_key:
            missing.append("CEREBRAS_API_KEY")
        return missing


settings = Settings()
