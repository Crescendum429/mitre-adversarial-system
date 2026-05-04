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

    # Recursion limit del grafo del atacante (LangGraph). 800 default calibrado
    # empiricamente: escenarios complejos (mrrobot full chain) requieren 200-300
    # transiciones de estado; 800 da margen 2x y permite rescatar runs con
    # replans. Valores menores (e.g., 100) cortan el ataque antes de completar.
    attacker_recursion_limit: int = 800

    # Tiempo de gracia entre detener el observer y declarar fin del experimento.
    # poll_interval*3+grace_seconds permite que el observer flush la ultima
    # ventana en curso antes del shutdown.
    observer_shutdown_grace_seconds: int = 15

    # Prompt caching (Anthropic ephemeral cache). Reduce input cost ~90% y
    # latencia en corridas repetidas. El system prompt del atacante (19k
    # tokens) se cachea con cache_control. OpenAI cachea automatico para
    # prompts >=1024 tokens identicos. Google no expone caching control.
    prompt_caching_enabled: bool = True

    # Cache TTL extendido (Anthropic 1h cache, beta extended-cache-ttl-2025).
    # Default 5min (False) cubre la mayoria de corridas dvwa (<5min). Para
    # corridas largas (mrrobot, dc1, log4shell, bpent) que duran >5min, el
    # cache 5min se invalida y se paga el premium (1.25x) repetidamente.
    # 1h cache cuesta 2x premium en write pero solo se paga UNA vez por
    # corrida; en runs >10min suele ahorrar costo neto.
    anthropic_cache_ttl_extended: bool = False

    # Reflector node (RefPentester style, Chen et al. arXiv:2505.07089).
    # Si el atacante falla N+ replans en la misma tactica, el siguiente
    # plan_tactic incluye un bloque de "reflexion estructurada" que invita
    # al LLM a listar intentos previos, identificar patrones recurrentes
    # y proponer un cambio cualitativo de enfoque (no solo retocar args).
    # Bajo costo (~ +500 tokens al prompt cuando se dispara) — alto valor
    # cuando el replan se atasca en bucles superficiales.
    reflector_enabled: bool = True
    reflector_trigger_attempts: int = 3

    # Extended thinking de Anthropic (Sonnet 4.5+, Opus 4.x). Mejora multi-step
    # reasoning a costa de output tokens adicionales. Default off para
    # reproducibilidad y costo controlado. Activar via env para ablation.
    anthropic_thinking_enabled: bool = False
    anthropic_thinking_budget_tokens: int = 5000

    # Reasoning effort para OpenAI o-series (o3, o4-mini, GPT-5). Valores:
    # 'minimal', 'low', 'medium', 'high'. None = default del modelo.
    openai_reasoning_effort: str = ""

    # Loop detection en el atacante: si la misma accion (mismo tool + args
    # firma) se repite N+ veces en las ultimas window acciones, forzar replan
    # con feedback explicito. Evita timeouts artificiales por bucles triviales
    # del LLM (caso D1 mrrobot OpenRouter: gobuster rockyou.txt 10+ veces).
    loop_detection_enabled: bool = True
    loop_detection_window: int = 6
    loop_detection_threshold: int = 3

    # Pre-flight check del modelo antes de empezar la corrida: smoke test
    # con un prompt minimo para detectar fallos de cuota / context size /
    # auth ANTES de gastar tokens. Aborta la corrida con mensaje claro si
    # falla. Default on; desactivar solo en tests.
    preflight_check_enabled: bool = True

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
