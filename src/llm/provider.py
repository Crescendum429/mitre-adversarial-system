"""
Abstraccion del proveedor de LLM. El resto del sistema llama get_chat_model()
sin saber si esta usando OpenAI o Anthropic. Esto permite cambiar de proveedor
con solo modificar LLM_PROVIDER en .env.

Ambos proveedores implementan la interfaz BaseChatModel de LangChain, asi que
son intercambiables en LangGraph sin modificar los grafos.
"""

from langchain_core.language_models import BaseChatModel

from src.config.settings import LLMProvider, settings


def _with_retry(model: BaseChatModel) -> BaseChatModel:
    """
    Envuelve un modelo con reintentos exponenciales ante rate limits.

    Tier 1 de OpenAI tiene 30K TPM para gpt-4.1; el atacante puede exceder
    este limite durante replanificaciones con contexto largo. Los reintentos
    con jitter evitan que el ataque se aborte por limites transitorios.
    """
    try:
        from openai import RateLimitError as OpenAIRateLimitError
    except Exception:
        OpenAIRateLimitError = Exception  # type: ignore

    try:
        from anthropic import RateLimitError as AnthropicRateLimitError
    except Exception:
        AnthropicRateLimitError = Exception  # type: ignore

    return model.with_retry(
        retry_if_exception_type=(OpenAIRateLimitError, AnthropicRateLimitError),
        wait_exponential_jitter=True,
        stop_after_attempt=6,
    )


def get_chat_model() -> BaseChatModel:
    """Retorna el modelo de chat configurado segun el proveedor seleccionado."""

    if settings.llm_provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI

        model = ChatOpenAI(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )
        return _with_retry(model)

    elif settings.llm_provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic

        model = ChatAnthropic(
            model=settings.anthropic_model,
            api_key=settings.anthropic_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )
        return _with_retry(model)

    raise ValueError(f"Proveedor LLM no soportado: {settings.llm_provider}")


def get_observer_model() -> BaseChatModel:
    """
    Retorna el modelo para el agente observador.

    El observer puede usar un proveedor distinto al atacante (ej. atacante en
    OpenAI/gpt-4.1 y observer en Anthropic/Sonnet) para evitar compartir el
    rate limit TPM entre ambos agentes. Se configura via OBSERVER_PROVIDER y
    OBSERVER_MODEL en .env.

    Si OBSERVER_PROVIDER no esta definido, usa el mismo proveedor que el
    agente principal.
    """
    provider = settings.observer_provider or settings.llm_provider

    if provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI

        model = ChatOpenAI(
            model=settings.observer_model,
            api_key=settings.openai_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )
        return _with_retry(model)

    elif provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic

        model = ChatAnthropic(
            model=settings.observer_model,
            api_key=settings.anthropic_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )
        return _with_retry(model)

    raise ValueError(f"Proveedor LLM no soportado para observer: {provider}")
