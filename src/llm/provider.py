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
    """Envuelve un modelo con reintentos exponenciales ante errores transitorios."""
    retry_types: list = []
    try:
        from openai import APIConnectionError, APITimeoutError, RateLimitError
        retry_types.extend([APIConnectionError, APITimeoutError, RateLimitError])
    except Exception:
        pass
    try:
        from anthropic import APIConnectionError as AnthropicConnErr
        from anthropic import APITimeoutError as AnthropicTimeoutErr
        from anthropic import RateLimitError as AnthropicRateErr
        retry_types.extend([AnthropicConnErr, AnthropicTimeoutErr, AnthropicRateErr])
    except Exception:
        pass
    if not retry_types:
        retry_types = [Exception]

    return model.with_retry(
        retry_if_exception_type=tuple(retry_types),
        wait_exponential_jitter=True,
        stop_after_attempt=8,
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
