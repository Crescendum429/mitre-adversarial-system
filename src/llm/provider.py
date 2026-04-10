"""
Abstraccion del proveedor de LLM. El resto del sistema llama get_chat_model()
sin saber si esta usando OpenAI o Anthropic. Esto permite cambiar de proveedor
con solo modificar LLM_PROVIDER en .env.

Ambos proveedores implementan la interfaz BaseChatModel de LangChain, asi que
son intercambiables en LangGraph sin modificar los grafos.
"""

from langchain_core.language_models import BaseChatModel

from src.config.settings import LLMProvider, settings


def get_chat_model() -> BaseChatModel:
    """Retorna el modelo de chat configurado segun el proveedor seleccionado."""

    if settings.llm_provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

    elif settings.llm_provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=settings.anthropic_model,
            api_key=settings.anthropic_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

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

        return ChatOpenAI(
            model=settings.observer_model,
            api_key=settings.openai_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

    elif provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(
            model=settings.observer_model,
            api_key=settings.anthropic_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

    raise ValueError(f"Proveedor LLM no soportado para observer: {provider}")
