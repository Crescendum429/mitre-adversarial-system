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

    Usa un modelo de menor costo (gpt-4o-mini) porque el observador procesa
    grandes volumenes de logs en cada ciclo de polling. El modelo principal
    queda reservado para el agente atacante que requiere mayor capacidad de
    razonamiento para planificar tecnicas de pentesting.
    """
    if settings.llm_provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=settings.observer_model,
            api_key=settings.openai_api_key,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

    # Para otros proveedores, usar el modelo principal
    return get_chat_model()
