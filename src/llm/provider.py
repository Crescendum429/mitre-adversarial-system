"""
Abstraccion del proveedor de LLM. El resto del sistema llama get_chat_model()
sin saber si esta usando OpenAI, Anthropic, Google, Groq, OpenRouter o Cerebras.
Esto permite cambiar de proveedor modificando LLM_PROVIDER / OBSERVER_PROVIDER
en .env.

Todos los proveedores se exponen como BaseChatModel de LangChain, asi que son
intercambiables en LangGraph sin modificar los grafos.

Este modulo tambien mantiene contadores globales de uso (USAGE_STATS) que el
resto del sistema lee al final de la corrida para reportar tokens y llamadas
por rol (atacante vs observer). La instrumentacion se aplica via subclase
RunnableLambda que envuelve el invoke() original sin alterar la interfaz.
"""

import threading
import time

from langchain_core.language_models import BaseChatModel

from src.config.settings import LLMProvider, settings


USAGE_STATS: dict[str, dict] = {
    "attacker": {
        "call_count": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "elapsed_seconds": 0.0,
        "model": "",
        "provider": "",
    },
    "observer": {
        "call_count": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "elapsed_seconds": 0.0,
        "model": "",
        "provider": "",
    },
}
_USAGE_LOCK = threading.Lock()


def reset_usage_stats() -> None:
    """Resetea los contadores — util para tests y corridas back-to-back."""
    for role in USAGE_STATS:
        USAGE_STATS[role].update(
            call_count=0, input_tokens=0, output_tokens=0,
            total_tokens=0, elapsed_seconds=0.0, model="", provider="",
        )


def _extract_usage(response) -> tuple[int, int]:
    """
    Extrae tokens de entrada/salida del response de LangChain.
    Distintos providers exponen esto de formas distintas; probamos varios paths.
    """
    usage = getattr(response, "usage_metadata", None) or {}
    if isinstance(usage, dict):
        in_t = int(usage.get("input_tokens") or 0)
        out_t = int(usage.get("output_tokens") or 0)
        if in_t or out_t:
            return in_t, out_t
    meta = getattr(response, "response_metadata", {}) or {}
    # OpenAI-compatible: meta["token_usage"] = {"prompt_tokens", "completion_tokens"}
    tu = meta.get("token_usage") or meta.get("usage") or {}
    if isinstance(tu, dict):
        in_t = int(tu.get("prompt_tokens") or tu.get("input_tokens") or 0)
        out_t = int(tu.get("completion_tokens") or tu.get("output_tokens") or 0)
        if in_t or out_t:
            return in_t, out_t
    return 0, 0


class _InstrumentedChatModel:
    """
    Proxy que delega en el modelo original pero registra tokens y latencia en
    USAGE_STATS[role] tras cada invoke. Mantiene compatibilidad con LangChain
    reexportando bind_tools y otros atributos del modelo original.
    """

    def __init__(self, model: BaseChatModel, role: str, provider: str, model_name: str):
        self._model = model
        self._role = role
        with _USAGE_LOCK:
            USAGE_STATS[role]["provider"] = provider
            USAGE_STATS[role]["model"] = model_name

    def invoke(self, *args, **kwargs):
        t0 = time.monotonic()
        response = self._model.invoke(*args, **kwargs)
        elapsed = time.monotonic() - t0
        in_t, out_t = _extract_usage(response)
        with _USAGE_LOCK:
            s = USAGE_STATS[self._role]
            s["call_count"] += 1
            s["input_tokens"] += in_t
            s["output_tokens"] += out_t
            s["total_tokens"] += in_t + out_t
            s["elapsed_seconds"] += elapsed
        return response

    def bind_tools(self, *args, **kwargs):
        # Si self._model es RunnableWithRetry (salida de _with_retry), no tiene
        # bind_tools — hay que acceder al modelo base y re-aplicar retry despues.
        inner = self._model
        if hasattr(inner, "bound") and hasattr(inner.bound, "bind_tools"):
            bound = inner.bound.bind_tools(*args, **kwargs)
            bound = _with_retry(bound)
        else:
            bound = inner.bind_tools(*args, **kwargs)
        return _InstrumentedChatModel(
            bound, self._role,
            USAGE_STATS[self._role]["provider"],
            USAGE_STATS[self._role]["model"],
        )

    def with_retry(self, *args, **kwargs):
        retried = self._model.with_retry(*args, **kwargs)
        return _InstrumentedChatModel(
            retried, self._role,
            USAGE_STATS[self._role]["provider"],
            USAGE_STATS[self._role]["model"],
        )

    def __getattr__(self, name):
        return getattr(self._model, name)


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


def _temperature_for(role: str) -> float:
    """Temperatura por rol. Cae a llm_temperature si no se definio explicitamente."""
    if role == "observer":
        return settings.observer_temperature
    return settings.attacker_temperature


def _build_model(provider: LLMProvider, model_name: str, role: str = "attacker") -> BaseChatModel:
    """
    Construye un BaseChatModel para el provider/modelo indicado.
    Se usa tanto en get_chat_model (atacante) como en get_observer_model.

    Aplica seed donde el proveedor lo soporta (OpenAI, Google, Groq, OpenRouter,
    Cerebras — todos exponen `seed` compatible con OpenAI). Anthropic no soporta
    seed a nivel API, asi que la reproducibilidad ahi depende solo de temp=0.
    """
    temp = _temperature_for(role)
    seed = settings.llm_seed

    if provider == LLMProvider.OPENAI:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model_name,
            api_key=settings.openai_api_key,
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
            seed=seed,
        )

    if provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic
        # Anthropic no soporta seed a nivel API; reproducibilidad viene de temp.
        return ChatAnthropic(
            model=model_name,
            api_key=settings.anthropic_api_key,
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
        )

    if provider == LLMProvider.GOOGLE:
        # Gemini soporta seed via generation_config (parametro model_kwargs).
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=model_name,
            google_api_key=settings.google_api_key,
            temperature=temp,
            max_output_tokens=settings.llm_max_tokens,
            model_kwargs={"seed": seed},
        )

    if provider == LLMProvider.GROQ:
        # Groq soporta seed compatible con OpenAI en modelos Llama y Qwen.
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=model_name,
            api_key=settings.groq_api_key,
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
            model_kwargs={"seed": seed},
        )

    if provider == LLMProvider.OPENROUTER:
        # OpenRouter es un gateway hacia muchos modelos open-weight. Algunos
        # corren en JAX/vLLM y no soportan `seed` per-request (devuelven error
        # 502). No pasamos seed; reproducibilidad depende de temp=0.
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=model_name,
            api_key=settings.openrouter_api_key,
            base_url="https://openrouter.ai/api/v1",
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
        )

    if provider == LLMProvider.CEREBRAS:
        # Cerebras soporta seed via model_kwargs.
        from langchain_cerebras import ChatCerebras
        return ChatCerebras(
            model=model_name,
            api_key=settings.cerebras_api_key,
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
            model_kwargs={"seed": seed},
        )

    raise ValueError(f"Proveedor LLM no soportado: {provider}")


def _model_for(provider: LLMProvider, role: str) -> str:
    """Devuelve el nombre de modelo configurado para (provider, rol)."""
    if role == "observer":
        if provider == LLMProvider.OPENAI:
            return settings.observer_model
        if provider == LLMProvider.ANTHROPIC:
            return settings.observer_model
        if provider == LLMProvider.GOOGLE:
            return settings.google_model
        if provider == LLMProvider.GROQ:
            return settings.groq_model
        if provider == LLMProvider.OPENROUTER:
            return settings.openrouter_model
        if provider == LLMProvider.CEREBRAS:
            return settings.cerebras_model
    # rol = atacante (o default)
    if provider == LLMProvider.OPENAI:
        return settings.openai_model
    if provider == LLMProvider.ANTHROPIC:
        return settings.anthropic_model
    if provider == LLMProvider.GOOGLE:
        return settings.google_model
    if provider == LLMProvider.GROQ:
        return settings.groq_model
    if provider == LLMProvider.OPENROUTER:
        return settings.openrouter_model
    if provider == LLMProvider.CEREBRAS:
        return settings.cerebras_model
    raise ValueError(f"Proveedor LLM no soportado: {provider}")


def get_chat_model() -> BaseChatModel:
    """Retorna el modelo de chat para el agente atacante."""
    provider = settings.llm_provider
    model_name = _model_for(provider, "attacker")
    model = _build_model(provider, model_name, role="attacker")
    retried = _with_retry(model)
    return _InstrumentedChatModel(retried, "attacker", provider.value, model_name)


def get_observer_model() -> BaseChatModel:
    """
    Retorna el modelo para el agente observador.

    OBSERVER_PROVIDER puede ser distinto al del atacante (heterogeneidad
    intencional para aislar efectos del proveedor sobre la clasificacion).
    Si no esta definido, usa el mismo proveedor que el atacante.
    """
    provider = settings.observer_provider or settings.llm_provider
    model_name = _model_for(provider, "observer")
    model = _build_model(provider, model_name, role="observer")
    retried = _with_retry(model)
    return _InstrumentedChatModel(retried, "observer", provider.value, model_name)
