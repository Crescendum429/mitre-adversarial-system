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


# Pricing por 1M tokens (USD), valores 2026-01 publicados por los providers.
# Tupla: (input, output, cache_read_discount, cache_write_premium).
# cache_read_discount es factor de input (Anthropic: 0.1, OpenAI: 0.5);
# cache_write_premium es factor de input (Anthropic: 1.25 para 5min ephemeral).
_PRICE_PER_M_TOKENS: dict[str, tuple[float, float, float, float]] = {
    # Anthropic
    "claude-opus-4-7": (5.0, 25.0, 0.1, 1.25),
    "claude-opus-4-5": (15.0, 75.0, 0.1, 1.25),
    "claude-sonnet-4-6": (3.0, 15.0, 0.1, 1.25),
    "claude-sonnet-4-5": (3.0, 15.0, 0.1, 1.25),
    "claude-sonnet-4-5-20250929": (3.0, 15.0, 0.1, 1.25),
    "claude-haiku-4-5": (1.0, 5.0, 0.1, 1.25),
    "claude-haiku-4-5-20251001": (1.0, 5.0, 0.1, 1.25),
    # OpenAI
    "gpt-4.1": (2.0, 8.0, 0.5, 1.0),
    "gpt-4.1-mini": (0.4, 1.6, 0.5, 1.0),
    "gpt-4.1-nano": (0.1, 0.4, 0.5, 1.0),
    "gpt-4o": (2.5, 10.0, 0.5, 1.0),
    "gpt-4o-mini": (0.15, 0.6, 0.5, 1.0),
    "o3": (2.0, 8.0, 0.5, 1.0),
    "o4-mini": (1.1, 4.4, 0.5, 1.0),
    # Google
    "gemini-2.5-pro": (1.25, 10.0, 0.0, 1.0),
    "gemini-2.5-flash": (0.075, 0.3, 0.0, 1.0),
    # Free-tier (cost = 0)
    "qwen-3-235b-a22b-instruct-2507": (0.0, 0.0, 0.0, 1.0),
    "openai/gpt-oss-120b:free": (0.0, 0.0, 0.0, 1.0),
    "llama-3.3-70b-versatile": (0.0, 0.0, 0.0, 1.0),
}


def estimate_cost_usd(role: str = "attacker") -> float:
    """Estima el costo USD acumulado para un role usando los contadores de USAGE_STATS.

    Usa el dict _PRICE_PER_M_TOKENS por nombre de modelo. Si el modelo no esta
    en el dict, retorna 0 (mejor under-report que sobre-estimar).
    """
    s = USAGE_STATS.get(role, {})
    model = (s.get("model") or "").lower()
    # Match exacto, despues prefix match (para que claude-sonnet-4-5-XXXXXX caiga
    # en claude-sonnet-4-5 si no se registra la fecha)
    prices = _PRICE_PER_M_TOKENS.get(model)
    if prices is None:
        for key, val in _PRICE_PER_M_TOKENS.items():
            if model.startswith(key) or key.startswith(model):
                prices = val
                break
    if prices is None:
        return 0.0
    inp, out, cache_disc, cache_prem = prices
    cache_read = int(s.get("cache_read_input_tokens", 0) or 0)
    cache_creation = int(s.get("cache_creation_input_tokens", 0) or 0)
    raw_input = int(s.get("input_tokens", 0) or 0)
    output_t = int(s.get("output_tokens", 0) or 0)
    # cache_read se cobra al cache_disc del precio; cache_creation al cache_prem
    cost = (
        raw_input * inp / 1_000_000
        + cache_read * inp * cache_disc / 1_000_000
        + cache_creation * inp * cache_prem / 1_000_000
        + output_t * out / 1_000_000
    )
    return round(cost, 4)


USAGE_STATS: dict[str, dict] = {
    "attacker": {
        "call_count": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "elapsed_seconds": 0.0,
        "model": "",
        "provider": "",
    },
    "observer": {
        "call_count": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
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
            total_tokens=0,
            cache_creation_input_tokens=0, cache_read_input_tokens=0,
            elapsed_seconds=0.0, model="", provider="",
        )


def _extract_usage(response) -> tuple[int, int, int, int]:
    """
    Extrae (input, output, cache_creation, cache_read) tokens del response.
    Distintos providers exponen esto de formas distintas; probamos varios paths.

    Anthropic LangChain expone cache_creation_input_tokens y cache_read_input_tokens
    en usage_metadata.input_token_details. OpenAI los expone en
    response_metadata.token_usage.prompt_tokens_details.cached_tokens (solo cached, sin
    creation). Google Gemini retorna prompt_token_count / candidates_token_count en
    response_metadata.usage_metadata.
    """
    cache_creation = 0
    cache_read = 0
    usage = getattr(response, "usage_metadata", None) or {}
    if isinstance(usage, dict):
        in_t = int(usage.get("input_tokens") or 0)
        out_t = int(usage.get("output_tokens") or 0)
        details = usage.get("input_token_details") or {}
        if isinstance(details, dict):
            cache_creation = int(details.get("cache_creation") or 0)
            cache_read = int(details.get("cache_read") or 0)
        if in_t or out_t or cache_creation or cache_read:
            return in_t, out_t, cache_creation, cache_read
    meta = getattr(response, "response_metadata", {}) or {}
    tu = meta.get("token_usage") or meta.get("usage") or {}
    if isinstance(tu, dict):
        in_t = int(tu.get("prompt_tokens") or tu.get("input_tokens") or 0)
        out_t = int(tu.get("completion_tokens") or tu.get("output_tokens") or 0)
        # OpenAI: cached tokens en prompt_tokens_details
        ptd = tu.get("prompt_tokens_details") or {}
        if isinstance(ptd, dict):
            cache_read = int(ptd.get("cached_tokens") or 0)
        # Anthropic raw response (sin LangChain unwrap): meta.usage tiene los keys
        if not (cache_creation or cache_read):
            cache_creation = int(tu.get("cache_creation_input_tokens") or 0)
            cache_read = int(tu.get("cache_read_input_tokens") or 0)
        if in_t or out_t or cache_creation or cache_read:
            return in_t, out_t, cache_creation, cache_read
    # Google Gemini: usage_metadata en response_metadata con keys distintos
    gum = meta.get("usage_metadata") or {}
    if isinstance(gum, dict):
        in_t = int(gum.get("prompt_token_count") or 0)
        out_t = int(gum.get("candidates_token_count") or 0)
        if in_t or out_t:
            return in_t, out_t, 0, 0
    # Last resort: log debug para que sea visible si todos los paths fallaron
    import logging as _logging
    _logging.getLogger(__name__).debug(
        f"No usage extraido de {type(response).__name__}; "
        f"meta keys={list(meta.keys()) if isinstance(meta, dict) else 'N/A'}"
    )
    return 0, 0, 0, 0


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
        in_t, out_t, cache_create, cache_read = _extract_usage(response)
        with _USAGE_LOCK:
            s = USAGE_STATS[self._role]
            s["call_count"] += 1
            s["input_tokens"] += in_t
            s["output_tokens"] += out_t
            s["total_tokens"] += in_t + out_t
            s["cache_creation_input_tokens"] += cache_create
            s["cache_read_input_tokens"] += cache_read
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
        # Reasoning effort: solo aplica a o-series (o3, o4-mini, GPT-5).
        # En GPT-4.1/4o se ignora silenciosamente. La presencia de "o3", "o4",
        # "gpt-5" en el nombre de modelo determina si pasamos el flag.
        kwargs: dict = dict(
            model=model_name,
            api_key=settings.openai_api_key,
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
            seed=seed,
        )
        is_o_series = any(s in model_name.lower() for s in ("o3", "o4-mini", "gpt-5"))
        if is_o_series and settings.openai_reasoning_effort:
            kwargs["reasoning_effort"] = settings.openai_reasoning_effort
            # o-series no acepta temperature explicito; se ignora pero por
            # cleanliness pasamos solo lo que el modelo entiende.
            kwargs.pop("temperature", None)
            kwargs.pop("seed", None)
        return ChatOpenAI(**kwargs)

    if provider == LLMProvider.ANTHROPIC:
        from langchain_anthropic import ChatAnthropic
        # Anthropic no soporta seed a nivel API; reproducibilidad viene de temp.
        # Extended thinking: opt-in por settings. Habilita razonamiento explicito
        # para Sonnet 4.5+, Opus 4.x. El budget_tokens se reserva del max_tokens.
        kwargs: dict = dict(
            model=model_name,
            api_key=settings.anthropic_api_key,
            temperature=temp,
            max_tokens=settings.llm_max_tokens,
        )
        if settings.anthropic_thinking_enabled:
            budget = max(1024, int(settings.anthropic_thinking_budget_tokens))
            kwargs["max_tokens"] = max(kwargs["max_tokens"], budget + 1024)
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}
            # Anthropic exige temperature=1 cuando thinking esta activo.
            kwargs["temperature"] = 1.0
        return ChatAnthropic(**kwargs)

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


def make_cacheable_system_content(text: str, role: str = "attacker") -> "str | list":
    """Construye el `content` de un SystemMessage con caching condicional al provider.

    Anthropic soporta `cache_control: ephemeral` en bloques de contenido para
    cachear el system prompt durante 5 min y obtener ~90% descuento en input
    tokens en llamadas subsiguientes (Anthropic prompt caching, julio 2024).
    OpenAI cachea automaticamente prompts >=1024 tokens identicos sin necesidad
    de marker. Google Gemini y otros providers reciben el texto plano.

    Para el atacante el provider activo es settings.llm_provider; para el
    observer puede ser settings.observer_provider distinto. El parametro `role`
    selecciona cual considerar.
    """
    if not settings.prompt_caching_enabled:
        return text
    if role == "observer":
        provider = settings.observer_provider or settings.llm_provider
    else:
        provider = settings.llm_provider
    if provider == LLMProvider.ANTHROPIC:
        return [
            {
                "type": "text",
                "text": text,
                "cache_control": {"type": "ephemeral"},
            }
        ]
    return text


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
