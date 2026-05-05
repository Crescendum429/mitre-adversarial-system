"""Tests E2E con mocks de LLM, Loki y Docker.

No invocan APIs reales — todo el stack se mockea para verificar el flujo
completo del grafo del atacante y del observer sin coste ni dependencia
de containers. Util para atrapar regresiones de refactor que los unit
tests aislados no detectan.

Estrategia:
  - FakeChatModel sustituye get_chat_model() / get_observer_model().
    Devuelve AIMessages predeterminados segun el numero de invocacion,
    simulando una corrida que avanza tacticas.
  - Mock de DockerClient.exec_in_attacker para no necesitar docker exec.
  - Mock de LokiClient.collect_window para retornar logs sinteticos.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage

from src.config.settings import LLMProvider, settings


class FakeChatModel:
    """Modelo LLM mock con respuestas determinables por sequence."""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.invoke_count = 0
        self._tools: list = []

    def invoke(self, messages):
        self.invoke_count += 1
        if not self.responses:
            return AIMessage(content="[FAKE] sin mas respuestas", id=f"fake-{self.invoke_count}")
        resp = self.responses.pop(0)
        if isinstance(resp, dict) and "tool_calls" in resp:
            return AIMessage(
                content=resp.get("content", ""),
                tool_calls=resp["tool_calls"],
                id=f"fake-{self.invoke_count}",
            )
        return AIMessage(
            content=resp if isinstance(resp, str) else str(resp),
            id=f"fake-{self.invoke_count}",
        )

    def bind_tools(self, tools):
        self._tools = list(tools)
        return self

    def with_retry(self, **_kwargs):
        return self


class TestAttackerHappyPath:
    """Verifica que plan_tactic + execute_tools producen un action_history
    valido cuando el LLM devuelve tool_calls validos. NO usa el graph
    completo (eso requeriria que el validator code-based pase, lo cual
    depende del scenario real con Loki/Docker activos)."""

    def test_plan_and_execute_first_action_with_mock(self, monkeypatch):
        from src.agents.attacker import nodes as attacker_nodes
        from src.agents.attacker import graph as attacker_graph

        attacker_nodes.reset_model_singleton()

        # Mock LLM: primer invoke produce run_nmap tool_call.
        fake = FakeChatModel(responses=[
            {
                "content": "Iniciando nmap",
                "tool_calls": [
                    {"name": "run_nmap", "args": {"target": "10.10.0.10"},
                     "id": "call-1"}
                ],
            },
        ])
        # Patchear en el alias de attacker.nodes (que importo via
        # `from src.llm.provider import get_chat_model`). Patchear en provider
        # directamente NO afecta porque el alias ya esta resuelto en el modulo
        # nodes — el patch al modulo provider no actualiza el alias en nodes.
        monkeypatch.setattr("src.llm.provider.get_chat_model", lambda: fake)
        monkeypatch.setattr("src.agents.attacker.nodes.get_chat_model", lambda: fake)

        # Mock DockerClient para no exec en containers reales
        class FakeResult:
            exit_code = 0
            stdout = "Nmap scan report for 10.10.0.10\nPORT 80/tcp open http"
            stderr = ""
        monkeypatch.setattr(
            "src.infrastructure.docker_client.DockerClient.exec_in_attacker",
            lambda self, cmd, timeout=120, container=None: FakeResult(),
        )

        # Build initial state y ejecutar plan + execute manualmente.
        state = attacker_graph.create_initial_state(
            target="10.10.0.10",
            tactics=["reconnaissance"],
            use_memory=False,
        )
        plan_result = attacker_nodes.plan_tactic(state)
        assert "messages" in plan_result
        # El message del LLM contiene tool_calls
        ai_msgs = [m for m in plan_result["messages"]
                   if hasattr(m, "tool_calls") and m.tool_calls]
        assert ai_msgs, "plan_tactic no produjo AIMessage con tool_calls"

        # Aplicar el resultado al state y ejecutar tools
        merged_state = {**state, **plan_result, "messages": plan_result["messages"]}
        exec_result = attacker_nodes.execute_tools(merged_state)
        history = exec_result.get("action_history", [])
        assert len(history) == 1
        assert history[0]["technique"] == "run_nmap"
        assert "Nmap scan report" in history[0]["output_preview"]


class TestObserverPipelineWithMocks:
    """Verifica que la pipeline del observer (collect -> triage -> classify)
    funciona end-to-end con LokiClient mockeado."""

    def test_observer_happy_path_classifies_recon(self, monkeypatch):
        from src.agents.observer import graph as observer_graph
        from src.agents.observer import nodes as observer_nodes

        # 1. Mock LokiClient.collect_window
        synthetic_logs = [
            {
                "labels": {"container_name": "dvwa"},
                "message": (
                    '10.10.0.5 - - [04/May/2026:17:30:00 +0000] '
                    '"GET /admin HTTP/1.1" 404 1234 "-" "Mozilla/5.0 gobuster/3.6"'
                ),
                "timestamp": "2026-05-04T17:30:00+00:00",
            },
        ] * 30  # mucho recon

        class FakeCollector:
            def collect_window(self, start=None, end=None):
                return synthetic_logs

            def summarize_logs(self, logs):
                return {"total": len(logs), "container_name": "dvwa"}

        # Reset internal collector singleton
        observer_nodes._collector = FakeCollector()

        # 2. Mock observer LLM para devolver JSON valido
        classification_response = json.dumps({
            "tactics_in_window": [{
                "tactic": "Reconnaissance",
                "tactic_id": "TA0043",
                "confidence": 0.95,
                "evidence": ["gobuster signature in UA"],
            }],
            "current_tactic": "Reconnaissance",
            "current_tactic_id": "TA0043",
            "confidence": 0.95,
            "reasoning": "Volumen alto de 404 con gobuster UA",
            "recommendation": "Block IP",
        })
        fake_llm = FakeChatModel(responses=[classification_response] * 5)
        observer_nodes._model = fake_llm
        monkeypatch.setattr("src.llm.provider.get_observer_model", lambda: fake_llm)

        # 3. Build initial state for observer
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        state = {
            "window_start": (now - timedelta(seconds=5)).isoformat(),
            "window_end": now.isoformat(),
            "fingerprint": "",
            "history": [],
            "raw_logs": [],
            "anomaly_count": 0,
            "triage_result": "no_signal",
        }

        # 4. Compile graph and invoke
        compiled = observer_graph.build_observer_graph()
        try:
            final = compiled.invoke(state)
        except Exception as e:
            pytest.fail(f"Observer graph fallo: {e}")

        # 5. Asserts: con la fixture de logs gobuster + UA tool, el triage debe
        # disparar 'signal' y classify debe producir Reconnaissance. El test
        # original aceptaba (None, Reconnaissance) — relajacion que dejaba pasar
        # el caso degenerado donde el grafo no clasifica nada. Endurecido:
        # exigimos signal del triage y tactic == Reconnaissance.
        assert final.get("triage_result") == "signal", \
            f"Esperaba triage 'signal' por logs gobuster, vi {final.get('triage_result')}"
        cls = final.get("current_classification")
        assert cls is not None, "classify_tactic debio producir current_classification"
        tactic = getattr(cls, "tactic", None) or (
            cls.get("tactic") if isinstance(cls, dict) else None
        )
        assert tactic == "Reconnaissance", f"Esperaba Reconnaissance, vi {tactic}"


class TestProviderRetryClassifierIntegration:
    """Smoke test: _with_retry NO debe explotar al envolver un modelo
    dummy con interfaz minima (with_retry method)."""

    def test_with_retry_wraps_dummy_model(self):
        from src.llm.provider import _with_retry

        captured = {}

        class DummyModel:
            def with_retry(self, **kwargs):
                captured.update(kwargs)
                return self  # simplificacion

        out = _with_retry(DummyModel())
        assert out is not None
        # Debe pasar retry_if_exception_type con tupla no vacia
        assert "retry_if_exception_type" in captured
        assert isinstance(captured["retry_if_exception_type"], tuple)
        assert len(captured["retry_if_exception_type"]) > 0
        # wait_exponential_jitter habilitado y stop_after_attempt 8
        assert captured.get("wait_exponential_jitter") is True
        assert captured.get("stop_after_attempt") == 8


class TestNewProvidersWiring:
    """Confirma que los providers DeepSeek y Kimi (OpenAI-compatible) se
    construyen sin error y respetan model + base_url. No hace llamadas reales
    a la API; solo valida el wiring."""

    def test_deepseek_provider_builds_chatopenai(self, monkeypatch):
        from src.config.settings import LLMProvider, settings
        from src.llm import provider

        monkeypatch.setattr(settings, "deepseek_api_key", "ds-test-key")
        monkeypatch.setattr(settings, "deepseek_model", "deepseek-chat")
        model = provider._build_model(LLMProvider.DEEPSEEK, "deepseek-chat", role="attacker")
        assert model is not None
        assert getattr(model, "model_name", "") == "deepseek-chat" or \
               getattr(model, "model", "") == "deepseek-chat"
        base = str(getattr(model, "openai_api_base", "") or
                   getattr(model, "base_url", ""))
        assert "deepseek" in base.lower(), f"base_url no apunta a deepseek: {base}"

    def test_kimi_provider_builds_chatopenai(self, monkeypatch):
        from src.config.settings import LLMProvider, settings
        from src.llm import provider

        monkeypatch.setattr(settings, "kimi_api_key", "kimi-test-key")
        monkeypatch.setattr(settings, "kimi_model", "kimi-k2-turbo-preview")
        model = provider._build_model(LLMProvider.KIMI, "kimi-k2-turbo-preview", role="observer")
        assert model is not None
        base = str(getattr(model, "openai_api_base", "") or
                   getattr(model, "base_url", ""))
        assert "moonshot" in base.lower(), f"base_url no apunta a moonshot: {base}"

    def test_pricing_dict_has_new_models(self):
        from src.llm.provider import _PRICE_PER_M_TOKENS
        for k in (
            "gpt-5.5",
            "gemini-3.1-pro",
            "deepseek-chat",
            "deepseek-v4-flash",
            "deepseek-v4-pro",
            "kimi-k2-turbo-preview",
        ):
            assert k in _PRICE_PER_M_TOKENS, f"pricing falta: {k}"

    def test_validate_credentials_detects_missing_new_keys(self, monkeypatch):
        from src.config.settings import LLMProvider, Settings
        s = Settings(
            llm_provider=LLMProvider.DEEPSEEK,
            observer_provider=LLMProvider.KIMI,
            deepseek_api_key="",
            kimi_api_key="",
        )
        missing = s.validate_credentials()
        assert "DEEPSEEK_API_KEY" in missing
        assert "KIMI_API_KEY" in missing


class TestRunAttackerExceptionHandling:
    """Regresion: run_attacker debe capturar quota/rate-limit/context-overflow
    de cualquier provider y emitir reporte parcial con la metadata acumulada.

    El bug previo capturaba unicamente anthropic.BadRequestError; con .env
    OpenAI un insufficient_quota despues de 8 reintentos llegaba como
    openai.RateLimitError sin captura -> action_history y tactic_evidence
    perdidos.
    """

    def _patch_graph(self, monkeypatch, exception_factory, history_payload):
        import src.main as m

        events_to_yield = [
            {"plan_tactic": {"current_tactic": "reconnaissance"}},
            {"execute_tools": {
                "current_tactic": "reconnaissance",
                "action_history": history_payload,
            }},
        ]

        class FakeGraph:
            def stream(self, initial_state, config):
                for ev in events_to_yield:
                    yield ev
                raise exception_factory()

        monkeypatch.setattr(m, "build_attacker_graph", lambda: FakeGraph())
        monkeypatch.setattr(
            m,
            "create_initial_state",
            lambda **kw: {
                "target": kw.get("target") or "10.10.0.10",
                "tactic_sequence": kw.get("tactics") or ["reconnaissance"],
                "action_history": [],
                "current_tactic": "",
            },
        )

    def test_openai_insufficient_quota_emits_partial(self, monkeypatch):
        import httpx
        import openai
        from src.main import run_attacker

        history = [{"tool": "run_nmap", "tactic": "reconnaissance"}]

        def make_exc():
            response = httpx.Response(
                429,
                request=httpx.Request("POST", "https://api.openai.com/v1/chat"),
            )
            return openai.RateLimitError(
                message=(
                    "Error code: 429 - {'error': {'code': 'insufficient_quota', "
                    "'message': 'You exceeded your current quota'}}"
                ),
                response=response,
                body={"error": {"code": "insufficient_quota"}},
            )

        self._patch_graph(monkeypatch, make_exc, history)
        state = run_attacker(
            tactics=["reconnaissance"],
            target="10.10.0.10",
            use_memory=False,
        )
        assert state.get("quota_exhausted") is True, (
            f"quota_exhausted no seteado tras OpenAI insufficient_quota. "
            f"state keys: {sorted(state)}"
        )
        assert state.get("action_history") == history, (
            "action_history acumulado se perdio tras la captura."
        )

    def test_anthropic_credit_balance_emits_partial(self, monkeypatch):
        import httpx
        from anthropic import BadRequestError as AnthropicBad
        from src.main import run_attacker

        history = [{"tool": "run_gobuster", "tactic": "reconnaissance"}]

        def make_exc():
            response = httpx.Response(
                400,
                request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
            )
            return AnthropicBad(
                message="credit balance is too low",
                response=response,
                body={
                    "error": {
                        "type": "invalid_request_error",
                        "message": "Your credit balance is too low",
                    }
                },
            )

        self._patch_graph(monkeypatch, make_exc, history)
        state = run_attacker(
            tactics=["reconnaissance"],
            target="10.10.0.10",
            use_memory=False,
        )
        assert state.get("quota_exhausted") is True
        assert state.get("action_history") == history

    def test_openai_rate_limit_sustained_emits_partial(self, monkeypatch):
        import httpx
        import openai
        from src.main import run_attacker

        history = [{"tool": "run_whatweb", "tactic": "reconnaissance"}]

        def make_exc():
            response = httpx.Response(
                429,
                request=httpx.Request("POST", "https://api.openai.com/v1/chat"),
            )
            return openai.RateLimitError(
                message="Error code: 429 - rate limit exceeded, please try again later",
                response=response,
                body={"error": {"code": "rate_limit_exceeded"}},
            )

        self._patch_graph(monkeypatch, make_exc, history)
        state = run_attacker(
            tactics=["reconnaissance"],
            target="10.10.0.10",
            use_memory=False,
        )
        assert state.get("rate_limit_exhausted") is True
        assert state.get("action_history") == history

    def test_unrelated_apistatuserror_propagates(self, monkeypatch):
        import httpx
        import openai
        import pytest
        from src.main import run_attacker

        history = [{"tool": "run_nmap", "tactic": "reconnaissance"}]

        def make_exc():
            response = httpx.Response(
                403,
                request=httpx.Request("POST", "https://api.openai.com/v1/chat"),
            )
            return openai.PermissionDeniedError(
                message="Error code: 403 - your organization is not authorized",
                response=response,
                body={"error": {"code": "permission_denied"}},
            )

        self._patch_graph(monkeypatch, make_exc, history)
        with pytest.raises(openai.APIStatusError):
            run_attacker(
                tactics=["reconnaissance"],
                target="10.10.0.10",
                use_memory=False,
            )


class TestSelectiveToolExposureInvariants:
    """Verifica las invariantes del selective tool exposure que
    podrian romper en runtime."""

    def test_all_tactic_subsets_are_subsets_of_full(self):
        from src.agents.attacker.tools import (ATTACKER_TOOLS,
                                                TACTIC_TO_TOOLS,
                                                select_tools_for_tactic)
        full_names = {t.name for t in ATTACKER_TOOLS}
        for tactic in TACTIC_TO_TOOLS:
            subset = select_tools_for_tactic(tactic)
            subset_names = {t.name for t in subset}
            assert subset_names.issubset(full_names), (
                f"Subset de {tactic} contiene tools no en ATTACKER_TOOLS: "
                f"{subset_names - full_names}"
            )

    def test_all_tactics_have_core_tools(self):
        from src.agents.attacker.tools import select_tools_for_tactic, _CORE_TOOLS
        for tactic in ("reconnaissance", "initial_access", "execution",
                       "discovery", "privilege_escalation"):
            subset = select_tools_for_tactic(tactic)
            names = {t.name for t in subset}
            for core in _CORE_TOOLS:
                assert core in names, f"Tactic {tactic} no tiene core tool {core}"

    def test_get_model_singleton_when_selective_off(self, monkeypatch):
        """Si selective=False, _get_model devuelve el singleton global
        sin importar el tactic param."""
        from src.agents.attacker import nodes as attacker_nodes
        attacker_nodes.reset_model_singleton()
        monkeypatch.setattr(settings, "attacker_selective_tools_enabled", False)
        fake = FakeChatModel(responses=[])
        monkeypatch.setattr("src.llm.provider.get_chat_model", lambda: fake)
        m1 = attacker_nodes._get_model("reconnaissance")
        m2 = attacker_nodes._get_model("execution")
        # Mismo objeto -> mismo singleton
        assert m1 is m2

    def test_get_model_distinct_when_selective_on(self, monkeypatch):
        """Si selective=True, _get_model crea modelo distinto por tactic."""
        from src.agents.attacker import nodes as attacker_nodes
        attacker_nodes.reset_model_singleton()
        monkeypatch.setattr(settings, "attacker_selective_tools_enabled", True)
        fake = FakeChatModel(responses=[])
        monkeypatch.setattr("src.llm.provider.get_chat_model", lambda: fake)
        m1 = attacker_nodes._get_model("reconnaissance")
        m2 = attacker_nodes._get_model("execution")
        # Distintos objetos -> distintos subsets bound
        assert m1 is not m2
