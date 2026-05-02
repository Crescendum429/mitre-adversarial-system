"""Tests para las cuatro mejoras post-cierre: caching, thinking, loop detection, preflight."""

import json

import pytest

from src.config.settings import LLMProvider, settings


# ---------- M1: Anthropic prompt caching ----------

def test_make_cacheable_returns_str_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "prompt_caching_enabled", False)
    monkeypatch.setattr(settings, "llm_provider", LLMProvider.ANTHROPIC)
    from src.llm.provider import make_cacheable_system_content
    out = make_cacheable_system_content("hello", role="attacker")
    assert out == "hello"


def test_make_cacheable_returns_blocks_for_anthropic(monkeypatch):
    monkeypatch.setattr(settings, "prompt_caching_enabled", True)
    monkeypatch.setattr(settings, "llm_provider", LLMProvider.ANTHROPIC)
    from src.llm.provider import make_cacheable_system_content
    out = make_cacheable_system_content("a long prompt here", role="attacker")
    assert isinstance(out, list)
    assert out[0]["type"] == "text"
    assert out[0]["text"] == "a long prompt here"
    assert out[0]["cache_control"] == {"type": "ephemeral"}


def test_make_cacheable_returns_str_for_non_anthropic(monkeypatch):
    monkeypatch.setattr(settings, "prompt_caching_enabled", True)
    monkeypatch.setattr(settings, "llm_provider", LLMProvider.OPENAI)
    from src.llm.provider import make_cacheable_system_content
    out = make_cacheable_system_content("prompt", role="attacker")
    assert out == "prompt"


def test_make_cacheable_observer_role_uses_observer_provider(monkeypatch):
    monkeypatch.setattr(settings, "prompt_caching_enabled", True)
    monkeypatch.setattr(settings, "llm_provider", LLMProvider.OPENAI)
    monkeypatch.setattr(settings, "observer_provider", LLMProvider.ANTHROPIC)
    from src.llm.provider import make_cacheable_system_content
    out = make_cacheable_system_content("p", role="observer")
    assert isinstance(out, list)
    assert out[0]["cache_control"] == {"type": "ephemeral"}


# ---------- M2: Extended thinking opt-in ----------

def test_thinking_disabled_by_default():
    assert settings.anthropic_thinking_enabled is False


def test_build_model_anthropic_thinking_passes_kwargs(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_thinking_enabled", True)
    monkeypatch.setattr(settings, "anthropic_thinking_budget_tokens", 3000)
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-test")
    captured = {}

    class FakeChatAnthropic:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    import sys as _s
    fake_mod = type(_s)("langchain_anthropic")
    fake_mod.ChatAnthropic = FakeChatAnthropic
    monkeypatch.setitem(_s.modules, "langchain_anthropic", fake_mod)

    from src.llm.provider import _build_model
    _build_model(LLMProvider.ANTHROPIC, "claude-sonnet-4-5", role="attacker")
    assert captured.get("thinking") == {"type": "enabled", "budget_tokens": 3000}
    assert captured.get("temperature") == 1.0
    assert captured.get("max_tokens") >= 4024


def test_build_model_openai_oseries_reasoning_effort(monkeypatch):
    monkeypatch.setattr(settings, "openai_reasoning_effort", "high")
    monkeypatch.setattr(settings, "openai_api_key", "sk-test")
    captured = {}

    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    import sys as _s
    fake_mod = type(_s)("langchain_openai")
    fake_mod.ChatOpenAI = FakeChatOpenAI
    monkeypatch.setitem(_s.modules, "langchain_openai", fake_mod)

    from src.llm.provider import _build_model
    _build_model(LLMProvider.OPENAI, "o4-mini", role="attacker")
    assert captured.get("reasoning_effort") == "high"
    # o-series no acepta temperature/seed; deben removerse
    assert "temperature" not in captured
    assert "seed" not in captured


def test_build_model_openai_gpt4_ignores_reasoning_effort(monkeypatch):
    monkeypatch.setattr(settings, "openai_reasoning_effort", "high")
    monkeypatch.setattr(settings, "openai_api_key", "sk-test")
    captured = {}

    class FakeChatOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    import sys as _s
    fake_mod = type(_s)("langchain_openai")
    fake_mod.ChatOpenAI = FakeChatOpenAI
    monkeypatch.setitem(_s.modules, "langchain_openai", fake_mod)

    from src.llm.provider import _build_model
    _build_model(LLMProvider.OPENAI, "gpt-4.1", role="attacker")
    # GPT-4.1 NO es o-series: reasoning_effort no debe pasarse
    assert "reasoning_effort" not in captured
    assert "temperature" in captured


# ---------- M3: Loop detection ----------

def test_loop_detection_disabled(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", False)
    from src.agents.attacker.nodes import _is_loop, _action_signature
    sig = _action_signature("run_nmap", {"target": "10.10.0.10"})
    history = [{"technique": "run_nmap", "command": '{"target": "10.10.0.10"}'}] * 5
    assert _is_loop(history, sig) is False


def test_loop_detection_triggers_on_3_repetitions(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 6)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _is_loop, _action_signature
    sig = _action_signature("run_gobuster", {"url": "x", "wordlist": "rockyou"})
    history = [
        {"technique": "run_gobuster", "command": '{"url": "x", "wordlist": "rockyou"}'},
        {"technique": "run_curl", "command": '{"url": "x"}'},
        {"technique": "run_gobuster", "command": '{"url": "x", "wordlist": "rockyou"}'},
    ]
    # Candidata + 2 previas iguales = threshold 3 → True
    assert _is_loop(history, sig) is True


def test_loop_detection_distinguishes_args(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 6)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _is_loop, _action_signature
    sig = _action_signature("run_gobuster", {"url": "x", "wordlist": "small"})
    history = [
        {"technique": "run_gobuster", "command": '{"url": "x", "wordlist": "rockyou"}'},
        {"technique": "run_gobuster", "command": '{"url": "x", "wordlist": "rockyou"}'},
    ]
    # Args distintos = no es loop
    assert _is_loop(history, sig) is False


def test_loop_detection_only_within_window(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 3)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _is_loop, _action_signature
    sig = _action_signature("run_nmap", {"target": "10.10.0.10"})
    # 2 matches en hace mucho, ventana=3 los descarta
    history = [
        {"technique": "run_nmap", "command": '{"target": "10.10.0.10"}'},
        {"technique": "run_nmap", "command": '{"target": "10.10.0.10"}'},
        {"technique": "run_curl", "command": '{}'},
        {"technique": "run_curl", "command": '{}'},
        {"technique": "run_curl", "command": '{}'},
    ]
    assert _is_loop(history, sig) is False


# ---------- M4: Preflight check ----------

def test_preflight_disabled_skips(monkeypatch):
    monkeypatch.setattr(settings, "preflight_check_enabled", False)
    from src.main import preflight_llm_check
    # No debe llamar al LLM ni lanzar excepcion
    preflight_llm_check()


def test_preflight_enabled_calls_both_models(monkeypatch):
    monkeypatch.setattr(settings, "preflight_check_enabled", True)
    calls = []

    class FakeModel:
        def __init__(self, label):
            self.label = label

        def invoke(self, msgs):
            calls.append(self.label)

            class R:
                content = "OK"
            return R()

    monkeypatch.setattr("src.llm.provider.get_chat_model", lambda: FakeModel("attacker"))
    monkeypatch.setattr("src.llm.provider.get_observer_model", lambda: FakeModel("observer"))

    from src.main import preflight_llm_check
    preflight_llm_check()
    assert calls == ["attacker", "observer"]


def test_preflight_aborts_on_failure(monkeypatch):
    monkeypatch.setattr(settings, "preflight_check_enabled", True)

    class BrokenModel:
        def invoke(self, msgs):
            raise RuntimeError("api key invalid")

    monkeypatch.setattr("src.llm.provider.get_chat_model", lambda: BrokenModel())
    monkeypatch.setattr("src.llm.provider.get_observer_model", lambda: BrokenModel())

    from src.main import preflight_llm_check
    with pytest.raises(SystemExit) as exc:
        preflight_llm_check()
    assert exc.value.code == 2
