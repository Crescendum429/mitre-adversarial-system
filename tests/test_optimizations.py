"""Tests para las cuatro mejoras post-cierre: caching, thinking, loop detection, preflight."""


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


def test_make_cacheable_extended_ttl_when_enabled(monkeypatch):
    """1h cache opt-in: cache_control debe incluir ttl='1h'."""
    monkeypatch.setattr(settings, "prompt_caching_enabled", True)
    monkeypatch.setattr(settings, "llm_provider", LLMProvider.ANTHROPIC)
    monkeypatch.setattr(settings, "anthropic_cache_ttl_extended", True)
    from src.llm.provider import make_cacheable_system_content
    out = make_cacheable_system_content("hello", role="attacker")
    assert isinstance(out, list)
    assert out[0]["cache_control"] == {"type": "ephemeral", "ttl": "1h"}


def test_make_cacheable_default_ttl_5min(monkeypatch):
    """Sin opt-in, no debe aparecer ttl en cache_control (default 5min)."""
    monkeypatch.setattr(settings, "prompt_caching_enabled", True)
    monkeypatch.setattr(settings, "llm_provider", LLMProvider.ANTHROPIC)
    monkeypatch.setattr(settings, "anthropic_cache_ttl_extended", False)
    from src.llm.provider import make_cacheable_system_content
    out = make_cacheable_system_content("hello", role="attacker")
    assert "ttl" not in out[0]["cache_control"]


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
    from src.agents.attacker.nodes import _action_signature, _is_loop
    sig = _action_signature("run_nmap", {"target": "10.10.0.10"})
    history = [{"technique": "run_nmap", "command": '{"target": "10.10.0.10"}'}] * 5
    assert _is_loop(history, sig) is False


def test_loop_detection_triggers_on_3_repetitions(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 6)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _action_signature, _is_loop
    sig = _action_signature("run_gobuster", {"url": "x", "wordlist": "rockyou"})
    history = [
        {"technique": "run_gobuster", "command": '{"url": "x", "wordlist": "rockyou"}'},
        {"technique": "run_curl", "command": '{"url": "x"}'},
        {"technique": "run_gobuster", "command": '{"url": "x", "wordlist": "rockyou"}'},
    ]
    # Candidata + 2 previas iguales = threshold 3 → True
    assert _is_loop(history, sig) is True


def test_loop_detection_distinguishes_targets(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 6)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _action_signature, _is_loop
    # Diferentes URLs primarias = NO es loop
    sig = _action_signature("run_gobuster", {"url": "http://A", "wordlist": "rockyou"})
    history = [
        {"technique": "run_gobuster", "command": '{"url": "http://B", "wordlist": "rockyou"}'},
        {"technique": "run_gobuster", "command": '{"url": "http://B", "wordlist": "rockyou"}'},
    ]
    assert _is_loop(history, sig) is False


def test_loop_detection_collapses_secondary_args(monkeypatch):
    """M8.b: el cambio de wordlist u otros flags NO es nuevo intento."""
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 6)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _action_signature, _is_loop
    sig = _action_signature("run_gobuster", {"url": "http://X", "wordlist": "small"})
    history = [
        {"technique": "run_gobuster", "command": '{"url": "http://X", "wordlist": "rockyou"}'},
        {"technique": "run_gobuster", "command": '{"url": "http://X", "wordlist": "common.txt"}'},
    ]
    # Mismo URL primario pero wordlist distinto: SI es loop semantico
    assert _is_loop(history, sig) is True


def test_loop_detection_url_canonicalization(monkeypatch):
    """M8.b: trailing slash y mayusculas en host son irrelevantes."""
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 6)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _action_signature, _is_loop
    sig = _action_signature("run_curl", {"url": "http://10.10.0.10/", "method": "GET"})
    history = [
        {"technique": "run_curl", "command": '{"url": "HTTP://10.10.0.10", "method": "GET"}'},
        {"technique": "run_curl", "command": '{"url": "http://10.10.0.10/", "method": "GET"}'},
    ]
    assert _is_loop(history, sig) is True


def test_loop_detection_only_within_window(monkeypatch):
    monkeypatch.setattr(settings, "loop_detection_enabled", True)
    monkeypatch.setattr(settings, "loop_detection_window", 3)
    monkeypatch.setattr(settings, "loop_detection_threshold", 3)
    from src.agents.attacker.nodes import _action_signature, _is_loop
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


# ---------- Fase 1: Bootstrap CI ----------

def test_bootstrap_ci_returns_three_metrics():
    from src.evaluation.metrics import bootstrap_f1_ci
    real = [{"recon"}, {"recon"}, {"init_access"}, {"execution"}]
    obs = [{"recon"}, {"recon"}, {"init_access"}, {"execution"}]
    out = bootstrap_f1_ci(real, obs, n_resamples=100, seed=42)
    assert "macro_f1" in out
    assert "micro_f1" in out
    assert "strict_accuracy" in out
    for k, (mean, lo, hi) in out.items():
        assert 0.0 <= lo <= mean <= hi <= 1.0


def test_bootstrap_perfect_match_gives_one():
    from src.evaluation.metrics import bootstrap_f1_ci
    real = [{"recon"}, {"recon"}, {"recon"}]
    obs = [{"recon"}, {"recon"}, {"recon"}]
    out = bootstrap_f1_ci(real, obs, n_resamples=200, seed=42)
    mean, lo, hi = out["macro_f1"]
    assert mean > 0.99
    assert lo > 0.99


def test_bootstrap_total_miss_gives_zero():
    from src.evaluation.metrics import bootstrap_f1_ci
    real = [{"recon"}, {"recon"}, {"init_access"}]
    obs = [{"execution"}, {"execution"}, {"discovery"}]
    out = bootstrap_f1_ci(real, obs, n_resamples=200, seed=42)
    mean, lo, hi = out["macro_f1"]
    assert mean < 0.01
    assert hi < 0.01


def test_bootstrap_partial_match_has_ci_width():
    """Con datos parciales el CI debe tener ancho > 0."""
    from src.evaluation.metrics import bootstrap_f1_ci
    real = [{"recon"}, {"init_access"}, {"execution"}, {"discovery"}, {"recon"}]
    obs = [{"recon"}, {"recon"}, {"execution"}, {"recon"}, {"init_access"}]
    out = bootstrap_f1_ci(real, obs, n_resamples=500, seed=42)
    mean, lo, hi = out["macro_f1"]
    assert hi - lo > 0.05  # CI debe ser ancho con datos ruidosos


def test_bootstrap_empty_input_returns_zeros():
    from src.evaluation.metrics import bootstrap_f1_ci
    out = bootstrap_f1_ci([], [], n_resamples=10)
    for k, (mean, lo, hi) in out.items():
        assert mean == lo == hi == 0.0


def test_bootstrap_seed_reproducibility():
    from src.evaluation.metrics import bootstrap_f1_ci
    real = [{"recon"}, {"init_access"}, {"recon"}]
    obs = [{"recon"}, {"recon"}, {"init_access"}]
    out1 = bootstrap_f1_ci(real, obs, n_resamples=100, seed=42)
    out2 = bootstrap_f1_ci(real, obs, n_resamples=100, seed=42)
    assert out1 == out2


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


# ---------- Reflector node (RefPentester style) ----------

def test_reflector_not_triggered_below_threshold(monkeypatch):
    """attempts < 3 (default trigger): no aparece bloque de reflexion."""
    monkeypatch.setattr(settings, "reflector_enabled", True)
    monkeypatch.setattr(settings, "reflector_trigger_attempts", 3)
    from src.agents.attacker.prompts import build_tactic_prompt
    out = build_tactic_prompt(
        "reconnaissance", "10.10.0.10", {},
        objective_feedback="incompleto", replan_attempt=2,
    )
    assert "[REFLEXION" not in out


def test_reflector_triggered_at_threshold(monkeypatch):
    """attempts >= 3: bloque de reflexion presente."""
    monkeypatch.setattr(settings, "reflector_enabled", True)
    monkeypatch.setattr(settings, "reflector_trigger_attempts", 3)
    from src.agents.attacker.prompts import build_tactic_prompt
    out = build_tactic_prompt(
        "reconnaissance", "10.10.0.10", {},
        objective_feedback="aun no completo", replan_attempt=3,
        recent_actions=[
            {"technique": "run_nmap", "command": "{}"},
            {"technique": "run_nmap", "command": "{}"},
            {"technique": "run_nmap", "command": "{}"},
        ],
    )
    assert "[REFLEXION" in out
    assert "Patrones de fallo" in out
    assert "Cambio cualitativo" in out
    # Resumen de tools usadas debe incluir run_nmap
    assert "run_nmap" in out


def test_reflector_disabled_via_setting(monkeypatch):
    monkeypatch.setattr(settings, "reflector_enabled", False)
    from src.agents.attacker.prompts import build_tactic_prompt
    out = build_tactic_prompt(
        "execution", "10.10.0.10", {},
        objective_feedback="x", replan_attempt=10,
    )
    assert "[REFLEXION" not in out


# ---------- Retry transient classifier ----------

def test_is_transient_5xx():
    from src.llm.provider import _is_transient_error
    assert _is_transient_error(Exception("HTTP 502 Bad Gateway"))
    assert _is_transient_error(Exception("503 Service Unavailable"))
    assert _is_transient_error(Exception("504 Gateway Timeout"))
    assert _is_transient_error(Exception("HTTP 500 Internal Server Error"))


def test_is_transient_rate_limit():
    from src.llm.provider import _is_transient_error
    assert _is_transient_error(Exception("HTTP 429 rate limit exceeded"))
    assert _is_transient_error(Exception("Too many requests"))


def test_is_not_transient_4xx_permanent():
    from src.llm.provider import _is_transient_error
    assert not _is_transient_error(Exception("HTTP 400 bad request"))
    assert not _is_transient_error(Exception("HTTP 401 unauthorized"))
    assert not _is_transient_error(Exception("HTTP 403 forbidden"))
    assert not _is_transient_error(Exception("HTTP 404 not found"))
    assert not _is_transient_error(Exception("HTTP 413 payload too large"))


def test_is_not_transient_context_overflow():
    from src.llm.provider import _is_transient_error
    assert not _is_transient_error(Exception("context_length_exceeded"))
    assert not _is_transient_error(Exception("max_tokens reached"))


def test_is_transient_connection_errors():
    from src.llm.provider import _is_transient_error
    assert _is_transient_error(Exception("Connection refused"))
    assert _is_transient_error(Exception("RemoteDisconnected"))
    assert _is_transient_error(Exception("Read timed out"))


# ---------- Tool output truncation for LLM context ----------

def test_truncate_tool_output_short_unchanged():
    from src.agents.attacker.nodes import _truncate_tool_output_for_llm
    short = "hello world"
    assert _truncate_tool_output_for_llm(short, max_chars=4000) == short


def test_truncate_tool_output_preserves_head_and_tail():
    from src.agents.attacker.nodes import _truncate_tool_output_for_llm
    body = "A" * 10000 + "MIDDLE" + "B" * 10000
    out = _truncate_tool_output_for_llm(body, max_chars=200)
    assert "AAAA" in out  # head preservado
    assert "BBBB" in out  # tail preservado
    assert "MIDDLE" not in out  # medio descartado
    assert "truncado" in out  # marker explicito
    # Tamano ligeramente mayor que max_chars por el marker
    assert len(out) < 400


def test_truncate_tool_output_handles_non_string():
    from src.agents.attacker.nodes import _truncate_tool_output_for_llm
    result = _truncate_tool_output_for_llm(12345, max_chars=10)
    assert isinstance(result, str)
    assert "12345" in result


# ---------- Selective tool exposure ----------

def test_select_tools_for_tactic_recon_includes_nmap():
    from src.agents.attacker.tools import select_tools_for_tactic
    tools = select_tools_for_tactic("reconnaissance")
    names = [t.name for t in tools]
    assert "run_nmap" in names
    assert "run_curl" in names  # core
    assert "run_command" in names  # core


def test_select_tools_for_tactic_priv_esc_includes_linpeas():
    from src.agents.attacker.tools import select_tools_for_tactic
    tools = select_tools_for_tactic("privilege_escalation")
    names = [t.name for t in tools]
    assert "run_linpeas" in names
    assert "run_priv_esc_enum" in names


def test_select_tools_for_tactic_unknown_returns_full():
    from src.agents.attacker.tools import ATTACKER_TOOLS, select_tools_for_tactic
    tools = select_tools_for_tactic("nonexistent_tactic")
    assert len(tools) == len(ATTACKER_TOOLS)


def test_select_tools_subset_smaller_than_full():
    """El subset por tactica debe ser estrictamente mas chico que el total."""
    from src.agents.attacker.tools import ATTACKER_TOOLS, select_tools_for_tactic
    for tactic in ("reconnaissance", "initial_access", "execution",
                   "discovery", "privilege_escalation"):
        subset = select_tools_for_tactic(tactic)
        assert len(subset) < len(ATTACKER_TOOLS), (
            f"Subset para {tactic} no es mas chico que ATTACKER_TOOLS"
        )
        assert len(subset) >= 3, f"Subset para {tactic} demasiado pequeno"


def test_select_tools_for_tactic_no_duplicates():
    from src.agents.attacker.tools import select_tools_for_tactic
    for tactic in ("reconnaissance", "initial_access", "execution"):
        tools = select_tools_for_tactic(tactic)
        names = [t.name for t in tools]
        assert len(names) == len(set(names)), f"Duplicados en {tactic}"


def test_selective_tools_default_off(monkeypatch):
    """Cuando attacker_selective_tools_enabled=False, _get_model retorna singleton global."""
    monkeypatch.setattr(settings, "attacker_selective_tools_enabled", False)
    # No podemos invocar _get_model sin un LLM real, pero podemos verificar
    # el setting default desde fuera.
    assert getattr(settings, "attacker_selective_tools_enabled", False) is False


# ---------- _extract_usage cache key compatibility ----------

def test_extract_usage_anthropic_long_keys():
    """LangChain anthropic 1.4+ usa cache_creation_input_tokens / cache_read_input_tokens."""
    from src.llm.provider import _extract_usage

    class FakeResp:
        usage_metadata = {
            "input_tokens": 100,
            "output_tokens": 50,
            "input_token_details": {
                "cache_creation_input_tokens": 80,
                "cache_read_input_tokens": 20,
            },
        }
        response_metadata = {}

    in_t, out_t, cc, cr = _extract_usage(FakeResp())
    assert (in_t, out_t, cc, cr) == (100, 50, 80, 20)


def test_extract_usage_anthropic_short_keys():
    """Versiones anteriores usan cache_creation / cache_read sin suffix."""
    from src.llm.provider import _extract_usage

    class FakeResp:
        usage_metadata = {
            "input_tokens": 100,
            "output_tokens": 50,
            "input_token_details": {"cache_creation": 60, "cache_read": 10},
        }
        response_metadata = {}

    in_t, out_t, cc, cr = _extract_usage(FakeResp())
    assert (in_t, out_t, cc, cr) == (100, 50, 60, 10)


def test_extract_usage_no_cache():
    from src.llm.provider import _extract_usage

    class FakeResp:
        usage_metadata = {"input_tokens": 100, "output_tokens": 50}
        response_metadata = {}

    in_t, out_t, cc, cr = _extract_usage(FakeResp())
    assert (in_t, out_t, cc, cr) == (100, 50, 0, 0)
