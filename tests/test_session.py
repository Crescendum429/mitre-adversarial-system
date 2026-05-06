"""Tests del session recorder."""

import json
from datetime import datetime, timezone
from pathlib import Path

from src.ui.session import (
    SessionEvent,
    SessionRecorder,
    _enrich_for_frontend,
    get_session,
)


class TestSessionRecorder:
    def test_record_event_default_agent_system(self):
        s = SessionRecorder()
        s.record("session_start", scenario="basic")
        assert len(s.events) == 1
        ev = s.events[0]
        assert ev.event_type == "session_start"
        assert ev.agent == "system"
        assert ev.payload["scenario"] == "basic"

    def test_attacker_event(self):
        s = SessionRecorder()
        s.attacker_event("tactic_start", tactic="reconnaissance")
        assert s.events[0].agent == "attacker"
        assert s.events[0].tactic == "reconnaissance"

    def test_observer_event(self):
        s = SessionRecorder()
        s.observer_event("triage", result="signal", signals_count=5)
        ev = s.events[0]
        assert ev.agent == "observer"
        assert ev.payload["result"] == "signal"
        assert ev.payload["signals_count"] == 5

    def test_reset_clears_events(self):
        s = SessionRecorder()
        s.attacker_event("tactic_start", tactic="recon")
        s.set_metadata(scenario="basic")
        s.reset()
        assert s.events == []
        assert s.metadata == {}

    def test_set_metadata(self):
        s = SessionRecorder()
        s.set_metadata(scenario="dvwa", seed=42)
        s.set_metadata(model="gpt-4.1")
        assert s.metadata["scenario"] == "dvwa"
        assert s.metadata["seed"] == 42
        assert s.metadata["model"] == "gpt-4.1"

    def test_to_dict_structure(self):
        s = SessionRecorder()
        s.set_metadata(scenario="basic")
        s.attacker_event("tool_call", tactic="recon", tool="nmap")
        d = s.to_dict()
        assert "metadata" in d
        assert "events" in d
        assert d["metadata"]["scenario"] == "basic"
        assert len(d["events"]) == 1
        assert d["events"][0]["agent"] == "attacker"

    def test_save_json_creates_file(self, tmp_path: Path):
        s = SessionRecorder()
        s.set_metadata(scenario="basic")
        s.attacker_event("tool_call", tactic="recon", tool="nmap")
        out = tmp_path / "session.json"
        s.save_json(out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["metadata"]["scenario"] == "basic"
        assert len(data["events"]) == 1

    def test_thread_safety(self):
        """Tests basicos de thread-safety: no debe perder eventos en concurrent record."""
        import threading
        s = SessionRecorder()

        def record_n(n: int):
            for i in range(n):
                s.attacker_event("tool_call", tactic="recon", tool=f"tool_{i}")

        threads = [threading.Thread(target=record_n, args=(50,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(s.events) == 200


class TestSessionSingleton:
    def test_get_session_returns_same_instance(self):
        s1 = get_session()
        s2 = get_session()
        assert s1 is s2

    def test_singleton_reset_persists(self):
        s = get_session()
        s.reset()
        s.attacker_event("test", tactic="t")
        assert len(s.events) == 1
        # Otra obtencion del singleton ve el mismo estado
        assert len(get_session().events) == 1
        s.reset()


class TestEnrichForFrontendPropagatesTacticsInWindow:
    """Regresion H1: el evento classify del observer transporta
    tactics_in_window como list[dict]; metrics.evaluate filtra con
    `isinstance(t, dict)` y descarta strings, cayendo al fallback
    single-label que degrada macro_f1/micro_f1 en el JSON persistido.

    Pre-fix el observer aplanaba la lista a list[str] al emitir el evento;
    post-fix la pasa intacta. Este test exercises el camino end-to-end
    desde el evento hasta evaluation.per_tactic.
    """

    def test_multilabel_observation_produces_fp_in_other_tactic(self):
        recorder = SessionRecorder()
        ts_pre = datetime(2026, 5, 6, 9, 59, 55, tzinfo=timezone.utc).isoformat()
        ws = datetime(2026, 5, 6, 10, 0, 0, tzinfo=timezone.utc).isoformat()
        ts_in = datetime(2026, 5, 6, 10, 0, 2, tzinfo=timezone.utc).isoformat()
        we = datetime(2026, 5, 6, 10, 0, 5, tzinfo=timezone.utc).isoformat()
        ts_post = datetime(2026, 5, 6, 10, 0, 10, tzinfo=timezone.utc).isoformat()

        recorder.set_metadata(
            scenario="basic",
            attacker_provider="openai",
            attacker_model="gpt-4.1",
            observer_provider="openai",
            observer_model="gpt-4.1-mini",
            seed=42,
            started_at=ts_pre,
        )
        # Atacante: initial_access antes de la ventana, durante, y despues
        # (para que attack_end > ws y la ventana NO sea post-ataque).
        for ts in (ts_pre, ts_in, ts_post):
            recorder.events.append(SessionEvent(
                timestamp=ts,
                agent="attacker",
                event_type="tool_call",
                tactic="initial_access",
                payload={"tool": "run_hydra"},
            ))
        recorder.events.append(SessionEvent(
            timestamp=ws,
            agent="observer",
            event_type="classify",
            tactic="initial_access",
            payload={
                "window_start": ws,
                "window_end": we,
                "tactics_in_window": [
                    {"tactic": "initial_access", "tactic_id": "TA0001"},
                    {"tactic": "reconnaissance", "tactic_id": "TA0043"},
                ],
            },
        ))

        data = recorder.to_dict()
        _enrich_for_frontend(data)

        ev = data["metadata"].get("evaluation")
        assert isinstance(ev, dict), "evaluation no fue inyectada por enrichment"
        per = ev.get("per_tactic", {})
        rec = per.get("reconnaissance", {})
        assert rec.get("fp", 0) == 1, (
            f"Esperaba fp=1 en reconnaissance (multi-label correcto), vi {rec}. "
            f"Si fp=0, el observer aplano tactics_in_window a list[str] y el "
            f"filtro isinstance(t, dict) en metrics descarto las observaciones "
            f"-> fallback single-label -> reconnaissance no cuenta como FP."
        )
        ia = per.get("initial_access", {})
        assert ia.get("tp", 0) == 1, (
            "initial_access esperaba tp=1 (real e observed coinciden)"
        )


class TestObserverClassifyEventCarriesWindow:
    """Regresion critica: el evento classify del observer debe transportar
    window_start y window_end del state. Sin esos campos, _enrich_for_frontend
    cae al timestamp del evento (= cuando el LLM termino de clasificar, no
    cuando empezo la ventana observada). El matching ground-truth en
    metrics.evaluate queda desfasado por 5-15s = mF1 colapsa a 0.

    Detectado al inspeccionar reports del Eje A donde Haiku 4.5 daba mF1=0
    pese a clasificar correctamente Reconnaissance / Initial Access.
    """

    def test_classify_event_includes_window_bounds_llm_path(self):
        from unittest.mock import patch
        from src.agents.observer import nodes as obs_nodes
        from src.ui.session import SessionRecorder

        recorder = SessionRecorder()
        with patch("src.agents.observer.nodes.get_session", lambda: recorder), \
             patch.object(obs_nodes, "_get_model") as mock_model, \
             patch.object(obs_nodes, "_parse_classification") as mock_parse:
            mock_parse.return_value = {
                "tactic": "Reconnaissance",
                "tactic_id": "TA0043",
                "confidence": 0.85,
                "tactics_in_window": [{"tactic": "Reconnaissance", "tactic_id": "TA0043"}],
                "evidence": ["nmap scan"],
                "reasoning": "test",
                "recommendation": "alert",
            }
            class _M:
                def invoke(self, *a, **kw):
                    class R: content = "{}"
                    return R()
            mock_model.return_value = _M()

            state = {
                "window_start": "2026-05-06T10:00:00+00:00",
                "window_end": "2026-05-06T10:00:05+00:00",
                "log_summary": "log",
                "anomaly_signals": {},
                "baseline_prior": None,
                "has_new_logs": True,
                "classification_history": [],
                "refinement_count": 0,
            }
            obs_nodes.classify_tactic(state)

        classify_evts = [e for e in recorder.events if e.event_type == "classify"]
        assert classify_evts, "no classify event emitido"
        p = classify_evts[0].payload
        assert p.get("window_start") == "2026-05-06T10:00:00+00:00", \
            f"window_start ausente o incorrecto en classify event: {p}"
        assert p.get("window_end") == "2026-05-06T10:00:05+00:00", \
            f"window_end ausente o incorrecto en classify event: {p}"

    def test_classify_event_includes_window_bounds_regex_only_path(self):
        from unittest.mock import patch
        from src.agents.observer import nodes as obs_nodes
        from src.ui.session import SessionRecorder

        recorder = SessionRecorder()
        with patch("src.agents.observer.nodes.get_session", lambda: recorder):
            state = {
                "window_start": "2026-05-06T11:00:00+00:00",
                "window_end": "2026-05-06T11:00:05+00:00",
                "has_new_logs": True,
                "anomaly_signals": {
                    "suspicious_ips": {
                        "10.10.0.5": {"login_success": 1, "tool_detected": True}
                    },
                    "webshell_commands": [],
                },
            }
            obs_nodes.derive_tactic_from_signals(state)

        classify_evts = [e for e in recorder.events if e.event_type == "classify"]
        assert classify_evts, "no classify event emitido en path regex_only"
        p = classify_evts[0].payload
        assert p.get("window_start") == "2026-05-06T11:00:00+00:00"
        assert p.get("window_end") == "2026-05-06T11:00:05+00:00"


class TestEnrichForFrontendInjectsBootstrapCi:
    """Regresion H2: cuando incremental_save corre durante el run,
    _enrich_for_frontend popula metadata.evaluation sin bootstrap_ci
    (porque _LAST_BOOTSTRAP_CI aun es None). Cuando _emit_report tardio
    setea metadata.bootstrap_ci al top-level, el gate "evaluation" not
    in md impedia el recompute y bootstrap_ci nunca llegaba dentro de
    evaluation. El frontend lee ev.bootstrap_ci -> sin CIs visibles.

    Post-fix: post-injection inyecta bootstrap_ci en evaluation cuando
    ya existe, sin tocar el gate.
    """

    def test_bootstrap_ci_set_after_evaluation_lands_in_evaluation(self):
        recorder = SessionRecorder()
        ws = datetime(2026, 5, 6, 10, 0, 0, tzinfo=timezone.utc).isoformat()
        we = datetime(2026, 5, 6, 10, 0, 5, tzinfo=timezone.utc).isoformat()

        recorder.set_metadata(
            scenario="basic",
            attacker_provider="openai",
            attacker_model="gpt-4.1",
            observer_provider="openai",
            observer_model="gpt-4.1-mini",
            seed=42,
            started_at=ws,
        )
        recorder.events.append(SessionEvent(
            timestamp=ws,
            agent="attacker",
            event_type="tool_call",
            tactic="reconnaissance",
            payload={"tool": "run_nmap"},
        ))
        recorder.events.append(SessionEvent(
            timestamp=ws,
            agent="observer",
            event_type="classify",
            tactic="reconnaissance",
            payload={
                "window_start": ws,
                "window_end": we,
                "tactics_in_window": [{"tactic": "reconnaissance"}],
            },
        ))

        # 1ra pasada: incremental_save corre antes que set_metadata bootstrap_ci.
        data1 = recorder.to_dict()
        _enrich_for_frontend(data1)
        recorder.metadata = data1["metadata"]
        assert "evaluation" in recorder.metadata
        assert "bootstrap_ci" not in recorder.metadata["evaluation"], (
            "Setup: bootstrap_ci no deberia existir aun en evaluation."
        )

        # 2da pasada: _emit_report tardio setea bootstrap_ci al top-level y
        # vuelve a guardar (otra invocacion de _enrich_for_frontend).
        recorder.set_metadata(
            bootstrap_ci={
                "macro_f1": {"mean": 0.5, "ci_low": 0.4, "ci_high": 0.6},
            }
        )
        data2 = recorder.to_dict()
        _enrich_for_frontend(data2)

        ev = data2["metadata"].get("evaluation", {})
        assert "bootstrap_ci" in ev, (
            "bootstrap_ci no fue inyectado en evaluation tras set_metadata "
            "tardio. Frontend en modo live no veria los IC95."
        )
        assert ev["bootstrap_ci"]["macro_f1"]["mean"] == 0.5


class TestEmitReportPersistsFinalMetadata:
    """Regresion: _emit_report debe poblar costs/tokens/bootstrap_ci antes del
    save_json final. El bug previo dejaba session_json_path como variable local
    de main() invisible al top-level _emit_report -> NameError -> set_metadata
    final nunca corre y los JSONs quedan sin attacker_cost_usd, time_*_llm_s,
    bootstrap_ci, tactic_duration_seconds.
    """

    def test_emit_report_writes_final_metadata(self, tmp_path: Path, monkeypatch):
        import src.main as m
        from src.infrastructure.docker_client import DOCKER_STATS
        from src.infrastructure.loki_client import LOKI_STATS
        from src.llm.provider import USAGE_STATS, reset_usage_stats

        reset_usage_stats()
        USAGE_STATS["attacker"].update(
            provider="openai",
            model="gpt-4.1",
            call_count=42,
            input_tokens=10_000,
            output_tokens=2_000,
            total_tokens=12_000,
            elapsed_seconds=120.5,
        )
        USAGE_STATS["observer"].update(
            provider="openai",
            model="gpt-4.1-mini",
            call_count=15,
            input_tokens=5_000,
            output_tokens=500,
            total_tokens=5_500,
            elapsed_seconds=45.0,
        )
        DOCKER_STATS["total_seconds"] = 60.0
        LOKI_STATS["total_seconds"] = 5.0

        bootstrap_ci_payload = {
            "macro_f1": {"mean": 0.485, "ci_low": 0.30, "ci_high": 0.69}
        }
        monkeypatch.setattr(m, "_LAST_BOOTSTRAP_CI", bootstrap_ci_payload)
        monkeypatch.setattr(
            m, "generate_report", lambda data, path: Path(path).write_text("stub")
        )

        session = get_session()
        session.reset()
        session.set_metadata(
            scenario="basic",
            attacker_provider="openai",
            attacker_model="gpt-4.1",
            observer_provider="openai",
            observer_model="gpt-4.1-mini",
        )

        class FakeArgs:
            no_report = False
            target = ""
            report_dir = str(tmp_path)
            scenario = "basic"

        scenario_config = {"tactics": ["reconnaissance"], "target": ""}
        attacker_state = {
            "attacker_elapsed_seconds": 175.0,
            "tactic_objective_met": {"reconnaissance": True},
            "tactic_duration_seconds": {"reconnaissance": 30.0},
            "action_history": [{"tool": "nmap"}, {"tool": "gobuster"}],
            "attempts_per_tactic": {"reconnaissance": 1},
            "matched_playbook": None,
            "target_fingerprint": "abc123",
        }
        json_path = tmp_path / "test_run.json"

        try:
            m._emit_report(
                FakeArgs(), scenario_config, attacker_state, [], json_path
            )
        finally:
            reset_usage_stats()
            DOCKER_STATS["total_seconds"] = 0.0
            LOKI_STATS["total_seconds"] = 0.0
            session.reset()

        assert json_path.exists()
        data = json.loads(json_path.read_text())
        md = data["metadata"]

        assert md.get("attacker_cost_usd", 0) > 0, (
            f"attacker_cost_usd vacio: posible regresion del NameError "
            f"que omitia el set_metadata final. metadata={list(md)}"
        )
        assert md.get("time_attacker_llm_s", 0) > 0
        assert md.get("time_observer_llm_s", 0) > 0
        assert md.get("bootstrap_ci") == bootstrap_ci_payload
        assert md.get("tactic_duration_seconds") == {"reconnaissance": 30.0}
        assert md.get("memory_hit") is False
        assert md.get("tool_calls") == 2
        assert md.get("finished_at"), "finished_at no fue seteado"
        assert md.get("tactics_completed") == 1
