"""Tests del session recorder."""

import json
from pathlib import Path

from src.ui.session import SessionRecorder, get_session


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
