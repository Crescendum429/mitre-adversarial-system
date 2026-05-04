"""Tests del generador de reporte HTML."""

from pathlib import Path

from src.ui.report import generate_report
from src.ui.session import SessionRecorder


class TestReportGeneration:
    def _build_session(self) -> dict:
        s = SessionRecorder()
        s.set_metadata(
            scenario="basic",
            attacker_provider="openai",
            attacker_model="gpt-4.1",
            seed=42,
        )
        s.system_event("session_start", scenario="basic")
        s.attacker_event("tactic_start", tactic="reconnaissance")
        s.attacker_event(
            "tool_call",
            tactic="reconnaissance",
            tool="run_nmap",
            args={"target": "10.10.0.10", "flags": "-sV"},
        )
        s.attacker_event(
            "tool_result",
            tactic="reconnaissance",
            tool="run_nmap",
            size=512,
            preview="80/tcp open http Apache",
        )
        s.attacker_event(
            "objective_check",
            tactic="reconnaissance",
            success=True,
            reason="Puerto 80 open",
            evidence={"port_80_open": True, "web_technologies": ["Apache"]},
        )
        s.attacker_event("tactic_end", tactic="reconnaissance", success=True)
        s.system_event("session_end")
        return s.to_dict()

    def test_generate_report_creates_file(self, tmp_path: Path):
        data = self._build_session()
        out = tmp_path / "report.html"
        generate_report(data, out)
        assert out.exists()

    def test_report_contains_metadata(self, tmp_path: Path):
        data = self._build_session()
        out = tmp_path / "report.html"
        generate_report(data, out)
        html = out.read_text()
        assert "basic" in html
        assert "gpt-4.1" in html
        assert "42" in html

    def test_report_contains_tactic_status(self, tmp_path: Path):
        data = self._build_session()
        out = tmp_path / "report.html"
        generate_report(data, out)
        html = out.read_text()
        assert "reconnaissance" in html
        assert "CUMPLIDA" in html

    def test_report_contains_tool_calls(self, tmp_path: Path):
        data = self._build_session()
        out = tmp_path / "report.html"
        generate_report(data, out)
        html = out.read_text()
        assert "run_nmap" in html
        assert "10.10.0.10" in html

    def test_report_with_observer_events(self, tmp_path: Path):
        s = SessionRecorder()
        s.set_metadata(scenario="basic")
        s.observer_event("triage", result="signal", signals_count=3)
        s.observer_event(
            "classify",
            tactic="Reconnaissance",
            confidence=0.95,
            tactics_in_window=["Reconnaissance"],
        )
        out = tmp_path / "report.html"
        generate_report(s.to_dict(), out)
        html = out.read_text()
        assert "Reconnaissance" in html
        assert "95%" in html

    def test_report_handles_failed_tactic(self, tmp_path: Path):
        s = SessionRecorder()
        s.set_metadata(scenario="basic")
        s.attacker_event("tactic_start", tactic="execution")
        s.attacker_event(
            "objective_check",
            tactic="execution",
            success=False,
            reason="RCE no verificada",
            attempts=15,
        )
        s.attacker_event("tactic_end", tactic="execution", success=False)
        out = tmp_path / "report.html"
        generate_report(s.to_dict(), out)
        html = out.read_text()
        assert "FALLIDA" in html

    def test_report_html_is_valid_structure(self, tmp_path: Path):
        data = self._build_session()
        out = tmp_path / "report.html"
        generate_report(data, out)
        html = out.read_text()
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert '<style>' in html

    def test_report_sanitizes_html_in_payload(self, tmp_path: Path):
        """Si el payload contiene HTML/JS malicioso, debe ser escapado."""
        s = SessionRecorder()
        s.set_metadata(scenario="basic")
        s.attacker_event(
            "tool_result",
            tactic="recon",
            tool="run_nmap",
            preview="<script>alert('xss')</script>",
        )
        out = tmp_path / "report.html"
        generate_report(s.to_dict(), out)
        html = out.read_text()
        assert "<script>alert(" not in html  # debe estar escapado
        assert "&lt;script&gt;" in html or "&lt;" in html
