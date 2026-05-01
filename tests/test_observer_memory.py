"""Tests del modulo de memoria/baseline del observador.

Justificacion: NIST SP 800-94 recomienda baselines per-asset para SIEMs;
estos tests aseguran que la baseline es estable, no contamina entre targets
distintos, y se actualiza correctamente.
"""

from pathlib import Path

import pytest

from src.agents.observer import memory


@pytest.fixture
def tmp_baseline(monkeypatch, tmp_path):
    f = tmp_path / "baselines.json"
    monkeypatch.setattr(memory, "BASELINE_FILE", f)
    yield f


def _log(container: str, method: str, status: str) -> dict:
    return {
        "labels": {"container_name": container},
        "message": (
            f'10.10.0.5 - - [01/Jan/2026:12:00:00 +0000] '
            f'"{method} /test HTTP/1.1" {status} 1234 "-" "-"'
        ),
    }


class TestComputeTrafficFingerprint:
    def test_empty_logs_returns_empty(self):
        assert memory.compute_traffic_fingerprint([]) == ""

    def test_deterministic(self):
        logs = [_log("dvwa", "GET", "200"), _log("dvwa", "POST", "302")]
        fp1 = memory.compute_traffic_fingerprint(logs)
        fp2 = memory.compute_traffic_fingerprint(logs)
        assert fp1 == fp2 and len(fp1) == 16

    def test_invariant_to_order(self):
        logs1 = [_log("dvwa", "GET", "200"), _log("dvwa", "POST", "302")]
        logs2 = [_log("dvwa", "POST", "302"), _log("dvwa", "GET", "200")]
        # Cuenta de methods/statuses es la misma → mismo fp
        assert memory.compute_traffic_fingerprint(logs1) == memory.compute_traffic_fingerprint(logs2)

    def test_different_container_different_fp(self):
        dvwa_logs = [_log("dvwa", "GET", "200")]
        wp_logs = [_log("mrrobot", "GET", "200")]
        assert (memory.compute_traffic_fingerprint(dvwa_logs)
                != memory.compute_traffic_fingerprint(wp_logs))

    def test_caps_at_200_logs_for_speed(self):
        """No debe colgar con miles de logs."""
        big = [_log("dvwa", "GET", "200")] * 5000
        fp = memory.compute_traffic_fingerprint(big)
        assert fp  # produce algo


class TestBaselinePersistence:
    def test_get_prior_missing_returns_none(self, tmp_baseline):
        assert memory.get_prior("nonexistent") is None

    def test_update_creates_entry(self, tmp_baseline):
        classifications = [
            {"tactic": "Reconnaissance"},
            {"tactic": "Reconnaissance"},
            {"tactic": "Initial Access"},
        ]
        memory.update_baseline("test_fp", classifications, target_summary="dvwa")
        prior = memory.get_prior("test_fp")
        assert prior is not None
        assert prior["windows_observed"] == 3
        dist = prior["tactic_distribution"]
        # 2/3 recon, 1/3 init_access
        assert dist["reconnaissance"] > dist.get("initial_access", 0)

    def test_update_normalizes_tactic_names(self, tmp_baseline):
        memory.update_baseline("fp", [{"tactic": "Initial Access"}])
        prior = memory.get_prior("fp")
        assert "initial_access" in prior["tactic_distribution"]

    def test_update_skips_none_tactics(self, tmp_baseline):
        memory.update_baseline("fp", [
            {"tactic": "Reconnaissance"},
            {"tactic": "none"},
            {"tactic": "none"},
        ])
        prior = memory.get_prior("fp")
        # Solo recon contado en distribution (none excluido)
        assert "reconnaissance" in prior["tactic_distribution"]
        assert "none" not in prior["tactic_distribution"]

    def test_incremental_update_merges_distributions(self, tmp_baseline):
        # Run 1: 2 recon
        memory.update_baseline("fp", [
            {"tactic": "Reconnaissance"},
            {"tactic": "Reconnaissance"},
        ])
        # Run 2: 2 init_access
        memory.update_baseline("fp", [
            {"tactic": "Initial Access"},
            {"tactic": "Initial Access"},
        ])
        prior = memory.get_prior("fp")
        # Total 4 ventanas, 50/50 recon/init_access
        assert prior["windows_observed"] == 4
        dist = prior["tactic_distribution"]
        assert abs(dist["reconnaissance"] - 0.5) < 0.01
        assert abs(dist["initial_access"] - 0.5) < 0.01


class TestRenderPriorForPrompt:
    def test_renders_distribution(self):
        prior = {
            "tactic_distribution": {
                "reconnaissance": 0.5,
                "initial_access": 0.3,
                "execution": 0.2,
            },
            "common_sequence": ["reconnaissance", "initial_access", "execution"],
            "windows_observed": 10,
            "target_summary": "dvwa local",
        }
        rendered = memory.render_prior_for_prompt(prior)
        assert "reconnaissance" in rendered.lower()
        assert "10" in rendered
        assert "dvwa local" in rendered

    def test_returns_empty_string_for_none(self):
        assert memory.render_prior_for_prompt(None) == ""
        assert memory.render_prior_for_prompt({}) == ""

    def test_empty_distribution_returns_empty(self):
        prior = {"tactic_distribution": {}, "windows_observed": 0}
        assert memory.render_prior_for_prompt(prior) == ""
