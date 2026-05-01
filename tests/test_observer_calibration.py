"""Tests del modulo de calibracion adaptativa del umbral.

Justificacion: Elkan 2001 (cost-sensitive) y Platt 1999 (calibracion por prior)
demandan que tacticas caras requieran mayor confianza y que un prior alto
relaje el umbral.
"""

import pytest

from src.agents.observer import calibration


class TestBaseThresholdsByTactic:
    def test_reconnaissance_low_threshold(self):
        # Tactica barata: FP solo descarta una ventana
        assert calibration.adaptive_threshold("Reconnaissance", None) == 0.55

    def test_privilege_escalation_high_threshold(self):
        # Tactica cara: FP escala a humano
        assert calibration.adaptive_threshold("Privilege Escalation", None) == 0.75

    def test_exfiltration_high_threshold(self):
        assert calibration.adaptive_threshold("Exfiltration", None) == 0.75

    def test_impact_high_threshold(self):
        assert calibration.adaptive_threshold("Impact", None) == 0.75

    def test_unknown_tactic_uses_default(self):
        assert calibration.adaptive_threshold("Wild Tactic", None) == calibration.DEFAULT_THRESHOLD

    def test_normalizes_case_and_spaces(self):
        a = calibration.adaptive_threshold("Initial Access", None)
        b = calibration.adaptive_threshold("initial_access", None)
        c = calibration.adaptive_threshold("INITIAL ACCESS", None)
        assert a == b == c


class TestPriorAdjustment:
    def test_prior_too_small_uses_base(self):
        prior = {
            "windows_observed": 2,  # < MIN_PRIOR_WINDOWS
            "tactic_distribution": {"reconnaissance": 0.9},
        }
        assert calibration.adaptive_threshold("Reconnaissance", prior) == 0.55

    def test_top3_tactic_gets_bonus(self):
        prior = {
            "windows_observed": 20,
            "tactic_distribution": {
                "reconnaissance": 0.50,
                "initial_access": 0.30,
                "execution": 0.15,
                "discovery": 0.05,
            },
        }
        # Reconnaissance esta en top-3 -> -0.10 sobre base 0.55 = 0.45
        assert calibration.adaptive_threshold("Reconnaissance", prior) == 0.45

    def test_out_of_top5_tactic_gets_penalty(self):
        prior = {
            "windows_observed": 20,
            "tactic_distribution": {
                "reconnaissance": 0.40,
                "initial_access": 0.30,
                "execution": 0.15,
                "discovery": 0.10,
                "credential_access": 0.05,
            },
        }
        # Privilege Escalation NO esta en top-5 -> +0.10 sobre base 0.75 = 0.85
        assert calibration.adaptive_threshold("Privilege Escalation", prior) == 0.85

    def test_in_top5_but_not_top3_uses_base(self):
        prior = {
            "windows_observed": 20,
            "tactic_distribution": {
                "reconnaissance": 0.40,
                "initial_access": 0.20,
                "execution": 0.15,
                "discovery": 0.15,  # 4to lugar
                "credential_access": 0.10,
            },
        }
        # Discovery esta en top-5 pero no top-3 -> base 0.60 sin ajuste
        assert calibration.adaptive_threshold("Discovery", prior) == 0.60

    def test_empty_distribution_uses_base(self):
        prior = {"windows_observed": 20, "tactic_distribution": {}}
        assert calibration.adaptive_threshold("Reconnaissance", prior) == 0.55

    def test_threshold_clamped_below_one(self):
        # Aun con tactica costosa fuera de top-5, no excede 0.95
        prior = {
            "windows_observed": 50,
            "tactic_distribution": {"reconnaissance": 1.0},
        }
        assert calibration.adaptive_threshold("Impact", prior) <= 0.95

    def test_threshold_clamped_above_zero(self):
        # Aun con tactica barata en top-3 frecuentisima, no baja de 0.30
        prior = {
            "windows_observed": 100,
            "tactic_distribution": {"reconnaissance": 0.99},
        }
        assert calibration.adaptive_threshold("Reconnaissance", prior) >= 0.30


class TestEndToEndScenarios:
    def test_first_run_no_prior_uses_base(self):
        # Escenario: target nuevo, primer run del observer
        for tactic in ("Reconnaissance", "Initial Access", "Privilege Escalation"):
            t = calibration.adaptive_threshold(tactic, None)
            assert t == calibration._TACTIC_BASE_THRESHOLD[
                calibration._normalize_tactic(tactic)
            ]

    def test_repeat_target_recon_dominant(self):
        # Escenario: target observado >=20 veces, recon es dominante
        # Esto refleja DVWA o WordPress tipico: scanner pesado al inicio.
        prior = {
            "windows_observed": 30,
            "tactic_distribution": {
                "reconnaissance": 0.60,
                "initial_access": 0.20,
                "execution": 0.15,
                "discovery": 0.05,
            },
        }
        # Recon en top-3, base 0.55 - 0.10 = 0.45
        assert calibration.adaptive_threshold("Reconnaissance", prior) == 0.45
        # Privilege Escalation no esta en top-5, sube a 0.85 (alerta cara)
        assert calibration.adaptive_threshold("Privilege Escalation", prior) == 0.85
