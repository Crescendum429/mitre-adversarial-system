"""Tests del sistema de memoria persistente del atacante."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from src.agents.attacker import memory


@pytest.fixture
def tmp_memory(monkeypatch):
    """Usa un archivo temporal de memoria por test para aislamiento."""
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "playbooks.json"
        monkeypatch.setattr(memory, "MEMORY_FILE", path)
        yield path


class TestComputeTargetFingerprint:
    def test_same_observables_produce_same_fp(self):
        ev = {
            "port_80_open": True,
            "web_technologies": ["Apache", "DVWA"],
            "discovered_paths": ["admin", "login.php"],
        }
        fp1 = memory.compute_target_fingerprint(ev)
        fp2 = memory.compute_target_fingerprint(ev)
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_tech_order_invariant(self):
        """El orden de web_technologies no debe cambiar el fingerprint."""
        ev1 = {
            "port_80_open": True,
            "web_technologies": ["Apache", "DVWA", "PHP"],
            "discovered_paths": ["admin"],
        }
        ev2 = {
            "port_80_open": True,
            "web_technologies": ["PHP", "DVWA", "Apache"],
            "discovered_paths": ["admin"],
        }
        assert memory.compute_target_fingerprint(ev1) == memory.compute_target_fingerprint(ev2)

    def test_different_tech_produces_different_fp(self):
        ev1 = {"port_80_open": True, "web_technologies": ["Apache"], "discovered_paths": ["x"]}
        ev2 = {"port_80_open": True, "web_technologies": ["nginx"], "discovered_paths": ["x"]}
        assert memory.compute_target_fingerprint(ev1) != memory.compute_target_fingerprint(ev2)

    def test_ignores_dotfiles(self):
        """Paths que empiezan con . se filtran (son ruido de gobuster)."""
        ev1 = {"port_80_open": True, "web_technologies": ["Apache"],
               "discovered_paths": [".htaccess", ".hta", "admin"]}
        ev2 = {"port_80_open": True, "web_technologies": ["Apache"],
               "discovered_paths": ["admin"]}
        assert memory.compute_target_fingerprint(ev1) == memory.compute_target_fingerprint(ev2)

    def test_empty_evidence_returns_empty(self):
        assert memory.compute_target_fingerprint({}) == ""

    def test_fingerprint_robust_to_path_variance(self):
        """Critico para reutilizacion de memoria: fingerprint IGNORA paths
        descubiertos (son variables entre runs por no-determinismo de
        gobuster). Solo port + tech importan.
        """
        ev_run_a = {
            "port_80_open": True, "web_technologies": ["Apache", "DVWA", "PHP"],
            "discovered_paths": ["robots.txt", "random_file.txt", "admin"],
        }
        ev_run_b = {
            "port_80_open": True, "web_technologies": ["Apache", "DVWA", "PHP"],
            "discovered_paths": ["login.php", "foo.html"],  # completamente distintos
        }
        ev_run_c = {
            "port_80_open": True, "web_technologies": ["Apache", "DVWA", "PHP"],
            "discovered_paths": [],  # ningun path (caso degenerate)
        }
        fp_a = memory.compute_target_fingerprint(ev_run_a)
        fp_b = memory.compute_target_fingerprint(ev_run_b)
        fp_c = memory.compute_target_fingerprint(ev_run_c)
        assert fp_a == fp_b == fp_c

    def test_fingerprint_same_across_target_instances(self):
        """Dos despliegues distintos del mismo tipo de target (ej: DVWA en
        10.10.0.10 y DVWA en otra IP) producen el MISMO fingerprint. Esto
        es DESEADO: el playbook aprendido generaliza a cualquier DVWA.
        """
        dvwa_instance_a = {
            "port_80_open": True,
            "web_technologies": ["Apache", "DVWA", "PHP"],
            "discovered_paths": ["login.php"],
        }
        dvwa_instance_b = {
            "port_80_open": True,
            "web_technologies": ["Apache", "DVWA", "PHP"],
            "discovered_paths": ["admin", "wp-login.php"],  # paths distintos
        }
        assert (
            memory.compute_target_fingerprint(dvwa_instance_a)
            == memory.compute_target_fingerprint(dvwa_instance_b)
        )

    def test_fingerprint_different_for_different_tech(self):
        """Tech stack distinta -> fingerprint distinto. No contaminamos
        playbooks entre tipos de target.
        """
        dvwa = {"port_80_open": True, "web_technologies": ["Apache", "DVWA", "PHP"]}
        wp = {"port_80_open": True, "web_technologies": ["Apache", "WordPress", "PHP"]}
        solr = {"http_port_open": 8983, "web_technologies": ["Apache Solr"]}
        fp_d = memory.compute_target_fingerprint(dvwa)
        fp_w = memory.compute_target_fingerprint(wp)
        fp_s = memory.compute_target_fingerprint(solr)
        assert fp_d != fp_w != fp_s != fp_d  # todos distintos entre si


class TestPlaybookPersistence:
    def test_lookup_returns_none_for_missing(self, tmp_memory):
        assert memory.lookup_playbook("abc123") is None

    def test_upsert_recon_creates_entry(self, tmp_memory):
        fp = "abc123"
        ev = {"port_80_open": True, "web_technologies": ["Apache"],
              "discovered_paths": ["admin"]}
        memory.upsert_playbook_recon(fp, "10.10.0.10", ev, actions_used=5)

        pb = memory.lookup_playbook(fp)
        assert pb is not None
        assert pb["last_target_ip"] == "10.10.0.10"
        assert pb["tactics"]["reconnaissance"]["best_run_actions"] == 5

    def test_upsert_keeps_best_actions(self, tmp_memory):
        fp = "xyz"
        ev = {"port_80_open": True, "web_technologies": ["X"], "discovered_paths": ["y"]}
        memory.upsert_playbook_recon(fp, "1.1.1.1", ev, actions_used=10)
        memory.upsert_playbook_recon(fp, "1.1.1.1", ev, actions_used=5)  # mejor
        memory.upsert_playbook_recon(fp, "1.1.1.1", ev, actions_used=7)  # peor
        pb = memory.lookup_playbook(fp)
        assert pb["tactics"]["reconnaissance"]["best_run_actions"] == 5

    def test_record_tactic_success_sanitizes_secrets(self, tmp_memory):
        fp = "abc"
        ev = {"port_80_open": True, "web_technologies": ["Apache"], "discovered_paths": ["x"]}
        memory.upsert_playbook_recon(fp, "1.1.1.1", ev, actions_used=3)
        memory.record_tactic_success(
            fingerprint=fp,
            tactic="initial_access",
            tool="run_http_session",
            args={
                "login_url": "http://target/login.php",
                "login_data": "username=admin&password=supersecret123&Login=Login",
                "password": "hunter2",
            },
            evidence={"login_verified": True},
            actions_used=5,
        )
        pb = memory.lookup_playbook(fp)
        entry = pb["tactics"]["initial_access"]
        assert entry["tool"] == "run_http_session"
        # El password NO debe aparecer en plaintext
        assert "supersecret123" not in json.dumps(entry)
        assert "hunter2" not in json.dumps(entry)
        # Los placeholders <discovered> SI deben aparecer
        assert "<discovered>" in json.dumps(entry)

    def test_record_run_completion_increments(self, tmp_memory):
        fp = "abc"
        ev = {"port_80_open": True, "web_technologies": ["X"], "discovered_paths": ["y"]}
        memory.upsert_playbook_recon(fp, "1.1.1.1", ev, actions_used=3)
        memory.record_run_completion(fp, all_successful=True)
        memory.record_run_completion(fp, all_successful=False)
        pb = memory.lookup_playbook(fp)
        assert pb["run_count"] == 2
        assert pb["successful_runs"] == 1


class TestPlaybookSanitization:
    def test_scrub_hex_hashes(self, tmp_memory):
        fp = "a"
        ev = {"port_80_open": True, "web_technologies": ["X"], "discovered_paths": ["y"]}
        memory.upsert_playbook_recon(fp, "1.1.1.1", ev, actions_used=3)
        memory.record_tactic_success(
            fingerprint=fp,
            tactic="discovery",
            tool="run_command",
            args={
                "command": "cat /home/robot/password.raw-md5",
                "output": "robot:5f4dcc3b5aa765d61d8327deb882cf99",
            },
            evidence={"discovered_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
            actions_used=2,
        )
        pb = memory.lookup_playbook(fp)
        entry_json = json.dumps(pb["tactics"]["discovery"])
        # El hash no debe aparecer literal en el playbook
        assert "5f4dcc3b5aa765d61d8327deb882cf99" not in entry_json
        assert "<hash>" in entry_json


class TestRenderForPrompt:
    def test_renders_basic_playbook(self):
        pb = {
            "target_summary": "Apache+DVWA+PHP",
            "run_count": 3,
            "successful_runs": 2,
            "tactics": {
                "reconnaissance": {
                    "best_run_actions": 4,
                    "key_findings": ["port_80_open"],
                },
                "initial_access": {
                    "tool": "run_http_session",
                    "payload_template": {"login_url": "http://x/login.php"},
                    "best_run_actions": 6,
                },
            },
        }
        rendered = memory.render_playbook_for_prompt(pb, "initial_access")
        assert "Apache+DVWA+PHP" in rendered
        assert "run_http_session" in rendered
        assert "3" in rendered
        assert "2 exitosas" in rendered


class TestHybridMemoryByModel:
    """Memoria hibrida: cross-model + per-model strategies."""

    def test_record_tactic_success_persists_per_model(self, tmp_memory):
        ev = {"port_80_open": True, "web_technologies": ["Apache"]}
        fp = memory.compute_target_fingerprint(ev)
        memory.upsert_playbook_recon(fp, "10.0.0.1", ev, 5, model_id="modelA")
        memory.record_tactic_success(
            fp, "execution", "run_http_session",
            {"login_url": "http://x"}, {"rce_verified": True}, 3,
            model_id="modelA",
        )
        pb = memory.lookup_playbook(fp)
        # Cross-model entry actualizada
        assert pb["tactics"]["execution"]["tool"] == "run_http_session"
        # Per-model entry tambien
        assert pb["tool_strategies"]["modelA"]["execution"]["tool"] == "run_http_session"
        assert pb["tool_strategies"]["modelA"]["execution"]["best_run_actions"] == 3

    def test_record_two_models_keeps_separate_strategies(self, tmp_memory):
        ev = {"port_80_open": True, "web_technologies": ["Apache"]}
        fp = memory.compute_target_fingerprint(ev)
        memory.upsert_playbook_recon(fp, "10.0.0.1", ev, 5, model_id="modelA")
        memory.record_tactic_success(
            fp, "execution", "run_http_session",
            {"login_url": "http://x"}, {"rce_verified": True}, 3,
            model_id="modelA",
        )
        memory.record_tactic_success(
            fp, "execution", "run_curl",
            {"url": "http://x?cmd=id"}, {"rce_verified": True}, 8,
            model_id="modelB",
        )
        pb = memory.lookup_playbook(fp)
        # Cada modelo tiene su propia estrategia
        assert pb["tool_strategies"]["modelA"]["execution"]["tool"] == "run_http_session"
        assert pb["tool_strategies"]["modelB"]["execution"]["tool"] == "run_curl"
        # Cross-model conserva el MEJOR (modelA con 3 acciones < modelB con 8)
        assert pb["tactics"]["execution"]["tool"] == "run_http_session"

    def test_render_prefers_per_model_when_match(self):
        pb = {
            "target_summary": "Apache",
            "run_count": 1,
            "successful_runs": 1,
            "tactics": {"execution": {"tool": "run_http_session", "best_run_actions": 3}},
            "tool_strategies": {
                "modelA": {"execution": {"tool": "run_curl", "best_run_actions": 5}},
            },
        }
        out = memory.render_playbook_for_prompt(pb, "execution", model_id="modelA")
        assert "run_curl" in out
        assert "tu propia ejecucion previa" in out
        assert "run_http_session" not in out

    def test_render_falls_back_to_cross_model_with_disclaimer(self):
        pb = {
            "target_summary": "Apache",
            "run_count": 1,
            "successful_runs": 1,
            "tactics": {"execution": {"tool": "run_http_session", "best_run_actions": 3}},
            "tool_strategies": {
                "modelA": {"execution": {"tool": "run_curl", "best_run_actions": 5}},
            },
        }
        # modelB nunca ejecuto -> fallback a cross-model con disclaimer
        out = memory.render_playbook_for_prompt(pb, "execution", model_id="modelB")
        assert "run_http_session" in out
        assert "OTRO modelo" in out
