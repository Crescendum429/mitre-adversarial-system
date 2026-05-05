"""
Session recorder: captura todos los eventos de una corrida (atacante + observador)
para visualizacion posterior y generacion de reportes HTML para la tesis.

Diseño minimalista: un singleton que cualquier nodo del grafo puede llamar
para registrar eventos. La estructura es JSON-friendly desde el inicio para
poder serializar a HTML/markdown/CSV sin transformaciones complejas.

Tipos de eventos registrados (event_type):

  ATACANTE:
    tactic_start    — comienza una tactica del kill chain
    plan            — el LLM planifica accion (con prompt si verbose)
    tool_call       — invocacion de herramienta (nmap, hydra, etc.)
    tool_result     — output de herramienta (truncado a N chars)
    objective_check — validador code-based dictamina cumplimiento
    replan          — feedback al LLM por validador rechazando
    tactic_end      — tactica cerrada (cumplida o rendida)
    memory_match    — fingerprint hace match con playbook previo
    memory_save     — playbook actualizado tras tactica exitosa

  OBSERVADOR:
    window_start    — inicio de procesamiento de ventana
    triage          — heuristicas T1-T10 (signal/no_signal)
    detect_anomaly  — perfilado de IPs sospechosas
    classify        — LLM clasifica tactica MITRE
    refine          — invocacion del refinement loop
    window_end      — fin de procesamiento de ventana

  GLOBAL:
    session_start, session_end, error
"""

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


@dataclass
class SessionEvent:
    """Evento atomico de una corrida."""
    timestamp: str
    agent: str          # "attacker", "observer", "system"
    event_type: str
    tactic: str = ""    # contexto de tactica (si aplica)
    payload: dict = field(default_factory=dict)


class SessionRecorder:
    """Singleton que acumula eventos de una corrida."""

    def __init__(self):
        self.events: list[SessionEvent] = []
        self.metadata: dict = {}
        self._lock = threading.Lock()
        self._enabled = True
        self._listeners: list[Callable[[SessionEvent], None]] = []

    def reset(self) -> None:
        """Limpia eventos. Llamar al inicio de cada corrida nueva."""
        with self._lock:
            self.events = []
            self.metadata = {}

    def subscribe(self, callback: Callable[[SessionEvent], None]) -> None:
        """Registra un callback que recibe cada evento al ser grabado.

        El dispatch ocurre fuera del lock para evitar reentradas si el listener
        a su vez llama a record(). Cualquier excepcion del listener se loguea
        pero no interrumpe el grabado.
        """
        with self._lock:
            self._listeners.append(callback)

    def set_metadata(self, **kwargs) -> None:
        with self._lock:
            self.metadata.update(kwargs)

    def record(
        self,
        event_type: str,
        agent: str = "system",
        tactic: str = "",
        **payload,
    ) -> None:
        """Registra un evento. Thread-safe."""
        if not self._enabled:
            return
        ev = SessionEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent=agent,
            event_type=event_type,
            tactic=tactic,
            payload=payload,
        )
        with self._lock:
            self.events.append(ev)
            listeners = list(self._listeners)
        for cb in listeners:
            try:
                cb(ev)
            except Exception as e:
                logging.getLogger(__name__).debug(f"listener {cb} fallo: {e}")

    def attacker_event(self, event_type: str, tactic: str = "", **payload) -> None:
        self.record(event_type, agent="attacker", tactic=tactic, **payload)

    def observer_event(self, event_type: str, **payload) -> None:
        self.record(event_type, agent="observer", **payload)

    def system_event(self, event_type: str, **payload) -> None:
        self.record(event_type, agent="system", **payload)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "metadata": dict(self.metadata),
                "events": [asdict(e) for e in self.events],
            }

    def save_json(self, path: Path) -> None:
        """Persiste la sesion como JSON estructurado.

        El JSON se enriquece con un schema compatible con el frontend
        web/frontend.html: agrega `evaluation`, `llm_usage`, `docker_stats`,
        `loki_stats`, `observer_pipeline`, `tactic_durations` derivados de
        events y de la metadata raw. La metadata raw original se preserva
        intacta — los nuevos campos son additive.
        """
        data = self.to_dict()
        try:
            _enrich_for_frontend(data)
        except Exception as exc:
            logging.getLogger(__name__).warning(
                f"frontend enrichment fallo: {exc}; persisting raw schema"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def _enrich_for_frontend(data: dict) -> None:
    """Mutates `data` in place adding the frontend-friendly schema views.

    Schema esperado por web/frontend.html:
      metadata.evaluation: {macro_f1, micro_f1, strict_accuracy, window_accuracy,
        evaluable_windows, total_windows, per_tactic, confusion_matrix,
        bootstrap_ci, agent}
      metadata.llm_usage: {attacker, observer} con call_count, input/output_tokens,
        cache_creation_input_tokens, cache_read_input_tokens, elapsed_seconds, provider
      metadata.docker_stats: {exec_count, total_seconds, error_count, timed_out_count}
      metadata.loki_stats: {query_count, total_seconds, error_count}
      metadata.observer_pipeline: {triage_signal, triage_no_signal, refine_calls, classify_calls}
      metadata.tactic_durations: dict[tactic, seconds]
    """
    md = data.setdefault("metadata", {})
    events = data.get("events", [])

    # 1. tactic_durations: rename del existente tactic_duration_seconds
    if "tactic_durations" not in md and md.get("tactic_duration_seconds"):
        md["tactic_durations"] = md["tactic_duration_seconds"]

    # 2. observer_pipeline: contar event_types
    if "observer_pipeline" not in md:
        ts_signal = ts_no = refines = classifies = 0
        for e in events:
            if e.get("agent") != "observer":
                continue
            et = e.get("event_type", "")
            payload = e.get("payload") or {}
            if et == "triage":
                if payload.get("triage_result") == "signal":
                    ts_signal += 1
                elif payload.get("triage_result") == "no_signal":
                    ts_no += 1
            elif et == "refine":
                refines += 1
            elif et == "classify":
                classifies += 1
        # Fallback: si no hay events 'triage', estimar desde classify count
        # vs total ventanas conocidas
        md["observer_pipeline"] = {
            "triage_signal": ts_signal or md.get("observer_classifications", 0),
            "triage_no_signal": ts_no,
            "refine_calls": refines,
            "classify_calls": classifies or md.get("observer_classifications", 0),
        }

    # 3. llm_usage: mapear keys planas attacker_*, observer_* a sub-objetos
    if "llm_usage" not in md:
        att_calls = sum(
            1 for e in events
            if e.get("agent") == "attacker" and e.get("event_type") in ("plan", "tool_call")
        )
        obs_calls = md.get("observer_classifications") or sum(
            1 for e in events
            if e.get("agent") == "observer" and e.get("event_type") == "classify"
        )
        md["llm_usage"] = {
            "attacker": {
                "provider": md.get("attacker_provider", ""),
                "model": md.get("attacker_model", ""),
                "call_count": att_calls,
                "input_tokens": md.get("attacker_input_tokens", 0),
                "output_tokens": md.get("attacker_output_tokens", 0),
                "cache_creation_input_tokens": md.get("attacker_cache_creation_tokens", 0),
                "cache_read_input_tokens": md.get("attacker_cache_read_tokens", 0),
                "elapsed_seconds": md.get("time_attacker_llm_s", 0.0),
                "cost_usd": md.get("attacker_cost_usd", 0.0),
            },
            "observer": {
                "provider": md.get("observer_provider", ""),
                "model": md.get("observer_model", ""),
                "call_count": obs_calls,
                "input_tokens": md.get("observer_input_tokens", 0),
                "output_tokens": md.get("observer_output_tokens", 0),
                "cache_creation_input_tokens": md.get("observer_cache_creation_tokens", 0),
                "cache_read_input_tokens": md.get("observer_cache_read_tokens", 0),
                "elapsed_seconds": md.get("time_observer_llm_s", 0.0),
                "cost_usd": md.get("observer_cost_usd", 0.0),
            },
        }

    # 4. docker_stats: contar tool_calls + errors desde events
    if "docker_stats" not in md:
        exec_count = sum(
            1 for e in events if e.get("event_type") == "tool_call"
        )
        error_count = sum(
            1 for e in events
            if e.get("event_type") == "tool_result"
            and (e.get("payload") or {}).get("exit_code", 0) != 0
        )
        md["docker_stats"] = {
            "exec_count": exec_count,
            "total_seconds": md.get("time_docker_exec_s", 0.0),
            "error_count": error_count,
            "timed_out_count": sum(
                1 for e in events
                if e.get("event_type") == "tool_result"
                and (e.get("payload") or {}).get("timed_out", False)
            ),
        }

    # 5. loki_stats: contar window_start del observer (proxy de queries)
    if "loki_stats" not in md:
        query_count = sum(
            1 for e in events
            if e.get("agent") == "observer" and e.get("event_type") == "window_start"
        ) or md.get("observer_classifications", 0)
        md["loki_stats"] = {
            "query_count": query_count,
            "total_seconds": md.get("time_loki_http_s", 0.0),
            "error_count": 0,
        }

    # 6. evaluation: computar via metrics.evaluate sobre events
    if "evaluation" not in md:
        try:
            from src.evaluation.metrics import dump_as_json, evaluate
            attacker_timeline = [
                {"timestamp": e.get("timestamp", ""), "tactic": e.get("tactic", "")}
                for e in events
                if e.get("agent") == "attacker" and e.get("tactic")
            ]
            observer_classifications = []
            for e in events:
                if e.get("agent") != "observer" or e.get("event_type") != "classify":
                    continue
                p = e.get("payload") or {}
                observer_classifications.append({
                    "timestamp": e.get("timestamp", ""),
                    "window_start": p.get("window_start", e.get("timestamp", "")),
                    "window_end": p.get("window_end", e.get("timestamp", "")),
                    "tactic": e.get("tactic", "") or p.get("tactic", ""),
                    "tactics_in_window": p.get("tactics_in_window", []),
                })
            if attacker_timeline and observer_classifications:
                report = evaluate(
                    observer_classifications,
                    attacker_timeline,
                    attacker_model=md.get("attacker_model", ""),
                    observer_model=md.get("observer_model", ""),
                    seed=md.get("seed"),
                    scenario=md.get("scenario", ""),
                )
                eval_dump = dump_as_json(report)
                ev = {
                    "agent": "observer",
                    **eval_dump.get("aggregate", {}),
                    "per_tactic": eval_dump.get("per_tactic", {}),
                    "confusion_matrix": eval_dump.get("confusion_matrix", {}),
                }
                if md.get("bootstrap_ci"):
                    ev["bootstrap_ci"] = md["bootstrap_ci"]
                md["evaluation"] = ev
        except Exception:
            # No bloquear el guardado si metrics falla — el frontend tolera
            # ausencia de evaluation.
            pass


# Singleton global. Los nodos lo importan y usan directamente.
_session = SessionRecorder()


def get_session() -> SessionRecorder:
    return _session
