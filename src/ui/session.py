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
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


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

    def reset(self) -> None:
        """Limpia eventos. Llamar al inicio de cada corrida nueva."""
        with self._lock:
            self.events = []
            self.metadata = {}

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
        """Persiste la sesion como JSON estructurado."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))


# Singleton global. Los nodos lo importan y usan directamente.
_session = SessionRecorder()


def get_session() -> SessionRecorder:
    return _session
