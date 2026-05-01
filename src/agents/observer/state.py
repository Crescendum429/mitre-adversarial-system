"""
Estado del agente observador para LangGraph.

El observador opera con informacion limitada: solo ve logs del sistema,
trafico de red y eventos de autenticacion. NO tiene acceso a las decisiones
del atacante. Esto simula la perspectiva real de un endpoint o SIEM.

El flujo implementa el patron Triage -> Investigate -> Classify -> Escalate
de los SOCs automatizados (Vinay 2025, arXiv:2512.06659):
  collect_logs -> triage_anomalies -> classify_tactic -> generate_recommendation
                        |                    |
                    (no signal)        (baja confianza)
                        END          -> refine_analysis -> classify_tactic
"""

from typing import TypedDict


class Classification(TypedDict, total=False):
    """Resultado de una clasificacion de tactica MITRE."""

    tactic: str
    tactic_id: str
    confidence: float
    evidence: list[str]
    reasoning: str
    recommendation: str
    timestamp: str
    window_start: str        # inicio de la ventana de logs analizada
    window_end: str          # fin de la ventana de logs analizada
    tactics_in_window: list  # todas las tacticas detectadas en esta ventana
    llm_latency_ms: int      # tiempo que el LLM tardo en esta clasificacion


class ObserverState(TypedDict, total=False):
    """
    Estado del agente observador.

    Flujo del grafo:
      collect_logs -> triage_anomalies --(signal)--> classify_tactic
                                       --(no_signal)--> END
      classify_tactic --(confianza < 0.6)--> refine_analysis -> classify_tactic
                      --(confianza >= 0.6)--> generate_recommendation -> END
    """

    # Ventana temporal de analisis
    window_start: str
    window_end: str

    # Logs recolectados de Loki
    raw_logs: list[dict]
    log_summary: str

    # Resultado del triaje (sin LLM)
    triage_result: str   # "signal" | "no_signal"
    anomaly_count: int   # cantidad de entradas flaggeadas por heuristicas

    # Clasificacion actual
    current_classification: Classification | None

    # Historial de clasificaciones previas (contexto temporal)
    classification_history: list[Classification]

    # Senales de ataque pre-calculadas por detect_anomalies (sin LLM)
    anomaly_signals: dict

    # IPs sospechosas acumuladas entre ciclos: ip -> {windows_flagged, cumulative_score, ...}
    suspect_list: dict

    # Control del loop de refinamiento
    refinement_count: int   # cuantas veces se refirio el analisis por baja confianza
    has_new_logs: bool
    error: str | None

    # Ablation: cuando False, triage_anomalies es pass-through (senal siempre que
    # haya logs) y detect_anomalies no calcula suspect_list ni sub-tacticas de
    # webshell. Permite medir el aporte de las heuristicas T1-T10 vs clasificacion
    # LLM pura sobre log_summary crudo.
    use_heuristics: bool

    # Memoria del observer (NIST SP 800-94 baselining): fingerprint del patron
    # de trafico HTTP. Permite consultar prior estadistico de tacticas
    # observadas previamente sobre targets con perfil similar.
    traffic_fingerprint: str
    baseline_prior: dict | None
