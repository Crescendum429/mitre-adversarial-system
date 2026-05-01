"""
Compilacion del grafo LangGraph del agente observador.

Implementa el patron Triage -> Investigate -> Classify -> Escalate
descrito en la literatura de SOCs automatizados (Vinay 2025, arXiv:2512.06659).

El grafo ya no es un pipeline lineal: usa edges condicionales para implementar
dos caracteristicas clave de LangGraph:

1. Cortocircuito de triaje: si no hay senal anomala, el grafo termina sin
   invocar al LLM. En un servidor con trafico normal esto elimina la mayoria
   de las llamadas al LLM.

2. Loop de refinamiento: si la confianza del LLM es baja segun el umbral
   adaptativo (ver calibration.py — depende de la tactica y del prior del
   fingerprint), el grafo activa refine_analysis (sin LLM) para generar una
   vista forense alternativa de los mismos logs, y vuelve a clasificar.
   Maximo 2 iteraciones.

Flujo:
  START -> collect_logs -> triage_anomalies
                               |
                    [no_signal] +-> END
                               |
                    [signal]   +-> detect_anomalies -> classify_tactic
                                                           |
                                  [confianza < umbral adaptativo] +-> refine_analysis -> classify_tactic
                                                           |
                                  [confianza >= umbral adaptativo] +-> generate_recommendation -> END
"""

import logging
from datetime import datetime, timedelta, timezone

from langgraph.graph import END, START, StateGraph

from src.agents.observer.calibration import DEFAULT_THRESHOLD, adaptive_threshold
from src.agents.observer.nodes import (
    classify_tactic,
    collect_logs,
    detect_anomalies,
    generate_recommendation,
    refine_analysis,
    triage_anomalies,
)
from src.agents.observer.state import ObserverState

logger = logging.getLogger(__name__)

# Umbral por defecto cuando la calibracion adaptativa no aplica (ver
# calibration.py para la justificacion academica).
CONFIDENCE_THRESHOLD = DEFAULT_THRESHOLD
MAX_REFINEMENTS = 2


def should_analyze(state: ObserverState) -> str:
    """
    Routing post-triage: determina si los logs tienen senal suficiente
    para invocar al LLM. La mayoria de los ciclos terminan aqui en
    entornos con trafico normal.
    """
    return state.get("triage_result", "no_signal")


def should_refine(state: ObserverState) -> str:
    """
    Routing post-classify: si la confianza es baja y no hemos refinado
    demasiado, volver a analizar con una vista alternativa de los logs.
    Esto implementa el paso 'Investigate' del patron SOC.

    El umbral es adaptativo (calibration.adaptive_threshold):
    - Cost-sensitive por tactica: tacticas caras (Privilege Escalation,
      Impact, Exfiltration) requieren mayor confianza antes de cerrar.
    - Bayesiano por prior: si la tactica esta en top-3 del prior del
      fingerprint, baja el umbral 0.10 (la prior soporta la clasificacion).
      Si esta fuera del top-5, sube 0.10 (clasificacion sorpresiva, pedir
      mas evidencia).
    """
    classification = state.get("current_classification")
    refinement_count = state.get("refinement_count", 0)

    if not classification:
        return "done"

    confidence = classification.get("confidence", 0.0)
    tactic = classification.get("tactic", "")
    threshold = adaptive_threshold(tactic, state.get("baseline_prior"))

    if confidence < threshold and refinement_count < MAX_REFINEMENTS:
        logger.info(
            f"[Observador] Confianza {confidence:.0%} < {threshold:.0%} "
            f"(adaptado para '{tactic}'), refinamiento #{refinement_count + 1}"
        )
        return "refine"

    return "done"


def build_observer_graph() -> StateGraph:
    """Construye y compila el grafo del agente observador."""
    graph = StateGraph(ObserverState)

    graph.add_node("collect_logs", collect_logs)
    graph.add_node("triage_anomalies", triage_anomalies)
    graph.add_node("detect_anomalies", detect_anomalies)
    graph.add_node("classify_tactic", classify_tactic)
    graph.add_node("refine_analysis", refine_analysis)
    graph.add_node("generate_recommendation", generate_recommendation)

    graph.add_edge(START, "collect_logs")
    graph.add_edge("collect_logs", "triage_anomalies")

    graph.add_conditional_edges(
        "triage_anomalies",
        should_analyze,
        {
            "signal": "detect_anomalies",
            "no_signal": END,
        },
    )

    graph.add_edge("detect_anomalies", "classify_tactic")

    graph.add_conditional_edges(
        "classify_tactic",
        should_refine,
        {
            "refine": "refine_analysis",
            "done": "generate_recommendation",
        },
    )

    graph.add_edge("refine_analysis", "classify_tactic")
    graph.add_edge("generate_recommendation", END)

    return graph.compile()


def create_observer_state(
    window_minutes: int = 5,
    history: list | None = None,
    suspect_list: dict | None = None,
    simulation_start: datetime | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    use_heuristics: bool = True,
    traffic_fingerprint: str = "",
    baseline_prior: dict | None = None,
) -> ObserverState:
    """
    Crea el estado inicial para una ejecucion del observador.

    Si se pasan window_start y window_end, se usan directamente (modo ventanas
    contiguas). Si no, se calcula como [now - window_minutes, now]. En ambos
    casos, si simulation_start es posterior a window_start, se aplica clamp.

    `traffic_fingerprint` y `baseline_prior` se persisten entre ventanas: la
    primera ventana del run los computa una vez (en collect_logs), las siguientes
    los reciben pre-computados aqui para reusar el prior sin recomputar.
    """
    if window_start is not None and window_end is not None:
        start = window_start
        end = window_end
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=window_minutes)

    if simulation_start is not None and start < simulation_start:
        start = simulation_start

    return ObserverState(
        window_start=start.isoformat(),
        window_end=end.isoformat(),
        raw_logs=[],
        log_summary="",
        triage_result="no_signal",
        anomaly_count=0,
        anomaly_signals={},
        suspect_list=suspect_list or {},
        current_classification=None,
        classification_history=history or [],
        refinement_count=0,
        has_new_logs=False,
        error=None,
        use_heuristics=use_heuristics,
        traffic_fingerprint=traffic_fingerprint,
        baseline_prior=baseline_prior,
    )
