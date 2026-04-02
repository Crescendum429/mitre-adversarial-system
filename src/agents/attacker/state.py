"""
Estado del agente atacante para LangGraph.

LangGraph opera sobre un estado compartido que fluye entre nodos del grafo.
Cada nodo recibe el estado actual, lo modifica, y retorna la version actualizada.
El framework persiste automaticamente el estado en cada transicion (checkpoint).

El TypedDict define el schema del estado. Los campos con Annotated + operador
especifican como se combinan actualizaciones parciales (ej: append a listas).
"""

from dataclasses import dataclass, field
from typing import Annotated, TypedDict

from langgraph.graph import add_messages


@dataclass
class ActionRecord:
    """Registro de una accion ejecutada por el atacante. Sirve como ground truth."""

    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    command: str
    output: str
    success: bool
    timestamp: str
    justification: str = ""


class AttackerState(TypedDict, total=False):
    """
    Estado completo del agente atacante.

    Este estado viaja entre los 4 nodos del grafo:
      plan_tactic -> execute_action -> validate_result -> advance_tactic

    El campo messages se usa para la interaccion con el LLM (patron ReAct).
    El campo action_history acumula las acciones ejecutadas para ground truth.
    """

    # Configuracion del escenario
    target: str
    tactic_sequence: list[str]

    # Estado de progreso
    current_tactic: str
    current_tactic_index: int
    actions_in_current_tactic: int

    # Datos acumulados durante el ataque
    collected_data: dict
    action_history: list[dict]

    # Accion en curso (decidida por el LLM, ejecutada por el executor)
    planned_action: dict | None

    # Control de flujo
    tactic_complete: bool
    attack_finished: bool
    error: str | None

    # Mensajes LLM (LangGraph acumula con add_messages)
    messages: Annotated[list, add_messages]
