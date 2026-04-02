"""
Compilacion del grafo LangGraph del agente atacante.

Este modulo conecta los nodos definidos en nodes.py con edges que definen
el flujo de ejecucion. El grafo resultante implementa el patron ReAct:
  razonar -> actuar -> observar -> razonar -> ...

El grafo se compila una vez y se puede ejecutar multiples veces con diferentes
estados iniciales (diferentes escenarios de ataque).

Estructura del grafo:

  START --> plan_tactic --> execute_tools --> validate_result --+
                ^                                              |
                |                                              v
                +---- [has tool_calls] ---------- [routing] ---+
                |                                              |
                +---- [no tool_calls]                          |
                |                                              v
                +------ plan_tactic <---- [not finished] -- advance_tactic
                                                               |
                                                          [finished]
                                                               |
                                                              END
"""

import logging

from langgraph.graph import END, START, StateGraph

from src.agents.attacker.nodes import (
    advance_tactic,
    execute_tools,
    plan_tactic,
    should_continue,
    should_loop,
    validate_result,
)
from src.agents.attacker.state import AttackerState
from src.config.mitre_mapping import get_implemented_tactics
from src.config.settings import settings

logger = logging.getLogger(__name__)


def build_attacker_graph() -> StateGraph:
    """
    Construye y compila el grafo del agente atacante.

    Retorna un grafo compilado listo para .invoke() o .stream().
    """
    graph = StateGraph(AttackerState)

    # Registrar nodos
    graph.add_node("plan_tactic", plan_tactic)
    graph.add_node("execute_tools", execute_tools)
    graph.add_node("validate_result", validate_result)
    graph.add_node("advance_tactic", advance_tactic)

    # Edges fijos
    graph.add_edge(START, "plan_tactic")
    graph.add_edge("plan_tactic", "execute_tools")
    graph.add_edge("execute_tools", "validate_result")

    # Routing condicional despues de validate_result:
    # Si el LLM emitio tool_calls -> volver a execute_tools
    # Si no -> ir a advance_tactic
    graph.add_conditional_edges(
        "validate_result",
        should_continue,
        {
            "execute_tools": "execute_tools",
            "advance_tactic": "advance_tactic",
        },
    )

    # Routing condicional despues de advance_tactic:
    # Si hay mas tacticas -> plan_tactic
    # Si no -> END
    graph.add_conditional_edges(
        "advance_tactic",
        should_loop,
        {
            "plan_tactic": "plan_tactic",
            "end": END,
        },
    )

    return graph.compile()


def create_initial_state(
    target: str | None = None,
    tactics: list[str] | None = None,
) -> AttackerState:
    """
    Crea el estado inicial para una ejecucion del agente atacante.

    Si no se especifican tacticas, usa las implementadas en orden de ataque.
    """
    if tactics is None:
        tactics = [t.name.lower().replace(" ", "_") for t in get_implemented_tactics()]

    target = target or settings.target_ip

    logger.info(f"Estado inicial: target={target}, tacticas={tactics}")

    return AttackerState(
        target=target,
        tactic_sequence=tactics,
        current_tactic=tactics[0] if tactics else "",
        current_tactic_index=0,
        actions_in_current_tactic=0,
        collected_data={},
        action_history=[],
        planned_action=None,
        tactic_complete=False,
        attack_finished=False,
        error=None,
        messages=[],
    )
