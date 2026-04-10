"""
Compilacion del grafo LangGraph del agente atacante.

Este modulo conecta los nodos definidos en nodes.py con edges que definen
el flujo de ejecucion. El grafo implementa ReAct con validacion objetiva:
  razonar -> actuar -> observar -> validar -> avanzar / replanear

Estructura del grafo:

  START --> plan_tactic --> execute_tools --> validate_result
                ^                                   |
                |                      [tool_calls] |
                |                                   |
                |                   +--- execute_tools (loop)
                |                   |
                |                   v
                |            check_objective
                |                   |
                |       [no cumplido] +--> plan_tactic (replan con feedback)
                |                   |
                |       [cumplido]   v
                +------------- advance_tactic
                                    |
                              [mas tacticas] --> plan_tactic
                                    |
                              [finalizado]
                                    v
                                   END
"""

import logging

from langgraph.graph import END, START, StateGraph

from src.agents.attacker.nodes import (
    advance_tactic,
    check_objective,
    execute_tools,
    plan_tactic,
    should_advance,
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
    Construye y compila el grafo del agente atacante con validacion
    objetiva por tactica.
    """
    graph = StateGraph(AttackerState)

    # Registrar nodos
    graph.add_node("plan_tactic", plan_tactic)
    graph.add_node("execute_tools", execute_tools)
    graph.add_node("validate_result", validate_result)
    graph.add_node("check_objective", check_objective)
    graph.add_node("advance_tactic", advance_tactic)

    # Edges fijos
    graph.add_edge(START, "plan_tactic")
    graph.add_edge("plan_tactic", "execute_tools")
    graph.add_edge("execute_tools", "validate_result")

    # Routing despues de validate_result:
    #   tool_calls -> loop a execute_tools
    #   no tool_calls -> check_objective
    graph.add_conditional_edges(
        "validate_result",
        should_continue,
        {
            "execute_tools": "execute_tools",
            "check_objective": "check_objective",
        },
    )

    # Routing despues de check_objective:
    #   objetivo cumplido (o intentos agotados) -> advance_tactic
    #   objetivo pendiente -> plan_tactic (replan con feedback)
    graph.add_conditional_edges(
        "check_objective",
        should_advance,
        {
            "advance_tactic": "advance_tactic",
            "plan_tactic": "plan_tactic",
        },
    )

    # Routing despues de advance_tactic:
    #   hay mas tacticas -> plan_tactic
    #   no -> END
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
        attempts_per_tactic={},
        collected_data={},
        action_history=[],
        tactic_evidence={},
        tactic_objective_met={},
        objective_feedback="",
        flags_found=[],
        planned_action=None,
        tactic_complete=False,
        attack_finished=False,
        error=None,
        messages=[],
    )
