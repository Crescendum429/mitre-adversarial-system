"""Compilacion del grafo LangGraph del agente atacante."""

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
    graph = StateGraph(AttackerState)

    graph.add_node("plan_tactic", plan_tactic)
    graph.add_node("execute_tools", execute_tools)
    graph.add_node("validate_result", validate_result)
    graph.add_node("check_objective", check_objective)
    graph.add_node("advance_tactic", advance_tactic)

    graph.add_edge(START, "plan_tactic")
    graph.add_edge("plan_tactic", "execute_tools")
    graph.add_edge("execute_tools", "validate_result")

    graph.add_conditional_edges(
        "validate_result",
        should_continue,
        {"execute_tools": "execute_tools", "check_objective": "check_objective"},
    )
    graph.add_conditional_edges(
        "check_objective",
        should_advance,
        {"advance_tactic": "advance_tactic", "plan_tactic": "plan_tactic"},
    )
    graph.add_conditional_edges(
        "advance_tactic",
        should_loop,
        {"plan_tactic": "plan_tactic", "end": END},
    )

    return graph.compile()


def create_initial_state(
    target: str | None = None,
    tactics: list[str] | None = None,
    use_memory: bool = True,
) -> AttackerState:
    """Crea el estado inicial para una ejecucion del agente atacante."""
    if tactics is None:
        tactics = [t.name.lower().replace(" ", "_") for t in get_implemented_tactics()]

    # Normaliza nombres de tacticas para evitar bugs por typos (espacios, upper).
    # La comparacion en validators y routing depende de strings lowercase
    # unificados. Filtra entradas vacias/None.
    tactics = [
        t.strip().lower().replace(" ", "_")
        for t in (tactics or [])
        if t and isinstance(t, str) and t.strip()
    ]

    if not tactics:
        raise ValueError(
            "tactics no puede estar vacio. Define al menos una tactica MITRE "
            "(ej: ['reconnaissance', 'initial_access', 'execution'])."
        )

    target = target or settings.target_ip
    if not target:
        raise ValueError(
            "target no definido. Pasa --target <IP> o configura TARGET_IP en .env."
        )

    logger.info(f"Estado inicial: target={target}, tacticas={tactics}, memoria={use_memory}")

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
        target_fingerprint="",
        matched_playbook=None,
        use_memory=use_memory,
        messages=[],
    )
