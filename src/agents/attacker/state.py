"""Estado del agente atacante para LangGraph."""

from dataclasses import dataclass
from typing import Annotated, TypedDict

from langgraph.graph import add_messages


@dataclass
class ActionRecord:
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
    target: str
    tactic_sequence: list[str]

    current_tactic: str
    current_tactic_index: int
    actions_in_current_tactic: int
    attempts_per_tactic: dict

    collected_data: dict
    action_history: list[dict]
    tactic_evidence: dict
    tactic_objective_met: dict
    objective_feedback: str
    flags_found: list

    planned_action: dict | None

    tactic_complete: bool
    attack_finished: bool
    error: str | None

    messages: Annotated[list, add_messages]
