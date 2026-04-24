"""Nodos del grafo LangGraph del agente atacante."""

import json
import logging
import time
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, SystemMessage, ToolMessage
from rich.console import Console

from src.agents.attacker.memory import (
    compute_target_fingerprint,
    lookup_playbook,
    record_run_completion,
    record_tactic_success,
    upsert_playbook_recon,
)
from src.agents.attacker.objectives import check_tactic_objective, scan_for_flags
from src.agents.attacker.prompts import ATTACKER_SYSTEM_PROMPT, build_tactic_prompt
from src.agents.attacker.state import AttackerState
from src.agents.attacker.tools import ATTACKER_TOOLS
from src.config.mitre_mapping import get_tactic_by_name
from src.config.settings import settings
from src.llm.provider import get_chat_model

logger = logging.getLogger(__name__)
_console = Console()

_SOFT_WARN_ACTIONS = 15
_HARD_WARN_ACTIONS = 30
_MAX_REPLAN_ATTEMPTS = 15

_model_with_tools = None
_model_lock = __import__("threading").Lock()


def _get_model():
    """Singleton thread-safe del modelo con tools bound.

    El lock previene doble inicializacion cuando plan_tactic y validate_result
    corren concurrentemente (raro pero posible con LangGraph streams).
    """
    global _model_with_tools
    if _model_with_tools is not None:
        return _model_with_tools
    with _model_lock:
        if _model_with_tools is None:
            # _InstrumentedChatModel.bind_tools maneja el unwrap de retry
            # internamente y re-aplica el proxy, preservando el conteo de tokens.
            _model_with_tools = get_chat_model().bind_tools(ATTACKER_TOOLS)
    return _model_with_tools


def reset_model_singleton():
    """Limpia el singleton del modelo. Usado entre tests/runs con distinto provider."""
    global _model_with_tools
    with _model_lock:
        _model_with_tools = None


def plan_tactic(state: AttackerState) -> dict:
    """Planifica la siguiente accion. En replanificaciones purga mensajes previos."""
    tactic_name = state.get("current_tactic", "reconnaissance")
    # Marca el inicio de la tactica si no fue marcada todavia (primer plan_tactic
    # de esa tactica). Los replans reutilizan el mismo timestamp de arranque.
    tactic_started_at = dict(state.get("tactic_started_at", {}))
    if tactic_name not in tactic_started_at:
        tactic_started_at[tactic_name] = time.monotonic()
    target_ip = state.get("target", settings.target_ip)
    collected_data = state.get("collected_data", {})
    objective_feedback = state.get("objective_feedback", "")
    attempts = state.get("attempts_per_tactic", {}).get(tactic_name, 0)

    tactic_history = [
        a for a in state.get("action_history", [])
        if a.get("tactic", "").lower() == tactic_name.lower()
    ]
    recent_actions = tactic_history[-6:]

    existing_messages = list(state.get("messages", []))

    purge_ops = []
    if objective_feedback:
        for m in existing_messages:
            if not isinstance(m, SystemMessage) and hasattr(m, "id") and m.id:
                purge_ops.append(RemoveMessage(id=m.id))

    has_system = any(isinstance(m, SystemMessage) for m in existing_messages)
    new_messages = list(purge_ops)
    if not has_system:
        new_messages.append(SystemMessage(
            content=ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip)
        ))

    matched_playbook = state.get("matched_playbook") if state.get("use_memory", True) else None

    tactic_prompt = build_tactic_prompt(
        tactic_name,
        target_ip,
        collected_data,
        objective_feedback=objective_feedback,
        recent_actions=recent_actions,
        replan_attempt=attempts,
        playbook=matched_playbook,
    )
    new_messages.append(HumanMessage(content=tactic_prompt))

    if objective_feedback:
        logger.info(
            f"[Atacante] Replanificando {tactic_name} (intento {attempts + 1}): "
            f"{objective_feedback[:120]}"
        )
    else:
        logger.info(f"[Atacante] Planificando accion para tactica: {tactic_name}")

    llm_context = [m for m in existing_messages if isinstance(m, SystemMessage)]
    if not llm_context:
        llm_context.append(new_messages[-2] if len(new_messages) > 1 else SystemMessage(
            content=ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip)
        ))
    llm_context.append(new_messages[-1])

    response = _get_model().invoke(llm_context)

    return {
        "messages": new_messages + [response],
        "objective_feedback": "",
        "tactic_started_at": tactic_started_at,
    }


def execute_tools(state: AttackerState) -> dict:
    """Ejecuta las herramientas solicitadas por el LLM."""
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None

    if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
        return {"messages": []}

    tool_map = {t.name: t for t in ATTACKER_TOOLS}
    tool_messages = []
    new_history = list(state.get("action_history", []))
    tactic_name = state.get("current_tactic", "unknown")
    tactic_info = get_tactic_by_name(tactic_name)

    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]

        logger.info(f"[Atacante] Ejecutando: {tool_name}({tool_args})")

        if tool_name in tool_map:
            try:
                result = tool_map[tool_name].invoke(tool_args)
            except Exception as e:
                result = f"Error ejecutando {tool_name}: {e}"
                logger.error(result)
        else:
            result = f"Herramienta '{tool_name}' no encontrada"

        tool_messages.append(ToolMessage(
            content=str(result),
            tool_call_id=tool_call["id"],
        ))

        new_history.append({
            "tactic": tactic_name,
            "tactic_id": tactic_info.id if tactic_info else "",
            "technique": tool_name,
            "command": json.dumps(tool_args),
            "output_preview": str(result)[:10000],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    actions_count = state.get("actions_in_current_tactic", 0) + len(tool_messages)

    return {
        "messages": tool_messages,
        "action_history": new_history,
        "actions_in_current_tactic": actions_count,
    }


def validate_result(state: AttackerState) -> dict:
    """Reflexiona sobre el ultimo resultado y decide si ejecuta mas tools o termina."""
    messages = list(state.get("messages", []))
    tactic_name = state.get("current_tactic", "")
    actions_count = state.get("actions_in_current_tactic", 0)

    if actions_count == _SOFT_WARN_ACTIONS:
        messages.append(HumanMessage(
            content=(
                f"[AUTO-EVAL] Llevas {actions_count} acciones en {tactic_name}. "
                "Reflexiona: ¿estas progresando o repitiendo variantes de lo mismo? "
                "Si detectas un loop, cambia de enfoque."
            )
        ))
    elif actions_count == _HARD_WARN_ACTIONS:
        messages.append(HumanMessage(
            content=(
                f"[ESCALACION] Llevas {actions_count} acciones sin cumplir el objetivo. "
                "Intenta una estrategia radicalmente diferente o declara el objetivo "
                "inalcanzable con justificacion."
            )
        ))

    response = _get_model().invoke(messages)
    return {"messages": [response]}


def check_objective(state: AttackerState) -> dict:
    """Validador code-based por tactica. Si falla, fuerza replanificacion."""
    tactic_name = state.get("current_tactic", "")
    success, reason, evidence = check_tactic_objective(state)

    collected = dict(state.get("collected_data", {}))
    collected.update(evidence)

    tactic_evidence = dict(state.get("tactic_evidence", {}))
    tactic_evidence[tactic_name] = evidence

    tactic_objective_met = dict(state.get("tactic_objective_met", {}))
    tactic_objective_met[tactic_name] = success

    flags = list(state.get("flags_found", []))
    # Scanner transversal: las keys pueden aparecer en outputs de cualquier
    # tactica (ej: key-1 en robots.txt durante recon, key-2 en /home/robot).
    # scan_for_flags asocia cada key-N-of-3.txt con el hash mas cercano.
    auto_keys = scan_for_flags({**state, "tactic_evidence": tactic_evidence})
    for k, v in auto_keys.items():
        if k not in evidence:
            evidence[k] = v
        if v not in flags:
            flags.append(v)
    for k, v in evidence.items():
        if k.startswith("key_") and v and v not in flags:
            flags.append(v)

    attempts = dict(state.get("attempts_per_tactic", {}))
    current_attempts = attempts.get(tactic_name, 0)

    # Calcula duracion de la tactica (solo cuando se cierra: exito o rendicion)
    started_at = state.get("tactic_started_at", {}).get(tactic_name)
    tactic_duration = dict(state.get("tactic_duration_seconds", {}))
    if started_at is not None and tactic_name not in tactic_duration:
        tactic_duration[tactic_name] = round(time.monotonic() - started_at, 2)

    if success:
        _console.print(
            f"[bold green]✓ OBJETIVO CUMPLIDO — {tactic_name}[/bold green]: {reason}"
        )
        logger.info(f"[Atacante] Objetivo cumplido: {tactic_name} — {reason}")

        memory_update = _handle_memory_on_success(state, tactic_name, evidence)

        return {
            "collected_data": collected,
            "tactic_evidence": tactic_evidence,
            "tactic_objective_met": tactic_objective_met,
            "flags_found": flags,
            "tactic_complete": True,
            "tactic_duration_seconds": tactic_duration,
            **memory_update,
        }

    # Objetivo no cumplido: decidir replanificacion o rendicion
    current_attempts += 1
    attempts[tactic_name] = current_attempts

    if current_attempts >= _MAX_REPLAN_ATTEMPTS:
        _console.print(
            f"[bold red]✗ OBJETIVO NO CUMPLIDO — {tactic_name}[/bold red] "
            f"(intentos agotados: {current_attempts}). Razon: {reason}"
        )
        logger.warning(
            f"[Atacante] Replan exhausted para {tactic_name} tras "
            f"{current_attempts} intentos: {reason}"
        )
        return {
            "collected_data": collected,
            "tactic_evidence": tactic_evidence,
            "tactic_objective_met": tactic_objective_met,
            "flags_found": flags,
            "attempts_per_tactic": attempts,
            "tactic_complete": True,
            "tactic_duration_seconds": tactic_duration,
            "objective_feedback": "",
        }

    _console.print(
        f"[yellow]⚠ OBJETIVO PENDIENTE — {tactic_name}[/yellow] "
        f"(intento {current_attempts}/{_MAX_REPLAN_ATTEMPTS}): {reason}"
    )
    logger.info(
        f"[Atacante] Replanificando {tactic_name} (intento {current_attempts}): {reason}"
    )

    return {
        "collected_data": collected,
        "tactic_evidence": tactic_evidence,
        "tactic_objective_met": tactic_objective_met,
        "attempts_per_tactic": attempts,
        "tactic_complete": False,
        "objective_feedback": reason,
    }


def advance_tactic(state: AttackerState) -> dict:
    """Avanza a la siguiente tactica o termina el ataque."""
    messages = state.get("messages", [])
    tactic_sequence = state.get("tactic_sequence", [])
    current_index = state.get("current_tactic_index", 0)

    purge = [
        RemoveMessage(id=m.id)
        for m in messages[:-1]
        if hasattr(m, "id") and m.id
    ]

    next_index = current_index + 1
    if next_index >= len(tactic_sequence):
        logger.info("[Atacante] Todas las tacticas completadas. Ataque finalizado.")
        if state.get("use_memory", True):
            fp = state.get("target_fingerprint", "")
            met = state.get("tactic_objective_met", {})
            all_ok = all(met.get(t) is True for t in tactic_sequence)
            record_run_completion(fp, all_ok)
        return {
            "attack_finished": True,
            "tactic_complete": True,
            "current_tactic_index": next_index,
            "messages": purge,
        }

    next_tactic = tactic_sequence[next_index]
    logger.info(f"[Atacante] Avanzando a tactica: {next_tactic}")

    return {
        "current_tactic": next_tactic,
        "current_tactic_index": next_index,
        "tactic_complete": True,
        "actions_in_current_tactic": 0,
        "messages": purge,
    }


def should_continue(state: AttackerState) -> str:
    """Routing despues de validate_result."""
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None

    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return "execute_tools"
    return "check_objective"


def should_advance(state: AttackerState) -> str:
    """Routing despues de check_objective."""
    if state.get("tactic_complete", False):
        return "advance_tactic"
    return "plan_tactic"


def should_loop(state: AttackerState) -> str:
    """Routing despues de advance_tactic."""
    if state.get("attack_finished", False):
        return "end"
    return "plan_tactic"


def _handle_memory_on_success(state: AttackerState, tactic: str, evidence: dict) -> dict:
    """Lookup de playbook tras Recon, recording de payload tras cualquier tactica."""
    if not state.get("use_memory", True):
        return {}

    actions_used = state.get("actions_in_current_tactic", 0)
    target_ip = state.get("target", "")
    update: dict = {}

    if tactic == "reconnaissance":
        fp = compute_target_fingerprint(evidence)
        if fp:
            existing = lookup_playbook(fp)
            upsert_playbook_recon(fp, target_ip, evidence, actions_used)
            update["target_fingerprint"] = fp
            if existing is not None:
                update["matched_playbook"] = existing
                runs = existing.get("run_count", 0)
                summary = existing.get("target_summary", "?")
                _console.print(
                    f"[bold yellow]🧠 MEMORIA: target conocido (fp={fp}, "
                    f"{runs} runs previas) — {summary}[/bold yellow]"
                )
                logger.info(
                    f"[Memory] Match para {fp}: {runs} runs previas; "
                    f"playbook con {len(existing.get('tactics', {}))} tacticas registradas"
                )
            else:
                logger.info(f"[Memory] Target nuevo, fingerprint registrado: {fp}")
        return update

    fp = state.get("target_fingerprint", "")
    if not fp:
        return {}

    last_action = _last_action_for_tactic(state, tactic)
    if last_action is None:
        return {}

    args = _parse_command_args(last_action.get("command", ""))
    record_tactic_success(
        fingerprint=fp,
        tactic=tactic,
        tool=last_action.get("technique", ""),
        args=args,
        evidence=evidence,
        actions_used=actions_used,
    )
    return {}


def _last_action_for_tactic(state: AttackerState, tactic: str) -> dict | None:
    history = state.get("action_history", [])
    matches = [a for a in history if a.get("tactic", "").lower() == tactic.lower()]
    return matches[-1] if matches else None


def _parse_command_args(command_json: str) -> dict:
    try:
        return json.loads(command_json)
    except Exception:
        return {}
