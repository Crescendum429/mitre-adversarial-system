"""
Nodos del grafo LangGraph del agente atacante.

Cada nodo es una funcion que recibe el estado actual del agente y retorna
una actualizacion parcial del estado. LangGraph se encarga de mergear la
actualizacion con el estado existente.

El flujo del grafo es:
  plan_tactic -> execute_tools -> validate_result -> check_objective -> advance_tactic
                     ^                                       |
                     |                                  [no cumplido]
                     +---------- [replan con feedback] ------+

plan_tactic: El LLM analiza la situacion y decide que herramienta usar.
execute_tools: Ejecuta las herramientas que el LLM solicito (tool calls).
validate_result: El LLM analiza el resultado y razona si debe continuar o terminar.
check_objective: Validador code-based que verifica si la tactica cumplio su objetivo.
advance_tactic: Transiciona a la siguiente tactica o termina el ataque.
"""

import json
import logging
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, SystemMessage, ToolMessage
from rich.console import Console

from src.agents.attacker.objectives import check_tactic_objective
from src.agents.attacker.prompts import ATTACKER_SYSTEM_PROMPT, build_tactic_prompt
from src.agents.attacker.state import AttackerState
from src.agents.attacker.tools import ATTACKER_TOOLS
from src.config.mitre_mapping import get_tactic_by_name
from src.config.settings import settings
from src.llm.provider import get_chat_model

logger = logging.getLogger(__name__)
_console = Console()

# Presupuesto de acciones por tactica: no es un corte duro, pero dispara
# escalacion de instrucciones al LLM (soft warn -> hard warn -> fail).
_SOFT_WARN_ACTIONS = 15
_HARD_WARN_ACTIONS = 30
_MAX_REPLAN_ATTEMPTS = 5

# El modelo con herramientas bindeadas. Se inicializa lazy para no requerir
# API key al importar el modulo.
_model_with_tools = None


def _get_model():
    global _model_with_tools
    if _model_with_tools is None:
        # bind_tools debe aplicarse al modelo base; luego se envuelve con retry.
        from src.llm.provider import _with_retry  # evita ciclo
        base = get_chat_model()  # ya viene con retry
        # Deshacer el retry wrapper para poder hacer bind_tools, luego reenvolver.
        inner = base.bound if hasattr(base, "bound") else base
        with_tools = inner.bind_tools(ATTACKER_TOOLS)
        _model_with_tools = _with_retry(with_tools)
    return _model_with_tools


def plan_tactic(state: AttackerState) -> dict:
    """
    Nodo planificador: el LLM decide que accion tomar.

    Construye un prompt con el contexto de la tactica actual, los datos
    recopilados, el historial de acciones recientes (para detectar loops),
    y feedback del validador de objetivos si el anterior intento fallo.

    En una replanificacion, purga el historial de mensajes de intentos
    anteriores (los mantiene como evidencia compacta en recent_actions)
    para evitar crecimiento descontrolado del contexto y rate limits.
    """
    tactic_name = state.get("current_tactic", "reconnaissance")
    target_ip = state.get("target", settings.target_ip)
    collected_data = state.get("collected_data", {})
    objective_feedback = state.get("objective_feedback", "")
    attempts = state.get("attempts_per_tactic", {}).get(tactic_name, 0)

    # Historial reciente de esta tactica (para detectar loops)
    tactic_history = [
        a for a in state.get("action_history", [])
        if a.get("tactic", "").lower() == tactic_name.lower()
    ]
    recent_actions = tactic_history[-6:]

    existing_messages = list(state.get("messages", []))

    # En replanificaciones: purgar mensajes intermedios para evitar acumulacion
    # de contexto. Conservar solo el SystemMessage y usar recent_actions como
    # evidencia comprimida del intento previo.
    purge_ops = []
    if objective_feedback:
        for m in existing_messages:
            if not isinstance(m, SystemMessage) and hasattr(m, "id") and m.id:
                purge_ops.append(RemoveMessage(id=m.id))

    # Prompt de sistema (solo primera vez)
    has_system = any(isinstance(m, SystemMessage) for m in existing_messages)
    new_messages = list(purge_ops)
    if not has_system:
        new_messages.append(SystemMessage(
            content=ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip)
        ))

    # Prompt de tactica con feedback y deteccion de loops
    tactic_prompt = build_tactic_prompt(
        tactic_name,
        target_ip,
        collected_data,
        objective_feedback=objective_feedback,
        recent_actions=recent_actions,
        replan_attempt=attempts,
    )
    new_messages.append(HumanMessage(content=tactic_prompt))

    if objective_feedback:
        logger.info(
            f"[Atacante] Replanificando {tactic_name} (intento {attempts + 1}): "
            f"{objective_feedback[:120]}"
        )
    else:
        logger.info(f"[Atacante] Planificando accion para tactica: {tactic_name}")

    # Construir el contexto efectivo para el LLM: system + prompt nuevo
    # (los mensajes purgados ya no aparecen porque los quitamos del estado)
    llm_context = [
        m for m in existing_messages
        if isinstance(m, SystemMessage)
    ]
    if not llm_context:
        llm_context.append(new_messages[-2] if len(new_messages) > 1 else SystemMessage(
            content=ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip)
        ))
    llm_context.append(new_messages[-1])  # HumanMessage con prompt

    response = _get_model().invoke(llm_context)

    return {
        "messages": new_messages + [response],
        "objective_feedback": "",  # limpiar feedback una vez usado
    }


def execute_tools(state: AttackerState) -> dict:
    """
    Nodo ejecutor: ejecuta las herramientas solicitadas por el LLM.

    Recorre los tool_calls del ultimo mensaje AI y ejecuta cada herramienta.
    Los resultados se agregan como ToolMessages para que el LLM los vea
    en la siguiente iteracion.

    Este nodo NO involucra al LLM. Es puramente mecanico: recibe tool_calls,
    ejecuta, retorna resultados.
    """
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

        # Registrar en action_history como ground truth
        new_history.append({
            "tactic": tactic_name,
            "tactic_id": tactic_info.id if tactic_info else "",
            "technique": tool_name,
            "command": json.dumps(tool_args),
            "output_preview": str(result)[:3000],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    actions_count = state.get("actions_in_current_tactic", 0) + len(tool_messages)

    return {
        "messages": tool_messages,
        "action_history": new_history,
        "actions_in_current_tactic": actions_count,
    }


def validate_result(state: AttackerState) -> dict:
    """
    Nodo reflexivo: el LLM analiza los resultados de la ultima accion y
    decide el siguiente paso. Puede:
      1. Emitir mas tool_calls -> volver a execute_tools
      2. Detener (sin tool_calls) -> pasar a check_objective para validacion

    No hay limite rigido de acciones, pero se inyectan advertencias
    progresivas para que el LLM razone sobre loops y estancamiento.
    """
    messages = list(state.get("messages", []))
    tactic_name = state.get("current_tactic", "")
    actions_count = state.get("actions_in_current_tactic", 0)

    # Soft warn: el LLM debe autoevaluar si esta en loop
    if actions_count == _SOFT_WARN_ACTIONS:
        messages.append(HumanMessage(
            content=(
                f"[AUTO-EVAL] Llevas {actions_count} acciones en {tactic_name}. "
                "Antes de la siguiente accion, reflexiona: ¿estas progresando hacia "
                "el objetivo concreto, o repitiendo comandos similares sin avanzar? "
                "Si detectas un loop, cambia de enfoque; si el objetivo es inalcanzable "
                "con las herramientas actuales, explicalo."
            )
        ))
    # Hard warn: el LLM debe decidir si continua o declara fallo
    elif actions_count == _HARD_WARN_ACTIONS:
        messages.append(HumanMessage(
            content=(
                f"[ESCALACION] Llevas {actions_count} acciones en {tactic_name} sin "
                "cumplir el objetivo concreto. Tienes dos opciones: (a) intentar una "
                "estrategia radicalmente diferente si aun crees que es posible, o "
                "(b) declarar que el objetivo es inalcanzable con justificacion. "
                "Elige una y actua en consecuencia — no sigas repitiendo variaciones "
                "del mismo enfoque."
            )
        ))

    response = _get_model().invoke(messages)
    return {"messages": [response]}


def check_objective(state: AttackerState) -> dict:
    """
    Nodo de validacion de objetivo: verifica en codigo si la tactica
    cumplio su criterio de exito concreto.

    Si NO cumplio y aun hay intentos disponibles, retorna feedback para
    que plan_tactic vuelva a planear con la informacion de lo que falta.
    Si cumplio, actualiza evidencia y deja que advance_tactic continue.
    """
    tactic_name = state.get("current_tactic", "")
    success, reason, evidence = check_tactic_objective(state)

    # Acumular evidencia en collected_data y tactic_evidence
    collected = dict(state.get("collected_data", {}))
    collected.update(evidence)

    tactic_evidence = dict(state.get("tactic_evidence", {}))
    tactic_evidence[tactic_name] = evidence

    tactic_objective_met = dict(state.get("tactic_objective_met", {}))
    tactic_objective_met[tactic_name] = success

    # Acumular flags descubiertos en orden
    flags = list(state.get("flags_found", []))
    for k, v in evidence.items():
        if k.startswith("key_") and v and v not in flags:
            flags.append(v)

    attempts = dict(state.get("attempts_per_tactic", {}))
    current_attempts = attempts.get(tactic_name, 0)

    if success:
        _console.print(
            f"[bold green]✓ OBJETIVO CUMPLIDO — {tactic_name}[/bold green]: {reason}"
        )
        logger.info(f"[Atacante] Objetivo cumplido: {tactic_name} — {reason}")
        return {
            "collected_data": collected,
            "tactic_evidence": tactic_evidence,
            "tactic_objective_met": tactic_objective_met,
            "flags_found": flags,
            "tactic_complete": True,
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
        # Se acepta el estado actual como fallo y se avanza para no trabarse
        return {
            "collected_data": collected,
            "tactic_evidence": tactic_evidence,
            "tactic_objective_met": tactic_objective_met,
            "flags_found": flags,
            "attempts_per_tactic": attempts,
            "tactic_complete": True,  # forzar advance
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
    """
    Nodo de transicion: avanza a la siguiente tactica o termina el ataque.

    Se ejecuta SOLO cuando check_objective aprobo el avance (tactic_complete=True).
    Purga mensajes para limitar contexto.
    """
    messages = state.get("messages", [])
    tactic_sequence = state.get("tactic_sequence", [])
    current_index = state.get("current_tactic_index", 0)

    # Purgar mensajes de la tactica anterior para evitar acumulacion de contexto.
    # Conservar solo el ultimo AIMessage como resumen para la siguiente tactica.
    purge = [
        RemoveMessage(id=m.id)
        for m in messages[:-1]
        if hasattr(m, "id") and m.id
    ]

    next_index = current_index + 1
    if next_index >= len(tactic_sequence):
        logger.info("[Atacante] Todas las tacticas completadas. Ataque finalizado.")
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
    """
    Funcion de routing despues de validate_result.

    - Si el LLM emitio tool_calls -> ejecutar mas tools
    - Si no -> pasar a check_objective para validacion
    """
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None

    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return "execute_tools"
    return "check_objective"


def should_advance(state: AttackerState) -> str:
    """
    Funcion de routing despues de check_objective.

    - Si el objetivo se cumplio (tactic_complete=True) -> advance_tactic
    - Si no -> volver a plan_tactic (replan con feedback)
    """
    if state.get("tactic_complete", False):
        return "advance_tactic"
    return "plan_tactic"


def should_loop(state: AttackerState) -> str:
    """
    Funcion de routing despues de advance_tactic.

    Decide si:
    - Continuar con la siguiente tactica (plan_tactic)
    - Terminar el ataque (end)
    """
    if state.get("attack_finished", False):
        return "end"
    return "plan_tactic"
