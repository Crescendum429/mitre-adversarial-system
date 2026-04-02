"""
Nodos del grafo LangGraph del agente atacante.

Cada nodo es una funcion que recibe el estado actual del agente y retorna
una actualizacion parcial del estado. LangGraph se encarga de mergear la
actualizacion con el estado existente.

El flujo del grafo es:
  plan_tactic -> execute_tools -> validate_result -> advance_tactic
                     ^                                    |
                     |                                    v
                     +---- [tactica no completa] ---------+

plan_tactic: El LLM analiza la situacion y decide que herramienta usar.
execute_tools: Ejecuta las herramientas que el LLM solicito (tool calls).
validate_result: El LLM analiza el resultado y decide si la tactica esta completa.
advance_tactic: Transiciona a la siguiente tactica o termina el ataque.
"""

import json
import logging
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, SystemMessage, ToolMessage

from src.agents.attacker.prompts import ATTACKER_SYSTEM_PROMPT, build_tactic_prompt
from src.agents.attacker.state import AttackerState
from src.agents.attacker.tools import ATTACKER_TOOLS
from src.config.mitre_mapping import get_tactic_by_name
from src.config.settings import settings
from src.llm.provider import get_chat_model

logger = logging.getLogger(__name__)

# El modelo con herramientas bindeadas. Se inicializa lazy para no requerir
# API key al importar el modulo.
_model_with_tools = None


def _get_model():
    global _model_with_tools
    if _model_with_tools is None:
        model = get_chat_model()
        _model_with_tools = model.bind_tools(ATTACKER_TOOLS)
    return _model_with_tools


def plan_tactic(state: AttackerState) -> dict:
    """
    Nodo planificador: el LLM decide que accion tomar.

    Construye un prompt con el contexto de la tactica actual y los datos
    recopilados. El LLM responde con texto (razonamiento) y opcionalmente
    con tool_calls (acciones a ejecutar).

    Si el LLM no emite tool_calls, se interpreta como que quiere comunicar
    algo (ej: "la tactica esta completa") sin ejecutar herramientas.
    """
    tactic_name = state.get("current_tactic", "reconnaissance")
    target_ip = state.get("target", settings.target_ip)
    collected_data = state.get("collected_data", {})

    # Construir mensajes para el LLM
    messages = list(state.get("messages", []))

    # Si es la primera invocacion de esta tactica, agregar el prompt de sistema
    # y el prompt de la tactica
    has_system = any(isinstance(m, SystemMessage) for m in messages)
    if not has_system:
        messages.insert(0, SystemMessage(
            content=ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip)
        ))

    # Agregar el prompt de tactica como mensaje del usuario
    tactic_prompt = build_tactic_prompt(tactic_name, target_ip, collected_data)
    messages.append(HumanMessage(content=tactic_prompt))

    logger.info(f"[Atacante] Planificando accion para tactica: {tactic_name}")

    response = _get_model().invoke(messages)

    return {"messages": [response]}


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
            "output_preview": str(result)[:500],
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
    Nodo validador: el LLM analiza los resultados y decide el siguiente paso.

    Despues de ejecutar herramientas, el LLM recibe los resultados (ToolMessages)
    y decide:
    1. Ejecutar otra herramienta (emite tool_calls) -> vuelve a execute_tools
    2. Declarar la tactica completa (texto sin tool_calls) -> advance_tactic
    3. Seguir razonando (texto sin tool_calls) -> advance_tactic evalua

    Tambien extrae datos relevantes del output para acumular en collected_data.
    """
    messages = list(state.get("messages", []))
    tactic_name = state.get("current_tactic", "")
    actions_count = state.get("actions_in_current_tactic", 0)

    # Si hay demasiadas acciones en esta tactica, forzar avance
    if actions_count >= settings.max_actions_per_tactic:
        logger.warning(
            f"[Atacante] Limite de acciones alcanzado ({actions_count}) para {tactic_name}"
        )
        messages.append(HumanMessage(
            content=(
                f"Has ejecutado {actions_count} acciones en esta tactica. "
                "Resume lo que lograste y los datos recopilados. "
                "Indica que la tactica esta completa."
            )
        ))

    response = _get_model().invoke(messages)
    return {"messages": [response]}


def advance_tactic(state: AttackerState) -> dict:
    """
    Nodo de transicion: determina si avanzar a la siguiente tactica o continuar.

    Analiza el ultimo mensaje del LLM para determinar si la tactica esta completa.
    Si esta completa, avanza al siguiente elemento de tactic_sequence.
    Si la secuencia esta agotada, marca el ataque como terminado.

    Tambien actualiza collected_data con informacion extraida del razonamiento
    del LLM (puertos encontrados, credenciales, etc.).
    """
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None
    tactic_sequence = state.get("tactic_sequence", [])
    current_index = state.get("current_tactic_index", 0)

    # Si el ultimo mensaje tiene tool_calls, la tactica no esta completa.
    # El grafo debe volver a execute_tools.
    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return {"tactic_complete": False}

    # Purgar mensajes de la tactica anterior para evitar acumulacion de contexto.
    # Conservar solo el ultimo AIMessage: contiene el resumen de lo encontrado
    # y sirve de contexto para la siguiente tactica.
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
    Funcion de routing condicional para el grafo.

    Despues de validate_result, decide si:
    - Volver a execute_tools (el LLM quiere ejecutar mas herramientas)
    - Ir a advance_tactic (el LLM termino de razonar)
    """
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None

    if isinstance(last_message, AIMessage) and last_message.tool_calls:
        return "execute_tools"
    return "advance_tactic"


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
