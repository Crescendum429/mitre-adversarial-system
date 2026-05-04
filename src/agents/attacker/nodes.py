"""Nodos del grafo LangGraph del agente atacante."""

import json
import logging
import time
from datetime import datetime, timezone

from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    RemoveMessage,
    SystemMessage,
    ToolMessage,
)
from rich.console import Console

from src.agents.attacker.memory import (
    compute_target_fingerprint,
    lookup_playbook,
    record_run_completion,
    record_tactic_failure,
    record_tactic_success,
    upsert_playbook_recon,
)
from src.agents.attacker.objectives import check_tactic_objective, scan_for_flags
from src.agents.attacker.prompts import ATTACKER_SYSTEM_PROMPT, build_tactic_prompt
from src.agents.attacker.state import AttackerState
from src.agents.attacker.tools import ATTACKER_TOOLS
from src.config.mitre_mapping import get_tactic_by_name
from src.config.settings import settings
from src.llm.provider import get_chat_model, make_cacheable_system_content
from src.ui.session import get_session

logger = logging.getLogger(__name__)
_console = Console()

_SOFT_WARN_ACTIONS = 15
_HARD_WARN_ACTIONS = 30
# Auto-advance: si el validator code-based dice OK tras >= N acciones, parar.
# Tres garantiza que el LLM tuvo oportunidad real de explorar; mas alto retrasa
# innecesariamente; mas bajo puede aceptar evidence prematura. Tres calibrado
# empiricamente sobre Sonnet 4.5 (cumple recon en accion 2-3) y Haiku 4.5
# (cumple recon en accion 5-7 tipicamente).
_MIN_ACTIONS_BEFORE_AUTOADVANCE = 3
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
        get_session().attacker_event("tactic_start", tactic=tactic_name)
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
            content=make_cacheable_system_content(
                ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip),
                role="attacker",
            )
        ))

    matched_playbook = state.get("matched_playbook") if state.get("use_memory", True) else None

    # model_id se usa para seleccionar la estrategia per-model en el playbook
    # (memoria hibrida: estrategia propia primero, fallback cross-model con
    # disclaimer). Tomado del USAGE_STATS para obtener el nombre real del modelo
    # en uso (ej: claude-sonnet-4-5-20250929).
    from src.llm.provider import USAGE_STATS as _USAGE
    current_model_id = (_USAGE.get("attacker", {}) or {}).get("model", "") or ""

    tactic_prompt = build_tactic_prompt(
        tactic_name,
        target_ip,
        collected_data,
        objective_feedback=objective_feedback,
        recent_actions=recent_actions,
        replan_attempt=attempts,
        playbook=matched_playbook,
        model_id=current_model_id,
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
            content=make_cacheable_system_content(
                ATTACKER_SYSTEM_PROMPT.format(target_ip=target_ip),
                role="attacker",
            )
        ))
    llm_context.append(new_messages[-1])

    response = _get_model().invoke(llm_context)

    return {
        "messages": new_messages + [response],
        "objective_feedback": "",
        "tactic_started_at": tactic_started_at,
    }


_PRIMARY_ARGS = {
    # tool_name -> tupla de keys que definen "el intento" (ignora flags)
    "run_nmap": ("target",),
    "run_nikto": ("target",),
    "run_whatweb": ("url",),
    "run_gobuster": ("url",),
    "run_gobuster_recursive": ("url",),
    "run_dirsearch": ("url",),
    "run_spider": ("url",),
    "run_wpscan": ("url",),
    "run_dns_enum": ("target",),
    "run_enum4linux": ("target",),
    "run_smbclient": ("target", "share"),
    "run_ftp": ("target",),
    "run_searchsploit": ("query",),
    "run_hydra_http_form": ("target", "login_path", "username"),
    "run_hydra": ("target", "service", "username"),
    "run_john": ("hash_format",),
    "run_http_session": ("login_url", "target_url", "target_method"),
    "run_sqlmap": ("url",),
    "run_curl": ("url", "method"),
    "run_command": ("command",),
    "run_web_shell": ("url", "cmd"),
    "run_ssh_exec": ("target", "username", "remote_command"),
    "run_file_upload": ("target_url", "file_path_on_attacker"),
    "run_msfvenom": ("payload",),
    "write_exploit_file": ("path",),
    "start_reverse_listener": ("port",),
    "serve_http": ("port",),
    "run_priv_esc_enum": ("webshell_url", "mode"),
    "run_linpeas": ("webshell_url", "mode"),
    "decode_string": ("data", "encoding"),
}


def _canonicalize_args(name: str, args: dict) -> dict:
    """Reduce args a las claves primarias que definen el intento.

    Ignora flags secundarios (e.g., timeout, threads, headers) y normaliza
    strings (lowercase host, strip whitespace). Detecta loops semánticos:
    `run_curl(url='http://X', method='GET', headers='User-Agent: a')` y
    `run_curl(url='http://X/', method='GET')` colapsan a la misma firma.
    """
    if not isinstance(args, dict):
        return {"_raw": str(args)}
    primary = _PRIMARY_ARGS.get(name)
    if primary is None:
        # tool desconocida: usar todos los args
        return {k: str(v).strip() for k, v in args.items()}
    out = {}
    for k in primary:
        v = args.get(k, "")
        s = str(v).strip()
        # Normalizar URLs: trim trailing /, lowercase host
        if k.endswith("url") or k == "target_url" or k == "login_url":
            s = s.rstrip("/").lower()
        out[k] = s
    return out


def _action_signature(name: str, args: dict) -> str:
    """Firma canonica de una accion para detectar loops semanticos."""
    canon = _canonicalize_args(name, args)
    return name + "::" + json.dumps(canon, sort_keys=True, default=str)


def _is_loop(history: list[dict], next_signature: str) -> bool:
    """Detecta si la accion siguiente repite N o mas veces la misma firma
    en una ventana reciente del historial.

    Usa los settings loop_detection_window y loop_detection_threshold; el
    threshold cuenta la accion candidata + las repeticiones previas. Solo
    chequea la tactica activa para no atrapar reuso legitimo entre tacticas.
    """
    from src.config.settings import settings as _s
    if not _s.loop_detection_enabled:
        return False
    window = max(1, int(_s.loop_detection_window))
    threshold = max(2, int(_s.loop_detection_threshold))
    recent = history[-window:]
    if len(recent) < threshold - 1:
        return False
    matches = 1  # cuenta la accion candidata
    for h in recent:
        sig = _action_signature(
            h.get("technique", ""),
            json.loads(h.get("command", "{}")) if isinstance(h.get("command"), str) else (h.get("command") or {}),
        )
        if sig == next_signature:
            matches += 1
    return matches >= threshold


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
    # Solo el historial de la tactica actual cuenta para loop detection
    tactic_history = [h for h in new_history if h.get("tactic") == tactic_name]

    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]

        logger.info(f"[Atacante] Ejecutando: {tool_name}({tool_args})")
        get_session().attacker_event(
            "tool_call",
            tactic=tactic_name,
            tool=tool_name,
            args=tool_args,
        )

        next_sig = _action_signature(tool_name, tool_args)
        if _is_loop(tactic_history, next_sig):
            result = (
                f"[LOOP_DETECTED] La invocacion {tool_name}({tool_args}) "
                f"se ha repetido en las ultimas acciones de la tactica "
                f"{tactic_name} sin progreso. NO se ejecuto. Cambia de approach: "
                f"prueba un wordlist distinto, otra herramienta, otro target_path, "
                f"o declara la tactica inalcanzable con justificacion."
            )
            logger.warning(f"[Atacante] LOOP detectado en {tool_name}, no ejecutado")
            get_session().attacker_event(
                "loop_detected",
                tactic=tactic_name,
                tool=tool_name,
                args=tool_args,
            )
        elif tool_name in tool_map:
            try:
                result = tool_map[tool_name].invoke(tool_args)
            except Exception as e:
                result = f"Error ejecutando {tool_name}: {e}"
                logger.error(result)
        else:
            result = f"Herramienta '{tool_name}' no encontrada"

        result_str = str(result)
        get_session().attacker_event(
            "tool_result",
            tactic=tactic_name,
            tool=tool_name,
            size=len(result_str),
            preview=result_str[:300],
        )

        tool_messages.append(ToolMessage(
            content=str(result),
            tool_call_id=tool_call["id"],
        ))

        new_history.append({
            "tactic": tactic_name,
            "tactic_id": tactic_info.id if tactic_info else "",
            "technique": tool_name,
            "command": json.dumps(tool_args),
            "output_preview": result_str[:10000],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    actions_count = state.get("actions_in_current_tactic", 0) + len(tool_messages)

    return {
        "messages": tool_messages,
        "action_history": new_history,
        "actions_in_current_tactic": actions_count,
    }


def validate_result(state: AttackerState) -> dict:
    """Reflexiona sobre el ultimo resultado y decide si ejecuta mas tools o termina.

    Auto-advance: si el validator code-based ya considera la tactica cumplida
    y se ejecutaron al menos `_MIN_ACTIONS_BEFORE_AUTOADVANCE` acciones,
    cortocircuitamos al LLM con un AIMessage vacio sin tool_calls. Eso route
    a check_objective que detectara success y avanzara, evitando que el LLM
    sobre-explore tras haber cumplido el objetivo. Critico para modelos como
    Haiku 4.5 que tienden a continuar curl-eando rutas tras el OK.
    """
    messages = list(state.get("messages", []))
    tactic_name = state.get("current_tactic", "")
    actions_count = state.get("actions_in_current_tactic", 0)

    # Pre-check: validator code-based ya OK?
    if actions_count >= _MIN_ACTIONS_BEFORE_AUTOADVANCE:
        try:
            success, reason, _evidence = check_tactic_objective(state)
        except Exception:
            success, reason = False, ""
        if success:
            logger.info(
                f"[Atacante] Auto-advance {tactic_name}: validator OK tras "
                f"{actions_count} acciones ({reason})"
            )
            get_session().attacker_event(
                "auto_advance",
                tactic=tactic_name,
                actions=actions_count,
                reason=reason,
            )
            # AIMessage sin tool_calls -> should_continue -> check_objective
            return {"messages": [AIMessage(
                content=f"[AUTO-ADVANCE] Objetivo de {tactic_name} verificado: {reason}"
            )]}

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
        get_session().attacker_event(
            "objective_check",
            tactic=tactic_name,
            success=True,
            reason=reason,
            evidence=dict(evidence),
        )
        get_session().attacker_event("tactic_end", tactic=tactic_name, success=True)

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
        get_session().attacker_event(
            "objective_check",
            tactic=tactic_name,
            success=False,
            reason=reason,
            attempts=current_attempts,
        )
        get_session().attacker_event("tactic_end", tactic=tactic_name, success=False)
        # M9: persistir el fallo en memoria para que la proxima corrida lo evite
        if state.get("use_memory", True):
            fp = state.get("target_fingerprint", "")
            if fp:
                try:
                    record_tactic_failure(fp, tactic_name, reason, current_attempts)
                except Exception as e:
                    logger.warning(f"[Memory] No se pudo persistir fallo: {e}")
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
    get_session().attacker_event(
        "replan",
        tactic=tactic_name,
        attempt=current_attempts,
        feedback=reason,
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

    # model_id activo para memoria hibrida (per-model strategies).
    from src.llm.provider import USAGE_STATS as _USAGE
    current_model = (_USAGE.get("attacker", {}) or {}).get("model", "") or ""

    if tactic == "reconnaissance":
        fp = compute_target_fingerprint(evidence)
        if fp:
            existing = lookup_playbook(fp, model_id=current_model)
            upsert_playbook_recon(fp, target_ip, evidence, actions_used, model_id=current_model)
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
                get_session().attacker_event(
                    "memory_match",
                    tactic=tactic,
                    fingerprint=fp,
                    runs_previas=runs,
                    summary=summary,
                )
            else:
                logger.info(f"[Memory] Target nuevo, fingerprint registrado: {fp}")
                get_session().attacker_event(
                    "memory_save", tactic=tactic, fingerprint=fp, new=True
                )
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
        model_id=current_model,
    )
    get_session().attacker_event(
        "memory_save",
        tactic=tactic,
        fingerprint=fp,
        tool=last_action.get("technique", ""),
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
