"""
Orquestador principal del sistema adversarial.

Coordina la ejecucion del agente atacante y el agente observador.
El flujo es:
  1. Verificar que la infraestructura Docker esta levantada
  2. Lanzar el agente atacante (ejecuta cadena de ataque)
  3. Mientras el atacante opera, el observador analiza logs periodicamente
  4. Al finalizar, comparar ground truth (atacante) vs clasificaciones (observador)
  5. Generar reporte de resultados

Los dos agentes corren en threads separados y no se comunican entre si.
El unico punto de contacto es indirecto: el atacante genera actividad que
produce logs, y el observador lee esos logs de Loki.

---
Uso de herramientas de IA en el desarrollo:

Este sistema es un proyecto de tesis desarrollado por Jesus Alarcon bajo
supervision del tutor Roberto Andrade (USFQ, 2026). A lo largo del desarrollo
se usaron herramientas de IA generativa (Claude Code, ChatGPT) como apoyo en
tareas especificas: depuracion de errores, revision de fragmentos de codigo,
busqueda de referencias academicas y redaccion tecnica.

El diseno de la arquitectura, la formulacion de la pregunta de investigacion,
la seleccion del stack tecnologico, la definicion de las metricas de evaluacion
y la validacion experimental son trabajo original del autor. El uso de IA fue
un apoyo puntual, no el motor del proyecto.
"""

import argparse
import logging
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from src.agents.attacker.graph import build_attacker_graph, create_initial_state
from src.agents.observer.graph import build_observer_graph, create_observer_state
from src.config.settings import settings
from src.infrastructure.docker_client import DockerClient
from src.ui.report import generate_report
from src.ui.session import get_session

console = Console()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%H:%M:%S]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
    # Silenciar loggers ruidosos
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def preflight_llm_check() -> None:
    """Smoke test del proveedor LLM antes de empezar la corrida.

    Detecta cuatro clases de fallos antes de gastar tokens / tiempo de Docker:
    (1) credenciales invalidas / cuota agotada — la API responde 401/429;
    (2) modelo que no existe en el proveedor (typo en .env);
    (3) context length insuficiente para el system prompt formateado real;
    (4) modelo no soporta tool calling (el atacante lo necesita).
    Aborta con mensaje claro si cualquiera falla. Ejecuta atacante y observer
    en serie para que el usuario vea cual de los dos rompe. El check del
    atacante envia el ATTACKER_SYSTEM_PROMPT real para validar context size.
    """
    if not settings.preflight_check_enabled:
        return
    from src.llm.provider import get_chat_model, get_observer_model
    from src.agents.attacker.prompts import ATTACKER_SYSTEM_PROMPT
    from src.agents.observer.prompts import OBSERVER_SYSTEM_PROMPT
    from langchain_core.messages import HumanMessage, SystemMessage

    targets = [
        ("atacante", get_chat_model, ATTACKER_SYSTEM_PROMPT.format(target_ip="10.10.0.10")),
        ("observador", get_observer_model, OBSERVER_SYSTEM_PROMPT),
    ]
    for label, factory, sys_prompt in targets:
        try:
            m = factory()
            # Smoke con el prompt REAL — atrapa context_length_exceeded ANTES
            # de gastar tokens en tools / docker.
            msgs = [
                SystemMessage(content=sys_prompt),
                HumanMessage(content="Responde unicamente con OK"),
            ]
            r = m.invoke(msgs)
            if not r or not getattr(r, "content", None):
                raise RuntimeError("respuesta vacia del modelo")
        except Exception as e:
            err_str = str(e)
            hint = ""
            if "context" in err_str.lower() or "too long" in err_str.lower() or "413" in err_str:
                hint = "El modelo no soporta el tamano del system prompt. "
            elif "401" in err_str or "auth" in err_str.lower():
                hint = "API key invalida. "
            elif "429" in err_str or "quota" in err_str.lower() or "rate" in err_str.lower():
                hint = "Cuota agotada o rate limit. "
            console.print(
                f"[red]Pre-flight check fallo para {label}: {type(e).__name__}: "
                f"{err_str[:300]}[/red]\n"
                f"[dim]{hint}Verifica .env: provider, modelo, API key y cuota.[/dim]"
            )
            sys.exit(2)
    console.print("[green]Pre-flight check OK (atacante + observador responden, prompt cabe en context).[/green]")


def verify_infrastructure(scenario: str = "basic"):
    """Verifica que los containers requeridos por el escenario estan corriendo."""
    missing_creds = settings.validate_credentials()
    if missing_creds:
        console.print(
            f"[red]Credenciales LLM faltantes en .env: {', '.join(missing_creds)}[/red]"
        )
        sys.exit(1)
    dc = DockerClient()
    base = ["attacker", "loki"]
    scenario_containers = {
        "basic": base + ["dvwa"],
        "recon_only": base + ["dvwa"],
        "dvwa": base + ["dvwa"],
        "full": base + ["dvwa"],
        "mrrobot": base + ["mrrobot"],
        "dc1": base + ["dc1"],
        "bpent": base + ["bpent"],
        "log4shell": base + ["log4shell"],
        "confluence": base + ["confluence", "confluence-db"],
    }
    required = scenario_containers.get(scenario, base + ["dvwa"])
    missing = [name for name in required if not dc.is_container_running(name)]
    if missing:
        console.print(
            f"[red]Containers no disponibles: {', '.join(missing)}[/red]\n"
            f"Ejecutar: docker compose -f docker/docker-compose.yml up -d"
        )
        sys.exit(1)
    console.print("[green]Infraestructura verificada. Todos los containers activos.[/green]")


def run_attacker(
    tactics: list[str] | None = None,
    target: str | None = None,
    use_memory: bool = True,
) -> dict:
    """
    Ejecuta el agente atacante y retorna el estado final.

    El grafo se ejecuta con stream() para poder ver el progreso en tiempo real.
    Cada paso del grafo emite un evento que podemos loguear.
    """
    graph = build_attacker_graph()
    initial_state = create_initial_state(target=target, tactics=tactics, use_memory=use_memory)

    console.print("\n[bold red]AGENTE ATACANTE INICIADO[/bold red]")
    console.print(f"  Target: {initial_state['target']}")
    console.print(f"  Tacticas: {initial_state['tactic_sequence']}")
    _attacker_t0 = time.monotonic()

    # graph.stream emite eventos parciales por nodo. Acumulamos los campos que
    # crecen (history, evidence, flags) porque un simple .update() perderia
    # los valores previos si el ultimo evento no los incluye. recursion_limit
    # alto (500) permite replanificacion sobre secuencias largas (14 tacticas
    # x varios intentos cada una).
    final_state = dict(initial_state)
    accumulated_history = []
    accumulated_evidence = {}
    accumulated_collected = {}
    accumulated_flags = []
    accumulated_met = {}
    accumulated_attempts = {}
    # GraphRecursionError se captura para emitir reporte parcial: sin esto el
    # sistema descarta toda la metadata acumulada cuando el atacante no
    # converge en recursion_limit acciones (caso tipico: OpenRouter free
    # atascado en init_access por sesgo de frecuencia).
    try:
        from langgraph.errors import GraphRecursionError
    except ImportError:
        GraphRecursionError = Exception

    try:
        for event in graph.stream(initial_state, {"recursion_limit": settings.attacker_recursion_limit}):
            for node_name, node_state in event.items():
                if node_name == "advance_tactic":
                    tactic = node_state.get("current_tactic", "")
                    if tactic:
                        console.print(f"  [yellow]>> Avanzando a: {tactic}[/yellow]")
                elif node_name == "execute_tools":
                    history = node_state.get("action_history", [])
                    if history:
                        accumulated_history = history
                        last = history[-1]
                        console.print(f"  [cyan]Ejecutado: {last.get('technique', '?')}[/cyan]")
                elif node_name == "check_objective":
                    ev = node_state.get("tactic_evidence", {})
                    if ev:
                        accumulated_evidence.update(ev)
                    cd = node_state.get("collected_data", {})
                    if cd:
                        accumulated_collected.update(cd)
                    flags = node_state.get("flags_found", [])
                    if flags:
                        accumulated_flags = flags
                    met = node_state.get("tactic_objective_met", {})
                    if met:
                        accumulated_met.update(met)
                    attempts = node_state.get("attempts_per_tactic", {})
                    if attempts:
                        accumulated_attempts.update(attempts)
                final_state.update(node_state)
    except GraphRecursionError as e:
        console.print(
            f"[bold yellow]⚠ RECURSION LIMIT alcanzado "
            f"({settings.attacker_recursion_limit}): {e}[/bold yellow]\n"
            f"[dim]Emitiendo reporte parcial con la metadata acumulada hasta "
            f"este punto. El atacante no convergio dentro del limite — "
            f"comportamiento esperado en escenarios donde el modelo se atasca "
            f"(p.ej. sesgo de frecuencia en user enumeration).[/dim]"
        )
        final_state["recursion_limit_hit"] = True

    final_state["action_history"] = accumulated_history
    if accumulated_evidence:
        final_state["tactic_evidence"] = accumulated_evidence
    if accumulated_collected:
        final_state["collected_data"] = accumulated_collected
    if accumulated_flags:
        final_state["flags_found"] = accumulated_flags
    if accumulated_met:
        final_state["tactic_objective_met"] = accumulated_met
    if accumulated_attempts:
        final_state["attempts_per_tactic"] = accumulated_attempts
    final_state["attacker_elapsed_seconds"] = round(time.monotonic() - _attacker_t0, 2)
    console.print("[bold red]AGENTE ATACANTE FINALIZADO[/bold red]\n")
    return final_state


def print_attack_summary(attacker_state: dict):
    """
    Imprime un resumen rico del ataque con objetivos cumplidos por tactica,
    evidencia concreta extraida y flags/keys capturados.
    """
    tactic_evidence = attacker_state.get("tactic_evidence", {})
    tactic_met = attacker_state.get("tactic_objective_met", {})
    tactic_sequence = attacker_state.get("tactic_sequence", [])
    action_history = attacker_state.get("action_history", [])
    flags = attacker_state.get("flags_found", [])
    attempts = attacker_state.get("attempts_per_tactic", {})

    # Contar acciones por tactica
    actions_per_tactic: dict = {}
    for a in action_history:
        t = a.get("tactic", "unknown")
        actions_per_tactic[t] = actions_per_tactic.get(t, 0) + 1

    summary = Table(title="Resumen del Ataque — Objetivos por Tactica", expand=True)
    summary.add_column("Tactica", style="bold", no_wrap=True)
    summary.add_column("Estado", no_wrap=True)
    summary.add_column("Acciones", justify="right", no_wrap=True)
    summary.add_column("Replan", justify="right", no_wrap=True)
    summary.add_column("Evidencia", overflow="fold")

    for tactic in tactic_sequence:
        met = tactic_met.get(tactic, None)
        if met is True:
            status = "[green]OK[/green]"
        elif met is False:
            status = "[red]FALLO[/red]"
        else:
            status = "[dim]--[/dim]"

        ev = tactic_evidence.get(tactic, {})
        ev_parts = []
        for k, v in ev.items():
            if isinstance(v, bool):
                if v:
                    ev_parts.append(k)
            elif isinstance(v, list):
                ev_parts.append(f"{k}={len(v)}")
            else:
                ev_parts.append(f"{k}={str(v)[:40]}")
        ev_str = ", ".join(ev_parts) if ev_parts else "[dim](vacia)[/dim]"

        attempt_count = attempts.get(tactic, 0)
        summary.add_row(
            tactic,
            status,
            str(actions_per_tactic.get(tactic, 0)),
            str(attempt_count),
            ev_str,
        )

    console.print(summary)

    # Recolectar keys encontradas buscando los campos key_* en tactic_evidence
    keys_found = {}
    for tactic, evidence in tactic_evidence.items():
        for k, v in evidence.items():
            if k.startswith("key_") and v:
                # key_1, key_2, key_3, ...
                keys_found[k] = (v, tactic)

    if keys_found:
        console.print(
            f"\n[bold green]Flags/Keys capturados ({len(keys_found)}):[/bold green]"
        )
        for key_name in sorted(keys_found.keys()):
            value, tactic = keys_found[key_name]
            console.print(f"  {key_name.replace('_', '-')} ({tactic}): {value}")
    elif flags:
        console.print(
            f"\n[bold green]Flags/Keys capturados ({len(flags)}):[/bold green]"
        )
        for f in flags:
            console.print(f"  - {f}")
    else:
        console.print("[dim]No se capturaron flags durante el ataque.[/dim]")

    total_actions = len(action_history)
    total_tactics = len(tactic_sequence)
    met_count = sum(1 for t in tactic_sequence if tactic_met.get(t) is True)
    console.print(
        f"\n[bold]Resumen:[/bold] "
        f"{met_count}/{total_tactics} objetivos cumplidos, "
        f"{total_actions} acciones totales ejecutadas"
    )


def run_observer_loop(
    stop_event: threading.Event,
    results: list,
    poll_interval: int | None = None,
    simulation_start: datetime | None = None,
    state_lock: "threading.RLock | None" = None,
    use_heuristics: bool = True,
):
    """
    Loop del observador que se ejecuta en un thread separado.

    Cada poll_interval segundos:
    1. Crea un estado con la ventana temporal actual
    2. Ejecuta el grafo del observador
    3. Acumula la clasificacion en results

    El parametro simulation_start evita que logs de corridas anteriores
    contaminen las primeras ventanas de analisis. state_lock protege el
    shared mutable state (history, suspect_list, results) contra la race
    condition con el thread principal que hace join() al final.

    Se detiene cuando stop_event es seteado por el thread principal.
    """
    interval = poll_interval or settings.observer_poll_interval
    interval_delta = timedelta(seconds=interval)
    graph = build_observer_graph()
    history: list = []
    suspect_list: dict = {}
    # Memoria del observer: el fingerprint y prior se computan en la primera
    # ventana con logs, luego se persisten para que las siguientes ventanas
    # los reutilicen sin recomputar (NIST SP 800-94 baselining).
    traffic_fingerprint: str = ""
    baseline_prior: dict | None = None
    lock = state_lock or threading.RLock()

    start_time = simulation_start or datetime.now(timezone.utc)
    last_end = start_time

    console.print("[bold blue]AGENTE OBSERVADOR INICIADO[/bold blue]")

    def process_window(ws: datetime, we: datetime) -> None:
        nonlocal history, suspect_list, traffic_fingerprint, baseline_prior
        with lock:
            current_history = list(history)
            current_suspect = dict(suspect_list)
            current_fp = traffic_fingerprint
            current_prior = baseline_prior

        state = create_observer_state(
            history=current_history,
            suspect_list=current_suspect,
            simulation_start=simulation_start,
            window_start=ws,
            window_end=we,
            use_heuristics=use_heuristics,
            traffic_fingerprint=current_fp,
            baseline_prior=current_prior,
        )
        result = graph.invoke(state)
        classification = result.get("current_classification")
        triage_result = result.get("triage_result", "no_signal")

        # Captura fingerprint/prior si fueron computados en esta ventana
        new_fp = result.get("traffic_fingerprint", "")
        new_prior = result.get("baseline_prior")
        with lock:
            if new_fp and not traffic_fingerprint:
                traffic_fingerprint = new_fp
                baseline_prior = new_prior

        if classification:
            # Anota el fingerprint en la clasificacion para que update_baseline
            # lo recupere al final del run.
            classification["traffic_fingerprint"] = (
                new_fp or current_fp or traffic_fingerprint
            )
            tiw = classification.get("tactics_in_window", [])
            if len(tiw) > 1:
                names = ", ".join(t.get("tactic", "?") for t in tiw)
                console.print(
                    f"  [blue]En ventana: {names} | "
                    f"Actual: {classification['tactic']} "
                    f"({classification['confidence']:.0%})[/blue]"
                )
            else:
                console.print(
                    f"  [blue]Clasificacion: {classification['tactic']} "
                    f"(confianza: {classification['confidence']:.0%})[/blue]"
                )
            with lock:
                results.append(classification)
                history = list(result.get("classification_history", current_history))
                suspect_list = dict(result.get("suspect_list", current_suspect))
        else:
            placeholder = {
                "tactic": "none",
                "tactic_id": "",
                "confidence": 1.0 if triage_result == "no_signal" else 0.0,
                "evidence": [],
                "reasoning": (
                    f"Triage corto circuito ({triage_result})."
                    if triage_result == "no_signal"
                    else "LLM no produjo clasificacion."
                ),
                "recommendation": "Continuar monitoreo normal.",
                "timestamp": we.isoformat(),
                "window_start": ws.isoformat(),
                "window_end": we.isoformat(),
                "tactics_in_window": [],
            }
            console.print(
                f"  [dim]Ventana sin actividad ({triage_result}) — "
                f"registrada como 'none'[/dim]"
            )
            with lock:
                results.append(placeholder)

    # Loop principal: procesa ventanas contiguas mientras no se señale parada.
    # `wait()` retorna True si el event fue seteado durante la espera, asi que
    # salimos inmediatamente en lugar de completar el ciclo.
    while not stop_event.is_set():
        now = datetime.now(timezone.utc)
        next_end = last_end + interval_delta

        if next_end > now:
            remaining = (next_end - now).total_seconds()
            if stop_event.wait(remaining):
                break
            continue

        try:
            process_window(last_end, next_end)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error en observador: {e}")

        last_end = next_end

    # Flush: procesar ventanas pendientes hasta "now". Limite maximo de iteraciones
    # para evitar loops infinitos si process_window genera excepciones recurrentes
    # o si `now` se corrompe.
    flush_deadline = datetime.now(timezone.utc)
    max_flush_iters = max(5, int((flush_deadline - last_end).total_seconds() / interval) + 3)
    pending = 0
    iters = 0
    while last_end < flush_deadline and iters < max_flush_iters:
        iters += 1
        next_end = min(last_end + interval_delta, flush_deadline)
        try:
            process_window(last_end, next_end)
            pending += 1
        except Exception as e:
            logging.getLogger(__name__).error(f"Error en observador (flush): {e}")
            break
        last_end = next_end

    if pending:
        console.print(f"[dim]Observador: {pending} ventanas pendientes procesadas[/dim]")

    console.print("[bold blue]AGENTE OBSERVADOR FINALIZADO[/bold blue]\n")


_ABBREV = {
    "reconnaissance": "recon",
    "initial_access": "init_access",
    "execution": "execution",
    "discovery": "discovery",
    "credential_access": "cred_access",
    "privilege_escalation": "priv_esc",
    "persistence": "persist",
    "lateral_movement": "lateral",
    "defense_evasion": "def_evasion",
    "command_and_control": "c2",
    "exfiltration": "exfil",
    "impact": "impact",
}


def _abbrev_list(tactics: list[str]) -> str:
    return ", ".join(
        _ABBREV.get(t.lower().replace(" ", "_"), t) for t in tactics
    )


def _normalize_tactic(name: str) -> str:
    """Normaliza nombres de táctica: lowercase + underscores unificados."""
    if not name:
        return ""
    return name.lower().strip().replace(" ", "_")


def compare_results(attacker_state: dict, observer_classifications: list):
    """
    Compara el ground truth del atacante con las clasificaciones del observador.

    Metricas reportadas (apropiadas para clasificacion multi-clase, ref.
    Sokolova & Lapalme 2009, "A systematic analysis of performance measures
    for classification tasks"):
      - Accuracy estricta: current_tactic observada coincide con la ultima
        tactica real en la ventana
      - Accuracy ventana: todas las tacticas reales estan presentes en
        tactics_in_window del observador
      - Precision/Recall/F1 por tactica (micro + macro): estandar en
        clasificacion multi-clase, ref. Cybench/Hans et al. 2025
      - Matriz de confusion: current_tactic real vs observada

    Solo ventanas DENTRO del rango del ataque (primera accion → ultima)
    cuentan para las metricas. Ventanas pre/post-ataque se marcan N/A/FP.
    """
    table = Table(title="Resultados: Ground Truth vs Clasificacion", expand=True)
    table.add_column("Ventana", style="dim", no_wrap=True)
    table.add_column("Real (actual)", style="red", no_wrap=True)
    table.add_column("Real (ventana)", style="dim red", overflow="fold", min_width=20)
    table.add_column("Obs (actual)", style="blue", no_wrap=True)
    table.add_column("Obs (ventana)", style="dim blue", overflow="fold", min_width=20)
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Match", justify="center", no_wrap=True)

    action_history = attacker_state.get("action_history", [])
    attacker_timeline = [
        {"timestamp": a.get("timestamp", ""), "tactic": a.get("tactic", "")}
        for a in action_history
    ]

    # Rango real del ataque usando objetos datetime (robusto vs strings)
    attack_end_dt: datetime | None = None
    for a in attacker_timeline:
        dt = _parse_ts(a.get("timestamp", ""))
        if dt is not None and (attack_end_dt is None or dt > attack_end_dt):
            attack_end_dt = dt

    # Ordenar clasificaciones cronologicamente por window_end parseado
    sorted_cls = sorted(
        observer_classifications,
        key=lambda c: _parse_ts(c.get("window_end", "")) or _parse_ts(c.get("timestamp", "")) or datetime.min.replace(tzinfo=timezone.utc),
    )

    strict_correct = 0
    window_correct = 0
    evaluable = 0

    # Acumuladores para precision/recall/F1 por tactica
    # tp[t] = # de ventanas donde t fue predicha y esta en real_in_window
    # fp[t] = # de ventanas donde t fue predicha pero NO esta en real_in_window
    # fn[t] = # de ventanas donde t esta en real_in_window pero NO fue predicha
    from collections import defaultdict
    tp: dict[str, int] = defaultdict(int)
    fp: dict[str, int] = defaultdict(int)
    fn: dict[str, int] = defaultdict(int)
    # Acumuladores para bootstrap CI 95% (sets multi-label por ventana evaluable)
    eval_real_sets: list[set[str]] = []
    eval_obs_sets: list[set[str]] = []

    # Matriz de confusion: real_actual -> observed_actual -> count
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    all_tactics: set[str] = set()

    for cls in sorted_cls:
        ws_str = cls.get("window_start", "")
        we_str = cls.get("window_end", "")
        real_in_window = _real_tactics_in_window(ws_str, we_str, attacker_timeline)

        observed_current = cls.get("tactic", "?")
        observed_in_window_raw = [
            t.get("tactic", "") for t in cls.get("tactics_in_window", [])
            if isinstance(t, dict)
        ]
        observed_in_window = [t for t in observed_in_window_raw if t and t.strip()]
        if not observed_in_window and observed_current and observed_current != "none":
            observed_in_window = [observed_current]

        last_real = real_in_window[-1] if real_in_window else "unknown"
        is_pre_attack = last_real in ("unknown", "")
        ws_dt = _parse_ts(ws_str)
        is_post_attack = bool(attack_end_dt) and (ws_dt is not None) and ws_dt > attack_end_dt
        is_none_obs = observed_current == "none"

        real_current_abbrev = (
            "-" if is_pre_attack else _ABBREV.get(_normalize_tactic(last_real), last_real)
        )
        real_window_abbrev = (
            _abbrev_list(real_in_window[:-1]) if len(real_in_window) > 1 else ""
        )
        obs_abbrev = (
            "-" if is_none_obs else _ABBREV.get(_normalize_tactic(observed_current), observed_current)
        )
        obs_window_list = [
            t for t in observed_in_window if not _tactics_match(t, observed_current)
        ]
        obs_window_abbrev = _abbrev_list(obs_window_list) if obs_window_list else ""

        if is_pre_attack or is_post_attack:
            label = "N/A" if is_none_obs else "FP"
            match_label = label
            match_style = "dim" if is_none_obs else "yellow"
        else:
            evaluable += 1

            # Match estricto: current_tactic == ultima tactica real
            strict_ok = _tactics_match(last_real, observed_current)
            if strict_ok:
                strict_correct += 1

            # Match ventana: todas las tacticas reales deben ser detectadas
            window_ok = all(
                any(_tactics_match(rt, ot) for ot in observed_in_window)
                for rt in real_in_window
            )
            if window_ok:
                window_correct += 1

            # Actualizar confusion matrix (current_tactic real vs observada)
            real_norm = _normalize_tactic(last_real)
            obs_norm = _normalize_tactic(observed_current) if not is_none_obs else "none"
            confusion[real_norm][obs_norm] += 1
            all_tactics.add(real_norm)
            if obs_norm != "none":
                all_tactics.add(obs_norm)

            # TP/FP/FN por tactica sobre tactics_in_window (multi-label)
            real_set = {_normalize_tactic(t) for t in real_in_window if t}
            obs_set = {_normalize_tactic(t) for t in observed_in_window if t}
            for t in real_set:
                if t in obs_set:
                    tp[t] += 1
                else:
                    fn[t] += 1
            for t in obs_set:
                if t not in real_set:
                    fp[t] += 1
            # Acumular para bootstrap CI 95%
            eval_real_sets.append(real_set)
            eval_obs_sets.append(obs_set)

            match_style = "green" if strict_ok else "red"
            match_label = "OK" if strict_ok else "MISS"

        table.add_row(
            cls.get("timestamp", "")[:19],
            real_current_abbrev,
            real_window_abbrev,
            obs_abbrev,
            obs_window_abbrev,
            f"{cls.get('confidence', 0):.0%}",
            f"[{match_style}]{match_label}[/{match_style}]",
        )

    console.print(table)
    console.print("[dim]Match estricto: Obs(actual) == ultima tactica real en ventana[/dim]")
    console.print("[dim]Match ventana: todas las tacticas reales presentes en Obs(ventana)[/dim]")
    console.print("[dim]N/A = ventana pre/post-ataque sin ground truth | FP = falso positivo[/dim]")

    if not observer_classifications:
        return

    total = len(observer_classifications)
    console.print(
        f"\n[bold]Ventanas totales registradas:[/bold] {total} "
        f"(evaluables: {evaluable})"
    )
    if evaluable == 0:
        console.print("[yellow]No hay ventanas evaluables.[/yellow]")
        return

    console.print(
        f"  Accuracy estricta: {strict_correct}/{evaluable} "
        f"= {strict_correct/evaluable:.1%}"
    )
    console.print(
        f"  Accuracy ventana: {window_correct}/{evaluable} "
        f"= {window_correct/evaluable:.1%}"
    )

    # Precision/Recall/F1 por tactica
    pr_table = Table(
        title="Metricas por tactica (multi-label, tactics_in_window)",
        expand=False,
    )
    pr_table.add_column("Tactica", style="bold")
    pr_table.add_column("TP", justify="right")
    pr_table.add_column("FP", justify="right")
    pr_table.add_column("FN", justify="right")
    pr_table.add_column("Precision", justify="right")
    pr_table.add_column("Recall", justify="right")
    pr_table.add_column("F1", justify="right")
    pr_table.add_column("Support", justify="right")

    tactics_sorted = sorted(all_tactics)
    total_tp = total_fp = total_fn = 0
    macro_precision = macro_recall = macro_f1 = 0.0
    macro_n = 0

    for t in tactics_sorted:
        tp_t, fp_t, fn_t = tp[t], fp[t], fn[t]
        support = tp_t + fn_t
        prec = tp_t / (tp_t + fp_t) if (tp_t + fp_t) else 0.0
        rec = tp_t / (tp_t + fn_t) if (tp_t + fn_t) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        pr_table.add_row(
            _ABBREV.get(t, t),
            str(tp_t), str(fp_t), str(fn_t),
            f"{prec:.2f}", f"{rec:.2f}", f"{f1:.2f}",
            str(support),
        )
        total_tp += tp_t
        total_fp += fp_t
        total_fn += fn_t
        if support > 0:
            macro_precision += prec
            macro_recall += rec
            macro_f1 += f1
            macro_n += 1

    micro_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    micro_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    pr_table.add_section()
    pr_table.add_row(
        "[bold]micro[/bold]",
        str(total_tp), str(total_fp), str(total_fn),
        f"{micro_p:.2f}", f"{micro_r:.2f}", f"{micro_f1:.2f}",
        str(total_tp + total_fn),
    )
    if macro_n:
        pr_table.add_row(
            "[bold]macro[/bold]",
            "", "", "",
            f"{macro_precision/macro_n:.2f}",
            f"{macro_recall/macro_n:.2f}",
            f"{macro_f1/macro_n:.2f}",
            "",
        )
    console.print(pr_table)

    # Bootstrap CI 95% sobre macro_f1, micro_f1, strict_accuracy.
    # Critico para n=1 corrida con multi-label sobre 10+ clases: las medias
    # solas no son comparables sin intervalo de confianza (Efron 1979).
    bootstrap_ci = None
    if eval_real_sets:
        try:
            from src.evaluation.metrics import bootstrap_f1_ci
            bootstrap_ci = bootstrap_f1_ci(
                eval_real_sets, eval_obs_sets, n_resamples=1000, seed=42,
            )
            t_ci = Table(title="Bootstrap 95% CI (1000 resamples)", expand=False)
            t_ci.add_column("Metrica", style="bold")
            t_ci.add_column("Mean", justify="right")
            t_ci.add_column("CI low", justify="right")
            t_ci.add_column("CI high", justify="right")
            t_ci.add_column("Width", justify="right")
            for k in ("macro_f1", "micro_f1", "strict_accuracy"):
                mean, lo, hi = bootstrap_ci[k]
                t_ci.add_row(k, f"{mean:.3f}", f"{lo:.3f}", f"{hi:.3f}", f"{hi-lo:.3f}")
            console.print(t_ci)
        except Exception as e:
            logging.getLogger(__name__).warning(f"Bootstrap CI fallo: {e}")

    # Persistir bootstrap CI en variable de modulo para que _emit_report lo lea.
    global _LAST_BOOTSTRAP_CI
    _LAST_BOOTSTRAP_CI = bootstrap_ci

    # Matriz de confusion
    if len(confusion) >= 1:
        cm_labels = sorted(set(list(confusion.keys()) +
                               [k for v in confusion.values() for k in v.keys()]))
        cm_table = Table(
            title="Matriz de confusion (filas=real, columnas=observado)",
            expand=False,
        )
        cm_table.add_column("real \\ obs", style="bold")
        for l in cm_labels:
            cm_table.add_column(_ABBREV.get(l, l), justify="right")
        for r in cm_labels:
            row_cells = [_ABBREV.get(r, r)]
            for c in cm_labels:
                v = confusion.get(r, {}).get(c, 0)
                style_wrap = "[green]{}[/green]" if r == c and v > 0 else "{}"
                row_cells.append(style_wrap.format(v) if v else "·")
            cm_table.add_row(*row_cells)
        console.print(cm_table)


_WARNED_NAIVE_TIMESTAMP = False
_LAST_BOOTSTRAP_CI: dict | None = None


def _parse_ts(ts: str) -> datetime | None:
    """Parsea un timestamp ISO 8601 aceptando sufijo Z y offsets explicitos.

    Retorna None si el timestamp es invalido o vacio, en lugar de raise.
    Normaliza a UTC para comparaciones consistentes. Emite warning UNA VEZ
    si encuentra timestamps sin timezone (bug silente reportado en el audit).
    """
    global _WARNED_NAIVE_TIMESTAMP
    if not ts:
        return None
    try:
        # Python 3.11+ acepta Z nativamente; replace garantiza compatibilidad <3.11
        normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            if not _WARNED_NAIVE_TIMESTAMP:
                logging.getLogger(__name__).warning(
                    f"Timestamp sin timezone detectado: {ts!r}. Asumiendo UTC. "
                    "Si el sistema corre en timezone distinta, las ventanas del "
                    "observer pueden desalinearse con el ground truth del atacante."
                )
                _WARNED_NAIVE_TIMESTAMP = True
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _real_tactics_in_window(window_start: str, window_end: str, timeline: list[dict]) -> list[str]:
    """Todas las tacticas del atacante activas durante una ventana de observacion.

    Usa comparacion de objetos datetime (no string) para evitar bugs por
    diferencias de formato ISO (Z vs +00:00, microsegundos, etc).
    """
    if not timeline:
        return ["unknown"]

    ws = _parse_ts(window_start)
    we = _parse_ts(window_end)
    if ws is None or we is None:
        return ["unknown"]

    tactics = []
    tactic_at_start = _find_closest_tactic(window_start, timeline)
    if tactic_at_start != "unknown":
        tactics.append(tactic_at_start)

    for entry in timeline:
        ts = _parse_ts(entry.get("timestamp", ""))
        if ts is None:
            continue
        if ws < ts <= we:
            t = entry.get("tactic", "")
            if t and t not in tactics:
                tactics.append(t)
    return tactics or ["unknown"]


def _window_midpoint(cls: dict) -> str:
    """Punto medio de la ventana de observacion para comparar con el ground truth."""
    t_start = _parse_ts(cls.get("window_start", ""))
    t_end = _parse_ts(cls.get("window_end", ""))
    if t_start and t_end:
        return (t_start + (t_end - t_start) / 2).isoformat()
    return cls.get("timestamp", "")


def _find_closest_tactic(timestamp: str, timeline: list[dict]) -> str:
    """Encuentra la tactica del atacante activa antes de un timestamp dado.

    Retorna "unknown" si el timestamp es anterior a cualquier accion del
    atacante (ventana pre-ataque) o si hay error en parsing.
    """
    target = _parse_ts(timestamp)
    if target is None or not timeline:
        return "unknown"

    closest = "unknown"
    for entry in timeline:
        ts = _parse_ts(entry.get("timestamp", ""))
        if ts is None:
            continue
        if ts <= target:
            closest = entry.get("tactic", "unknown") or "unknown"
        else:
            break
    return closest


def _tactics_match(real: str, observed: str) -> bool:
    """Compara tacticas normalizando nombres (case + underscore/space)."""
    if not real or not observed:
        return False
    return real.lower().replace("_", " ").strip() == observed.lower().replace("_", " ").strip()


def print_timing_summary(
    attacker_state: dict,
    observer_classifications: list,
    session_elapsed_seconds: float,
) -> None:
    """
    Reporta todas las metricas medibles de la corrida:
    - Wall-clock y timings por agente.
    - Tokens / llamadas / latencias LLM por rol (atacante vs observer).
    - Tiempo por tactica del atacante.
    - Triage short-circuit rate (windows que evitaron LLM).
    - Refinamiento rate (windows que necesitaron Investigate).
    - Docker tool execution stats (n execs, latencia total, timeouts).
    - Loki HTTP query stats (n queries, latencia total, errores).
    - Tiempo por componente y throughput estimado del observer.
    """
    from src.llm.provider import USAGE_STATS
    from src.infrastructure.docker_client import DOCKER_STATS
    from src.infrastructure.loki_client import LOKI_STATS
    from src.agents.observer.nodes import OBSERVER_NODE_STATS

    attacker_s = float(attacker_state.get("attacker_elapsed_seconds", 0.0) or 0.0)
    latencies_ms = [
        int(c["llm_latency_ms"])
        for c in observer_classifications
        if isinstance(c, dict) and c.get("llm_latency_ms") is not None
    ]

    def _fmt_hms(secs: float) -> str:
        m, s = divmod(int(secs), 60)
        h, m = divmod(m, 60)
        return f"{h:d}h {m:02d}m {s:02d}s" if h else f"{m:d}m {s:02d}s"

    # 1) Tiempos globales
    t_time = Table(title="Tiempos de ejecucion", expand=False)
    t_time.add_column("Metrica", style="bold")
    t_time.add_column("Valor", justify="right")
    t_time.add_row("Wall-clock total de la sesion", _fmt_hms(session_elapsed_seconds))
    t_time.add_row("Atacante (run_attacker)", _fmt_hms(attacker_s))
    console.print(t_time)

    # 2) Tiempo por tactica del atacante
    tactic_durations = attacker_state.get("tactic_duration_seconds", {}) or {}
    tactic_objective_met = attacker_state.get("tactic_objective_met", {}) or {}
    if tactic_durations:
        t_tactic = Table(title="Tiempo por tactica (atacante)", expand=False)
        t_tactic.add_column("Tactica", style="bold")
        t_tactic.add_column("Duracion", justify="right")
        t_tactic.add_column("Estado", justify="center")
        for t, secs in tactic_durations.items():
            status = "OK" if tactic_objective_met.get(t) is True else "FAIL" if tactic_objective_met.get(t) is False else "-"
            t_tactic.add_row(t, _fmt_hms(float(secs)), status)
        console.print(t_tactic)

    # 3) Uso del LLM por rol
    t_llm = Table(title="Uso del LLM por agente", expand=False)
    t_llm.add_column("Metrica", style="bold")
    t_llm.add_column("Atacante", justify="right")
    t_llm.add_column("Observer", justify="right")
    a = USAGE_STATS.get("attacker", {})
    o = USAGE_STATS.get("observer", {})
    t_llm.add_row("Proveedor", str(a.get("provider") or "-"), str(o.get("provider") or "-"))
    t_llm.add_row("Modelo", str(a.get("model") or "-"), str(o.get("model") or "-"))
    t_llm.add_row("Llamadas LLM", str(a.get("call_count", 0)), str(o.get("call_count", 0)))
    t_llm.add_row("Tokens input", f"{a.get('input_tokens', 0):,}", f"{o.get('input_tokens', 0):,}")
    t_llm.add_row("Tokens output", f"{a.get('output_tokens', 0):,}", f"{o.get('output_tokens', 0):,}")
    t_llm.add_row("Tokens total", f"{a.get('total_tokens', 0):,}", f"{o.get('total_tokens', 0):,}")
    t_llm.add_row(
        "Cache creation tokens",
        f"{a.get('cache_creation_input_tokens', 0):,}",
        f"{o.get('cache_creation_input_tokens', 0):,}",
    )
    t_llm.add_row(
        "Cache read tokens",
        f"{a.get('cache_read_input_tokens', 0):,}",
        f"{o.get('cache_read_input_tokens', 0):,}",
    )
    # Hit rate = cache_read / (cache_read + input_tokens) — refleja porcentaje
    # del input que se sirvio desde cache; clave para verificar M1.
    for role_label, stats in [("Atacante", a), ("Observer", o)]:
        cr = int(stats.get("cache_read_input_tokens", 0) or 0)
        it = int(stats.get("input_tokens", 0) or 0)
        denom = cr + it
        rate = (cr / denom * 100) if denom else 0.0
        # solo agregar columna unica para no romper la tabla; loggea en consola aparte
        if role_label == "Atacante":
            t_llm.add_row("Cache hit rate", f"{rate:.1f}%",
                          f"{((int(o.get('cache_read_input_tokens', 0) or 0) / max(int(o.get('cache_read_input_tokens', 0) or 0) + int(o.get('input_tokens', 0) or 0), 1)) * 100):.1f}%")
            break
    t_llm.add_row("Tiempo sumado LLM", _fmt_hms(float(a.get("elapsed_seconds", 0.0) or 0.0)),
                  _fmt_hms(float(o.get("elapsed_seconds", 0.0) or 0.0)))
    # Costo estimado USD (M9): incluye precio diferencial por cache_read/creation.
    from src.llm.provider import estimate_cost_usd
    a_cost = estimate_cost_usd("attacker")
    o_cost = estimate_cost_usd("observer")
    t_llm.add_row("Costo estimado (USD)", f"${a_cost:.4f}", f"${o_cost:.4f}")
    t_llm.add_row("Costo total (USD)", f"${a_cost + o_cost:.4f}", "")
    if a.get("call_count", 0):
        t_llm.add_row("Tokens/llamada (avg)",
                      f"{a.get('total_tokens', 0)/max(a.get('call_count', 1), 1):.0f}",
                      f"{o.get('total_tokens', 0)/max(o.get('call_count', 1), 1):.0f}")
    if latencies_ms:
        latencies_sorted = sorted(latencies_ms)
        p50 = latencies_sorted[len(latencies_sorted) // 2]
        p95 = latencies_sorted[min(len(latencies_sorted) - 1, int(len(latencies_sorted) * 0.95))]
        avg_ms = sum(latencies_ms) / len(latencies_ms)
        t_llm.add_row("Observer — latencia avg", "-", f"{avg_ms/1000:.2f} s")
        t_llm.add_row("Observer — latencia p50", "-", f"{p50/1000:.2f} s")
        t_llm.add_row("Observer — latencia p95", "-", f"{p95/1000:.2f} s")
    console.print(t_llm)

    # 4) Pipeline del observer (triage + refine + classify)
    obs = OBSERVER_NODE_STATS
    total_wins = obs.get("triage_signal", 0) + obs.get("triage_no_signal", 0)
    if total_wins:
        sc_rate = obs.get("triage_no_signal", 0) / total_wins
        t_obs = Table(title="Pipeline del observer", expand=False)
        t_obs.add_column("Metrica", style="bold")
        t_obs.add_column("Valor", justify="right")
        t_obs.add_row("Ventanas procesadas", str(total_wins))
        t_obs.add_row("Triage signal (fueron al LLM)", str(obs.get("triage_signal", 0)))
        t_obs.add_row("Triage no-signal (corto-circuito)", str(obs.get("triage_no_signal", 0)))
        t_obs.add_row("Tasa de corto-circuito", f"{sc_rate:.1%}")
        t_obs.add_row("Refinamientos invocados", str(obs.get("refine_calls", 0)))
        t_obs.add_row("Clasificaciones totales", str(obs.get("classify_calls", 0)))
        if obs.get("triage_signal", 0):
            reclass_ratio = obs.get("classify_calls", 0) / obs.get("triage_signal", 1)
            t_obs.add_row("Clasificaciones por ventana anomalica", f"{reclass_ratio:.2f}")
        console.print(t_obs)

    # 5) Tool execution (Docker exec del atacante)
    dstats = DOCKER_STATS
    if dstats.get("exec_count", 0):
        t_docker = Table(title="Ejecucion de herramientas (Docker)", expand=False)
        t_docker.add_column("Metrica", style="bold")
        t_docker.add_column("Valor", justify="right")
        t_docker.add_row("Execs totales", str(dstats.get("exec_count", 0)))
        t_docker.add_row("Tiempo total de ejecucion", _fmt_hms(float(dstats.get("total_seconds", 0.0) or 0.0)))
        if dstats.get("exec_count", 0):
            avg = float(dstats.get("total_seconds", 0.0) or 0.0) / int(dstats.get("exec_count", 1))
            t_docker.add_row("Tiempo promedio por exec", f"{avg:.2f} s")
        t_docker.add_row("Execs que excedieron timeout", str(dstats.get("timed_out_count", 0)))
        t_docker.add_row("Execs con error de API", str(dstats.get("error_count", 0)))
        console.print(t_docker)

    # 5b) Loki HTTP query stats (observer)
    lstats = LOKI_STATS
    if lstats.get("query_count", 0):
        t_loki = Table(title="Consultas a Loki (observer)", expand=False)
        t_loki.add_column("Metrica", style="bold")
        t_loki.add_column("Valor", justify="right")
        t_loki.add_row("Queries totales", str(lstats.get("query_count", 0)))
        t_loki.add_row("Tiempo total HTTP", _fmt_hms(float(lstats.get("total_seconds", 0.0) or 0.0)))
        if lstats.get("query_count", 0):
            avg = float(lstats.get("total_seconds", 0.0) or 0.0) / int(lstats.get("query_count", 1))
            t_loki.add_row("Tiempo promedio por query", f"{avg*1000:.0f} ms")
        t_loki.add_row("Queries con error", str(lstats.get("error_count", 0)))
        console.print(t_loki)

    # 5c) Tiempo por componente (atacante LLM, observer LLM, docker, loki)
    t_components = Table(title="Tiempo por componente (corrida completa)", expand=False)
    t_components.add_column("Componente", style="bold")
    t_components.add_column("Segundos", justify="right")
    t_components.add_column("% wall-clock", justify="right")
    a_llm = float(a.get("elapsed_seconds", 0.0) or 0.0)
    o_llm = float(o.get("elapsed_seconds", 0.0) or 0.0)
    docker_s = float(dstats.get("total_seconds", 0.0) or 0.0)
    loki_s = float(lstats.get("total_seconds", 0.0) or 0.0)
    wall = max(session_elapsed_seconds, 1e-6)
    for label, secs in [
        ("LLM atacante", a_llm),
        ("LLM observer", o_llm),
        ("Docker exec", docker_s),
        ("Loki HTTP", loki_s),
    ]:
        t_components.add_row(label, f"{secs:.1f}", f"{100*secs/wall:.1f}%")
    t_components.add_row("Wall-clock total", f"{wall:.1f}", "100.0%")
    console.print(t_components)

    # 5d) Throughput observer y backlog (latencia LLM vs intervalo de polling).
    # Backlog ~= ceil(latencia_promedio_obs / poll_interval) - 1; si > 0 indica
    # que las ventanas se acumulan mas rapido de lo que el observer las procesa.
    poll_interval = settings.observer_poll_interval
    if latencies_ms and poll_interval > 0:
        avg_obs_latency_s = sum(latencies_ms) / len(latencies_ms) / 1000.0
        backlog_ratio = avg_obs_latency_s / poll_interval - 1.0
        t_thr = Table(title="Throughput del observer", expand=False)
        t_thr.add_column("Metrica", style="bold")
        t_thr.add_column("Valor", justify="right")
        t_thr.add_row("Intervalo de polling", f"{poll_interval} s")
        t_thr.add_row("Latencia promedio LLM observer", f"{avg_obs_latency_s:.2f} s")
        t_thr.add_row(
            "Backlog acumulado (ratio)",
            f"{backlog_ratio:+.2f}" + (" (acumula)" if backlog_ratio > 0 else " (drena)")
        )
        console.print(t_thr)

    # 6) Acciones por tactica + intentos (resumen condensado)
    actions = attacker_state.get("action_history", []) or []
    attempts = attacker_state.get("attempts_per_tactic", {}) or {}
    actions_per_tactic: dict = {}
    for a_ in actions:
        t = a_.get("tactic", "unknown")
        actions_per_tactic[t] = actions_per_tactic.get(t, 0) + 1
    if actions_per_tactic:
        t_act = Table(title="Acciones e intentos por tactica", expand=False)
        t_act.add_column("Tactica", style="bold")
        t_act.add_column("Acciones", justify="right")
        t_act.add_column("Replans", justify="right")
        for t in actions_per_tactic:
            t_act.add_row(t, str(actions_per_tactic[t]), str(attempts.get(t, 0)))
        console.print(t_act)


def main():
    parser = argparse.ArgumentParser(description="Sistema Adversarial MITRE ATT&CK")
    parser.add_argument(
        "--scenario", default="basic",
        help="Escenario a ejecutar (basic, full)"
    )
    parser.add_argument(
        "--target", default=None,
        help="IP del target (default: config)"
    )
    parser.add_argument(
        "--observer-interval", type=int, default=10,
        help="Ventana de polling del observador en segundos. Default 10s "
             "(calibrado para capturar tacticas rapidas tipo RCE; ref: Bhuyan "
             "et al. 2014 'On the Effectiveness of Sliding Windows for Network "
             "Anomaly Detection'). Ventanas mas largas (20-30s) reducen costo "
             "de LLM pero pierden recall en tacticas que duran <5s."
    )
    parser.add_argument(
        "--attacker-only", action="store_true",
        help="Ejecutar solo el atacante sin observador"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--tool-output", action="store_true",
        help="Mostrar output raw de las herramientas ejecutadas (nmap, nikto, hydra, etc.)"
    )
    parser.add_argument(
        "--no-memory", action="store_true",
        help="Deshabilita la memoria de playbooks (cold run, util para ablation)"
    )
    parser.add_argument(
        "--no-heuristics", action="store_true",
        help="Ablation: el observador saltea T1-T10 y clasifica solo con LLM sobre log_summary"
    )
    parser.add_argument(
        "--report-dir", default="data/reports",
        help="Directorio de salida de reportes HTML/JSON post-run (default: data/reports)"
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Salta la generacion del reporte HTML al final"
    )
    parser.add_argument(
        "--dashboard", action="store_true",
        help="Activa dashboard Live (Rich split-screen) que muestra atacante + "
             "observador en tiempo real. Convive con los logs estandar."
    )
    args = parser.parse_args()

    if args.tool_output:
        import os as _os
        _os.environ["SHOW_TOOL_OUTPUT"] = "1"

    setup_logging(args.verbose)
    verify_infrastructure(scenario=args.scenario)
    preflight_llm_check()

    # Inicia el session recorder para capturar todos los eventos del run.
    session = get_session()
    session.reset()
    attacker_model_name = (
        settings.openai_model if settings.llm_provider.value == "openai"
        else settings.anthropic_model if settings.llm_provider.value == "anthropic"
        else settings.google_model if settings.llm_provider.value == "google"
        else settings.groq_model if settings.llm_provider.value == "groq"
        else settings.openrouter_model if settings.llm_provider.value == "openrouter"
        else settings.cerebras_model
    )
    session.set_metadata(
        scenario=args.scenario,
        attacker_provider=settings.llm_provider.value,
        attacker_model=attacker_model_name,
        observer_provider=(settings.observer_provider.value if settings.observer_provider
                            else settings.llm_provider.value),
        observer_model=settings.observer_model,
        seed=settings.llm_seed,
        attacker_temperature=settings.attacker_temperature,
        observer_temperature=settings.observer_temperature,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    session.system_event("session_start", scenario=args.scenario)

    dashboard = None
    if args.dashboard:
        from src.ui.dashboard import LiveDashboard
        dashboard = LiveDashboard(
            scenario=args.scenario,
            target=args.target or "",
            attacker_model=attacker_model_name,
            observer_model=settings.observer_model,
        )
        session.subscribe(dashboard.push_event)
        dashboard.start()

    # Definir tacticas y target por escenario
    scenarios = {
        "basic": {
            "tactics": ["reconnaissance", "initial_access", "execution", "discovery"],
            "target": None,
        },
        "recon_only": {
            "tactics": ["reconnaissance"],
            "target": None,
        },
        "dvwa": {
            "tactics": [
                "reconnaissance",
                "initial_access",
                "execution",
                "discovery",
                "credential_access",
                "privilege_escalation",
            ],
            "target": "10.10.0.10",
        },
        "mrrobot": {
            "tactics": [
                "reconnaissance",
                "initial_access",
                "execution",
                "discovery",
                "credential_access",
                "privilege_escalation",
            ],
            "target": "10.10.0.20",
        },
        "dc1": {
            "tactics": [
                "reconnaissance",
                "initial_access",
                "execution",
                "discovery",
                "credential_access",
                "privilege_escalation",
            ],
            "target": "10.10.0.30",
        },
        "bpent": {
            "tactics": [
                "reconnaissance",
                "initial_access",
                "execution",
                "discovery",
                "credential_access",
                "privilege_escalation",
            ],
            "target": "10.10.0.40",
        },
        # Log4Shell — RCE vía JNDI injection sin autenticacion.
        # Escenario compacto: Recon + Execution + Discovery.
        # Initial Access y Credential Access NO aplican (RCE es pre-auth).
        "log4shell": {
            "tactics": [
                "reconnaissance",
                "execution",
                "discovery",
            ],
            "target": "10.10.0.50",
        },
        # Confluence OGNL — RCE vía expression injection sin autenticacion.
        "confluence": {
            "tactics": [
                "reconnaissance",
                "execution",
                "discovery",
            ],
            "target": "10.10.0.60",
        },
        "full": {
            "tactics": [
                "reconnaissance", "initial_access", "execution",
                "discovery", "persistence", "privilege_escalation",
                "credential_access", "lateral_movement",
            ],
            "target": None,
        },
    }
    scenario_config = scenarios.get(args.scenario, scenarios["basic"])
    tactics = scenario_config["tactics"]
    target = args.target or scenario_config["target"]
    if dashboard is not None:
        dashboard.attacker_total_tactics = len(tactics)
        dashboard.target = target or ""

    if args.attacker_only:
        # Solo atacante, sin observador
        try:
            attacker_state = run_attacker(tactics=tactics, target=target, use_memory=not args.no_memory)
            print_attack_summary(attacker_state)
            _emit_report(args, scenario_config, attacker_state, [])
        finally:
            if dashboard is not None:
                dashboard.stop()
        return

    # Ejecucion completa: atacante + observador en paralelo
    try:
        _run_full_session(args, scenario_config, tactics, target)
    finally:
        if dashboard is not None:
            dashboard.stop()


def _run_full_session(args, scenario_config: dict, tactics: list, target: str | None) -> None:
    """Cuerpo de la corrida completa atacante + observer (extraido para que main()
    pueda envolverlo en try/finally para shutdown del dashboard)."""
    observer_results: list = []
    stop_event = threading.Event()
    observer_lock = threading.RLock()

    # Timestamp de inicio de esta simulacion: el observador no debe mirar logs
    # anteriores a este punto (evita contaminacion de corridas previas).
    simulation_start = datetime.now(timezone.utc)
    _session_t0 = time.monotonic()

    # Iniciar observador en thread separado. El lock protege observer_results,
    # history y suspect_list (estado compartido con el thread principal que
    # hace join() y luego lee results).
    observer_thread = threading.Thread(
        target=run_observer_loop,
        args=(stop_event, observer_results, args.observer_interval, simulation_start, observer_lock),
        kwargs={"use_heuristics": not args.no_heuristics},
        daemon=True,
    )
    observer_thread.start()

    # Dar tiempo al observador para su primera recoleccion
    time.sleep(3)

    # Ejecutar atacante en el thread principal
    attacker_state = run_attacker(tactics=tactics, target=target, use_memory=not args.no_memory)

    # Dar tiempo al observador para clasificar las ultimas acciones.
    # Tres ciclos completos: el que estaba en curso termina + dos mas que ven
    # el estado final del ataque, dando al observador tiempo suficiente para
    # capturar tacticas que el atacante completo rapidamente.
    time.sleep(args.observer_interval * 3 + settings.observer_shutdown_grace_seconds)
    stop_event.set()
    # Join con timeout suficiente para permitir que se complete la ventana
    # actual + el flush de pendientes. Si el observer tiene N ventanas
    # pendientes, cada una puede tardar hasta 30s (LLM + loki), así que
    # damos un margen proporcional al intervalo.
    observer_thread.join(timeout=args.observer_interval * 4 + 30)
    if observer_thread.is_alive():
        logging.getLogger(__name__).warning(
            "Observer thread did not finish in time; proceeding with current results."
        )

    # Leer results bajo lock (consistency con el thread background)
    with observer_lock:
        observer_results_snapshot = list(observer_results)

    _session_elapsed = round(time.monotonic() - _session_t0, 2)

    # Resumen del ataque: objetivos cumplidos, evidencia extraida, flags
    print_attack_summary(attacker_state)

    # Comparar resultados del observador
    compare_results(attacker_state, observer_results_snapshot)

    # Reporte de tiempos de ejecucion
    print_timing_summary(attacker_state, observer_results_snapshot, _session_elapsed)

    # Actualiza baseline del observer (NIST SP 800-94 baselining): persiste el
    # prior estadistico de tacticas observadas para que la proxima corrida sobre
    # el mismo tipo de target tenga prior calibrado.
    _update_observer_memory(observer_results_snapshot, attacker_state)

    _emit_report(args, scenario_config, attacker_state, observer_results_snapshot)


def _update_observer_memory(observer_results: list, attacker_state: dict) -> None:
    """Persiste la baseline del observer si hubo clasificaciones."""
    if not observer_results:
        return
    try:
        from src.agents.observer.memory import update_baseline
        # Recovery del fingerprint usado: lo guardamos en el primer resultado
        # del observer si hubo. Si no, usamos heuristica basada en target.
        target = attacker_state.get("target", "")
        # Construimos el fingerprint a posteriori del traffic_fingerprint que
        # quedo en alguna clasificacion (es el mismo a traves de ventanas).
        # Si no esta, usamos el target IP como fp degraded.
        fp = next(
            (c.get("traffic_fingerprint", "") for c in observer_results
             if isinstance(c, dict) and c.get("traffic_fingerprint")),
            "",
        )
        if not fp:
            # Fallback: hash del target (menos preciso pero funcional)
            import hashlib as _h
            fp = _h.sha256(f"target:{target}".encode()).hexdigest()[:16]
        target_summary = f"target_ip={target}"
        update_baseline(fp, observer_results, target_summary=target_summary)
        console.print(f"[dim]💾 Observer baseline actualizada (fp={fp})[/dim]")
    except Exception as e:
        logging.getLogger(__name__).warning(f"No se pudo actualizar baseline observer: {e}")


def _estimate_cost(role: str) -> float:
    from src.llm.provider import estimate_cost_usd
    return estimate_cost_usd(role)


def _emit_report(args, scenario_config: dict, attacker_state: dict, observer_results: list) -> None:
    """Genera reporte HTML + JSON post-run con todos los eventos capturados."""
    if args.no_report:
        return
    from src.llm.provider import USAGE_STATS
    from src.infrastructure.docker_client import DOCKER_STATS
    from src.infrastructure.loki_client import LOKI_STATS

    session = get_session()
    fp = attacker_state.get("target_fingerprint", "") or ""
    matched = attacker_state.get("matched_playbook")
    memory_runs_previas = 0
    if isinstance(matched, dict):
        memory_runs_previas = int(matched.get("run_count", 0) or 0)
    memory_hit = bool(matched)

    obs_latencies_ms = [
        int(c["llm_latency_ms"])
        for c in observer_results
        if isinstance(c, dict) and c.get("llm_latency_ms") is not None
    ]
    avg_obs_latency_s = (
        sum(obs_latencies_ms) / len(obs_latencies_ms) / 1000.0
        if obs_latencies_ms else 0.0
    )
    poll_interval = settings.observer_poll_interval
    backlog_ratio = (
        avg_obs_latency_s / poll_interval - 1.0
        if obs_latencies_ms and poll_interval > 0
        else 0.0
    )

    a_stats = USAGE_STATS.get("attacker", {})
    o_stats = USAGE_STATS.get("observer", {})

    session.set_metadata(
        finished_at=datetime.now(timezone.utc).isoformat(),
        elapsed_seconds=attacker_state.get("attacker_elapsed_seconds", 0),
        target=args.target or scenario_config.get("target", ""),
        tactics_planned=scenario_config.get("tactics", []),
        tactics_completed=sum(
            1 for t in scenario_config.get("tactics", [])
            if attacker_state.get("tactic_objective_met", {}).get(t) is True
        ),
        observer_classifications=len(observer_results),
        # Memoria del atacante
        memory_hit=memory_hit,
        memory_fingerprint=fp,
        memory_runs_previas=memory_runs_previas,
        # Tiempo por componente
        time_attacker_llm_s=float(a_stats.get("elapsed_seconds", 0.0) or 0.0),
        time_observer_llm_s=float(o_stats.get("elapsed_seconds", 0.0) or 0.0),
        time_docker_exec_s=float(DOCKER_STATS.get("total_seconds", 0.0) or 0.0),
        time_loki_http_s=float(LOKI_STATS.get("total_seconds", 0.0) or 0.0),
        # Cache hits (verificacion de M1 prompt caching)
        attacker_cache_creation_tokens=int(a_stats.get("cache_creation_input_tokens", 0) or 0),
        attacker_cache_read_tokens=int(a_stats.get("cache_read_input_tokens", 0) or 0),
        observer_cache_creation_tokens=int(o_stats.get("cache_creation_input_tokens", 0) or 0),
        observer_cache_read_tokens=int(o_stats.get("cache_read_input_tokens", 0) or 0),
        # Costo USD estimado (M9): usa pricing 2026-01. Si modelo no listado, 0.
        attacker_cost_usd=_estimate_cost("attacker"),
        observer_cost_usd=_estimate_cost("observer"),
        # Throughput observer
        observer_avg_latency_s=avg_obs_latency_s,
        observer_poll_interval_s=poll_interval,
        observer_backlog_ratio=backlog_ratio,
        # Tactic durations (ya calculadas por el grafo del atacante)
        tactic_duration_seconds=attacker_state.get("tactic_duration_seconds", {}),
        # Conteos brutos para tabla
        tool_calls=len(attacker_state.get("action_history", []) or []),
        replans=sum(
            int(v) for v in (attacker_state.get("attempts_per_tactic", {}) or {}).values()
        ),
        # Bootstrap 95% CI (Fase 1 — defensa estadistica vs n=1)
        bootstrap_ci=_LAST_BOOTSTRAP_CI,
    )
    session.system_event("session_end")

    from pathlib import Path
    out_dir = Path(args.report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{args.scenario}_{ts_tag}"

    # JSON crudo (analizable por scripts)
    json_path = out_dir / f"{base}.json"
    session.save_json(json_path)

    # HTML autosuficiente para revision visual / tesis
    html_path = out_dir / f"{base}.html"
    generate_report(session.to_dict(), html_path)

    console.print(
        f"\n[bold cyan]📄 Reporte HTML generado:[/bold cyan] {html_path}\n"
        f"[dim]   JSON crudo: {json_path}[/dim]"
    )


if __name__ == "__main__":
    main()
