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


def verify_infrastructure(scenario: str = "basic"):
    """Verifica que los containers requeridos por el escenario estan corriendo."""
    dc = DockerClient()
    base = ["attacker", "loki"]
    scenario_containers = {
        "basic": base + ["dvwa"],
        "recon_only": base + ["dvwa"],
        "dvwa": base + ["dvwa"],
        "full": base + ["dvwa"],
        "mrrobot": base + ["mrrobot"],
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
) -> dict:
    """
    Ejecuta el agente atacante y retorna el estado final.

    El grafo se ejecuta con stream() para poder ver el progreso en tiempo real.
    Cada paso del grafo emite un evento que podemos loguear.
    """
    graph = build_attacker_graph()
    initial_state = create_initial_state(target=target, tactics=tactics)

    console.print("\n[bold red]AGENTE ATACANTE INICIADO[/bold red]")
    console.print(f"  Target: {initial_state['target']}")
    console.print(f"  Tacticas: {initial_state['tactic_sequence']}")

    # Inicializar final_state con initial_state para preservar campos que no
    # cambian entre eventos (tactic_sequence, target, etc)
    final_state = dict(initial_state)
    accumulated_history = []
    accumulated_evidence = {}
    accumulated_collected = {}
    accumulated_flags = []
    accumulated_met = {}
    accumulated_attempts = {}
    for event in graph.stream(initial_state, {"recursion_limit": 500}):
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
    summary.add_column("Evidencia clave", overflow="fold")

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
        f"\n[bold]Resumen ejecutivo:[/bold] "
        f"{met_count}/{total_tactics} objetivos cumplidos, "
        f"{total_actions} acciones totales ejecutadas"
    )


def run_observer_loop(
    stop_event: threading.Event,
    results: list,
    poll_interval: int | None = None,
    simulation_start: datetime | None = None,
):
    """
    Loop del observador que se ejecuta en un thread separado.

    Cada poll_interval segundos:
    1. Crea un estado con la ventana temporal actual
    2. Ejecuta el grafo del observador
    3. Acumula la clasificacion en results

    El parametro simulation_start evita que logs de corridas anteriores
    contaminen las primeras ventanas de analisis.

    Se detiene cuando stop_event es seteado por el thread principal.
    """
    interval = poll_interval or settings.observer_poll_interval
    interval_delta = timedelta(seconds=interval)
    graph = build_observer_graph()
    history = []
    suspect_list = {}

    start_time = simulation_start or datetime.now(timezone.utc)
    last_end = start_time

    console.print("[bold blue]AGENTE OBSERVADOR INICIADO[/bold blue]")

    def process_window(ws: datetime, we: datetime) -> None:
        nonlocal history, suspect_list
        state = create_observer_state(
            history=history,
            suspect_list=suspect_list,
            simulation_start=simulation_start,
            window_start=ws,
            window_end=we,
        )
        result = graph.invoke(state)
        classification = result.get("current_classification")
        triage_result = result.get("triage_result", "no_signal")

        if classification:
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
            results.append(classification)
            history = result.get("classification_history", history)
            suspect_list = result.get("suspect_list", suspect_list)
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
            results.append(placeholder)

    while not stop_event.is_set():
        now = datetime.now(timezone.utc)
        next_end = last_end + interval_delta

        if next_end > now:
            stop_event.wait((next_end - now).total_seconds())
            continue

        try:
            process_window(last_end, next_end)
        except Exception as e:
            logging.getLogger(__name__).error(f"Error en observador: {e}")

        last_end = next_end

    now = datetime.now(timezone.utc)
    pending = 0
    while last_end < now:
        next_end = min(last_end + interval_delta, now)
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


def compare_results(attacker_state: dict, observer_classifications: list):
    """
    Compara el ground truth del atacante con las clasificaciones del observador.

    Accuracy calculada solo sobre ventanas que caen dentro del rango del ataque
    real (desde la primera accion hasta la ultima). Las ventanas fuera de ese
    rango se muestran pero marcadas como N/A.
    """
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
        return ", ".join(_ABBREV.get(t.lower().replace(" ", "_"), t) for t in tactics)

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

    attack_start = min((a["timestamp"] for a in attacker_timeline), default="")
    attack_end = max((a["timestamp"] for a in attacker_timeline), default="")

    # Ordenar clasificaciones cronologicamente por window_end
    sorted_cls = sorted(
        observer_classifications,
        key=lambda c: c.get("window_end", c.get("timestamp", "")),
    )

    strict_correct = 0
    window_correct = 0
    evaluable = 0

    for cls in sorted_cls:
        ws = cls.get("window_start", "")
        we = cls.get("window_end", "")
        real_in_window = _real_tactics_in_window(ws, we, attacker_timeline)

        observed_current = cls.get("tactic", "?")
        observed_in_window = [
            t.get("tactic", "") for t in cls.get("tactics_in_window", [])
        ]
        if not observed_in_window and observed_current and observed_current != "none":
            observed_in_window = [observed_current]

        last_real = real_in_window[-1] if real_in_window else "unknown"
        is_pre_attack = last_real in ("unknown", "")
        is_post_attack = bool(attack_end) and ws > attack_end
        is_none_obs = observed_current == "none"

        real_current_abbrev = (
            "-" if is_pre_attack else _ABBREV.get(last_real.lower().replace(" ", "_"), last_real)
        )
        real_window_abbrev = (
            _abbrev_list(real_in_window[:-1]) if len(real_in_window) > 1 else ""
        )
        obs_abbrev = (
            "-" if is_none_obs else _ABBREV.get(observed_current.lower().replace(" ", "_"), observed_current)
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
            strict_ok = _tactics_match(last_real, observed_current)
            if strict_ok:
                strict_correct += 1
            window_ok = all(
                any(_tactics_match(rt, ot) for ot in observed_in_window)
                for rt in real_in_window
            )
            if window_ok:
                window_correct += 1
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
    console.print("[dim]N/A = ventana pre-ataque sin ground truth | FP = falso positivo[/dim]")

    if observer_classifications:
        total = len(observer_classifications)
        console.print(
            f"\nVentanas totales registradas: {total} "
            f"(evaluables con ground truth: {evaluable})"
        )
        if evaluable > 0:
            console.print(
                f"Accuracy actual (estricta): {strict_correct}/{evaluable} "
                f"({strict_correct/evaluable:.0%})"
            )
            console.print(
                f"Accuracy ventana (tacticas completas): {window_correct}/{evaluable} "
                f"({window_correct/evaluable:.0%})"
            )
        else:
            console.print("No hay ventanas evaluables.")


def _real_tactics_in_window(window_start: str, window_end: str, timeline: list[dict]) -> list[str]:
    """Todas las tacticas del atacante activas durante una ventana de observacion."""
    if not timeline:
        return ["unknown"]
    tactics = []
    tactic_at_start = _find_closest_tactic(window_start, timeline)
    if tactic_at_start != "unknown":
        tactics.append(tactic_at_start)
    for entry in timeline:
        ts = entry.get("timestamp", "")
        if window_start < ts <= window_end:
            t = entry.get("tactic", "")
            if t and t not in tactics:
                tactics.append(t)
    return tactics or ["unknown"]


def _window_midpoint(cls: dict) -> str:
    """Punto medio de la ventana de observacion para comparar con el ground truth."""
    ws, we = cls.get("window_start", ""), cls.get("window_end", "")
    if ws and we:
        try:
            t_start = datetime.fromisoformat(ws)
            t_end = datetime.fromisoformat(we)
            return (t_start + (t_end - t_start) / 2).isoformat()
        except Exception:
            pass
    return cls.get("timestamp", "")


def _find_closest_tactic(timestamp: str, timeline: list[dict]) -> str:
    """
    Encuentra la tactica del atacante activa antes de un timestamp dado.

    Retorna "unknown" si el timestamp es anterior a cualquier accion del
    atacante (ventana pre-ataque).
    """
    if not timeline or not timestamp:
        return "unknown"
    closest = "unknown"
    for entry in timeline:
        if entry["timestamp"] <= timestamp:
            closest = entry["tactic"]
        else:
            break
    return closest


def _tactics_match(real: str, observed: str) -> bool:
    """Compara tacticas normalizando nombres."""
    if not real or not observed:
        return False
    return real.lower().replace("_", " ") == observed.lower().replace("_", " ")


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
        "--observer-interval", type=int, default=30,
        help="Intervalo de polling del observador en segundos"
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
    args = parser.parse_args()

    if args.tool_output:
        import os as _os
        _os.environ["SHOW_TOOL_OUTPUT"] = "1"

    setup_logging(args.verbose)
    verify_infrastructure(scenario=args.scenario)

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

    if args.attacker_only:
        # Solo atacante, sin observador
        attacker_state = run_attacker(tactics=tactics, target=target)
        print_attack_summary(attacker_state)
        return

    # Ejecucion completa: atacante + observador en paralelo
    observer_results = []
    stop_event = threading.Event()

    # Timestamp de inicio de esta simulacion: el observador no debe mirar logs
    # anteriores a este punto (evita contaminacion de corridas previas).
    simulation_start = datetime.now(timezone.utc)

    # Iniciar observador en thread separado
    observer_thread = threading.Thread(
        target=run_observer_loop,
        args=(stop_event, observer_results, args.observer_interval, simulation_start),
        daemon=True,
    )
    observer_thread.start()

    # Dar tiempo al observador para su primera recoleccion
    time.sleep(3)

    # Ejecutar atacante en el thread principal
    attacker_state = run_attacker(tactics=tactics, target=target)

    # Dar tiempo al observador para clasificar las ultimas acciones.
    # Tres ciclos completos: el que estaba en curso termina + dos mas que ven
    # el estado final del ataque, dando al observador tiempo suficiente para
    # capturar tacticas que el atacante completo rapidamente.
    time.sleep(args.observer_interval * 3 + 15)
    stop_event.set()
    observer_thread.join(timeout=10)

    # Resumen del ataque: objetivos cumplidos, evidencia extraida, flags
    print_attack_summary(attacker_state)

    # Comparar resultados del observador
    compare_results(attacker_state, observer_results)


if __name__ == "__main__":
    main()
