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

    # stream() emite el estado actualizado despues de cada nodo (solo los campos que cambio)
    # Acumulamos action_history separadamente porque el ultimo nodo (advance_tactic)
    # no lo incluye en su retorno.
    final_state = {}
    accumulated_history = []
    for event in graph.stream(initial_state, {"recursion_limit": 100}):
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
            final_state.update(node_state)

    final_state["action_history"] = accumulated_history
    console.print("[bold red]AGENTE ATACANTE FINALIZADO[/bold red]\n")
    return final_state


def run_observer_loop(
    stop_event: threading.Event,
    results: list,
    poll_interval: int | None = None,
):
    """
    Loop del observador que se ejecuta en un thread separado.

    Cada poll_interval segundos:
    1. Crea un estado con la ventana temporal actual
    2. Ejecuta el grafo del observador
    3. Acumula la clasificacion en results

    Se detiene cuando stop_event es seteado por el thread principal.
    """
    interval = poll_interval or settings.observer_poll_interval
    graph = build_observer_graph()
    history = []
    suspect_list = {}

    console.print("[bold blue]AGENTE OBSERVADOR INICIADO[/bold blue]")

    while not stop_event.is_set():
        try:
            state = create_observer_state(
                window_minutes=max(3, interval // 60 + 2),
                history=history,
                suspect_list=suspect_list,
            )
            result = graph.invoke(state)

            classification = result.get("current_classification")
            if classification and classification.get("tactic") != "none":
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

        except Exception as e:
            logging.getLogger(__name__).error(f"Error en observador: {e}")

        stop_event.wait(interval)

    console.print("[bold blue]AGENTE OBSERVADOR FINALIZADO[/bold blue]\n")


def compare_results(attacker_state: dict, observer_classifications: list):
    """
    Compara el ground truth del atacante con las clasificaciones del observador.

    Metrica: accuracy por ventana — alguna tactica detectada por el observador coincide
    con alguna tactica real activa durante esa ventana de observacion.

    Se usa ventana completa (no punto medio) porque el atacante puede avanzar varias
    tacticas dentro de un solo ciclo de polling.
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

    table = Table(title="Resultados: Ground Truth vs Clasificacion", expand=False)
    table.add_column("Ventana", style="dim", no_wrap=True)
    table.add_column("Real (actual)", style="red", no_wrap=True)
    table.add_column("Real (ventana)", style="dim red", max_width=36)
    table.add_column("Obs (actual)", style="blue", max_width=16)
    table.add_column("Conf", justify="right", no_wrap=True)
    table.add_column("Match", justify="center", no_wrap=True)

    action_history = attacker_state.get("action_history", [])
    attacker_timeline = [
        {"timestamp": a.get("timestamp", ""), "tactic": a.get("tactic", "")}
        for a in action_history
    ]

    strict_correct = 0

    for cls in observer_classifications:
        real_in_window = _real_tactics_in_window(
            cls.get("window_start", ""),
            cls.get("window_end", ""),
            attacker_timeline,
        )

        observed_current = cls.get("tactic", "?")
        # La tactica "actual" real es la ultima ejecutada en la ventana
        last_real = real_in_window[-1] if real_in_window else "unknown"

        real_current_abbrev = _ABBREV.get(last_real.lower().replace(" ", "_"), last_real)
        real_window_abbrev = _abbrev_list(real_in_window[:-1]) if len(real_in_window) > 1 else ""
        obs_abbrev = _ABBREV.get(observed_current.lower().replace(" ", "_"), observed_current)

        # Match estricto: obs (actual) debe coincidir con la ultima tactica real
        strict_ok = _tactics_match(last_real, observed_current)
        if strict_ok:
            strict_correct += 1

        match_style = "green" if strict_ok else "red"
        match_label = "OK" if strict_ok else "MISS"

        table.add_row(
            cls.get("timestamp", "")[:19],
            real_current_abbrev,
            real_window_abbrev,
            obs_abbrev,
            f"{cls.get('confidence', 0):.0%}",
            f"[{match_style}]{match_label}[/{match_style}]",
        )

    console.print(table)
    console.print("[dim]Match estricto: Obs(actual) == ultima tactica real en ventana[/dim]")

    if observer_classifications:
        total = len(observer_classifications)
        console.print(f"\nAccuracy (estricta): {strict_correct}/{total} ({strict_correct/total:.0%})")


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
    """Encuentra la tactica del atacante mas cercana a un timestamp dado."""
    if not timeline or not timestamp:
        return "unknown"
    # Buscar la ultima accion del atacante antes del timestamp del observador
    closest = timeline[0]["tactic"]
    for entry in timeline:
        if entry["timestamp"] <= timestamp:
            closest = entry["tactic"]
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
        console.print(f"\nAcciones ejecutadas: {len(attacker_state.get('action_history', []))}")
        return

    # Ejecucion completa: atacante + observador en paralelo
    observer_results = []
    stop_event = threading.Event()

    # Iniciar observador en thread separado
    observer_thread = threading.Thread(
        target=run_observer_loop,
        args=(stop_event, observer_results, args.observer_interval),
        daemon=True,
    )
    observer_thread.start()

    # Dar tiempo al observador para su primera recoleccion
    time.sleep(3)

    # Ejecutar atacante en el thread principal
    attacker_state = run_attacker(tactics=tactics, target=target)

    # Dar tiempo al observador para clasificar las ultimas acciones.
    # Dos ciclos completos: el que estaba en curso termina + uno mas que ve
    # el estado final del ataque con window_end despues de todas las tacticas.
    time.sleep(args.observer_interval * 2 + 10)
    stop_event.set()
    observer_thread.join(timeout=10)

    # Comparar resultados
    compare_results(attacker_state, observer_results)


if __name__ == "__main__":
    main()
