"""
Benchmark reproducible de todas las maquinas disponibles.

Corre el atacante en serie sobre N escenarios y produce un JSON con:
  - metadata (modelo, seed, timestamp, version del codigo via git hash)
  - resultados por escenario (tacticas completadas, acciones, replans)
  - tiempos y tokens agregados

Uso:
    python scripts/run_benchmark.py \\
        --scenarios basic mrrobot \\
        --runs-per-scenario 3 \\
        --output data/benchmark_$(date +%Y%m%d_%H%M%S).json

Filosofia: esto es LO QUE EL TRIBUNAL VA A CORRER. Debe ser determinista
(mismo seed), debe limpiar estado entre corridas, y debe producir un JSON
parseable para generar tablas del paper.
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _git_hash() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _clean_state(scenario: str) -> None:
    """Limpia webshells residuales del target. Critico para reproducibilidad:
    si shell.php quedo de una corrida previa, el atacante podria saltarse el
    paso de deploy y parecer mas rapido que en realidad.
    """
    target_container = {
        "basic": "dvwa",
        "dvwa": "dvwa",
        "mrrobot": "mrrobot",
        "dc1": "dc1",
        "bpent": "bpent",
        "log4shell": "log4shell",
        "confluence": "confluence",
    }.get(scenario)
    if not target_container:
        return
    # Limpia cualquier .php nuevo en el document root del target
    try:
        subprocess.run(
            ["docker", "exec", target_container, "bash", "-c",
             "find /var/www/html -name '*.php' -newer /var/www/html/index.* "
             "-delete 2>/dev/null; rm -f /var/www/html/shell.php /var/www/html/hackable/shell.php 2>/dev/null"],
            capture_output=True,
            timeout=10,
        )
    except Exception:
        pass


def _run_scenario(scenario: str, python_exec: str, use_memory: bool = True) -> dict:
    """Ejecuta un scenario y captura el resultado.

    Retorna dict con: scenario, tactics_met, total_actions, total_replans,
    elapsed_seconds, stdout_tail (ultimos 4KB para debugging).
    """
    cmd = [
        python_exec, "-m", "src.main",
        "--scenario", scenario,
        "--attacker-only",
    ]
    if not use_memory:
        cmd.append("--no-memory")

    t0 = time.monotonic()
    result = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    elapsed = round(time.monotonic() - t0, 2)

    # Parse del resumen: "Resumen: N/M objetivos cumplidos, K acciones..."
    stdout = result.stdout or ""
    tactics_met = _grep_int(stdout, r"Resumen:\s*(\d+)/\d+\s+objetivos")
    tactics_total = _grep_int(stdout, r"Resumen:\s*\d+/(\d+)\s+objetivos")
    total_actions = _grep_int(stdout, r"(\d+)\s+acciones totales")
    total_replans = _count_replans(stdout)

    return {
        "scenario": scenario,
        "exit_code": result.returncode,
        "tactics_met": tactics_met,
        "tactics_total": tactics_total,
        "total_actions": total_actions,
        "total_replans": total_replans,
        "elapsed_seconds": elapsed,
        "stdout_tail": stdout[-4000:],
        "used_memory": use_memory,
    }


def _grep_int(text: str, pattern: str) -> int:
    import re
    m = re.search(pattern, text)
    return int(m.group(1)) if m else -1


def _count_replans(text: str) -> int:
    import re
    return len(re.findall(r"⚠ OBJETIVO PENDIENTE", text))


def main():
    p = argparse.ArgumentParser(description="Benchmark reproducible")
    p.add_argument("--scenarios", nargs="+", default=["basic"],
                   help="Lista de escenarios a correr")
    p.add_argument("--runs-per-scenario", type=int, default=1,
                   help="Corridas por escenario (para medir varianza)")
    p.add_argument("--output", type=Path, default=None,
                   help="Path JSON de salida. Default: data/benchmark_<ts>.json")
    p.add_argument("--no-memory", action="store_true",
                   help="Desactiva memoria para medir cold runs")
    p.add_argument("--python-exec", default=sys.executable,
                   help="Python executable (usa el mismo venv que pytest)")
    args = p.parse_args()

    output = args.output or (
        REPO_ROOT / "data" / f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)

    # Carga config actual para metadata
    from src.config.settings import settings
    report = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_hash(),
            "attacker_provider": settings.llm_provider.value,
            "attacker_model": settings.openai_model if settings.llm_provider.value == "openai" else "varies",
            "seed": settings.llm_seed,
            "attacker_temperature": settings.attacker_temperature,
            "python": sys.version,
        },
        "results": [],
    }

    total_scenarios = len(args.scenarios) * args.runs_per_scenario
    current = 0
    for scenario in args.scenarios:
        for run_idx in range(args.runs_per_scenario):
            current += 1
            print(f"\n[{current}/{total_scenarios}] {scenario} (run {run_idx+1})")
            _clean_state(scenario)
            # Memoria: borrar en la primera corrida de cada escenario para
            # medir cold; despues queda para warm runs
            if run_idx == 0:
                memory_file = REPO_ROOT / "data" / "attack_playbooks.json"
                memory_file.unlink(missing_ok=True)

            r = _run_scenario(
                scenario,
                python_exec=args.python_exec,
                use_memory=not args.no_memory,
            )
            r["run_index"] = run_idx
            report["results"].append(r)
            print(
                f"  → {r['tactics_met']}/{r['tactics_total']} tacticas, "
                f"{r['total_actions']} acciones, {r['total_replans']} replans, "
                f"{r['elapsed_seconds']:.1f}s"
            )

    output.write_text(json.dumps(report, indent=2))
    print(f"\nReporte guardado en {output}")

    # Summary final
    by_scenario: dict = {}
    for r in report["results"]:
        by_scenario.setdefault(r["scenario"], []).append(r)
    print("\n=== RESUMEN ===")
    for sc, runs in by_scenario.items():
        ok = sum(1 for r in runs if r["tactics_met"] == r["tactics_total"])
        avg_actions = sum(r["total_actions"] for r in runs) / len(runs)
        avg_replans = sum(r["total_replans"] for r in runs) / len(runs)
        print(
            f"  {sc}: {ok}/{len(runs)} corridas completas, "
            f"avg_actions={avg_actions:.1f}, avg_replans={avg_replans:.1f}"
        )


if __name__ == "__main__":
    main()
