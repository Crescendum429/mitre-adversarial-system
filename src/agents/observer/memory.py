"""
Memoria del observador: prior por fingerprint del patron de trafico.

Justificacion academica:
  - NIST SP 800-94 (Guide to Intrusion Detection and Prevention Systems):
    SIEMs efectivos mantienen una BASELINE del trafico de cada activo
    monitoreado para distinguir actividad normal de anomala. La baseline se
    usa como prior bayesiano en deteccion estadistica.
  - Vinay (2025) arXiv:2512.06659: presenta el patron Triage -> Investigate
    -> Classify -> Escalate como arquitectura para SOCs basados en LLM,
    incluyendo memoria historica como componente del modulo de Investigate.
  - Sokolova & Lapalme (2009): metricas P/R/F1 mejoran cuando el
    clasificador integra prior conocido de la distribucion de clases.

Diseño minimalista:
  - Fingerprint: hash estable del patron de trafico observado en una ventana
    de baseline (los primeros N requests al inicio de la corrida).
  - Almacenamiento: data/observer_baselines.json — dict {fp -> baseline_dict}.
  - Uso: el observer al clasificar consulta el prior y lo inyecta en el prompt
    como "tactic distribution observada en runs previos sobre este target".
  - Update: tras cada run, se actualiza la distribucion de tacticas del fp.

NO es replay de respuestas: es prior estadistico que el LLM puede usar o
ignorar segun la evidencia del log actual. Es deliberadamente conservador.
"""

import hashlib
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[3]
BASELINE_FILE = Path(
    os.environ.get(
        "MITRE_OBSERVER_BASELINE_FILE",
        str(_REPO_ROOT / "data" / "observer_baselines.json"),
    )
)
SCHEMA_VERSION = 1


def compute_traffic_fingerprint(raw_logs: list[dict]) -> str:
    """
    Fingerprint del patron de trafico HTTP observado.

    Estable ante variaciones de timing y ordering, depende solo de la
    composicion estructural: containers que generan logs, distribucion de
    metodos HTTP, distribucion de status codes (top-3).
    """
    if not raw_logs:
        return ""

    containers = Counter()
    methods = Counter()
    statuses = Counter()
    apache_re = re.compile(r'"\s*(\w+)\s+\S+\s+HTTP/[^"]+"\s+(\d{3})')

    for log in raw_logs[:200]:  # cap para estabilidad y velocidad
        cn = log.get("labels", {}).get("container_name") or log.get("labels", {}).get("container", "")
        if cn:
            containers[cn] += 1
        msg = log.get("message", "")
        m = apache_re.search(msg)
        if m:
            methods[m.group(1).upper()] += 1
            statuses[m.group(2)] += 1

    # Para estabilidad ante ties (mismo count), ordenamos por (count desc,
    # nombre asc). most_common() no garantiza orden en ties.
    def _stable_top(c: Counter, n: int) -> list:
        return sorted(c.items(), key=lambda x: (-x[1], x[0]))[:n]

    parts = []
    if containers:
        parts.append("ctr:" + ",".join(c for c, _ in _stable_top(containers, 2)))
    if methods:
        parts.append("met:" + ",".join(sorted(methods.keys())))
    if statuses:
        parts.append("st:" + ",".join(s for s, _ in _stable_top(statuses, 3)))

    if not parts:
        return ""

    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def load_baselines() -> dict:
    if not BASELINE_FILE.exists():
        return {"version": SCHEMA_VERSION, "baselines": {}}
    try:
        data = json.loads(BASELINE_FILE.read_text())
        if "baselines" not in data:
            return {"version": SCHEMA_VERSION, "baselines": {}}
        return data
    except Exception as e:
        logger.warning(f"[ObserverMemory] Archivo corrupto, reinicializando: {e}")
        return {"version": SCHEMA_VERSION, "baselines": {}}


def save_baselines(data: dict) -> None:
    BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def get_prior(fingerprint: str) -> dict | None:
    """
    Devuelve el prior estadistico para este fingerprint, o None si no hay datos.

    Estructura del prior:
      {
        "tactic_distribution": {tactic: probability},  # de runs previos
        "common_sequence": [tactic, tactic, ...],       # kill chain mas frecuente
        "windows_observed": int,                        # tamaño de la muestra
        "first_seen": iso_ts,
        "last_seen": iso_ts,
      }

    El prior debe usarse como SUGERENCIA, no certeza. Si la evidencia del log
    actual contradice el prior, gana la evidencia.
    """
    if not fingerprint:
        return None
    data = load_baselines()
    return data["baselines"].get(fingerprint)


def update_baseline(
    fingerprint: str,
    classifications: list[dict],
    target_summary: str = "",
) -> None:
    """
    Actualiza la baseline tras una corrida.

    classifications: lista de dicts con al menos 'tactic' (la observada por
                     el observer) por cada ventana procesada.
    """
    if not fingerprint or not classifications:
        return

    data = load_baselines()
    bl = data["baselines"].setdefault(fingerprint, {
        "first_seen": _now(),
        "tactic_distribution": {},
        "common_sequence": [],
        "windows_observed": 0,
        "target_summary": target_summary,
    })

    # Update incremental con suavizado: nueva info pesa segun N ventanas.
    # Excluimos 'none' del prior porque es la categoria DEFAULT — incluirla
    # sesga el clasificador hacia "no hay ataque" en runs futuras.
    counts: Counter = Counter()
    for c in classifications:
        t = (c.get("tactic", "") or "").lower().strip()
        if not t or t == "?" or t == "none":
            continue
        counts[t.replace(" ", "_")] += 1

    if not counts:
        return

    # Mezcla con distribucion previa (peso por numero de ventanas)
    prev_dist = bl.get("tactic_distribution", {})
    prev_n = bl.get("windows_observed", 0)
    new_n = sum(counts.values())
    total_n = prev_n + new_n

    new_dist = {}
    all_tactics = set(prev_dist) | set(counts)
    for t in all_tactics:
        prev_p = prev_dist.get(t, 0.0)
        new_p = counts.get(t, 0) / new_n if new_n else 0.0
        # Promedio ponderado
        new_dist[t] = round(
            (prev_p * prev_n + new_p * new_n) / total_n,
            4,
        ) if total_n else 0.0

    bl["tactic_distribution"] = new_dist
    bl["windows_observed"] = total_n
    bl["last_seen"] = _now()
    bl["target_summary"] = target_summary or bl.get("target_summary", "")

    # Sequence: secuencia de tacticas no-none mas reciente
    sequence = [
        c.get("tactic", "").lower().strip().replace(" ", "_")
        for c in classifications
        if c.get("tactic") and c.get("tactic") != "none"
    ]
    if sequence:
        bl["common_sequence"] = sequence[:30]  # cap

    save_baselines(data)


def render_prior_for_prompt(prior: dict) -> str:
    """Formatea el prior para inyectar en el prompt del observer."""
    if not prior:
        return ""

    dist = prior.get("tactic_distribution", {})
    if not dist:
        return ""

    # Top 5 tacticas mas observadas
    top = sorted(dist.items(), key=lambda x: -x[1])[:5]
    dist_str = ", ".join(f"{t}: {p:.0%}" for t, p in top if p > 0)

    sequence = prior.get("common_sequence", [])
    seq_str = " → ".join(sequence[:6]) if sequence else "(sin secuencia previa)"

    n = prior.get("windows_observed", 0)
    summary = prior.get("target_summary", "")

    lines = [
        "PRIOR DEL OBSERVADOR (de runs previos sobre target con patron de trafico similar):",
        f"  Distribucion de tacticas: {dist_str}",
        f"  Kill chain tipica observada: {seq_str}",
        f"  Tamano de muestra: {n} ventanas",
    ]
    if summary:
        lines.append(f"  Target summary: {summary}")
    lines.append(
        "  USO: este prior es SUGESTIVO, no determina tu clasificacion. Si la "
        "evidencia del log actual contradice el prior, prevalece la evidencia. "
        "El prior es util para decidir entre clasificaciones equiprobables."
    )
    return "\n".join(lines)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
