"""Memoria persistente del atacante: playbooks por fingerprint del target."""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Path absoluto basado en la ubicacion del modulo (sube 3 niveles: attacker/ →
# agents/ → src/ → project_root). Evita que la memoria se escriba en lugares
# distintos segun el cwd (bug critico para reproducibilidad entre corridas).
_REPO_ROOT = Path(__file__).resolve().parents[3]
MEMORY_FILE = Path(
    os.environ.get("MITRE_MEMORY_FILE", str(_REPO_ROOT / "data" / "attack_playbooks.json"))
)
SCHEMA_VERSION = 1

_SECRET_KEY_HINTS = {"password", "pwd", "pass", "credential", "hash", "token", "secret"}
_HEX_HASH_RE = re.compile(r"\b[a-f0-9]{16,128}\b", re.IGNORECASE)


def compute_target_fingerprint(recon_evidence: dict) -> str:
    """Hash de observables MAXIMAMENTE ESTABLES del recon.

    Decision de diseno (ref: similitud a fingerprinting activo de MirrorSoft
    Signature-based Target Profiling, NSS Labs 2023): el fingerprint usa solo
    observables que SIEMPRE se descubren en el recon exitoso, no observables
    que dependen del orden o profundidad del scan.

    Componentes usados:
      1. port_http_open (derivado de nmap, siempre descubierto si recon paso)
      2. web_technologies (derivado de banner HTTP y fingerprinting, estable
         a traves de runs porque nmap + whatweb producen el mismo output
         para la misma stack)

    Componentes NO usados (intencionalmente):
      - paths descubiertos por gobuster: VARIABLE entre runs (el agente usa
        wordlists distintos, diferentes profundidades de recursion, paths
        aleatorios). Dos runs del mismo target con distinto gobuster = distinto
        fingerprint, lo cual mata la utilidad de la memoria.
      - IP del target: el mismo tipo de target puede tener IPs distintas.
      - Puertos no estandar especificos: se consolidan en port_http_open.

    Implicaciones:
    - Dos instancias distintas del MISMO tipo de target (ej: dos despliegues
      de DVWA) producen el mismo fingerprint → la memoria se generaliza.
      Esto es DESEADO: si aprendi a vulnerar DVWA una vez, el playbook sirve
      para cualquier DVWA.
    - Si dos targets tienen tech_stack distinta (Apache+DVWA vs Apache+WordPress),
      los fingerprints difieren → no contaminamos playbooks entre tipos.
    """
    parts = []

    if recon_evidence.get("port_80_open") or recon_evidence.get("http_port_open"):
        port = recon_evidence.get("http_port_open", 80)
        parts.append(f"port:{port}")

    techs = recon_evidence.get("web_technologies", [])
    if techs:
        parts.append("tech:" + ",".join(sorted(t.lower() for t in techs)))

    if not parts:
        return ""

    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def load_playbooks() -> dict:
    if not MEMORY_FILE.exists():
        return {"version": SCHEMA_VERSION, "playbooks": {}}
    try:
        data = json.loads(MEMORY_FILE.read_text())
        if "playbooks" not in data:
            return {"version": SCHEMA_VERSION, "playbooks": {}}
        return data
    except Exception as e:
        logger.warning(f"[Memory] Archivo corrupto, reinicializando: {e}")
        return {"version": SCHEMA_VERSION, "playbooks": {}}


def save_playbooks(data: dict) -> None:
    MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    MEMORY_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def lookup_playbook(fingerprint: str) -> dict | None:
    if not fingerprint:
        return None
    data = load_playbooks()
    return data["playbooks"].get(fingerprint)


def upsert_playbook_recon(
    fingerprint: str,
    target_ip: str,
    recon_evidence: dict,
    actions_used: int,
) -> None:
    if not fingerprint:
        return
    data = load_playbooks()
    pb = data["playbooks"].setdefault(fingerprint, _new_playbook(target_ip, recon_evidence))
    pb["last_seen"] = _now()
    pb["last_target_ip"] = target_ip
    pb_recon = pb["tactics"].setdefault("reconnaissance", {})
    prev_best = pb_recon.get("best_run_actions")
    if prev_best is None or actions_used < prev_best:
        pb_recon["best_run_actions"] = actions_used
    pb_recon["key_findings"] = _summarize_recon(recon_evidence)
    save_playbooks(data)


def record_tactic_success(
    fingerprint: str,
    tactic: str,
    tool: str,
    args: dict,
    evidence: dict,
    actions_used: int,
) -> None:
    if not fingerprint or tactic == "reconnaissance":
        return
    data = load_playbooks()
    pb = data["playbooks"].get(fingerprint)
    if pb is None:
        return
    entry = pb["tactics"].setdefault(tactic, {})
    entry["tool"] = tool
    entry["payload_template"] = _sanitize_args(args)
    entry["evidence_keys"] = sorted(k for k in evidence if not k.startswith("_"))
    prev_best = entry.get("best_run_actions")
    if prev_best is None or actions_used < prev_best:
        entry["best_run_actions"] = actions_used
    save_playbooks(data)


def record_run_completion(fingerprint: str, all_successful: bool) -> None:
    if not fingerprint:
        return
    data = load_playbooks()
    pb = data["playbooks"].get(fingerprint)
    if pb is None:
        return
    pb["run_count"] = pb.get("run_count", 0) + 1
    if all_successful:
        pb["successful_runs"] = pb.get("successful_runs", 0) + 1
        pb["last_full_success"] = _now()
    save_playbooks(data)


def record_tactic_failure(
    fingerprint: str,
    tactic: str,
    reason: str,
    attempts: int,
) -> None:
    """Persiste fallos de una tactica para que la proxima corrida los evite.

    El playbook acumula 'failed_tactics': {tactic: {reasons: [...], attempts: N,
    last_failed: iso_timestamp}}. El prompt de la siguiente corrida lo lee en
    `render_playbook_for_prompt` y advierte al LLM "esta tactica fracaso N
    veces; no repitas el approach que fallo: <razon>".
    """
    if not fingerprint:
        return
    data = load_playbooks()
    pb = data["playbooks"].get(fingerprint)
    if pb is None:
        return
    failed = pb.setdefault("failed_tactics", {})
    entry = failed.setdefault(tactic, {"reasons": [], "attempts": 0})
    entry["attempts"] = max(int(entry.get("attempts", 0)), int(attempts))
    reason_short = (reason or "")[:240]
    if reason_short and reason_short not in entry["reasons"]:
        entry["reasons"].append(reason_short)
        # capar a 5 razones para no inflar
        entry["reasons"] = entry["reasons"][-5:]
    entry["last_failed"] = _now()
    save_playbooks(data)


def render_playbook_for_prompt(pb: dict, current_tactic: str) -> str:
    """Formatea el playbook para inyectar en el prompt de planificación."""
    lines = [
        f"Target observado previamente: {pb.get('target_summary', '?')}",
        f"Ejecuciones previas: {pb.get('run_count', 0)} "
        f"({pb.get('successful_runs', 0)} exitosas)",
    ]
    # M9: si esta tactica fallo en runs previos, advertir explicitamente.
    failed_entry = (pb.get("failed_tactics") or {}).get(current_tactic)
    if failed_entry:
        lines.append("")
        lines.append(
            f"⚠ ADVERTENCIA: esta tactica ({current_tactic}) fallo en "
            f"{failed_entry.get('attempts', 0)} intentos previos. Razones:"
        )
        for r in failed_entry.get("reasons", [])[-3:]:
            lines.append(f"  - {r}")
        lines.append("Cambia de approach respecto a esos intentos.")
    tactic_entry = pb.get("tactics", {}).get(current_tactic)
    if tactic_entry:
        tool = tactic_entry.get("tool", "?")
        payload = tactic_entry.get("payload_template", {})
        best = tactic_entry.get("best_run_actions", "?")
        lines.append(f"")
        lines.append(f"En esta táctica ({current_tactic}) funcionó:")
        lines.append(f"  Tool: {tool}")
        if payload:
            lines.append(f"  Argumentos sugeridos:")
            for k, v in payload.items():
                v_str = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
                if len(v_str) > 200:
                    v_str = v_str[:200] + "..."
                lines.append(f"    {k}: {v_str}")
        lines.append(f"  Mejor corrida previa: {best} acción(es)")
    else:
        completed = sorted(t for t in pb.get("tactics", {}) if t != "reconnaissance")
        if completed:
            lines.append(f"")
            lines.append(f"Tácticas previamente exitosas en este target: {', '.join(completed)}")
            lines.append("Esta táctica ({}) no tiene playbook todavía.".format(current_tactic))
    return "\n".join(lines)


def _new_playbook(target_ip: str, recon_evidence: dict) -> dict:
    return {
        "target_summary": _summary_from_recon(recon_evidence),
        "first_seen": _now(),
        "last_seen": _now(),
        "last_target_ip": target_ip,
        "run_count": 0,
        "successful_runs": 0,
        "tactics": {},
    }


def _summary_from_recon(evidence: dict) -> str:
    techs = evidence.get("web_technologies", [])
    paths = evidence.get("discovered_paths", [])
    bits = []
    if techs:
        bits.append("+".join(techs[:4]))
    if paths:
        sample = ",".join(paths[:5])
        bits.append(f"paths=[{sample}]")
    return "; ".join(bits) if bits else "(sin descripción)"


def _summarize_recon(evidence: dict) -> list[str]:
    out = []
    if evidence.get("port_80_open"):
        out.append("port_80_open")
    techs = evidence.get("web_technologies", [])
    if techs:
        out.append(f"tech={','.join(techs)}")
    paths = evidence.get("discovered_paths", [])
    if paths:
        out.append(f"paths={','.join(paths[:8])}")
    return out


def _sanitize_args(args: dict) -> dict:
    out = {}
    for k, v in args.items():
        if isinstance(v, dict):
            out[k] = _sanitize_args(v)
        elif isinstance(v, str):
            out[k] = _scrub_string(k, v)
        else:
            out[k] = v
    return out


def _scrub_string(key: str, value: str) -> str:
    key_l = key.lower()
    if any(h in key_l for h in _SECRET_KEY_HINTS):
        return "<discovered>"
    redacted = _HEX_HASH_RE.sub("<hash>", value)
    redacted = re.sub(
        r"(password|pwd|pass)=([^&'\"\s]+)",
        r"\1=<discovered>",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(login:\s*\S+\s+password:\s*)\S+",
        r"\1<discovered>",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
