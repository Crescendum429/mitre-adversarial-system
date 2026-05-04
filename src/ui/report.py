"""
Generador de reporte HTML post-run. Toma eventos del SessionRecorder y produce
un reporte autosuficiente (HTML + CSS embebido) que el tribunal puede revisar
sin instalar nada.

Estructura del reporte:
  1. Header con metadata (modelo, seed, scenario, timestamp, git commit)
  2. Resumen ejecutivo (tacticas cumplidas, acciones, replans, keys)
  3. Timeline cronologico interactivo
  4. Por tactica: prompt, herramientas, evidencia, validador feedback
  5. Observador: ventanas con triage, classify, refinement
  6. Metricas (P/R/F1 si hay datos del observador)

Diseño deliberadamente sobrio (alineado con 'el codigo debe ser sobrio sin
simbolos ni comentarios excesivos'). HTML semantico, CSS minimo, sin JS
innecesario.
"""

import html
import json
from datetime import datetime
from pathlib import Path

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0d1117; color: #c9d1d9; line-height: 1.5; padding: 20px; }
.container { max-width: 1400px; margin: 0 auto; }
h1, h2, h3 { color: #58a6ff; margin: 16px 0 8px; }
h1 { font-size: 22px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
h2 { font-size: 18px; margin-top: 24px; }
h3 { font-size: 15px; color: #79c0ff; }
.metadata { background: #161b22; padding: 12px 16px; border-radius: 6px;
            border: 1px solid #30363d; font-size: 13px; }
.metadata table { width: 100%; }
.metadata td { padding: 3px 8px; }
.metadata td:first-child { color: #8b949e; width: 180px; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 12px; margin: 16px 0; }
.stat-card { background: #161b22; padding: 12px 16px; border-radius: 6px;
             border: 1px solid #30363d; }
.stat-card .label { font-size: 11px; color: #8b949e; text-transform: uppercase;
                    letter-spacing: 0.5px; }
.stat-card .value { font-size: 22px; font-weight: 600; color: #c9d1d9;
                    margin-top: 4px; }
.stat-card.ok .value { color: #3fb950; }
.stat-card.fail .value { color: #f85149; }
table.tactics { width: 100%; border-collapse: collapse; margin: 12px 0; }
table.tactics th, table.tactics td { padding: 8px 12px; text-align: left;
                                       border-bottom: 1px solid #21262d; }
table.tactics th { background: #161b22; color: #8b949e; font-size: 12px;
                    font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
table.tactics tr:hover { background: #161b22; }
.tactic-status { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.tactic-status.ok { background: rgba(63, 185, 80, 0.2); color: #3fb950; }
.tactic-status.fail { background: rgba(248, 81, 73, 0.2); color: #f85149; }
.tactic-status.pending { background: rgba(180, 180, 180, 0.2); color: #8b949e; }

.timeline { margin: 16px 0; }
.event { display: grid; grid-template-columns: 90px 100px 1fr; gap: 12px;
         padding: 8px 12px; border-left: 3px solid transparent;
         border-bottom: 1px solid #21262d; font-size: 13px; }
.event:hover { background: #161b22; }
.event .ts { color: #8b949e; font-family: monospace; font-size: 11px; }
.event .agent { font-weight: 600; font-size: 11px; text-transform: uppercase;
                 letter-spacing: 0.5px; }
.event.attacker { border-left-color: #f85149; }
.event.attacker .agent { color: #f85149; }
.event.observer { border-left-color: #58a6ff; }
.event.observer .agent { color: #58a6ff; }
.event.system { border-left-color: #8b949e; }
.event.system .agent { color: #8b949e; }
.event .desc { color: #c9d1d9; }
.event .desc code { background: #161b22; padding: 1px 6px; border-radius: 3px;
                     font-family: 'SF Mono', monospace; font-size: 12px;
                     color: #79c0ff; }
.event-tactic { font-size: 11px; color: #8b949e; }
.evidence { background: #0d1117; padding: 10px 12px; border-radius: 4px;
            border: 1px solid #30363d; margin: 8px 0; font-family: monospace;
            font-size: 12px; white-space: pre-wrap; max-height: 280px;
            overflow-y: auto; word-break: break-all; }
details { margin: 8px 0; }
details summary { cursor: pointer; padding: 6px 10px; background: #161b22;
                   border-radius: 4px; user-select: none; font-size: 13px;
                   color: #79c0ff; }
details summary:hover { background: #21262d; }
details[open] summary { background: #21262d; }
.event-content { padding: 8px 12px 8px 24px; }
.tactic-block { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
                 padding: 14px 18px; margin: 12px 0; }
.tactic-block.ok { border-left: 3px solid #3fb950; }
.tactic-block.fail { border-left: 3px solid #f85149; }
.confusion-matrix { border-collapse: collapse; margin: 12px 0; font-size: 12px; }
.confusion-matrix th, .confusion-matrix td { padding: 6px 10px; border: 1px solid #30363d;
                                              text-align: center; }
.confusion-matrix th { background: #161b22; color: #8b949e; }
.confusion-matrix td.diag { background: rgba(63, 185, 80, 0.1); color: #3fb950;
                              font-weight: 600; }
footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #30363d;
          color: #8b949e; font-size: 12px; text-align: center; }
.legend { display: inline-flex; gap: 16px; font-size: 12px; color: #8b949e;
          margin: 8px 0; }
.legend span { display: inline-flex; align-items: center; gap: 6px; }
.legend .dot { width: 10px; height: 10px; border-radius: 50%; }
.legend .dot.attacker { background: #f85149; }
.legend .dot.observer { background: #58a6ff; }
.legend .dot.system { background: #8b949e; }
"""


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _fmt_ts(iso_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt.strftime("%H:%M:%S")
    except Exception:
        return iso_ts[:19]


def _format_payload_short(event_type: str, payload: dict) -> str:
    """Una linea corta describiendo el evento para el timeline."""
    if event_type == "tactic_start":
        return f"<b>{_esc(payload.get('tactic', '?'))}</b> iniciada"
    if event_type == "tool_call":
        tool = payload.get("tool", "?")
        args = payload.get("args", {})
        args_str = ", ".join(f"{k}={_truncate(v, 40)}" for k, v in list(args.items())[:3])
        return f"<code>{_esc(tool)}</code>({_esc(args_str)})"
    if event_type == "tool_result":
        size = payload.get("size", 0)
        preview = _truncate(payload.get("preview", ""), 80)
        return f"resultado: {size} chars — {_esc(preview)}"
    if event_type == "objective_check":
        ok = payload.get("success", False)
        reason = _truncate(payload.get("reason", ""), 100)
        marker = "✓" if ok else "✗"
        return f"{marker} <b>{_esc(payload.get('tactic', '?'))}</b>: {_esc(reason)}"
    if event_type == "replan":
        attempt = payload.get("attempt", 0)
        feedback = _truncate(payload.get("feedback", ""), 120)
        return f"replan #{attempt}: {_esc(feedback)}"
    if event_type == "tactic_end":
        ok = payload.get("success", False)
        marker = "✓" if ok else "✗"
        return f"{marker} <b>{_esc(payload.get('tactic', '?'))}</b> cerrada"
    if event_type == "memory_match":
        fp = payload.get("fingerprint", "")[:12]
        runs = payload.get("runs_previas", 0)
        return f"🧠 fingerprint <code>{_esc(fp)}</code> — {runs} runs previas"
    if event_type == "memory_save":
        fp = payload.get("fingerprint", "")[:12]
        return f"💾 playbook actualizado <code>{_esc(fp)}</code>"
    if event_type == "triage":
        result = payload.get("result", "?")
        signals = payload.get("signals_count", 0)
        return f"triage: <b>{_esc(result)}</b> ({signals} señales)"
    if event_type == "classify":
        tactic = payload.get("tactic", "?")
        conf = payload.get("confidence", 0)
        return f"clasificacion: <b>{_esc(tactic)}</b> ({conf:.0%})"
    if event_type == "refine":
        return f"refinement #{payload.get('count', 0)}"
    if event_type == "window_start":
        return "ventana iniciada"
    if event_type == "window_end":
        return "ventana cerrada"
    if event_type == "session_start":
        return f"<b>sesion iniciada</b>: {_esc(payload.get('scenario', '?'))}"
    if event_type == "session_end":
        return "<b>sesion finalizada</b>"
    if event_type == "error":
        return f"<span style='color:#f85149'>error: {_esc(payload.get('message', ''))}</span>"
    return _esc(event_type)


def _truncate(s, n: int) -> str:
    s = str(s)
    return s[:n] + "..." if len(s) > n else s


def _build_metadata_section(metadata: dict) -> str:
    rows = ""
    for key, label in [
        ("scenario", "Escenario"),
        ("attacker_provider", "Atacante - proveedor"),
        ("attacker_model", "Atacante - modelo"),
        ("observer_provider", "Observador - proveedor"),
        ("observer_model", "Observador - modelo"),
        ("seed", "Seed"),
        ("attacker_temperature", "Temperatura atacante"),
        ("observer_temperature", "Temperatura observador"),
        ("git_commit", "Git commit"),
        ("started_at", "Inicio"),
        ("finished_at", "Fin"),
        ("elapsed_seconds", "Duracion (s)"),
    ]:
        val = metadata.get(key)
        if val is None:
            continue
        rows += f"<tr><td>{_esc(label)}</td><td><code>{_esc(val)}</code></td></tr>"
    return f"<div class='metadata'><table>{rows}</table></div>"


def _build_summary_section(metadata: dict, events: list[dict]) -> str:
    tactic_results = {}
    actions_per_tactic = {}
    replans_per_tactic = {}
    for ev in events:
        if ev["event_type"] == "objective_check" and ev["agent"] == "attacker":
            tactic = ev["tactic"]
            tactic_results[tactic] = ev["payload"].get("success", False)
        if ev["event_type"] == "tool_call" and ev["agent"] == "attacker":
            tactic = ev["tactic"]
            actions_per_tactic[tactic] = actions_per_tactic.get(tactic, 0) + 1
        if ev["event_type"] == "replan" and ev["agent"] == "attacker":
            tactic = ev["tactic"]
            replans_per_tactic[tactic] = replans_per_tactic.get(tactic, 0) + 1

    total_tactics = len(tactic_results)
    cumplidas = sum(1 for v in tactic_results.values() if v)
    total_actions = sum(actions_per_tactic.values())
    total_replans = sum(replans_per_tactic.values())
    obs_classifications = sum(1 for ev in events if ev["event_type"] == "classify")

    cards = []
    cards.append(f"""<div class='stat-card {"ok" if cumplidas == total_tactics and total_tactics > 0 else "fail" if total_tactics > 0 else ""}'>
        <div class='label'>Tacticas</div>
        <div class='value'>{cumplidas}/{total_tactics}</div></div>""")
    cards.append(f"""<div class='stat-card'>
        <div class='label'>Acciones atacante</div>
        <div class='value'>{total_actions}</div></div>""")
    cards.append(f"""<div class='stat-card'>
        <div class='label'>Replans</div>
        <div class='value'>{total_replans}</div></div>""")
    cards.append(f"""<div class='stat-card'>
        <div class='label'>Clasificaciones obs.</div>
        <div class='value'>{obs_classifications}</div></div>""")

    grid = "<div class='summary-grid'>" + "".join(cards) + "</div>"

    rows = "<table class='tactics'><thead><tr><th>Tactica</th><th>Estado</th><th>Acciones</th><th>Replans</th></tr></thead><tbody>"
    for t in tactic_results:
        ok = tactic_results[t]
        status = f"<span class='tactic-status {'ok' if ok else 'fail'}'>{'CUMPLIDA' if ok else 'FALLIDA'}</span>"
        rows += f"<tr><td><b>{_esc(t)}</b></td><td>{status}</td><td>{actions_per_tactic.get(t, 0)}</td><td>{replans_per_tactic.get(t, 0)}</td></tr>"
    rows += "</tbody></table>"

    return grid + rows


def _build_timeline(events: list[dict], filter_agent: str = None) -> str:
    if filter_agent:
        events = [e for e in events if e["agent"] == filter_agent]

    rows = []
    for ev in events:
        ts = _fmt_ts(ev["timestamp"])
        agent = ev["agent"]
        agent_label = agent.upper()
        desc = _format_payload_short(ev["event_type"], ev["payload"])
        tactic_badge = f"<div class='event-tactic'>{_esc(ev['tactic'])}</div>" if ev["tactic"] else ""

        # Detalles expandibles para eventos con payload util
        details_html = ""
        if ev["event_type"] in ("tool_call", "tool_result", "classify", "objective_check", "replan"):
            payload_pretty = json.dumps(ev["payload"], indent=2, ensure_ascii=False)
            details_html = f"""<details><summary>detalle</summary><div class='event-content'><pre class='evidence'>{_esc(payload_pretty)}</pre></div></details>"""

        rows.append(f"""<div class='event {agent}'>
            <div class='ts'>{ts}</div>
            <div class='agent'>{agent_label}</div>
            <div>
                <div class='desc'>{desc}</div>
                {tactic_badge}
                {details_html}
            </div>
        </div>""")
    return "<div class='timeline'>" + "".join(rows) + "</div>"


def _build_per_tactic_detail(events: list[dict]) -> str:
    """Por cada táctica del atacante: bloque con prompts, tools, evidencia."""
    by_tactic: dict = {}
    for ev in events:
        if ev["agent"] != "attacker" or not ev["tactic"]:
            continue
        by_tactic.setdefault(ev["tactic"], []).append(ev)

    if not by_tactic:
        return "<p>Sin tacticas registradas.</p>"

    blocks = []
    for tactic, tactic_events in by_tactic.items():
        success = None
        for ev in tactic_events:
            if ev["event_type"] == "objective_check":
                success = ev["payload"].get("success")
        css_class = "ok" if success else "fail" if success is False else ""

        n_tools = sum(1 for e in tactic_events if e["event_type"] == "tool_call")
        n_replans = sum(1 for e in tactic_events if e["event_type"] == "replan")

        # Tools usadas con frecuencia
        tool_freq: dict = {}
        for e in tactic_events:
            if e["event_type"] == "tool_call":
                tool = e["payload"].get("tool", "?")
                tool_freq[tool] = tool_freq.get(tool, 0) + 1
        tool_summary = ", ".join(f"<code>{_esc(t)}</code>×{c}" for t, c in
                                  sorted(tool_freq.items(), key=lambda x: -x[1])[:6])

        # Evidence al final de la tactica
        evidence = {}
        for e in reversed(tactic_events):
            if e["event_type"] == "objective_check":
                evidence = e["payload"].get("evidence", {})
                break

        blocks.append(f"""<div class='tactic-block {css_class}'>
            <h3>{_esc(tactic)} — {n_tools} acciones, {n_replans} replans</h3>
            <p><b>Tools:</b> {tool_summary if tool_summary else '(ninguna)'}</p>
            <p><b>Evidencia:</b></p>
            <pre class='evidence'>{_esc(json.dumps(evidence, indent=2, ensure_ascii=False))}</pre>
            <details><summary>{len(tactic_events)} eventos en esta tactica</summary>
                <div class='event-content'>{_build_timeline(tactic_events)}</div>
            </details>
        </div>""")
    return "".join(blocks)


def _build_observer_section(events: list[dict]) -> str:
    """Sección dedicada al observador: ventanas, clasificaciones, refinements."""
    obs_events = [e for e in events if e["agent"] == "observer"]
    if not obs_events:
        return "<p>Sin eventos del observador (corrida con --attacker-only).</p>"

    classifications = [e for e in obs_events if e["event_type"] == "classify"]
    triages = [e for e in obs_events if e["event_type"] == "triage"]
    refines = [e for e in obs_events if e["event_type"] == "refine"]

    summary = f"""<p>
        <b>{len(triages)}</b> ventanas procesadas |
        <b>{sum(1 for t in triages if t['payload'].get('result') == 'signal')}</b> con señales |
        <b>{len(classifications)}</b> clasificaciones |
        <b>{len(refines)}</b> refinements
    </p>"""

    if not classifications:
        return summary + "<p>Ninguna ventana clasificada.</p>"

    rows = "<table class='tactics'><thead><tr><th>Timestamp</th><th>Tactica</th><th>Confianza</th><th>Refinements</th></tr></thead><tbody>"
    for cl in classifications:
        ts = _fmt_ts(cl["timestamp"])
        tactic = cl["payload"].get("tactic", "?")
        conf = cl["payload"].get("confidence", 0)
        refine_count = cl["payload"].get("refinement_count", 0)
        rows += f"<tr><td><code>{ts}</code></td><td><b>{_esc(tactic)}</b></td><td>{conf:.0%}</td><td>{refine_count}</td></tr>"
    rows += "</tbody></table>"

    return summary + rows


def generate_report(
    session_data: dict,
    output_path: Path,
) -> Path:
    """
    Genera el HTML report a partir del session JSON.

    session_data: dict con keys 'metadata' y 'events' (de SessionRecorder.to_dict).
    output_path: ruta del HTML de salida.

    Retorna el path final escrito.
    """
    metadata = session_data.get("metadata", {})
    events = session_data.get("events", [])

    title = f"Reporte — {metadata.get('scenario', 'unknown')}"

    body = f"""
    <h1>{_esc(title)}</h1>
    <h2>Metadata</h2>
    {_build_metadata_section(metadata)}
    <h2>Resumen ejecutivo</h2>
    {_build_summary_section(metadata, events)}
    <h2>Detalle por tactica del atacante</h2>
    {_build_per_tactic_detail(events)}
    <h2>Observador</h2>
    {_build_observer_section(events)}
    <h2>Timeline completo</h2>
    <div class='legend'>
        <span><span class='dot attacker'></span>Atacante</span>
        <span><span class='dot observer'></span>Observador</span>
        <span><span class='dot system'></span>Sistema</span>
    </div>
    {_build_timeline(events)}
    <footer>
        Generado por src/ui/report.py — Sistema Adversarial MITRE ATT&amp;CK (USFQ 2026)
    </footer>
    """

    html_doc = f"""<!DOCTYPE html>
<html lang="es"><head>
<meta charset="utf-8"><title>{_esc(title)}</title>
<style>{_CSS}</style>
</head><body><div class='container'>
{body}
</div></body></html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_doc, encoding="utf-8")
    return output_path
