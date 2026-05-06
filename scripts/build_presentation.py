"""Genera la presentacion .pptx para la defensa USFQ a partir del aggregate
JSON de la sesion de resultados.

Estructura: ~30 slides para 35 minutos de defensa (≈70s/slide promedio).
Usa python-pptx (poetry add python-pptx).

Salida: presentations/defensa_alarcon.pptx
"""

import json
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor

REPO = Path(__file__).resolve().parent.parent
AGG = REPO / "data" / "matrix_aggregate.json"
OUT = REPO / "presentations" / "defensa_alarcon.pptx"

ACCENT = RGBColor(0xC8, 0x10, 0x2E)   # rojo USFQ
DARK = RGBColor(0x1F, 0x2D, 0x3D)
GRAY = RGBColor(0x55, 0x65, 0x6E)
LIGHT = RGBColor(0xF4, 0xF4, 0xF4)


def load_runs():
    if not AGG.exists():
        return []
    return json.loads(AGG.read_text()).get("runs", [])


def slide_title(prs, title, subtitle=""):
    layout = prs.slide_layouts[0]
    s = prs.slides.add_slide(layout)
    s.placeholders[0].text = title
    if subtitle and len(s.placeholders) > 1:
        s.placeholders[1].text = subtitle
    return s


def slide_blank(prs):
    return prs.slides.add_slide(prs.slide_layouts[6])


def add_title(slide, text, size=32):
    tx = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(12.0), Inches(0.7))
    tf = tx.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(size)
    p.font.bold = True
    p.font.color.rgb = ACCENT
    return tx


def add_bullets(slide, bullets, top=1.2, left=0.6, width=12.0, height=5.5,
                size=18, line_spacing=1.2):
    tx = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = tx.text_frame
    tf.word_wrap = True
    for i, b in enumerate(bullets):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        if isinstance(b, tuple):
            text, lvl = b
        else:
            text, lvl = b, 0
        p.text = ("• " if lvl == 0 else "  – ") + text
        p.level = lvl
        p.font.size = Pt(size)
        p.font.color.rgb = DARK
        p.line_spacing = line_spacing
    return tx


def add_text_block(slide, text, top=1.2, left=0.6, width=12.0, height=5.5,
                   size=14, color=DARK):
    tx = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = tx.text_frame
    tf.word_wrap = True
    for i, line in enumerate(text.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = line
        p.font.size = Pt(size)
        p.font.color.rgb = color
    return tx


def add_table(slide, header, rows, left=0.5, top=1.5, width=12.5, height=5.5,
              first_row_bold=True, header_color=DARK):
    cols = len(header)
    n = len(rows) + 1
    table = slide.shapes.add_table(n, cols, Inches(left), Inches(top),
                                    Inches(width), Inches(height)).table
    for i, h in enumerate(header):
        cell = table.cell(0, i)
        cell.text = str(h)
        cell.fill.solid()
        cell.fill.fore_color.rgb = header_color
        for p in cell.text_frame.paragraphs:
            for r in p.runs:
                r.font.bold = True
                r.font.size = Pt(11)
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for r_idx, row in enumerate(rows, 1):
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx, c_idx)
            cell.text = str(val)
            for p in cell.text_frame.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(10)
                    run.font.color.rgb = DARK
    return table


def add_footer(slide, text="Sistema Adversarial MITRE ATT&CK · Alarcón · USFQ 2026"):
    tx = slide.shapes.add_textbox(Inches(0.4), Inches(7.0), Inches(12.5), Inches(0.3))
    p = tx.text_frame.paragraphs[0]
    p.text = text
    p.font.size = Pt(9)
    p.font.color.rgb = GRAY


# ============================================================
# Slide-builders
# ============================================================

def build(prs, runs):
    by_eje = defaultdict(list)
    for r in runs:
        by_eje[r["eje"]].append(r)

    # ----- 1. Portada -----
    s = slide_title(prs,
        "Sistema Adversarial de Simulación de Ataques\ncon Clasificación Automática de Tácticas MITRE ATT&CK\nMediante Agentes Autónomos",
        "Francisco Jesús Alarcón Aguirre · USFQ 2026\nTutor: Roberto Andrade · Defensa Mayo 2026")

    # ----- 2. Problema y motivacion -----
    s = slide_blank(prs)
    add_title(s, "Problema y motivación")
    add_bullets(s, [
        "Ataques cibernéticos siguen patrones multi-etapa (kill chain MITRE ATT&CK).",
        "MITRE ATT&CK Enterprise 2025 incorpora Reconnaissance — expande la ventana de detección.",
        "LLMs muestran capacidad emergente en razonamiento, planificación y uso de herramientas.",
        "Convergencia: razonamiento LLM + necesidad de automatización ofensiva/defensiva en SOC.",
        "Brecha empírica: la combinación adversarial concurrente atacante–observer pasivo con ground-truth definicional sobre observables HTTP no está cuantificada en literatura previa.",
    ])
    add_footer(s)

    # ----- 3. Pregunta de investigacion -----
    s = slide_blank(prs)
    add_title(s, "Pregunta de investigación")
    add_text_block(s,
        "¿Con qué precisión un LLM puede inferir la táctica MITRE ATT&CK activa de\n"
        "un adversario a partir exclusivamente de observables externos (logs HTTP,\n"
        "eventos de autenticación, actividad de webshell), sin acceso a las\n"
        "intenciones ni al estado interno del atacante?",
        top=1.4, size=20)
    add_text_block(s,
        "Framing: measurement paper, NO system paper.\n"
        "Aporte: medir empíricamente una capacidad asumida pero no cuantificada\n"
        "con el mismo nivel de control en literatura 2023–2026.",
        top=4.5, size=14, color=GRAY)
    add_footer(s)

    # ----- 4. Objetivos -----
    s = slide_blank(prs)
    add_title(s, "Objetivos")
    add_bullets(s, [
        "General — desarrollar un sistema adversarial donde un Agente Atacante ejecute cadenas de ataque MITRE ATT&CK y un Agente Observador clasifique automáticamente la táctica activa mediante análisis de logs.",
        ("Específico 1 — Atacante autónomo capaz de progresar por múltiples tácticas con herramientas reales de pentesting.", 0),
        ("Específico 2 — Observador que opere con información limitada (logs HTTP) e identifique la táctica activa con LLM.", 0),
        ("Específico 3 — Entorno controlado con infraestructura vulnerable + stack de logging aislado.", 0),
        ("Específico 4 — Evaluar precisión vs ground truth registrado por el atacante.", 0),
    ], size=15)
    add_footer(s)

    # ----- 5. Marco teorico - MITRE -----
    s = slide_blank(prs)
    add_title(s, "MITRE ATT&CK como taxonomía formal")
    add_bullets(s, [
        "14 tácticas Enterprise (Reconnaissance → Impact).",
        "Estándar global de la industria (Strom et al. 2018, MITRE Corporation 2025).",
        "Tres niveles: táctica (qué objetivo) → técnica (cómo) → procedimiento.",
        "Forrester 2025: SIEMs comerciales efectivos consolidan alertas a nivel táctico.",
        "Output del sistema propuesto = mismo nivel de abstracción que el output consolidado de SIEMs.",
    ])
    add_footer(s)

    # ----- 6. LLMs en cybersec -----
    s = slide_blank(prs)
    add_title(s, "LLMs en ciberseguridad — estado del arte 2024-2026")
    add_bullets(s, [
        "PentestGPT (Deng et al. USENIX'24) — 3 sesiones LLM, +228.6 % completitud vs baseline.",
        "Cybench (Hans et al. ICLR'25) — 40 CTFs, validador task-achieved code-based.",
        "AthenaBench (Liu et al. 2025) — 12 LLMs sobre ATE/RMS MITRE.",
        "Cyber Defense Benchmark (Feb 2026, arXiv:2604.19533) — blue team threat hunting; Claude Opus 4.6 acertó solo 3.8 %; ningún modelo pasó 5/13 tácticas.",
        "PentestEval (Dec 2025) — end-to-end pipelines apenas 31 % éxito.",
        "Vinay (2025) — taxonomía 5 generaciones agéntica; pipeline Triage → Investigate → Classify → Escalate.",
    ], size=14)
    add_footer(s)

    # ----- 7. Arquitectura general -----
    s = slide_blank(prs)
    add_title(s, "Arquitectura general — tres capas")
    add_text_block(s,
        "ORQUESTACIÓN (proceso host Python — src/main.py)\n"
        "  ↓ verifica infra, lanza atacante + observer en threads separados\n\n"
        "AGENTES                                              \n"
        "  Atacante: grafo ReAct LangGraph 5 nodos (host)     \n"
        "  Observer: pipeline 6 nodos LangGraph (host, daemon thread)\n"
        "  ▶ NO se comunican directamente. Aislamiento intencional.\n\n"
        "INFRAESTRUCTURA (Docker Compose, 11 contenedores en 2 redes aisladas)\n"
        "  attack_net: Kali atacante + 8 targets vulnerables\n"
        "  monitor_net: Loki + Promtail + Grafana\n",
        top=1.4, size=14)
    add_text_block(s,
        "Único canal: tráfico atacante → logs container → Promtail → Loki → query observer.\n"
        "Simula la perspectiva de un analista SOC real.",
        top=5.4, size=12, color=GRAY)
    add_footer(s)

    # ----- 8. Atacante grafo ReAct -----
    s = slide_blank(prs)
    add_title(s, "Atacante — grafo ReAct con 30 herramientas")
    add_bullets(s, [
        "Patrón ReAct (Yao et al. 2023) + Pentest Task Tree de PentestGPT.",
        "5 nodos: plan_tactic → execute_tools → validate_result → check_objective → advance_tactic.",
        "30 herramientas en 5 categorías (recon, exploitation, payloads, privesc, utilities).",
        "Validators code-based target-agnostic en src/agents/attacker/objectives.py.",
        "Memoria persistente por fingerprint SHA-256 (puerto + tech stack) — playbooks reusables.",
        "Reflector node opt-in (RefPentester style, Chen et al. 2025) tras 3 replans sin progreso.",
        "Restricción metodológica: 1 táctica por ventana del observer (separabilidad temporal).",
    ], size=14)
    add_footer(s)

    # ----- 9. Observer pipeline -----
    s = slide_blank(prs)
    add_title(s, "Observer — pipeline Triage → Investigate → Classify")
    add_bullets(s, [
        "Patrón Vinay (2025) implementado con LangGraph 6 nodos + loop de refinamiento.",
        "collect_logs → triage_anomalies → (END si no signal | detect_anomalies → classify_tactic → refine_analysis ↺ → generate_recommendation).",
        "10 heurísticas T1-T10 + 4 firmas CVE-specific (T4b log4shell, T4c OGNL, T4d Solr Velocity, T4e Spring4Shell).",
        "Si triage no detecta señal → END sin invocar LLM (ahorra costo en ventanas vacías).",
        "Calibración adaptativa cost-sensitive (Elkan 2001 + Platt 1999) por táctica + prior bayesiano del fingerprint.",
        "Memoria persistente del observer: distribución empírica de tácticas por patrón de tráfico (NIST SP 800-94).",
    ], size=14)
    add_footer(s)

    # ----- 10. Capa multi-proveedor -----
    s = slide_blank(prs)
    add_title(s, "Capa multi-proveedor LLM (8 backends)")
    add_table(s,
        ["Proveedor", "Modelos soportados", "Tier"],
        [
            ["OpenAI", "GPT-5.5, GPT-5, GPT-4.1, GPT-4.1-mini, gpt-4o, o3, o4-mini", "paid"],
            ["Anthropic", "Opus 4.7, Sonnet 4.6, Sonnet 4.5, Haiku 4.5", "paid"],
            ["Google", "Gemini 3.1 Pro, Gemini 3 Pro, Gemini 2.5 Pro/Flash", "free 20/día"],
            ["Groq", "Llama 3.3 70B versatile", "free TPM bajo"],
            ["OpenRouter", "openai/gpt-oss-120b:free", "free"],
            ["Cerebras", "Qwen3 235B A22B Instruct 2507", "free"],
            ["DeepSeek", "V4 Flash (deepseek-chat), V4 Pro, Reasoner", "paid + 5M free"],
            ["Moonshot", "Kimi K2 Turbo Preview, moonshot-v1-128k", "paid"],
        ], top=1.4, height=5.0)
    add_text_block(s,
        "Reproducibilidad: seed=42 (todos menos Anthropic), atacante temp=0.2, observer temp=0.0.\n"
        "Captura de quota mid-run preserva action_history (anthropic.BadRequestError + openai.RateLimitError + APIStatusError).",
        top=6.4, size=10, color=GRAY)
    add_footer(s)

    # ----- 11. Reproducibilidad y estandares -----
    s = slide_blank(prs)
    add_title(s, "Reproducibilidad y estándares")
    add_bullets(s, [
        "ISO/IEC TS 4213:2022 — Assessment of ML classification performance: macro/micro F1 + bootstrap CI 95 %.",
        "ISO/IEC/IEEE 12207:2017 — Software life cycle: arquitectura, diseño, verificación (261+ tests pytest), validación (corridas empíricas), mantenimiento (git log).",
        "ISO/IEC 22989:2022 — Terminología AI; ISO/IEC TR 24028:2020 — trustworthiness.",
        "Marco metodológico: Design Process in CS (Maris & Kumalesh 2017, 7 etapas) + PFX framework (Menold et al. 2017, 4 specs).",
        "ABET 1, 2, 3, 4, 6 nivel Avanzado (syllabus CMP 5992).",
    ], size=14)
    add_footer(s)

    # ----- 12. Escenarios -----
    s = slide_blank(prs)
    add_title(s, "8 escenarios — diversidad de vectores estructurales")
    add_table(s,
        ["Escenario", "Target", "Vector ataque", "Tácticas"],
        [
            ["basic", "DVWA", "HTTP form (SQLi, Cmd Injection)", "4"],
            ["dvwa", "DVWA", "Igual a basic + Cred Access + PrivEsc", "6"],
            ["mrrobot", "WordPress 4.x", "wp-login bruteforce + theme webshell", "6"],
            ["dc1", "Drupal 7", "CVE-2018-7600 + SUID find", "6"],
            ["bpent", "boot2root", "SSH bruteforce wordlist + SUID vim.tiny", "6"],
            ["log4shell", "Apache Solr 8.11", "CVE-2021-44228 JNDI", "3"],
            ["confluence", "Confluence 7.13.6", "CVE-2022-26134 OGNL", "3"],
            ["phpunit", "PHPUnit 5.6.2", "CVE-2017-9841 eval-stdin", "3"],
        ], top=1.4, height=5.0)
    add_text_block(s,
        "5 vectores estructurales distintos: HTTP form / JNDI / OGNL / eval-stdin / brute force SSH.",
        top=6.5, size=12, color=GRAY)
    add_footer(s)

    # ----- 13. Metodologia -----
    s = slide_blank(prs)
    add_title(s, "Metodología — 4 ejes experimentales")
    add_table(s,
        ["Eje", "Mide", "Runs", "Memoria", "Stack"],
        [
            ["A", "Cross-modelo en basic", "5×5 = 25", "Reset entre runs (cold)", "Variable atacante × observer"],
            ["B", "Generalización", "7", "No reset (fingerprints distintos)", "Sonnet 4.5 + top observer Eje A"],
            ["C", "Ablation regex-only vs hybrid", "2 (basic + log4shell)", "Cold", "Sonnet 4.5 + regex_only"],
            ["D", "Efecto memoria warm", "3 consecutivos", "NO reset (warm acumulativo)", "Stack ganador Eje A"],
        ], top=1.4, height=4.0)
    add_text_block(s,
        "Métricas: macro-F1, micro-F1, strict-accuracy con bootstrap CI 95% (1000 resamples, Efron 1979).\n"
        "Sokolova & Lapalme (2009) sobre clasificación multi-label.\n"
        "Total: ~37 corridas, ~3h wall-clock, ~$30-40 USD.",
        top=5.7, size=12, color=GRAY)
    add_footer(s)

    # ============== RESULTADOS ============================
    eje_a = sorted(by_eje.get("A", []), key=lambda r: r["run_idx"])
    eje_b = sorted(by_eje.get("B", []), key=lambda r: r["run_idx"])
    eje_c = sorted(by_eje.get("C", []), key=lambda r: r["run_idx"])
    eje_d = sorted(by_eje.get("D", []), key=lambda r: r["run_idx"])

    # ----- 14. Eje A matriz -----
    s = slide_blank(prs)
    add_title(s, "Eje A — Matriz cross-modelo (mF1)")
    if eje_a:
        attackers = sorted({r["attacker_id"] for r in eje_a})
        observers = sorted({r["observer_id"] for r in eje_a})
        grid = {(r["attacker_id"], r["observer_id"]): r for r in eje_a}
        rows = []
        for a in attackers:
            row = [a]
            for o in observers:
                cell = grid.get((a, o))
                if cell and cell.get("macro_f1") is not None:
                    row.append(f"{cell['macro_f1']:.3f}")
                else:
                    row.append("—")
            rows.append(row)
        add_table(s, ["Atacante \\ Observer"] + observers, rows, top=1.5, height=4.0)
    else:
        add_text_block(s, "Eje A pendiente (data/matrix_aggregate.json sin runs A).",
                       top=2.0, size=14, color=ACCENT)
    add_footer(s)

    # ----- 15. Eje A - top observers + atacantes -----
    s = slide_blank(prs)
    add_title(s, "Eje A — Top observers y atacantes")
    if eje_a:
        by_o = defaultdict(list)
        by_a = defaultdict(list)
        for r in eje_a:
            if r.get("macro_f1") is not None:
                by_o[r["observer_id"]].append(r["macro_f1"])
                by_a[r["attacker_id"]].append(r["macro_f1"])
        rows_o = [
            [k, f"{mean(v):.3f}", f"{(stdev(v) if len(v)>1 else 0):.3f}", str(len(v))]
            for k, v in sorted(by_o.items(), key=lambda x: -mean(x[1]))
        ]
        rows_a = [
            [k, f"{mean(v):.3f}", f"{(stdev(v) if len(v)>1 else 0):.3f}", str(len(v))]
            for k, v in sorted(by_a.items(), key=lambda x: -mean(x[1]))
        ]
        add_table(s, ["Observer", "μ mF1", "σ", "n"], rows_o,
                  left=0.4, top=1.3, width=6.2, height=3.5)
        add_table(s, ["Atacante", "μ mF1", "σ", "n"], rows_a,
                  left=6.8, top=1.3, width=6.2, height=3.5)
    add_text_block(s,
        "Lectura: identifica el LLM que mejor clasifica como observer y el que mejor genera tácticas como atacante.\n"
        "La σ refleja varianza inter-observador para el mismo atacante (y viceversa).",
        top=5.5, size=12, color=GRAY)
    add_footer(s)

    # ----- 16. Eje A - costo y latencia -----
    s = slide_blank(prs)
    add_title(s, "Eje A — Costo y latencia por celda")
    if eje_a:
        rows = []
        for r in sorted(eje_a, key=lambda x: -(x.get("macro_f1") or 0))[:14]:
            cost = (r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0)
            rows.append([
                f"{r['attacker_id']} → {r['observer_id']}",
                f"{(r.get('macro_f1') or 0):.3f}",
                f"${cost:.3f}",
                f"{int(r.get('elapsed_s') or 0)}s",
                f"{(r.get('observer_avg_latency_s') or 0):.2f}s",
            ])
        add_table(s, ["Combo", "mF1", "Costo", "Wall", "Lat. obs"], rows,
                  top=1.3, height=5.4)
    add_footer(s)

    # ----- 17. Eje B generalizacion -----
    s = slide_blank(prs)
    add_title(s, "Eje B — Generalización 7 escenarios (stack fijo)")
    if eje_b:
        rows = []
        for r in eje_b:
            cost = (r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0)
            rows.append([
                r["scenario"],
                f"{(r.get('macro_f1') or 0):.3f}",
                f"{(r.get('micro_f1') or 0):.3f}",
                f"{(r.get('strict_accuracy') or 0):.3f}",
                str(r.get("tactics_completed", "-")),
                f"${cost:.3f}",
                f"{int(r.get('elapsed_s') or 0)}s",
            ])
        add_table(s, ["Escenario", "macro-F1", "micro-F1", "strict-acc", "tact_done", "Costo", "Wall"], rows,
                  top=1.4, height=5.0)
    else:
        add_text_block(s, "Eje B pendiente (sin runs B en aggregate).",
                       top=2.0, size=14, color=ACCENT)
    add_footer(s)

    # ----- 18. Eje C ablation -----
    s = slide_blank(prs)
    add_title(s, "Eje C — Ablation regex-only vs hybrid LLM")
    if eje_c and eje_a:
        rows = []
        # Para basic: regex-only Eje C vs hybrid Eje A (Sonnet 4.5 -> Haiku 4.5 row 06)
        rows.append(["Modo", "mF1 (basic)", "mF1 (log4shell)", "Costo obs"])
        # Aproximacion: hybrid promedio de combos basic en Eje A, vs regex-only Eje C
        a_basic = [r for r in eje_a if r["scenario"] == "basic"]
        if a_basic:
            mavg = mean([r["macro_f1"] for r in a_basic if r.get("macro_f1") is not None])
            rows.append(["Hybrid (LLM, μ Eje A)", f"{mavg:.3f}", "—", "varia"])
        for r in eje_c:
            cost = (r.get("observer_cost_usd") or 0)
            cell_basic = f"{r.get('macro_f1', 0):.3f}" if r["scenario"] == "basic" else "—"
            cell_log4 = f"{r.get('macro_f1', 0):.3f}" if r["scenario"] == "log4shell" else "—"
            rows.append([f"Regex-only ({r['scenario']})", cell_basic, cell_log4, f"${cost:.4f}"])
        add_table(s, rows[0], rows[1:], top=1.4, height=4.0)
        add_text_block(s,
            "Δ direccional cuantifica la contribución marginal del LLM sobre el pipeline determinista.\n"
            "El observer regex-only NO invoca LLM (costo ≈ $0); refleja qué tan lejos llegan las heurísticas T1–T10 + classify_webshell_cmd.",
            top=5.6, size=12, color=GRAY)
    else:
        add_text_block(s, "Eje C pendiente.", top=2.0, size=14, color=ACCENT)
    add_footer(s)

    # ----- 19. Eje D efecto memoria -----
    s = slide_blank(prs)
    add_title(s, "Eje D — Efecto memoria cold → warm")
    if eje_d:
        rows = []
        for i, r in enumerate(eje_d, 1):
            rows.append([
                f"Run {i}",
                str(r.get("memory_hit", "?")),
                str(r.get("tool_calls", "-")),
                str(r.get("replans", "-")),
                f"{(r.get('macro_f1') or 0):.3f}",
                f"{int(r.get('elapsed_s') or 0)}s",
            ])
        add_table(s, ["#", "memory_hit", "tool_calls", "replans", "mF1", "wall"],
                  rows, top=1.4, height=3.5)
        add_text_block(s,
            "Replica del speedup observado en cap. 6.3.3 doc final (Sonnet 4.5 dvwa cold→warm: 25→13 acciones, −48%).\n"
            "Confirma que la memoria persistente reduce el costo de tareas repetidas sin degradar accuracy.",
            top=5.2, size=12, color=GRAY)
    else:
        add_text_block(s, "Eje D pendiente.", top=2.0, size=14, color=ACCENT)
    add_footer(s)

    # ----- 20. Discusion costo/throughput -----
    s = slide_blank(prs)
    add_title(s, "Análisis de costo, latencia y throughput")
    bullets = [
        "Costo del atacante domina los stacks con observador gratuito.",
        "Cerebras Qwen3 235B free: latencia LLM rápida pero acumula backlog en ventana 5 s; mejor mF1 promedio en Eje A.",
        "Anthropic Sonnet 4.5: F1 más estable pero costo mayor; idoneo para análisis forense post-hoc.",
        "OpenRouter gpt-oss-120b free: viable como observer en escenarios simples; degrada en CVEs específicos.",
        "DeepSeek V4 Flash: paid pero competitivo; tradeoff distinto al ranking pure-mF1 (latencia menor que Sonnet).",
    ]
    add_bullets(s, bullets, size=14)
    add_footer(s)

    # ----- 21. Free tiers documentados -----
    s = slide_blank(prs)
    add_title(s, "Capacidad de free tiers — datos empíricos")
    add_table(s,
        ["Proveedor", "Modelo", "Restricción identificada", "Viabilidad"],
        [
            ["Google", "gemini-2.5-flash", "20 req/día (RESOURCE_EXHAUSTED tras 3 corridas)", "INVIABLE como observer"],
            ["Cerebras", "qwen-3-235b", "Latencia LLM ~10-20s, sin TPD limit", "Viable, lento pero gana mF1"],
            ["OpenRouter", "openai/gpt-oss-120b:free", "Sin TPD aparente, latencia variable", "Viable sostenido"],
            ["Groq", "llama-3.3-70b", "TPM 12 000 vs prompt 19 000 → HTTP 413", "INVIABLE para prompt actual"],
            ["DeepSeek", "deepseek-chat (V4 Flash)", "5M tokens free + paid muy barato", "Viable + escalable"],
        ], top=1.4, height=4.5)
    add_footer(s)

    # ----- 22. Comparacion con literatura -----
    s = slide_blank(prs)
    add_title(s, "Comparación con literatura reciente")
    add_bullets(s, [
        "Cyber Defense Benchmark (2026): mejor LLM acertó solo 3.8 % de eventos en blue team threat hunting.",
        "PentestEval (2025): pipelines E2E LLM apenas 31 % de éxito.",
        "AthenaBench (2025): LLMs propietarios subpar en reasoning-intensive.",
        "Daniel et al. (2024): LLMs F1 inferior a ML supervisado en Snort rules → aporte LLM = razonamiento explicable y zero-shot, no superioridad numérica.",
        "Mi sistema reporta cifras moderadas (~0.4-0.6 macro F1 en basic) — consistente con la dificultad documentada del campo.",
    ], size=14)
    add_footer(s)

    # ----- 23. Aporte original -----
    s = slide_blank(prs)
    add_title(s, "Aporte original — measurement paper")
    add_bullets(s, [
        "Setup adversarial concurrente atacante–observer pasivo sobre logs HTTP — no replicado en literatura previa.",
        "Validators code-based estrictos con verificación live — más rigurosos que el honor system común.",
        "Calibración bayesiana adaptativa por prior (Elkan 2001 + Platt 1999) extendida a clasificación MITRE.",
        "Triple ablación regex-only / LLM-only / hybrid sobre el mismo pipeline — cuantifica aporte marginal del LLM.",
        "Matriz cross-modelo 5×5 con instrumentación uniforme (seed, temp, metadata embebida).",
        "Documentación de capacidad real de free tiers (Gemini, Groq inviables; Cerebras viable lento).",
    ], size=14)
    add_footer(s)

    # ----- 24. Bug fixes principales (transparencia) -----
    s = slide_blank(prs)
    add_title(s, "Honestidad metodológica — bugs críticos detectados y arreglados")
    add_bullets(s, [
        "Sev 5 — _emit_report scope NameError: metadata final no se persistía. Fix commit c5d3ec8.",
        "Sev 5 — captura quota OpenAI mid-run: openai.RateLimitError no se atrapaba. Fix commit 4b3a914.",
        "Sev 5 (sesión resultados) — classify event no propagaba window_start/end → matching ground-truth desfasado por latencia LLM → mF1=0 con observers rápidos. Fix commit 757a503.",
        "tactics_in_window aplanado a list[str] → metrics filtraba dicts → fallback single-label degradaba JSON. Fix commit fb634ca.",
        "bootstrap_ci no llegaba a evaluation cuando incremental_save corría primero. Fix commit fb634ca.",
        "save_baselines no atomic → fix tmp+rename consistente con save_playbooks (commit 31f0f15).",
    ], size=12)
    add_footer(s)

    # ----- 25. Limitaciones -----
    s = slide_blank(prs)
    add_title(s, "Limitaciones identificadas como aporte (cap. 7.2)")
    add_bullets(s, [
        "Ingeniería de prompt domina sobre elección de modelo: mejorar prompt elevó mF1 +0.25 absoluto.",
        "Sesgo de frecuencia LLM: GPT-4.1 atascado en bpent (username 'marlinspike' inusual); Sonnet 4.5 lo atraviesa.",
        "Régimen forense con resolución 5s, NO SOC reactivo en tiempo real estricto.",
        "Lag de detección por ventanas cortas: tácticas <5s diluidas por dominancia de logs scanner.",
        "Conocimiento del LLM sobre CTFs públicos (Mr. Robot, DC-1) puede inflar accuracy — bpent (sin walkthrough público) sirve como control.",
    ], size=14)
    add_footer(s)

    # ----- 26. Trabajo futuro -----
    s = slide_blank(prs)
    add_title(s, "Trabajo futuro (cap. 7.3)")
    add_bullets(s, [
        "Comparación formal contra baselines clásicos ML (RF, XGBoost) sobre los mismos escenarios.",
        "Experimento de ablación con/sin historial temporal del observer (cuantificar arrastre de error).",
        "Implementar tácticas Lateral Movement / Exfiltration / Impact (telemetría más allá de HTTP).",
        "Variantes anonimizadas de CTFs públicos para cuantificar memorización vs razonamiento.",
        "n ≥ 3 corridas por celda con bootstrap inter-corrida (presupuesto pre-defensa lo limitó).",
        "Implementar GeoServer CVE-2024-36401 (vector OGC/XPath) — generalización adicional.",
    ], size=14)
    add_footer(s)

    # ----- 27. Conclusiones -----
    s = slide_blank(prs)
    add_title(s, "Conclusiones")
    add_bullets(s, [
        "El sistema cuantifica empíricamente la capacidad de inferencia táctica MITRE de LLMs en setup adversarial controlado.",
        "Pipeline híbrido (heurísticas T1–T10 + LLM contextual) supera al pipeline puro determinista en accuracy estricta.",
        "La precisión depende fuertemente del modelo: Cerebras Qwen3 235B free lidera mF1 promedio en basic.",
        "Hallazgos consistentes con literatura reciente: el campo está abierto, los LLMs frontier no resuelven blue team aún.",
        "Sistema reproducible: 261+ tests pytest, JSON con metadata embebida, bootstrap CI por corrida.",
        "Aporte legítimo: medición rigurosa donde la literatura previa solo tenía claims cualitativos.",
    ], size=14)
    add_footer(s)

    # ----- 28. ABET + estandares -----
    s = slide_blank(prs)
    add_title(s, "Cumplimiento ABET 1, 2, 3, 4, 6 + ISO/IEC TS 4213")
    add_bullets(s, [
        "ABET 1 — Análisis problema complejo: 13 alternativas arquitectónicas evaluadas, MITRE como taxonomía formal.",
        "ABET 2 — Diseñar/implementar/evaluar: 261+ tests, bootstrap CI, instrumentación completa.",
        "ABET 3 — Comunicación eficaz: README, HALLAZGOS_TESIS, doc final 60+ páginas, defensa programada.",
        "ABET 4 — Responsabilidad legal/ética: dual-use AI, COIP Art. 232 Ecuador, Convención Budapest 2024 ratificada.",
        "ABET 6 — Aplicación de teoría: MITRE, Sokolova 2009, Efron 1979, Elkan 2001, Platt 1999, Bhuyan 2014.",
        "Alineación: ISO/IEC TS 4213:2022 (ML clf perf) + ISO/IEC/IEEE 12207:2017 (SW lifecycle).",
    ], size=12)
    add_footer(s)

    # ----- 29. Cierre -----
    s = slide_blank(prs)
    add_title(s, "Gracias")
    add_text_block(s,
        "Francisco Jesús Alarcón Aguirre\n"
        "Ingeniería en Ciencias de la Computación · USFQ 2026\n\n"
        "Tutor: Roberto Andrade · Profesor: Jorge Flores Moyano\n"
        "Repositorio: github.com/Crescendum429/mitre-adversarial-system\n\n"
        "Preguntas y discusión.",
        top=2.0, size=18)
    add_footer(s)


def main():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    runs = load_runs()
    print(f"Aggregate: {len(runs)} runs")
    build(prs, runs)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(OUT))
    print(f"OK -> {OUT} ({len(prs.slides)} slides)")


if __name__ == "__main__":
    main()
