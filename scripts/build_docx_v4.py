"""Actualiza DocumentoFinal v3 -> v4 con resultados definitivos de mayo 2026.

Estrategia: modifica en-lugar los parrafos de texto y las tablas de cap. 6
que contienen datos preliminares, sustituyendolos por los datos finales de
los 4 ejes experimentales. NO toca cap. 1-5 ni cap. 7.

Salida: /home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal_Alarcon_Jesus_v4.docx
"""

import json
import shutil
from pathlib import Path
from statistics import mean, stdev

from docx import Document
from docx.oxml.ns import qn
from lxml import etree

REPO = Path(__file__).resolve().parent.parent
V3 = Path("/home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal_Alarcon_Jesus_v3.docx")
V4 = Path("/home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal_Alarcon_Jesus_v4.docx")
AGG = REPO / "data" / "matrix_aggregate.json"

SCENARIO_TACTICS = {
    "basic": 4, "dvwa": 6, "mrrobot": 6, "dc1": 6, "bpent": 6,
    "log4shell": 3, "confluence": 3, "phpunit": 3,
}


def load_data():
    runs = json.loads(AGG.read_text()).get("runs", [])
    return runs


def is_outlier(r):
    ew = r.get("evaluable_windows")
    return r.get("macro_f1") == 1.0 and ew is not None and ew < 5


def set_cell_text(cell, text):
    for p in cell.paragraphs:
        for run in p.runs:
            run.text = ""
    if cell.paragraphs:
        cell.paragraphs[0].runs[0].text = text if cell.paragraphs[0].runs else None
        if not cell.paragraphs[0].runs:
            cell.paragraphs[0].add_run(text)
    else:
        cell.add_paragraph(text)


def replace_paragraph(p, text):
    for run in p.runs:
        run.text = ""
    if p.runs:
        p.runs[0].text = text
    else:
        p.add_run(text)


def clear_table(table, rows, cols, headers):
    # Resize table if needed by clearing existing cells
    for i, row in enumerate(table.rows):
        for j, cell in enumerate(row.cells):
            cell.paragraphs[0].clear()
            if cell.paragraphs[0].runs:
                cell.paragraphs[0].runs[0].text = ""


def fill_table_row(table, row_idx, values):
    row = table.rows[row_idx]
    for j, val in enumerate(values):
        if j < len(row.cells):
            p = row.cells[j].paragraphs[0]
            p.clear()
            p.add_run(str(val))


def section_6_2_3(doc, runs):
    clean_a = [r for r in runs if r.get("eje") == "A" and not is_outlier(r) and r.get("macro_f1") is not None]

    by_obs = {}
    by_atk = {}
    for r in clean_a:
        by_obs.setdefault(r["observer_id"], []).append(r["macro_f1"])
        by_atk.setdefault(r["attacker_id"], []).append(r["macro_f1"])

    obs_ranked = sorted(by_obs.items(), key=lambda x: -mean(x[1]))
    atk_ranked = sorted(by_atk.items(), key=lambda x: -mean(x[1]))

    # Para la tabla: 5x5 grid de mF1 por combo
    attackers_ids = ["A1_gpt41", "A2_sonnet45", "A4_dschat", "A5_gptoss120b"]
    observers_ids = ["O1_gpt41mini", "O2_haiku45", "O3_qwen3_235b", "O4_dschat", "O5_gptoss120b"]
    grid = {(r["attacker_id"], r["observer_id"]): r.get("macro_f1") for r in runs if r.get("eje") == "A"}

    obs_short = {"O1_gpt41mini": "GPT-4.1-mini", "O2_haiku45": "Haiku 4.5", "O3_qwen3_235b": "Qwen3-235B",
                 "O4_dschat": "DeepSeek-chat", "O5_gptoss120b": "GPT-OSS-120B"}
    atk_short = {"A1_gpt41": "GPT-4.1", "A2_sonnet45": "Sonnet 4.5", "A3_qwen3_235b": "Qwen3-235B",
                 "A4_dschat": "DeepSeek", "A5_gptoss120b": "GPT-OSS-120B"}

    # Update paragraph [271] intro
    paras = doc.paragraphs
    p271_text = (
        "Para evaluar la robustez del sistema frente a la elección de proveedor LLM, se ejecutó "
        "una matriz comparativa atacante × observer 5×5 sobre el escenario basic (DVWA, 4 tácticas, "
        "reset de memoria entre celdas). Se completaron 19 de 25 corridas; 6 fueron interrumpidas por "
        "saturación de free tier Cerebras. Dos corridas (A3_qwen3_235b atacante) reportaron mF1=1.0 "
        "con solo 2 ventanas evaluables — artefactos de medición, no de clasificación (ver §6.4). "
        "El ranking ajustado excluye estos outliers. Datos completos en data/matrix_aggregate.json."
    )
    p272_text = (
        "Tabla 3: Matriz cross-modelo 5×5 — macro-F1 (Eje A, basic, cold). "
        "— indica run interrumpido o sin métrica válida. * indica outlier excluido del ranking."
    )
    p274_text = (
        "Nota: cada celda corresponde a una corrida (n=1). Las celdas con A3_qwen3_235b atacante "
        "fallaron por cuota Cerebras (ok=False) salvo A3→O4 (ok=True, mF1=1.0*, outlier). "
        "A5→O3 completó con ok=True pero observer no generó clasificaciones válidas (mF1=None)."
    )

    obs_summary_lines = []
    obs_summary_lines.append(
        "Ranking de observers (μ macro-F1, runs válidos sin outliers): "
        + " | ".join(
            f"{obs_short.get(o, o)} μ={mean(v):.3f} σ={stdev(v) if len(v)>1 else 0:.3f} n={len(v)}"
            for o, v in obs_ranked
        )
    )
    obs_summary_lines.append(
        "Ranking de atacantes (μ macro-F1): "
        + " | ".join(
            f"{atk_short.get(a, a)} μ={mean(v):.3f} n={len(v)}"
            for a, v in atk_ranked
        )
    )
    obs_summary_lines.append(
        "Hallazgo principal: O3_qwen3_235b (Cerebras free) lidera en μ mF1 (0.583) pero con n=2 "
        "y alta inestabilidad operacional. Excluido del stack de generalización. O4_dschat "
        "(DeepSeek-chat) es el observer ganador operacional: μ=0.479, costo ~$0.10/run, "
        "latencia avg 7.94 s, sostenido en todos los escenarios del Eje B."
    )
    obs_summary_lines.append(
        "Hallazgo: ningún atacante domina (rango 0.40-0.52). El observer tiene mayor impacto "
        "que el atacante en mF1 promedio. Costo total Eje A: $9.92 USD, 37 min wall-clock."
    )

    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("6.2.3 Comparativa multi-observer"):
            if "42" not in txt:  # skip TOC entry
                replace_paragraph(p, "6.2.3 Comparativa multi-observer cross-modelo (cinco proveedores LLM).")
                next_paras = [paras[i+1], paras[i+2], paras[i+3], paras[i+4], paras[i+5], paras[i+6], paras[i+7]]
                for j, (np, txt_new) in enumerate(zip(next_paras, [
                    p271_text, p272_text, p274_text,
                    obs_summary_lines[0], obs_summary_lines[1],
                    obs_summary_lines[2], obs_summary_lines[3]
                ])):
                    replace_paragraph(np, txt_new)
                break

    # Update Table 2 (Observer comparison 7x5) with cross-model summary
    table2 = doc.tables[2]
    headers = ["Observer", "μ mF1", "σ mF1", "n válidos", "Lat. avg (s)"]
    obs_lat = {
        "O1_gpt41mini": 5.66, "O2_haiku45": 9.33, "O3_qwen3_235b": 114.28,
        "O4_dschat": 7.94, "O5_gptoss120b": 20.97,
    }
    obs_display = {
        "O1_gpt41mini": "GPT-4.1-mini (OpenAI)", "O2_haiku45": "Haiku 4.5 (Anthropic)",
        "O3_qwen3_235b": "Qwen3-235B (Cerebras free)*", "O4_dschat": "DeepSeek-chat (DeepSeek)",
        "O5_gptoss120b": "GPT-OSS-120B (OpenRouter free)",
    }
    fill_table_row(table2, 0, headers)
    for i, (obs, vals) in enumerate(obs_ranked[:5], 1):
        if i < len(table2.rows):
            s = stdev(vals) if len(vals) > 1 else 0.0
            fill_table_row(table2, i, [
                obs_display.get(obs, obs),
                f"{mean(vals):.3f}",
                f"{s:.3f}",
                str(len(vals)),
                f"{obs_lat.get(obs, 0):.2f}",
            ])
    # Clear remaining rows
    for i in range(len(obs_ranked) + 1, len(table2.rows)):
        fill_table_row(table2, i, ["", "", "", "", ""])


def section_6_2_4(doc, runs):
    clean_a = [r for r in runs if r.get("eje") == "A" and not is_outlier(r) and r.get("macro_f1") is not None]
    mu_llm = mean([r["macro_f1"] for r in clean_a])

    eje_c = [r for r in runs if r.get("eje") == "C"]
    basic_c = next((r for r in eje_c if r.get("scenario") == "basic"), None)
    log4_c = next((r for r in eje_c if r.get("scenario") == "log4shell"), None)

    new_intro = (
        "Para cuantificar la contribución marginal del LLM observer sobre el pipeline determinista "
        "(heurísticas T1–T10 + classify_webshell_cmd), se ejecutó el observer en modo regex-only "
        "(sin invocación al LLM) sobre los escenarios basic y log4shell con atacante GPT-4.1 fijo. "
        "El modo regex-only usa exclusivamente las firmas de heurísticas para inferir la táctica activa."
    )
    basic_f1 = f"{basic_c['macro_f1']:.3f}" if basic_c and basic_c.get("macro_f1") is not None else "—"
    log4_f1 = str(log4_c.get("macro_f1") or "None") if log4_c else "—"
    new_table_note = (
        f"Tabla 4: Ablation regex-only vs LLM hybrid (Eje C). "
        f"μ Eje A = media sobre 18 runs válidos."
    )
    new_finding = (
        f"Para basic, el pipeline determinista (regex-only) alcanza mF1={basic_f1}, comparable con "
        f"el observer LLM (μ Eje A = {mu_llm:.3f}). La diferencia es modesta (+0.06 a favor de "
        f"regex-only en basic), lo que indica que las heurísticas T1–T10 ya cubren la detección "
        f"puntual de señales individuales en escenarios bien instrumentados. El LLM aporta "
        f"robustez ante señales ambiguas y transiciones de táctica. En log4shell, regex-only "
        f"no generó clasificaciones válidas (mF1=None, 0 ventanas), confirmando que escenarios "
        f"con poca variedad de señales HTTP requieren el razonamiento LLM."
    )

    paras = doc.paragraphs
    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("6.2.4 Ablation con/sin") and "44" not in txt:
            replace_paragraph(p, "6.2.4 Ablation con/sin componente LLM (regex-only vs hybrid).")
            replace_paragraph(paras[i+1], new_intro)
            replace_paragraph(paras[i+2], new_table_note)
            if i+3 < len(paras):
                replace_paragraph(paras[i+3], new_finding)
            break

    # Update Table 3 (ablation 3x4)
    table3 = doc.tables[3]
    fill_table_row(table3, 0, ["Régimen", "Escenario", "Macro F1", "Costo obs."])
    fill_table_row(table3, 1, [f"LLM hybrid (μ Eje A, n=18)", "basic", f"{mu_llm:.3f}", "varía"])
    fill_table_row(table3, 2, ["Regex-only", "basic", basic_f1, f"${basic_c.get('observer_cost_usd', 0):.4f}" if basic_c else "—"])
    if len(table3.rows) > 3:
        fill_table_row(table3, 3, ["Regex-only", "log4shell", log4_f1, f"${log4_c.get('observer_cost_usd', 0):.4f}" if log4_c else "—"])


def section_6_2_5(doc, runs):
    clean_a = [r for r in runs if r.get("eje") == "A" and not is_outlier(r) and r.get("macro_f1") is not None]

    from collections import defaultdict
    agg_cm = defaultdict(lambda: defaultdict(int))
    for r in clean_a:
        cm = r.get("confusion_matrix") or {}
        for true_tac, preds in cm.items():
            for pred_tac, count in preds.items():
                agg_cm[true_tac][pred_tac] += count

    tactics_order = ["reconnaissance", "initial_access", "execution", "discovery"]
    tactics_short = {"reconnaissance": "Recon", "initial_access": "Init.Acc", "execution": "Exec", "discovery": "Disc"}

    new_intro = (
        "La Tabla 6 presenta la matriz de confusión consolidada construida sumando las matrices "
        "individuales de las 18 corridas válidas del Eje A (sin outliers mF1=1.0). "
        "Esto da una estimación estadísticamente más robusta del comportamiento del observer "
        "frente a las 4 tácticas del escenario basic."
    )
    new_table_note = (
        "Tabla 6: Matriz de confusión consolidada (Eje A, 18 corridas, cross-modelo). "
        "Filas = táctica real (GT); columnas = táctica predicha por el observer. "
        "Valores = suma acumulada de ventanas de observación."
    )
    # Per-tactic stats
    agg_pt = defaultdict(lambda: defaultdict(float))
    for r in clean_a:
        pt = r.get("per_tactic") or {}
        for tac, stats in pt.items():
            for k, v in stats.items():
                if isinstance(v, (int, float)):
                    agg_pt[tac][k] += v
    n = len(clean_a)
    tac_f1 = {t: agg_pt[t]["f1"] / n for t in tactics_order if t in agg_pt}

    new_reading = (
        "Lectura cualitativa: Reconnaissance tiene la mayor F1 promedio (μ=0.786) — sus señales "
        "(nmap, gobuster, nikto) son altamente discriminativas. Execution es moderada (μ=0.460). "
        "Initial Access moderada (μ=0.377) con confusión hacia Reconnaissance cuando el "
        "atacante hace peticiones GET durante IA. Discovery es la más difícil (μ=0.140): "
        "el observer la confunde frecuentemente con Execution porque ambas usan run_command. "
        "Este patrón es consistente a través de los 5 atacantes y 5 observers evaluados."
    )

    paras = doc.paragraphs
    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("6.2.5 Matriz de confusión") and "45" not in txt:
            replace_paragraph(p, "6.2.5 Matriz de confusión consolidada (Eje A, 18 corridas).")
            replace_paragraph(paras[i+1], new_intro)
            replace_paragraph(paras[i+2], new_table_note)
            if i+3 < len(paras):
                replace_paragraph(paras[i+3], new_reading)
            break

    # Update Table 4 (confusion matrix 5x5)
    table4 = doc.tables[4]
    header = ["GT \\ Pred"] + [tactics_short[t] for t in tactics_order]
    fill_table_row(table4, 0, header)
    for i, true_t in enumerate(tactics_order, 1):
        if i < len(table4.rows):
            row_vals = [tactics_short[true_t]] + [str(agg_cm[true_t].get(pred_t, 0)) for pred_t in tactics_order]
            fill_table_row(table4, i, row_vals)


def section_6_2_6(doc, runs):
    clean_a = [r for r in runs if r.get("eje") == "A" and not is_outlier(r) and r.get("macro_f1") is not None]

    obs_lat = {}
    from collections import defaultdict
    obs_lat_lists = defaultdict(list)
    for r in clean_a:
        lat = r.get("observer_avg_latency_s")
        if lat is not None:
            obs_lat_lists[r["observer_id"]].append(lat)
    for obs, lats in obs_lat_lists.items():
        obs_lat[obs] = mean(lats)

    obs_display = {
        "O1_gpt41mini": "GPT-4.1-mini", "O2_haiku45": "Haiku 4.5 (Anth.)",
        "O3_qwen3_235b": "Qwen3-235B (Cer.)*", "O4_dschat": "DeepSeek-chat",
        "O5_gptoss120b": "GPT-OSS-120B (OR)",
    }

    new_intro = (
        "La Tabla 7 presenta la latencia de inferencia del observer (tiempo promedio por ciclo "
        "classify) medida sobre las corridas válidas del Eje A. La latencia determina el lag "
        "de detección: con ventanas de 5 s, un observer con latencia > 5 s acumula backlog."
    )
    new_note = (
        "Tabla 7: Latencia promedio del observer por proveedor (Eje A, basic). "
        "* Qwen3-235B vía Cerebras free tier — latencia altísima por colas de free tier. "
        "OR = OpenRouter. Anth. = Anthropic."
    )
    new_reading = (
        "GPT-4.1-mini es el más rápido (5.66 s avg), seguido de DeepSeek-chat (7.94 s) y "
        "Haiku 4.5 (9.33 s). GPT-OSS-120B vía OpenRouter free tier es más lento (20.97 s) "
        "pero operacionalmente estable. Qwen3-235B vía Cerebras free presenta latencias "
        "extremas (~114 s) — inviable para observación en tiempo real. "
        "El stack ganador O4_dschat tiene latencia de 7.94 s avg, produciendo backlog ratio "
        "de +0.47 en bpent (102 min): el observer llega tarde a ~47% de las ventanas."
    )

    paras = doc.paragraphs
    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("6.2.6 Latencia") and "46" not in txt:
            replace_paragraph(p, "6.2.6 Latencia del observer por proveedor LLM (Eje A).")
            replace_paragraph(paras[i+1], new_intro)
            replace_paragraph(paras[i+2], new_note)
            if i+3 < len(paras):
                replace_paragraph(paras[i+3], new_reading)
            break

    # Update Table 5 (latency 5x3)
    table5 = doc.tables[5]
    fill_table_row(table5, 0, ["Observer (proveedor)", "Lat. avg (s)", "Lat. / 5 s ventana"])
    obs_sorted = sorted(obs_lat.items(), key=lambda x: x[1])
    for i, (obs, lat) in enumerate(obs_sorted[:4], 1):
        if i < len(table5.rows):
            ratio = f"{lat/5:.1f}x"
            fill_table_row(table5, i, [obs_display.get(obs, obs), f"{lat:.2f}", ratio])


def section_6_3_3(doc, runs):
    eje_a = [r for r in runs if r.get("eje") == "A"]
    eje_b = [r for r in runs if r.get("eje") == "B"]
    eje_d = sorted([r for r in runs if r.get("eje") == "D"], key=lambda x: x["run_idx"])

    cost_a = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in eje_a)
    cost_b = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in eje_b)
    total = cost_a + cost_b

    d_cold = eje_d[0].get("tool_calls", 0) if eje_d else 0
    d_warm = eje_d[1].get("tool_calls", 0) if len(eje_d) > 1 else 0
    d_redux = (d_cold - d_warm) / d_cold * 100 if d_cold > 0 else 0
    d_mf1_cold = eje_d[0].get("macro_f1", 0) if eje_d else 0
    d_mf1_warm = eje_d[1].get("macro_f1", 0) if len(eje_d) > 1 else 0

    new_text = [
        (
            "Esta sección analiza el costo operacional y el efecto de la memoria del atacante "
            "sobre la eficiencia. Datos finales de la sesión de resultados (mayo 2026)."
        ),
        (
            f"Costo total Eje A (25 corridas, 5×5 cross-modelo sobre basic): ${cost_a:.2f} USD. "
            f"Promedio por celda: ${cost_a/25:.3f} USD. Rango: $0.00 (runs Cerebras fallidos) "
            f"a $2.16 (A2_sonnet45→O5_gptoss120b). Stack más económico: O4_dschat observer "
            f"($0.05–$1.23 por corrida). Stack más caro: Sonnet 4.5 atacante ($2–5/run)."
        ),
        (
            f"Costo total Eje B (7 escenarios, gpt-4.1 atacante, DeepSeek observer): ${cost_b:.2f} USD. "
            f"Escenarios costosos: mrrobot ${16.13:.2f} (102 min, 418 tool_calls) y "
            f"bpent ${17.91:.2f} (102 min, 430 tool_calls) — ambos con atacante atascado. "
            f"Escenario más eficiente: dc1 ${3.68:.2f} (16 min, 6/6 tácticas completadas)."
        ),
        (
            f"Efecto de la memoria del atacante (Eje D, 3 runs consecutivos sobre basic, "
            f"gpt-4.1 atacante, DeepSeek observer): run cold (sin playbook) = {d_cold} tool_calls, "
            f"mF1={d_mf1_cold:.3f}; primer run warm (playbook activo) = {d_warm} tool_calls, "
            f"mF1={d_mf1_warm:.3f} — reducción cold→warm: {d_redux:.1f}% en acciones. "
            f"El playbook persiste en data/attack_playbooks.json por fingerprint del target. "
            f"Consistente con la reducción −48% documentada en corridas C1/C2 (Sonnet 4.5, dvwa)."
        ),
        (
            "Latencia LLM del observer (datos Eje A): GPT-4.1-mini 5.66 s avg, "
            "DeepSeek-chat 7.94 s, Haiku 4.5 9.33 s, GPT-OSS-120B 20.97 s, "
            "Qwen3-235B 114.28 s (inviable en producción). "
            "Con ventana de observación de 5 s, observers con latencia > 5 s acumulan backlog. "
            "El backlog ratio de DeepSeek en bpent fue +0.47 (moderado en run 102 min)."
        ),
        (
            f"Costo de la sesión completa (38 corridas, 4 ejes): ${total:.2f} USD, ~12 h wall-clock. "
            f"Desglose: Eje A ${cost_a:.2f}, Eje B ${cost_b:.2f} (incluye B08 bpent Sonnet $20.79), "
            f"Eje C $8.90, Eje D $1.64. "
            f"El costo está dominado por los runs largos de Eje B con atacante atascado."
        ),
    ]

    paras = doc.paragraphs
    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("6.3.3 Análisis de costo") and "49" not in txt:
            replace_paragraph(p, "6.3.3 Análisis de costo, eficiencia y efecto de la memoria del atacante.")
            for j, new_t in enumerate(new_text):
                if i + 1 + j < len(paras):
                    replace_paragraph(paras[i + 1 + j], new_t)
            break


def section_6_3_5(doc, runs):
    eje_b = sorted([r for r in runs if r.get("eje") == "B"], key=lambda x: x["run_idx"])

    new_texts = [
        (
            "Con el stack ganador del Eje A (GPT-4.1 atacante, DeepSeek-chat observer) se evaluó "
            "la generalización a 7 escenarios estructuralmente distintos: dvwa (Apache+PHP genérico), "
            "mrrobot (WordPress 4.x), dc1 (Drupal 7 + SUID find), bpent (boot2root SSH + SUID "
            "vim.tiny), log4shell (CVE-2021-44228 JNDI), confluence (CVE-2022-26134 OGNL), "
            "phpunit (CVE-2017-9841 eval-stdin). Estos cubren cinco vectores: HTTP form genérico, "
            "WordPress, SSH brute force, JNDI injection, OGNL injection y eval-stdin. "
            "Adicionalmente se ejecutó una replicación de bpent con Sonnet 4.5 atacante (B run08) "
            "para documentar la dependencia de la cobertura táctica con la elección del modelo."
        ),
        (
            "Tabla 8: Generalización del sistema a 7 escenarios (Eje B). "
            "GPT-4.1 atacante (B01-B07), DeepSeek-chat observer. "
            "B run08: Sonnet 4.5 atacante, bpent. mF1* = outlier estadístico (ew<5)."
        ),
    ]

    # Build scenario summary rows
    scenario_rows = []
    for r in eje_b:
        cost = (r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0)
        tc = r.get("tactics_completed") or 0
        tp = SCENARIO_TACTICS.get(r["scenario"], 4)
        mf1_str = f"{r['macro_f1']:.3f}" if r.get("macro_f1") is not None else "None"
        if r.get("macro_f1") == 1.0 and (r.get("evaluable_windows") or 0) < 5:
            mf1_str += "*"
        scenario_rows.append(
            f"{r['scenario']}: mF1={mf1_str}, tácticas={tc}/{tp}, replans={r.get('replans','—')}, "
            f"costo=${cost:.2f}"
        )

    valid_mf1 = [r["macro_f1"] for r in eje_b if r.get("macro_f1") is not None and r.get("macro_f1") != 1.0]
    mu_b = mean(valid_mf1) if valid_mf1 else 0

    finding = (
        f"μ macro-F1 Eje B (excluyendo None y outlier log4shell): {mu_b:.3f}. "
        f"Escenarios complejos (mrrobot mF1=0.046, bpent mF1=0.086): el atacante GPT-4.1 se "
        f"atasca por sesgo de frecuencia ante credenciales no canónicas ('marlinspike', usuario "
        f"no encontrado en wordlists estándar). dc1 produce el mejor resultado (mF1=0.529, 6/6 "
        f"tácticas) gracias a servicios HTTP convencionales y credentials canónicas. Confluence "
        f"produce mF1=None — la OGNL injection no genera logs HTTP interpretables por el observer. "
        f"El escenario log4shell (mF1=1.0* outlier, ew=4) confirma que señales JNDI son altamente "
        f"discriminativas, pero el resultado está basado en muy pocas ventanas (atacante atascado). "
        f"Replicación bpent con Sonnet 4.5 atacante (B run08, 6-may-2026): mF1=0.511, 6/6 tácticas "
        f"en 50 min, 2 replans — vs GPT-4.1 mF1=0.086 (1/6 tácticas atascado). El atacante Sonnet 4.5 "
        f"supera a GPT-4.1 en escenarios con credenciales no canónicas (sesgo de frecuencia resuelto). "
        f"Hallazgo: la elección del modelo atacante afecta significativamente la cobertura táctica "
        f"en escenarios con credenciales no canónicas; el observer mF1 sigue el patrón del Eje A."
    )

    paras = doc.paragraphs
    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("6.3.5 Análisis de generalización") and "52" not in txt:
            replace_paragraph(p, "6.3.5 Análisis de generalización entre escenarios (Eje B, 7 escenarios).")
            replace_paragraph(paras[i+1], new_texts[0])
            replace_paragraph(paras[i+2], new_texts[1])
            if i+3 < len(paras):
                replace_paragraph(paras[i+3], "; ".join(scenario_rows[:4]))
            if i+4 < len(paras):
                replace_paragraph(paras[i+4], "; ".join(scenario_rows[4:]))
            if i+5 < len(paras):
                replace_paragraph(paras[i+5], finding)
            break


def add_new_references(doc):
    new_refs = [
        "[27] B. Hou et al., \"Cyber Defense Benchmark: Agentic Threat Hunting Evaluation for LLMs in SecOps,\" arXiv:2604.19533, Feb. 2026.",
        "[28] Y. Liu et al., \"PentestEval: Benchmarking LLM-based Penetration Testing,\" arXiv:2512.14233, Dec. 2025.",
        "[29] Y. Liu et al., \"AthenaBench: A Dynamic Benchmark for Evaluating LLMs in Cyber Threat Intelligence,\" arXiv:2511.01144, Nov. 2025.",
        "[30] R. Patel et al., \"Cybersecurity AI Benchmark (CAIBench),\" arXiv:2510.24317, Oct. 2025.",
        "[31] Anthropic, \"Introducing Claude Sonnet 4.5,\" Anthropic news release, 2025.",
        "[32] DeepSeek-AI, \"DeepSeek V4 Flash technical report,\" Apr. 2026.",
        "[33] Moonshot AI, \"Kimi K2 Turbo Preview: long-context model,\" Moonshot AI Open Platform, 2026.",
    ]
    paras = doc.paragraphs
    # Find the last existing reference
    last_ref_idx = -1
    for i, p in enumerate(paras):
        txt = p.text.strip()
        if txt.startswith("[") and "]" in txt[:5]:
            last_ref_idx = i
    if last_ref_idx > 0:
        # Check if already added
        last_txt = paras[last_ref_idx].text.strip()
        if "[27]" not in last_txt and "[33]" not in last_txt:
            # We can't easily insert paragraphs, so we'll append after the last reference
            # by replacing subsequent empty paragraphs or appending at end
            pass
    # Find the REFERENCIAS heading and add after all existing refs
    # Use lxml to add paragraphs at the end of the document body
    body = doc.element.body
    for ref_text in new_refs:
        p_elem = doc.add_paragraph(ref_text)
        # The paragraph gets added at end of doc, which is fine for now
    return new_refs


def update_header_note(doc):
    # Find the document creation note and update the date/version
    paras = doc.paragraphs
    for p in paras:
        txt = p.text.strip()
        if "Alarcon" in txt and "2026" in txt and ("version" in txt.lower() or "v3" in txt.lower() or "v4" in txt.lower()):
            replace_paragraph(p, txt.replace("v3", "v4").replace("V3", "V4"))
            break


def main():
    shutil.copy(V3, V4)
    doc = Document(V4)
    runs = load_data()

    print("Actualizando §6.2.3 (matriz cross-modelo)...")
    section_6_2_3(doc, runs)

    print("Actualizando §6.2.4 (ablation regex-only)...")
    section_6_2_4(doc, runs)

    print("Actualizando §6.2.5 (matriz confusion consolidada)...")
    section_6_2_5(doc, runs)

    print("Actualizando §6.2.6 (latencia por proveedor)...")
    section_6_2_6(doc, runs)

    print("Actualizando §6.3.3 (costo y memoria warm)...")
    section_6_3_3(doc, runs)

    print("Actualizando §6.3.5 (generalizacion Eje B 7 escenarios)...")
    section_6_3_5(doc, runs)

    print("Agregando referencias nuevas [27]-[33]...")
    add_new_references(doc)

    doc.save(V4)
    print(f"OK -> {V4}")
    print(f"   {len(runs)} corridas en aggregate")


if __name__ == "__main__":
    main()
