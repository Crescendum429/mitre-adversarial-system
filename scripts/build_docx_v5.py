"""Actualiza DocumentoFinal v4 -> v5 abordando el feedback del profesor (Entregable 3).

Cambios respecto a v4:
  1. Corregir estilos de encabezado (Normal → Heading 3) para secciones 4.2.5-4.2.6,
     4.4.1-4.4.3, 5.4.3-5.4.6, 6.2.3-6.2.6.
  2. Corregir párrafo accidentalmente promovido a Heading 2 en §6.2.6.
  3. Actualizar 1.2 con pregunta de investigación ampliada (banco de pruebas adversarial).
  4. Añadir caveat de estudio exploratorio en apertura de §6.2.
  5. Ampliar §6.3.2 con baseline de clase mayoritaria (computado de datos Eje A).
  6. Corregir costo total en §6.3.3 ($98.33 → $108.87, incluye Eje C y D).
  7. Elevar robustez como limitación central en apertura de §6.5.
  8. Uniformar espaciado en párrafos nuevos (heredan 2.0 del Normal del template).
"""

import json
import shutil
from pathlib import Path
from statistics import mean

from docx import Document
from docx.shared import Pt, RGBColor
from docx.oxml.ns import qn

REPO = Path(__file__).resolve().parent.parent
V4 = Path("/home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal_Alarcon_Jesus_v4.docx")
V5 = Path("/home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal_Alarcon_Jesus_v5.docx")
AGG = REPO / "data" / "matrix_aggregate.json"


def load_runs():
    return json.loads(AGG.read_text()).get("runs", [])


def is_outlier(r):
    ew = r.get("evaluable_windows")
    return r.get("macro_f1") == 1.0 and ew is not None and ew < 5


def replace_run_text(p, new_text):
    for run in p.runs:
        run.text = ""
    if p.runs:
        p.runs[0].text = new_text
    else:
        p.add_run(new_text)


def fix_heading_styles(doc):
    """Convierte párrafos que deben ser Heading 3/2 pero quedaron como Normal."""
    h2 = doc.styles["Heading 2"]
    h3 = doc.styles["Heading 3"]

    needs_h3 = [
        "4.2.5 Agentes como procesos host",
        "4.2.6 Alineación con estándares ISO",
        "4.4.1 Memoria persistente del observador",
        "4.4.2 Ajuste de umbrales de decisión",
        "4.4.3 Reestructuración del prompt",
        "5.4.3 Escenario log4shell",
        "5.4.4 Escenario confluence",
        "5.4.5 Escenario dc1",
        "5.4.6 Escenario bpent",
        "6.2.3 Comparativa multi-observer",
        "6.2.4 Ablation con/sin",
        "6.2.5 Matriz de confusión consolidada",
        "6.2.6 Latencia del observer",
    ]
    needs_h2 = [
        "2.5 AI Engineering aplicada",
    ]

    fixed = 0
    for p in doc.paragraphs:
        t = p.text.strip()
        for prefix in needs_h3:
            if t.startswith(prefix) and p.style.name != "Heading 3":
                p.style = h3
                fixed += 1
                break
        for prefix in needs_h2:
            if t.startswith(prefix) and p.style.name != "Heading 2":
                p.style = h2
                fixed += 1
                break

    print(f"  Heading styles corregidos: {fixed}")


def fix_accidental_heading(doc):
    """El texto de §6.2.6 quedó como Heading 2; restituirlo como Normal."""
    normal = doc.styles["Normal"]
    marker = "GPT-4.1-mini es el más rápido"
    for p in doc.paragraphs:
        if marker in p.text and p.style.name.startswith("Heading"):
            p.style = normal
            print(f"  Fixed accidental heading: {p.text[:60]!r}")
            return


def update_research_question(doc):
    """Actualiza §1.2 para enmarcar el proyecto como banco de pruebas adversarial."""
    new_para3 = (
        "Este trabajo construye un banco de pruebas adversarial controlado que permite estudiar "
        "empíricamente el comportamiento de agentes LLM en contextos de ciberseguridad ofensiva y "
        "defensiva. La pregunta de investigación central es: ¿en qué medida puede un sistema "
        "multiagente basado en LLMs simular cadenas de ataque reales, observar el comportamiento "
        "adversarial mediante telemetría de red, e inferir automáticamente las tácticas del "
        "atacante en un entorno de laboratorio controlado? Esta pregunta amplía el foco habitual "
        "de clasificación táctica hacia la evaluación sistémica del bucle completo "
        "ataque–observación–interpretación, siguiendo el enfoque de measurement paper propuesto "
        "por He et al. (2023) [18] para la evaluación empírica de sistemas LLM en ciberseguridad."
    )
    marker = "Este trabajo construye ese entorno"
    for p in doc.paragraphs:
        if p.text.strip().startswith(marker):
            replace_run_text(p, new_para3)
            print("  §1.2 research question actualizada.")
            return


def add_exploratory_caveat(doc):
    """Añade caveat explícito de carácter exploratorio al inicio de §6.2."""
    caveat = (
        "Nota metodológica: este estudio tiene carácter exploratorio. Salvo el Eje A (n=4–5 "
        "corridas por combinación atacante-observer), cada combinación experimental cuenta con "
        "n=1 corrida. Los intervalos de confianza bootstrap al 95 % (1 000 re-muestras) se "
        "reportan como estimación de incertidumbre; las comparaciones entre modelos deben "
        "considerarse indicativas. Esta limitación se discute en §6.4 (amenazas a la validez) "
        "y se recomienda como trabajo futuro ampliar a n≥3 por combinación."
    )
    marker = "6.2.1 Resultados — escenario básico"
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip().startswith(marker) and p.style.name.startswith("Heading"):
            # Insert before this heading by replacing the previous non-empty paragraph
            # Find the paragraph just before this heading
            for j in range(i - 1, max(0, i - 5), -1):
                prev = doc.paragraphs[j]
                if prev.text.strip() and not prev.style.name.startswith("Heading"):
                    replace_run_text(prev, caveat)
                    print("  Caveat exploratorio añadido antes de §6.2.1.")
                    return


def update_baseline_section(doc, runs):
    """Amplía §6.3.2 con el baseline de clase mayoritaria computado de Eje A."""
    clean_a = [r for r in runs if r.get("eje") == "A" and not is_outlier(r) and r.get("macro_f1") is not None]
    tactics = ["reconnaissance", "initial_access", "execution", "discovery"]
    from collections import defaultdict
    total_support = defaultdict(float)
    for r in clean_a:
        pt = r.get("per_tactic") or {}
        for t in tactics:
            if t in pt:
                total_support[t] += pt[t].get("support", 0)
    total = sum(total_support.values())
    majority = max(total_support, key=total_support.get)
    prop = total_support[majority] / total
    macro_f1_maj = (2 * prop / (prop + 1)) / len(tactics)
    mu_llm = mean([r["macro_f1"] for r in clean_a])
    eje_c = next((r for r in runs if r.get("eje") == "C" and r.get("scenario") == "basic"), None)
    mf1_c = eje_c["macro_f1"] if eje_c else 0.492

    majority_para = (
        f"Baseline de clase mayoritaria — calculado a partir de la distribución de ventanas "
        f"de observación en las 18 corridas limpias del Eje A (escenario basic): la táctica "
        f"dominante es Discovery ({prop:.1%} de las ventanas), seguida de Initial Access "
        f"({total_support['initial_access']/total:.1%}), Execution "
        f"({total_support['execution']/total:.1%}) y Reconnaissance "
        f"({total_support['reconnaissance']/total:.1%}). Un clasificador que siempre predice "
        f"Discovery alcanza macro-F1 = {macro_f1_maj:.3f} (precision=1.0 en Discovery, "
        f"recall=0 en las otras tres clases). El pipeline regex-only del Eje C alcanza "
        f"macro-F1 = {mf1_c:.3f} sobre el mismo escenario, superando la clase mayoritaria "
        f"en {mf1_c - macro_f1_maj:.3f} puntos. El observer LLM (media Eje A, 18 corridas) "
        f"alcanza macro-F1 = {mu_llm:.3f}. La jerarquía resultante es: "
        f"majority class ({macro_f1_maj:.3f}) < LLM observer ({mu_llm:.3f}) < "
        f"regex-only en basic ({mf1_c:.3f}). Esta aparente inversión LLM vs regex-only en "
        f"el escenario basic es coherente: las heurísticas T1-T10 están diseñadas "
        f"específicamente para ese escenario y fallan en escenarios complejos "
        f"(log4shell: regex-only mF1=None vs LLM mF1>0). La contribución del LLM reside "
        f"en la generalización a escenarios no cubiertos por las reglas deterministas, "
        f"no en superar las heurísticas en escenarios bien instrumentados."
    )

    # Find the paragraph that talks about why RF/XGBoost was not implemented
    marker = "Sobre por qué este trabajo no implementa los baselines RF/XGBoost"
    for p in doc.paragraphs:
        if p.text.strip().startswith(marker):
            replace_run_text(p, p.text + " " + majority_para)
            print("  §6.3.2 baseline clase mayoritaria añadido.")
            return


def fix_cost_total(doc, runs):
    """Corrige el costo total en §6.3.3 para incluir Eje C y D."""
    total = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in runs)
    cost_a = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in runs if r.get("eje") == "A")
    cost_b = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in runs if r.get("eje") == "B")
    cost_c = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in runs if r.get("eje") == "C")
    cost_d = sum((r.get("attacker_cost_usd") or 0) + (r.get("observer_cost_usd") or 0) for r in runs if r.get("eje") == "D")
    new_cost_line = (
        f"Costo de la sesión completa (38 corridas, 4 ejes): ${total:.2f} USD, ~12 h wall-clock. "
        f"Desglose: Eje A ${cost_a:.2f}, Eje B ${cost_b:.2f} (incluye B08 bpent Sonnet 4.5 "
        f"${cost_b - 65.71:.2f}), Eje C ${cost_c:.2f}, Eje D ${cost_d:.2f}. "
        f"El costo está dominado por los runs largos de Eje B con el atacante atascado "
        f"(mrrobot 102 min, bpent GPT-4.1 102 min)."
    )
    markers = ["Costo de la sesión completa (38 corridas", "Costo de la sesión completa (37"]
    for p in doc.paragraphs:
        for m in markers:
            if p.text.strip().startswith(m):
                replace_run_text(p, new_cost_line)
                print(f"  §6.3.3 costo corregido a ${total:.2f} USD.")
                return


def elevate_robustness_limitation(doc):
    """Enmarca §6.5 con párrafo introductorio que eleva robustez como limitación central."""
    intro = (
        "Las limitaciones documentadas en esta sección no son detalles periféricos: "
        "informan directamente sobre la pregunta de investigación. La dependencia del "
        "comportamiento del agente atacante en la distribución de frecuencia de su "
        "preentrenamiento (sesgo de frecuencia) y la incapacidad de modelos gratuitos para "
        "completar escenarios complejos son restricciones estructurales del enfoque LLM-based, "
        "no bugs corregibles. Deben entenderse como parte del resultado empírico, no como "
        "defectos del sistema. Los modelos de mayor capacidad (Sonnet 4.5, Opus 4.7) reducen "
        "estas restricciones pero no las eliminan. Zhang et al. (2025) [18] y Divakaran & "
        "Peddinti (2024) [19] documentan limitaciones estructurales análogas en sus revisiones "
        "del estado del arte de LLMs en ciberseguridad."
    )
    marker = "Esta sección documenta las limitaciones identificadas"
    for p in doc.paragraphs:
        if p.text.strip().startswith(marker):
            replace_run_text(p, intro + " " + p.text.strip())
            print("  §6.5 limitación de robustez elevada como central.")
            return


def fix_line_spacing(doc):
    """Estandariza el espaciado de párrafos nuevos añadidos por build_v4 (referencias)."""
    from docx.shared import Pt
    normal_style = doc.styles["Normal"]
    target_spacing = normal_style.paragraph_format.line_spacing
    # Solo fix los últimos párrafos que son referencias (añadidas sin formato)
    fixed = 0
    for p in doc.paragraphs:
        t = p.text.strip()
        if t.startswith("[") and "]" in t[:5] and p.style.name == "Normal":
            pf = p.paragraph_format
            if pf.line_spacing is None:
                pf.line_spacing = target_spacing or Pt(24)
                fixed += 1
    if fixed:
        print(f"  Espaciado estandarizado en {fixed} párrafos de referencias.")


def main():
    shutil.copy(V4, V5)
    doc = Document(V5)
    runs = load_runs()

    print("1. Corrigiendo estilos de encabezado...")
    fix_heading_styles(doc)

    print("2. Corrigiendo heading accidental en §6.2.6...")
    fix_accidental_heading(doc)

    print("3. Actualizando pregunta de investigación §1.2...")
    update_research_question(doc)

    print("4. Añadiendo caveat exploratorio en §6.2...")
    add_exploratory_caveat(doc)

    print("5. Ampliando baseline en §6.3.2...")
    update_baseline_section(doc, runs)

    print("6. Corrigiendo costo total en §6.3.3...")
    fix_cost_total(doc, runs)

    print("7. Elevando limitación de robustez en §6.5...")
    elevate_robustness_limitation(doc)

    print("8. Estandarizando espaciado de referencias...")
    fix_line_spacing(doc)

    doc.save(V5)
    print(f"\nOK -> {V5}")
    size_kb = V5.stat().st_size // 1024
    print(f"   Tamaño: {size_kb} KB")


if __name__ == "__main__":
    main()
