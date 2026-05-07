"""Elimina todas las menciones de costos del documento final.

El usuario indica que la mayoria de cifras de costo son incorrectas
(diferencias entre tarifas vigentes vs facturadas, redondeos, etc.).
Estrategia: omitir toda la informacion economica y reformular las
secciones afectadas para enfocarse en wall-clock, tool_calls y mF1.

Conserva el termino tecnico "cost-sensitive" (Elkan 2001) que no es un
numero sino un marco conceptual de classification con costos asimetricos.
"""

from copy import deepcopy
from pathlib import Path

from docx import Document

FINAL = Path("/home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal-ProyectoIntegrador-Alarcon.docx")


def replace_run_text(p, new_text):
    for run in p.runs:
        run.text = ""
    if p.runs:
        p.runs[0].text = new_text
    else:
        p.add_run(new_text)


def find_p(doc, predicate, label=""):
    for p in doc.paragraphs:
        if predicate(p):
            return p
    print(f"  [WARN] no se encontro: {label}")
    return None


# ---------------------------------------------------------------------------
# 1. Renombrar §6.3.3 (heading + TOC)
# ---------------------------------------------------------------------------

NUEVO_HEADING_633 = "6.3.3 Análisis de eficiencia y efecto de la memoria del atacante."

def fix_633_heading(doc):
    # Cuerpo (heading)
    for p in doc.paragraphs:
        if p.text.strip() == "6.3.3 Análisis de costo, eficiencia y efecto de la memoria del atacante.":
            replace_run_text(p, NUEVO_HEADING_633)
            print("  Heading §6.3.3 renombrado.")
            break
    # TOC entry
    for p in doc.paragraphs:
        if "6.3.3 Análisis de costo, latencia y throughput" in p.text or \
           "6.3.3 Análisis de costo" in p.text:
            new_text = p.text.replace(
                "6.3.3 Análisis de costo, latencia y throughput",
                "6.3.3 Análisis de eficiencia y memoria del atacante",
            ).replace(
                "6.3.3 Análisis de costo, eficiencia y efecto de la memoria del atacante",
                "6.3.3 Análisis de eficiencia y memoria del atacante",
            )
            replace_run_text(p, new_text)
            print("  TOC §6.3.3 renombrado.")


# ---------------------------------------------------------------------------
# 2. Reemplazar §6.3.3 contenido (5 parrafos consecutivos)
# ---------------------------------------------------------------------------

NUEVA_SEC_633_INTRO = (
    "Esta sección analiza la eficiencia operacional del sistema y el "
    "efecto de la memoria del atacante sobre el número de acciones "
    "necesarias para completar las cadenas de ataque. Datos finales "
    "de la sesión de resultados (mayo 2026)."
)

NUEVA_SEC_633_EJE_A = (
    "Eje A (25 corridas, 5×5 cross-modelo sobre basic): wall-clock "
    "agregado de 37 min sobre las 25 corridas; el subset de 19 "
    "corridas válidas concentra la mayor parte del tiempo. El stack "
    "operacional ganador (GPT-4.1 atacante + DeepSeek-chat observer) "
    "completa una corrida sobre basic en 1-2 min wall-clock con 4/4 "
    "tácticas."
)

NUEVA_SEC_633_EJE_B = (
    "Eje B (7 escenarios, GPT-4.1 atacante, DeepSeek observer): los "
    "escenarios donde el atacante se atasca en Initial Access "
    "(mrrobot 102 min, 418 tool_calls; bpent-GPT4.1 102 min, 430 "
    "tool_calls) consumen aproximadamente un orden de magnitud más "
    "wall-clock y tool_calls que los escenarios donde el atacante "
    "completa la cadena (dc1 16 min, 6/6 tácticas, 47 tool_calls). "
    "Esta asimetría es coherente con la limitación de frequency bias "
    "documentada en §6.5: los runs de scope condition no solo fallan "
    "en la métrica del observer, sino que también son los más "
    "costosos en eficiencia."
)

NUEVA_SEC_633_EJE_D = (
    "Efecto de la memoria sobre el atacante y el observer (Eje D): "
    "tres corridas consecutivas sobre basic, GPT-4.1 atacante, "
    "DeepSeek observer, sin reset de memoria entre runs. D1 (cold, "
    "sin playbook): 19 tool_calls, 0 replans, mF1=0,425. D2 (warm, "
    "playbook activo): 13 tool_calls, 0 replans, mF1=0,518. D3 "
    "(warm + prior bayesiano acumulado): 38 tool_calls, 4 replans, "
    "mF1=0,552. Efecto sobre el atacante: cold→warm D1→D2 muestra "
    "reducción del 31,6 % en acciones (19→13 tool_calls), coherente "
    "con la reducción −48 % en corridas Sonnet 4.5/dvwa (Eje C). El "
    "incremento en D3 (13→38 tool_calls, +4 replans) no contradice "
    "este patrón: con el playbook disponible, el atacante prueba "
    "hipótesis adicionales en lugar de resignarse al primer intento, "
    "lo que incrementa el cómputo pero también el mF1. Efecto sobre "
    "el observer: la mF1 mejora monotónicamente entre corridas "
    "(0,425→0,518→0,552, +29,9 % acumulado sobre cold), atribuible a "
    "la acumulación del prior bayesiano en data/observer_baselines.json "
    "que ajusta los umbrales de confianza adaptativos hacia la "
    "distribución empírica del target."
)

NUEVA_SEC_633_TOTAL = (
    "Sesión completa (38 corridas, 4 ejes): aproximadamente 12 h de "
    "wall-clock acumulado, dominado por los runs largos del Eje B con "
    "el atacante atascado (mrrobot y bpent con GPT-4.1 GBU, ~102 min "
    "cada uno). Los reportes individuales en data/reports/*.json "
    "incluyen el desglose de tokens consumidos por agente y "
    "proveedor para extrapolación operacional posterior."
)


def fix_633_content(doc):
    # P305 — intro
    p = find_p(doc, lambda p: p.text.startswith("Esta sección analiza el costo operacional"), "[305]")
    if p:
        replace_run_text(p, NUEVA_SEC_633_INTRO)
        print("  §6.3.3 [305] intro reformulada (sin costos).")

    # P306 — Eje A
    p = find_p(doc, lambda p: p.text.startswith("Costo total Eje A (25 corridas, 5×5 cross-modelo sobre basic)"), "[306]")
    if p:
        replace_run_text(p, NUEVA_SEC_633_EJE_A)
        print("  §6.3.3 [306] Eje A reformulado (wall-clock).")

    # P307 — Eje B
    p = find_p(doc, lambda p: p.text.startswith("Costo total Eje B (7 escenarios, gpt-4.1 atacante"), "[307]")
    if p:
        replace_run_text(p, NUEVA_SEC_633_EJE_B)
        print("  §6.3.3 [307] Eje B reformulado (eficiencia, no costo).")

    # P308 — Eje D
    p = find_p(doc, lambda p: p.text.startswith("Efecto de la memoria sobre el atacante y el observer (Eje D)"), "[308]")
    if p:
        replace_run_text(p, NUEVA_SEC_633_EJE_D)
        print("  §6.3.3 [308] Eje D sin costos.")

    # P310 — total
    p = find_p(doc, lambda p: p.text.startswith("Costo de la sesión completa (38 corridas, 4 ejes)"), "[310]")
    if p:
        replace_run_text(p, NUEVA_SEC_633_TOTAL)
        print("  §6.3.3 [310] sesión completa sin costos.")

    # P312 — extrapolación tokens (eliminar)
    p = find_p(doc, lambda p: p.text.startswith("Para extrapolación de costos a escala"), "[312]")
    if p:
        replace_run_text(
            p,
            "Para extrapolación operacional, los reportes individuales en "
            "data/reports/*.json incluyen desglose de tokens y de wall-clock "
            "por agente; el observer DeepSeek-chat consume aproximadamente "
            "100-175 K tokens por corrida según escenario.",
        )
        print("  §6.3.3 [312] extrapolación tokens reformulada.")


# ---------------------------------------------------------------------------
# 3. §6.2.3 [279] [280] - quitar mención costo
# ---------------------------------------------------------------------------

def fix_62_3(doc):
    # P279 — DeepSeek $0.10/run
    p = find_p(doc, lambda p: "DeepSeek-chat) es el observer" in p.text and "$0.10/run" in p.text, "[279]")
    if p:
        new = p.text.replace(", costo ~$0.10/run,", "")
        replace_run_text(p, new)
        print("  §6.2.3 [279] $0.10/run removido.")

    # P280 — Costo total Eje A
    p = find_p(doc, lambda p: "Costo total Eje A: $11,83 USD" in p.text, "[280]")
    if p:
        new = p.text.replace(
            " Costo total Eje A: $11,83 USD, 37 min wall-clock (suma de las "
            "25 corridas; el subset de 19 corridas válidas representa $9,92).",
            " Wall-clock agregado Eje A: 37 min sobre las 25 corridas.",
        )
        replace_run_text(p, new)
        print("  §6.2.3 [280] costo Eje A reemplazado por wall-clock.")


# ---------------------------------------------------------------------------
# 4. §6.3.5 niveles - quitar costos
# ---------------------------------------------------------------------------

def fix_635_niveles(doc):
    # Nivel 1
    p = find_p(doc, lambda p: p.text.startswith("Nivel 1 — cadenas de ataque completadas íntegramente"), "[320] Nivel 1")
    if p:
        new = p.text.replace(
            "dc1: mF1=0,529, tácticas=6/6, replans=3, costo=$3,68 (Drupal 7",
            "dc1: mF1=0,529, tácticas=6/6, replans=3 (Drupal 7",
        ).replace(
            "bpent (B run08, Sonnet 4.5 atacante): mF1=0,511, tácticas=6/6, "
            "replans=2, costo=$20,79, 50 min wall-clock",
            "bpent (B run08, Sonnet 4.5 atacante): mF1=0,511, tácticas=6/6, "
            "replans=2, 50 min wall-clock",
        )
        replace_run_text(p, new)
        print("  §6.3.5 [320] Nivel 1 sin costos.")

    # Nivel 2 + 3 (parrafo combinado)
    p = find_p(doc, lambda p: p.text.startswith("Nivel 2 — Initial Access exitoso"), "[321] Nivel 2+3")
    if p:
        new = p.text
        # Nivel 2
        new = new.replace(
            "dvwa: mF1=0,415, tácticas=5/6, replans=23, costo=$6,06 (Lateral Movement",
            "dvwa: mF1=0,415, tácticas=5/6, replans=23 (Lateral Movement",
        )
        new = new.replace(
            "phpunit: mF1=0,261, tácticas=2/3, replans=25, costo=$9,80 (vector POST",
            "phpunit: mF1=0,261, tácticas=2/3, replans=25 (vector POST",
        )
        new = new.replace(
            "log4shell: mF1=1,000*, tácticas=1/3, replans=31, costo=$8,37 (mF1 outlier",
            "log4shell: mF1=1,000*, tácticas=1/3, replans=31 (mF1 outlier",
        )
        new = new.replace(
            "confluence: mF1=None, tácticas=2/3, replans=22, costo=$3,76 (OGNL",
            "confluence: mF1=None, tácticas=2/3, replans=22 (OGNL",
        )
        # Nivel 3
        new = new.replace(
            "mrrobot (GPT-4.1 atacante): mF1=0,046, replans=32, costo=$16,13;",
            "mrrobot (GPT-4.1 atacante): mF1=0,046, replans=32, 102 min wall-clock;",
        )
        new = new.replace(
            "bpent (GPT-4.1 atacante, B run04): mF1=0,086, replans=25, "
            "costo=$17,91.",
            "bpent (GPT-4.1 atacante, B run04): mF1=0,086, replans=25, "
            "102 min wall-clock.",
        )
        replace_run_text(p, new)
        print("  §6.3.5 [321] Niveles 2+3 sin costos.")


# ---------------------------------------------------------------------------
# 5. §4.2.4 [195] - quitar "costo por sesión"
# ---------------------------------------------------------------------------

def fix_4_2_4_intro(doc):
    p = find_p(
        doc,
        lambda p: "tres criterios: calidad de razonamiento para flujos agénticos" in p.text,
        "[195]",
    )
    if p:
        new = p.text.replace(
            "tres criterios: calidad de razonamiento para flujos agénticos, "
            "latencia de respuesta y costo por sesión de simulación, "
            "incluyendo los límites de tasa (tokens por minuto, TPM) impuestos "
            "por la API del proveedor",
            "tres criterios: calidad de razonamiento para flujos agénticos, "
            "latencia de respuesta e implicaciones operacionales de los "
            "límites de tasa (tokens por minuto, TPM) impuestos por la API "
            "del proveedor",
        )
        replace_run_text(p, new)
        print("  §4.2.4 [195] criterios sin 'costo por sesión'.")


# ---------------------------------------------------------------------------
# 6. Tabla 3 (ablation) - quitar columna Costo obs
# ---------------------------------------------------------------------------

def fix_tabla_ablation(doc):
    # Buscar la tabla con header "Régimen | Escenario | Macro F1 | Costo obs."
    for ti, t in enumerate(doc.tables):
        if not t.rows:
            continue
        header = [c.text.strip() for c in t.rows[0].cells]
        if header == ["Régimen", "Escenario", "Macro F1", "Costo obs."]:
            for row in t.rows:
                # Limpiar la 4ta celda (costo)
                if len(row.cells) >= 4:
                    cell = row.cells[3]
                    for p in cell.paragraphs:
                        for run in p.runs:
                            run.text = ""
                    if cell.paragraphs and not cell.paragraphs[0].runs:
                        cell.paragraphs[0].add_run("")
            # Reemplazar header de la 4ta celda por algo neutro
            header_cell = t.rows[0].cells[3]
            for p in header_cell.paragraphs:
                for run in p.runs:
                    run.text = ""
            if header_cell.paragraphs:
                header_cell.paragraphs[0].add_run("ew")
            print(f"  Tabla {ti+1} (ablation): columna 'Costo obs.' vaciada (header → 'ew').")
            return
    print("  [WARN] Tabla ablation no encontrada.")


# ---------------------------------------------------------------------------
# 7. Buscar otras menciones residuales de costo en el documento
# ---------------------------------------------------------------------------

def fix_residuales(doc):
    """Pasa final que escanea y reformula menciones cortas de costos."""
    fixes_aplicados = 0
    for p in doc.paragraphs:
        original = p.text
        new = original
        # Patrones residuales
        if "el costo está dominado por los runs largos" in new:
            new = new.replace(
                "El costo está dominado por los runs largos",
                "El wall-clock está dominado por los runs largos",
            )
        if "(modelo + observer)" in new and "$" in new:
            # casos puntuales tipo "$X (modelo + observer)"
            pass

        # Tachar referencias a USD redundantes
        if new != original:
            replace_run_text(p, new)
            fixes_aplicados += 1
    if fixes_aplicados:
        print(f"  Residuales: {fixes_aplicados} parrafos limpiados.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    doc = Document(FINAL)

    print("1. Renombrar §6.3.3 (heading + TOC)...")
    fix_633_heading(doc)

    print("2. Reformular §6.3.3 contenido (5 párrafos)...")
    fix_633_content(doc)

    print("3. §6.2.3 [279] [280] limpiar costos...")
    fix_62_3(doc)

    print("4. §6.3.5 niveles - quitar costos...")
    fix_635_niveles(doc)

    print("5. §4.2.4 [195] - quitar 'costo por sesión'...")
    fix_4_2_4_intro(doc)

    print("6. Tabla ablation - vaciar columna Costo obs...")
    fix_tabla_ablation(doc)

    print("7. Residuales...")
    fix_residuales(doc)

    doc.save(FINAL)
    print(f"\nOK -> {FINAL}")
    print(f"   Tamaño: {FINAL.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
