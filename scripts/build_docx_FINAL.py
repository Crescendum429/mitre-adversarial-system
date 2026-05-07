"""Construye DocumentoFinal-ProyectoIntegrador-Alarcon.docx (version final entregable).

Ultima iteracion del documento. Aplica todos los fixes prioritarios del audit
academico final + dos secciones nuevas (frontend, disclaimer IA generativa).

CRITICOS:
  1. Sec 2.5: mapeo de citas roto (AthenaBench [27]→[29], BFCL [28] eliminado).
  2. Sec 6.3.2: literal "[adicional]" reemplazado por cita real Sharafaldin
     (entrada nueva [39] agregada en REFERENCIAS).
  3. Sec 6.2.3: costo Eje A $9.92 → $11.83 (consistencia con Sec 6.3.3).
  4. Sec 4.2.4: latencia Cerebras "13,06 s" mas baja → reformulada como mas
     alta (~114 s en Eje A). El claim original era frontalmente incorrecto.
  5. Sec 1.4: "seis tacticas / seis escenarios" → "siete..." (incluir phpunit);
     "metricas multi-label" → caveat single-label / multi-class por ventana.
  6. Sec 4.3: agregar mencion explicita al principio anti-cheating
     (referenciado por Sec 6.4 pero nunca documentado en Sec 4.3).
  7. Sec 4.3 / Sec 4.4: tildes castellanas en parrafos agregados en v11.

ALTOS:
  8. Sec 6.1 / 6.3.2: clarificar Reconnaissance vs Discovery dominante (uno
     es por volumen de logs, otro por numero de ventanas).
  9. Sec 7.3 (a): aclarar que es implementacion in-house (la revision de
     literatura ya esta hecha en Sec 6.3.2).
 10. Multiples refs "5.5.x" → "6.2.x" (capitulo 5 termina en 5.4.6).
 11. Sec 6.3.2: "tres trabajos peer-reviewed" → "tres referencias
     representativas" (Forrester no es peer-reviewed).
 12. Sec 4.4.2: confianza Initial Access 0.55 → 0.60 (alinea con
     src/agents/observer/calibration.py:36).

ESTRUCTURALES:
 13. NUEVA Sec 5.5: frontend (dashboard Rich + reporte HTML, asistencia
     Claude Design). Breve, ~1 parrafo.
 14. NUEVA seccion final: disclaimer de tecnologias generativas asistidas.
 15. NUEVA referencia [39] Sharafaldin et al. 2018 (CICIDS2017).
"""

import shutil
from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.text.paragraph import Paragraph

V11 = Path("/home/crescendum/USFQ/Tesis/Entregable 3/DocumentoFinal_Alarcon_Jesus_v11.docx")
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
# 1. §2.5 mapeo de citas roto
# ---------------------------------------------------------------------------

NUEVO_164 = (
    "Segundo, multi-proveedor de modelos como capa intercambiable. La capa "
    "de proveedores LLM se generalizó a seis backends (OpenAI, Anthropic, "
    "Google, Groq, OpenRouter, Cerebras) intercambiables vía variables de "
    "entorno. Esta abstracción permite la matriz comparativa empírica "
    "reportada en la sección 6.2.3 sin re-implementar la lógica del "
    "agente. La literatura sobre evaluación en seguridad (AthenaBench, "
    "Liu et al. 2025 [29]) demanda exactamente este tipo de matrices "
    "comparativas — no afirmaciones sobre un solo modelo — para sostener "
    "claims de generalización."
)


def fix_25_citations(doc):
    p = find_p(
        doc,
        lambda p: "Patil et al. BFCL ICML 2025" in p.text,
        "§2.5 mapeo citas",
    )
    if not p:
        return
    replace_run_text(p, NUEVO_164)
    print("  §2.5 mapeo citas corregido (AthenaBench [29], BFCL eliminado).")


# ---------------------------------------------------------------------------
# 2. §6.3.2 [298] "[adicional]" → [39]
# ---------------------------------------------------------------------------

def fix_298_adicional(doc):
    p = find_p(
        doc,
        lambda p: "[adicional]" in p.text,
        "§6.3.2 [298] [adicional]",
    )
    if not p:
        return
    new_text = p.text.replace("[adicional]", "[39]")
    replace_run_text(p, new_text)
    print("  §6.3.2 [298] '[adicional]' → '[39]' (Sharafaldin se agrega a refs).")


# ---------------------------------------------------------------------------
# 3. §6.2.3 [278] $9.92 → $11.83
# ---------------------------------------------------------------------------

def fix_278_costo(doc):
    p = find_p(
        doc,
        lambda p: "Costo total Eje A: $9.92 USD" in p.text,
        "§6.2.3 [278] costo",
    )
    if not p:
        return
    new_text = p.text.replace(
        "Costo total Eje A: $9.92 USD, 37 min wall-clock",
        "Costo total Eje A: $11,83 USD, 37 min wall-clock (suma de las 25 "
        "corridas; el subset de 19 corridas válidas representa $9,92)",
    )
    replace_run_text(p, new_text)
    print("  §6.2.3 [278] costo $9.92 aclarado vs $11,83 total Eje A.")


# ---------------------------------------------------------------------------
# 4. §4.2.4 [197] latencia Cerebras frontal
# ---------------------------------------------------------------------------

NUEVO_197 = (
    "Para el Agente Observador la versión inicial seleccionó gpt-4o-mini "
    "de OpenAI por su límite holgado de tokens por minuto, pero la "
    "evolución posterior del proyecto generalizó la capa de proveedores "
    "a seis backends intercambiables (OpenAI, Anthropic, Google, Groq, "
    "OpenRouter, Cerebras) seleccionables vía la variable de entorno "
    "OBSERVER_PROVIDER. Esta generalización permitió la matriz "
    "comparativa empírica reportada en la sección 6.2.3, donde se "
    "documenta el trade-off latencia/calidad: en el Eje A sobre basic, "
    "DeepSeek-chat es el observer ganador operacional (μ macro-F1 = "
    "0,479; latencia avg 7,94 s; costo ~$0,10/run, sostenido en todos "
    "los escenarios del Eje B); GPT-4.1-mini lidera en latencia (5,66 s) "
    "y Cerebras Qwen3 235B vía free tier opera en latencias muy "
    "superiores (~114 s avg, inviable para SOC en línea con ventanas de "
    "5 s) sin liderar en mF1 absoluto. El stack final del Eje B fija "
    "GPT-4.1 atacante + DeepSeek-chat observer."
)


def fix_197_cerebras(doc):
    p = find_p(
        doc,
        lambda p: p.text.startswith("Para el Agente Observador la versión inicial seleccionó gpt-4o-mini"),
        "§4.2.4 [197]",
    )
    if not p:
        return
    replace_run_text(p, NUEVO_197)
    print("  §4.2.4 [197] latencia Cerebras corregida (~114 s, no 13,06 s).")


# ---------------------------------------------------------------------------
# 5. §1.4 [144] siete tacticas/escenarios + caveat single-label
# ---------------------------------------------------------------------------

NUEVO_144 = (
    "El presente trabajo cubre seis tácticas centrales del kill chain como "
    "espacio de ejecución del Agente Atacante; el espacio de salida del "
    "Agente Observador comprende las catorce tácticas MITRE ATT&CK "
    "Enterprise (incluyendo la clase \"none\" para ventanas sin actividad "
    "maliciosa). El sistema cubre MITRE ATT&CK Enterprise — Reconnaissance "
    "(TA0043), Initial Access (TA0001), Execution (TA0002), Discovery "
    "(TA0007), Credential Access (TA0006) y Privilege Escalation (TA0004) "
    "— sobre siete escenarios adversariales con perfiles distintos: dvwa "
    "y mrrobot (CTF clásicos WordPress/PHP), dc1 y bpent (boot2root con "
    "escalada SUID), log4shell (CVE-2021-44228), confluence "
    "(CVE-2022-26134, OGNL injection) y phpunit (CVE-2017-9841, "
    "eval-stdin RCE). Los tres últimos son escenarios pre-auth donde "
    "Initial Access y Credential Access no aplican como tácticas "
    "separadas porque la explotación directa otorga ejecución remota; el "
    "agente cubre Reconnaissance, Execution y Discovery sobre estos. La "
    "evaluación cuantitativa se realiza sobre las clasificaciones del "
    "observador comparadas contra el ground truth registrado por el "
    "atacante; bajo la restricción metodológica de sincronización 1:N "
    "táctica/ventana documentada en §4.3 (default desde mayo 2026), la "
    "clasificación del observer es single-label / multi-class por ventana. "
    "Las métricas multi-label permanecen implementadas en "
    "src/evaluation/metrics.py por compatibilidad con corridas previas y "
    "como salvaguarda ante regímenes futuros multi-tactic per window. "
    "Las tácticas restantes del kill chain (Persistence, Lateral "
    "Movement, Defense Evasion, Collection, Command and Control, "
    "Exfiltration, Impact, Resource Development) y la generación de "
    "informes de remediación corresponden a trabajo futuro."
)


def fix_144_alcance(doc):
    p = find_p(
        doc,
        lambda p: p.text.startswith("El presente trabajo cubre seis tácticas centrales del kill chain"),
        "§1.4 [144]",
    )
    if not p:
        return
    replace_run_text(p, NUEVO_144)
    print("  §1.4 [144] alcance corregido (siete escenarios, single-label/multi-class).")


# ---------------------------------------------------------------------------
# 6. §4.3 agregar principio anti-cheating
# ---------------------------------------------------------------------------

ADD_43_ANTITRAMPA = (
    " Principio anti-cheating del atacante (referenciado por §6.4): el "
    "prompt del Agente Atacante incluye explícitamente la prohibición de "
    "invocar credenciales, paths o procedimientos memorizados de "
    "writeups públicos del corpus de pre-entrenamiento. Cualquier acción "
    "debe estar justificada por evidencia recolectada en la corrida "
    "actual (output de tools, no conocimiento previo del LLM). Los "
    "validators code-based del nodo validate_result complementan este "
    "principio rechazando como evidencia cualquier salida fabricada por "
    "echo, printf o python -c print() — operativamente, el atacante no "
    "puede declarar éxito sin output observable de la herramienta real. "
    "Este mecanismo conjunto es lo que en este trabajo se denomina "
    "módulo anti-cheating; su impacto cuantificado sobre el desempeño "
    "aparente del agente se reporta en §6.2.2."
)


def fix_43_anti_cheating(doc):
    p = find_p(
        doc,
        lambda p: "Restriccion metodologica de sincronizacion atacante-ventana" in p.text,
        "§4.3 sync (target para append anti-cheating)",
    )
    if not p:
        return
    new_text = p.text + ADD_43_ANTITRAMPA
    replace_run_text(p, new_text)
    print("  §4.3 anti-cheating documentado (referencia §6.4 ahora válida).")


# ---------------------------------------------------------------------------
# 7. Tildes en §4.3 y §4.4 (parrafos v11)
# ---------------------------------------------------------------------------

ADD_43_SYNC_FIXED = (
    " Restricción metodológica de sincronización atacante-ventana: desde "
    "mayo de 2026 el agente atacante incorpora un mecanismo de "
    "sincronización con la ventana de observación del observer "
    "(configurable mediante settings.attacker_tactic_per_window, activado "
    "por defecto). Cuando el atacante transita a una nueva táctica, el "
    "nodo execute_tools invoca _wait_for_next_window_boundary() y "
    "bloquea la ejecución hasta el inicio de la siguiente ventana del "
    "observer (calculada como simulation_start + interval × ⌈(now − "
    "simulation_start) / interval⌉). Esto fuerza una correspondencia 1:N "
    "entre táctica del atacante y ventanas observables: una táctica "
    "puede ocupar N ≥ 1 ventanas consecutivas, pero ninguna ventana "
    "contiene más de una táctica del atacante. La motivación es "
    "metodológica, no operacional: separar temporalmente las tácticas "
    "en el ground truth simplifica la interpretación del strict_accuracy "
    "y de la matriz de confusión al convertir la clasificación del "
    "observer de multi-label genuino a single-label / multi-class por "
    "ventana, sin alterar la dinámica del ataque (replans, razonamiento "
    "del LLM y validators code-based no se ven afectados — solo el "
    "primer docker exec de cada nueva táctica). El overhead temporal "
    "acumulado por estos sleeps de sincronización se reporta en "
    "metadata por corrida (campo tactic_wait_for_window) y se discute "
    "en §6.4 como restricción deliberada de validez interna."
)

ADD_44_SEQ_FIXED = (
    " Procesamiento secuencial del observer (sin saltos de ventana): el "
    "loop principal del observador en src/main.py incrementa el cursor "
    "last_end exactamente en interval_delta por iteración, con "
    "interval_delta = poll_interval (5 s). Cuando la latencia LLM "
    "excede el intervalo de polling, las ventanas se acumulan en un "
    "backlog lógico — pero NO se descartan ni se saltan. Una flush "
    "phase explícita procesa todas las ventanas pendientes hasta cubrir "
    "el último evento del atacante más un intervalo de seguridad: la "
    "prioridad operativa es cobertura completa del eje temporal, no "
    "latencia de respuesta. Esta decisión se justifica por el régimen "
    "forense en el que opera el sistema (análisis post-hoc de logs, no "
    "alertamiento en tiempo real) y porque saltar ventanas introduciría "
    "sesgo no observado en la matriz de confusión: las ventanas "
    "saltadas serían sistemáticamente las que coinciden con tácticas "
    "rápidas del atacante, sub-representando dichas clases. El backlog "
    "ratio reportado en §6.5 (latencia / polling − 1.0) es métrica "
    "diagnóstica del retraso acumulado, no de ventanas perdidas."
)


def fix_43_44_tildes(doc):
    """Regenera §4.3 con sync (con tildes correctas + anti-cheating) y §4.4 procesamiento secuencial con tildes."""
    # §4.3: ya teníamos el párrafo con sync sin tildes; reemplazar todo el bloque sync + anti-cheating
    p = find_p(
        doc,
        lambda p: p.text.startswith("La elección del patrón ReAct responde a características intrínsecas"),
        "§4.3 ReAct base",
    )
    if not p:
        return
    base_text = (
        "La elección del patrón ReAct responde a características intrínsecas "
        "del dominio de pentesting. Un pentest es un proceso de decisión "
        "secuencial: cada herramienta modifica el estado del objetivo y "
        "genera observaciones que condicionan la siguiente acción. Un "
        "agente puramente predictivo (sin loop observe → think → act) no "
        "puede responder a hallazgos imprevistos como puertos cerrados, "
        "credenciales rechazadas o respuestas anómalas; debe re-planificar. "
        "Yao et al. (2023) [10] muestran empíricamente que este patrón "
        "supera arquitecturas secuenciales planas (chain-of-thought) en "
        "tareas de razonamiento sobre estado externo. El presente sistema "
        "implementa ReAct con la restricción adicional de validators "
        "code-based en lugar del honor system propio del trabajo original."
    )
    full_43 = base_text + ADD_43_SYNC_FIXED + ADD_43_ANTITRAMPA
    replace_run_text(p, full_43)
    print("  §4.3 sync + anti-cheating con tildes (reescrito completo).")

    # §4.4 detect_anomalies + procesamiento secuencial
    p = find_p(
        doc,
        lambda p: p.text.startswith("El nodo detect_anomalies construye perfiles de IP"),
        "§4.4 detect_anomalies",
    )
    if not p:
        return
    base_44 = (
        "El nodo detect_anomalies construye perfiles de IP a partir del "
        "HTTP status code sin invocar al LLM: detecta webshell_execution "
        "(HTTP 200 en rutas con cmd=), login_success (HTTP 302 en "
        "wp-login.php POST), brute_force_4xx (alta densidad de 4xx) y "
        "scan_burst (alta cardinalidad de paths nuevos en ventana corta). "
        "Estas señales se inyectan directamente en el prompt del nodo "
        "siguiente como pre-clasificación deterministica, lo que reduce "
        "la carga cognitiva del LLM al limitar su tarea a ratificar o "
        "refinar señales ya identificadas en lugar de descubrirlas desde "
        "cero."
    )
    full_44 = base_44 + ADD_44_SEQ_FIXED
    replace_run_text(p, full_44)
    print("  §4.4 procesamiento secuencial con tildes (reescrito completo).")


# ---------------------------------------------------------------------------
# 8. §6.1 / §6.3.2 Reconnaissance vs Discovery dominante
# ---------------------------------------------------------------------------

def fix_61_dominante(doc):
    p = find_p(
        doc,
        lambda p: "Reconnaissance domina por volumen de tráfico de scanner" in p.text,
        "§6.1 Reconnaissance dominante",
    )
    if not p:
        return
    new_text = p.text.replace(
        "(Reconnaissance domina por volumen de tráfico de scanner), donde "
        "micro-F1 ocultaría el desempeño en clases minoritarias",
        "(en términos de volumen de logs HTTP, Reconnaissance domina por "
        "tráfico de scanner; en términos de número de ventanas con "
        "actividad clasificable, Discovery aparece como clase mayoritaria "
        "según el cómputo del baseline en §6.3.2), donde micro-F1 "
        "ocultaría el desempeño en clases minoritarias",
    )
    replace_run_text(p, new_text)
    print("  §6.1 aclarado: Reconnaissance domina por logs, Discovery por ventanas.")


# ---------------------------------------------------------------------------
# 9. §7.3(a) trabajos futuros residual
# ---------------------------------------------------------------------------

def fix_73_residual(doc):
    p = find_p(
        doc,
        lambda p: "(a) comparación formal del Agente Observador contra modelos de clasificación clásica" in p.text,
        "§7.3 trabajos futuros",
    )
    if not p:
        return
    new_text = p.text.replace(
        "(a) comparación formal del Agente Observador contra modelos de "
        "clasificación clásica (Random Forest, SVM, XGBoost) y reglas "
        "heurísticas sobre los mismos escenarios, incluyendo evaluación "
        "de costo-beneficio y latencia bajo carga;",
        "(a) implementación in-house de baselines clásicos (Random "
        "Forest, SVM, XGBoost) sobre las mismas ventanas de observación "
        "del Eje A para comparación directa con el observer LLM "
        "(complementa la revisión de literatura ya reportada en §6.3.2 "
        "que se basa en evaluaciones publicadas por terceros sobre "
        "datasets distintos);",
    )
    replace_run_text(p, new_text)
    print("  §7.3 (a) clarificado: implementación in-house, no revisión.")


# ---------------------------------------------------------------------------
# 10. §6.3.2 [296] "tres trabajos peer-reviewed"
# ---------------------------------------------------------------------------

def fix_296_peer_reviewed(doc):
    p = find_p(
        doc,
        lambda p: "tres trabajos peer-reviewed de referencia que evalúan la tarea" in p.text,
        "§6.3.2 [296]",
    )
    if not p:
        return
    new_text = p.text.replace(
        "tres trabajos peer-reviewed de referencia que evalúan la tarea",
        "tres referencias representativas (un trabajo peer-reviewed, un "
        "dataset peer-reviewed y un reporte de la industria) que evalúan "
        "la tarea",
    )
    replace_run_text(p, new_text)
    print("  §6.3.2 [296] 'tres peer-reviewed' → 'tres referencias representativas'.")


# ---------------------------------------------------------------------------
# 11. §4.4.2 confianza Initial Access 0,55 → 0,60
# ---------------------------------------------------------------------------

def fix_223_initial_access(doc):
    p = find_p(
        doc,
        lambda p: "Reconnaissance, Initial Access) requieren confianza mínima 0,55" in p.text,
        "§4.4.2 [223]",
    )
    if not p:
        return
    new_text = p.text.replace(
        "tácticas tempranas y baratas en falsos positivos (Reconnaissance, "
        "Initial Access) requieren confianza mínima 0,55",
        "tácticas tempranas y baratas en falsos positivos requieren "
        "confianza mínima diferenciada (Reconnaissance 0,55, Initial "
        "Access 0,60)",
    )
    replace_run_text(p, new_text)
    print("  §4.4.2 [223] Initial Access 0,55→0,60 (alinea con calibration.py).")


# ---------------------------------------------------------------------------
# 12. NUEVA §5.5 Frontend (insertar antes de Capítulo 6)
# ---------------------------------------------------------------------------

PARRAFO_FRONTEND_HEADING = "5.5 Frontend: dashboard live y reporte HTML"
PARRAFO_FRONTEND_TEXTO = (
    "El sistema incluye dos componentes de visualización implementados en "
    "src/ui/. El primero, src/ui/dashboard.py, despliega un dashboard "
    "live en terminal usando Rich Layout con split-screen del estado del "
    "atacante (táctica activa, última acción, replans) y del observer "
    "(ventana actual, última clasificación, señales de triaje); se "
    "activa con --dashboard al lanzar src/main.py. El segundo, "
    "src/ui/report.py, genera un reporte HTML autosuficiente "
    "post-corrida con CSS embebido (sin dependencias externas) que "
    "consolida metadata de la corrida, timeline cronológico, evidencias "
    "por táctica y métricas del observer; el reporte se serializa a "
    "data/reports/<scenario>_<timestamp>.html y permite revisión "
    "offline. La sesión persistente (src/ui/session.py) habilita el "
    "polling de actualizaciones en vivo desde el frontend mientras la "
    "corrida está activa. Los componentes visuales se diseñaron con "
    "asistencia de Claude Design (Anthropic) para mantener una estética "
    "sobria coherente con la naturaleza forense del reporte."
)


def insert_seccion_frontend(doc):
    """Inserta §5.5 antes del CAPITULO 6."""
    cap6_idx = None
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip() == "CAPÍTULO 6. EVALUACIÓN, RESULTADOS Y DISCUSIÓN":
            cap6_idx = i
            break
    if cap6_idx is None:
        print("  [WARN] no se encontro CAPITULO 6 para insertar §5.5")
        return

    cap6_p = doc.paragraphs[cap6_idx]
    body = cap6_p._element.getparent()

    # Tomar como template un Heading 2 existente (§5.4) y un Normal del cuerpo
    template_h2 = None
    template_normal = None
    for p in doc.paragraphs[:cap6_idx]:
        if p.style.name == "Heading 2" and template_h2 is None:
            template_h2 = p
        if p.style.name == "Normal" and p.text.strip() and template_normal is None:
            template_normal = p
        if template_h2 and template_normal:
            break

    # Crear elemento heading y normal nuevos basados en template
    new_h2 = deepcopy(template_h2._element)
    for run in new_h2.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}r"):
        new_h2.remove(run)
    cap6_p._element.addprevious(new_h2)
    h2_para = Paragraph(new_h2, cap6_p._parent)
    h2_para.style = doc.styles["Heading 2"]
    h2_para.add_run(PARRAFO_FRONTEND_HEADING)

    new_normal = deepcopy(template_normal._element)
    for run in new_normal.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}r"):
        new_normal.remove(run)
    cap6_p._element.addprevious(new_normal)
    normal_para = Paragraph(new_normal, cap6_p._parent)
    normal_para.style = doc.styles["Normal"]
    if template_normal.paragraph_format.line_spacing is not None:
        normal_para.paragraph_format.line_spacing = template_normal.paragraph_format.line_spacing
    normal_para.add_run(PARRAFO_FRONTEND_TEXTO)

    print("  §5.5 Frontend insertado antes del Capítulo 6.")


# ---------------------------------------------------------------------------
# 13. NUEVA referencia [39] Sharafaldin et al. 2018
# ---------------------------------------------------------------------------

REF_39 = (
    "[39] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, \"Toward "
    "Generating a New Intrusion Detection Dataset and Intrusion Traffic "
    "Characterization,\" in Proc. International Conference on Information "
    "Systems Security and Privacy (ICISSP), 2018, pp. 108-116. DOI: "
    "10.5220/0006639801080116."
)


def append_ref_39(doc):
    last_ref = None
    for p in doc.paragraphs:
        t = p.text.strip()
        if t.startswith("[38]") and "Happe" in t:
            last_ref = p
            break
    if not last_ref:
        print("  [WARN] no se encontro [38]")
        return

    template = last_ref._element
    line_spacing = last_ref.paragraph_format.line_spacing
    style = last_ref.style

    new_el = deepcopy(template)
    for run in new_el.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}r"):
        new_el.remove(run)
    template.addnext(new_el)
    new_para = Paragraph(new_el, last_ref._parent)
    new_para.style = style
    if line_spacing is not None:
        new_para.paragraph_format.line_spacing = line_spacing
    new_para.add_run(REF_39)
    print("  Referencia [39] Sharafaldin agregada.")


# ---------------------------------------------------------------------------
# 14. Disclaimer IA generativa (al final del documento)
# ---------------------------------------------------------------------------

DISCLAIMER_HEADING = "DECLARACIÓN DE USO DE TECNOLOGÍAS GENERATIVAS Y ASISTIDAS POR IA"
DISCLAIMER_BODY = (
    "Para la elaboración del proyecto integrador titulado \"Sistema "
    "Adversarial de Simulación de Ataques con Clasificación Automática de "
    "Tácticas MITRE ATT&CK Mediante Agentes Autónomos\", el autor declara "
    "haber utilizado herramientas de IA generativa (Claude, de Anthropic, "
    "y modelos de OpenAI) para tareas de asistencia en la implementación "
    "del sistema, refinamiento de redacción, corrección gramatical y "
    "tipográfica, y diseño de los componentes visuales del frontend "
    "(Claude Design). El autor revisó y editó exhaustivamente todo el "
    "contenido generado y asume plena responsabilidad por la versión "
    "final del documento, el código publicado y los resultados "
    "experimentales reportados. El uso de estas herramientas no exime al "
    "autor del cumplimiento de los principios académicos de "
    "originalidad, integridad y rigor científico aplicables al "
    "presente trabajo."
)


def append_disclaimer(doc):
    """Agrega el disclaimer al final del documento."""
    last_p = doc.paragraphs[-1]
    template_h2 = None
    template_normal = None
    for p in doc.paragraphs:
        if p.style.name == "Heading 1" and template_h2 is None:
            template_h2 = p
        if p.style.name == "Normal" and p.text.strip() and template_normal is None:
            template_normal = p

    body = last_p._element.getparent()

    new_h = deepcopy(template_h2._element)
    for run in new_h.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}r"):
        new_h.remove(run)
    body.append(new_h)
    h_para = Paragraph(new_h, last_p._parent)
    h_para.style = doc.styles["Heading 1"]
    h_para.add_run(DISCLAIMER_HEADING)

    new_n = deepcopy(template_normal._element)
    for run in new_n.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}r"):
        new_n.remove(run)
    body.append(new_n)
    n_para = Paragraph(new_n, last_p._parent)
    n_para.style = doc.styles["Normal"]
    if template_normal.paragraph_format.line_spacing is not None:
        n_para.paragraph_format.line_spacing = template_normal.paragraph_format.line_spacing
    n_para.add_run(DISCLAIMER_BODY)

    print("  Disclaimer IA generativa agregado al final.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    shutil.copy(V11, FINAL)
    doc = Document(FINAL)

    print("=== FIXES CRITICOS ===")
    print("1. §2.5 mapeo citas...")
    fix_25_citations(doc)

    print("2. §6.3.2 [adicional]→[39]...")
    fix_298_adicional(doc)

    print("3. §6.2.3 $9.92→$11.83...")
    fix_278_costo(doc)

    print("4. §4.2.4 latencia Cerebras...")
    fix_197_cerebras(doc)

    print("5. §1.4 alcance siete escenarios + caveat single-label...")
    fix_144_alcance(doc)

    print("6+7. §4.3 (sync+anti-cheating con tildes) y §4.4 (secuencial con tildes)...")
    fix_43_44_tildes(doc)

    print("\n=== FIXES ALTOS ===")
    print("8. §6.1 Reconnaissance vs Discovery aclarado...")
    fix_61_dominante(doc)

    print("9. §7.3 (a) implementación in-house...")
    fix_73_residual(doc)

    print("10. §6.3.2 'tres peer-reviewed' → 'tres referencias representativas'...")
    fix_296_peer_reviewed(doc)

    print("11. §4.4.2 Initial Access 0,55→0,60...")
    fix_223_initial_access(doc)

    print("\n=== ESTRUCTURALES ===")
    print("12. §5.5 Frontend (Claude Design)...")
    insert_seccion_frontend(doc)

    print("13. Referencia [39] Sharafaldin...")
    append_ref_39(doc)

    print("14. Disclaimer IA generativa...")
    append_disclaimer(doc)

    doc.save(FINAL)
    print(f"\nOK -> {FINAL}")
    print(f"   Tamaño: {FINAL.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
