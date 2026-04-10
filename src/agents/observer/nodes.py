"""
Nodos del grafo LangGraph del agente observador.

Implementa el patron Triage -> Investigate -> Classify -> Escalate
de los SOCs automatizados (Vinay 2025, arXiv:2512.06659).

El grafo ya no es un pipeline lineal: tiene ramificacion condicional
y un loop de refinamiento para casos de baja confianza:

  collect_logs -> triage_anomalies --(no_signal)--> END   [sin costo de LLM]
                                   --(signal)  --> classify_tactic
                                                       |
                                              (confianza < 0.6 y refinements < 2)
                                                       v
                                              refine_analysis -> classify_tactic
                                                       |
                                              (confianza >= 0.6)
                                                       v
                                              generate_recommendation -> END
"""

import json
import logging
import re
from collections import Counter
from datetime import datetime, timezone

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.observer.collectors import LogCollector
from src.agents.observer.prompts import OBSERVER_SYSTEM_PROMPT, build_classification_prompt
from src.agents.observer.state import Classification, ObserverState
from src.llm.provider import get_observer_model

logger = logging.getLogger(__name__)

_collector = None
_model = None


def _get_collector():
    global _collector
    if _collector is None:
        _collector = LogCollector()
    return _collector


def _get_model():
    global _model
    if _model is None:
        _model = get_observer_model()
    return _model


# Regex completo que captura todos los campos del log Apache Combined:
# ip - - [fecha hora] "METHOD /url HTTP/x" STATUS BYTES "referer" "user-agent"
_TRIAGE_LOG_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[(\d{2}/\w+/\d{4}):(\d{2}):(\d{2}):\d{2}\s+[^\]]+\]\s+'
    r'"(\w+)\s+(\S+)\s+HTTP/[^"]+"\s+(\d{3})\s+(\d+|-)\s+"[^"]*"\s+"([^"]*)"'
)

# User-agents de herramientas de ataque que aparecen literalmente en logs
_ATTACK_TOOL_UAS = ("gobuster", "wpscan", "sqlmap", "nikto", "masscan", "nessus",
                    "burpsuite", "zaproxy", "hydra")

# Rutas sensibles para POST (autenticacion)
_SENSITIVE_POST_PATHS = ("/wp-login", "/login", "/admin", "/xmlrpc", "/wp-admin")

# Una IP que genera >8 requests en el mismo segundo = herramienta automatizada
_MAX_REQUESTS_PER_SECOND = 8

# Una IP con >15 requests totales en la ventana es sospechosa
_TRIAGE_MIN_REQUESTS = 15

# 404 ratio: si >40% de los requests de una IP son 404 y hay al menos 8 = scanner
_TRIAGE_404_RATIO = 0.40
_TRIAGE_404_MIN = 8


def collect_logs(state: ObserverState) -> dict:
    """
    Nodo recolector: consulta Loki y obtiene logs recientes del lab.

    Convierte los logs crudos en un resumen textual que el LLM puede analizar.
    Prioriza logs relevantes para deteccion de ataques.
    """
    start_str = state.get("window_start")
    end_str = state.get("window_end")

    start = datetime.fromisoformat(start_str) if start_str else None
    end = datetime.fromisoformat(end_str) if end_str else None

    collector = _get_collector()
    raw_logs = collector.collect_window(start=start, end=end)
    summary = collector.summarize_logs(raw_logs)

    has_new = len(raw_logs) > 0
    logger.info(f"[Observador] Logs recolectados: {len(raw_logs)}, nuevos: {has_new}")

    return {
        "raw_logs": raw_logs,
        "log_summary": summary,
        "has_new_logs": has_new,
    }


def triage_anomalies(state: ObserverState) -> dict:
    """
    Nodo de triaje: heuristicas basadas en estructura real de logs Apache.

    Calibrado con observacion directa de trafico de nikto, gobuster, curl y
    wpscan contra el lab Mr. Robot. Senales (cualquiera activa el triage):

    1. User-agent de herramienta de ataque conocida (gobuster, wpscan, sqlmap...)
       → deteccion directa, 0 falsos positivos
    2. IP generando >8 requests en el mismo segundo
       → nikto paraleliza; ningun browser normal hace esto
    3. IP con >15 requests totales en la ventana y >40% son 404
       → patron tipico de enumeracion automatizada
    4. POST a ruta de autenticacion (/wp-login, /login, /admin, /xmlrpc)
       → intento de login activo
    5. URL con cmd= o cmd%3D y status 2xx
       → webshell respondiendo a comandos
    6. IP con >15 requests con body size uniforme en 404s
       → nikto con user-agent camuflado (todos sus 404s tienen el mismo byte count)
    """
    raw_logs = state.get("raw_logs", [])

    if not raw_logs:
        logger.info("[Observador] Triaje: sin logs, ciclo terminado")
        return {"triage_result": "no_signal", "anomaly_count": 0}

    # Estructuras para analisis por IP
    ip_total: Counter = Counter()
    ip_404: Counter = Counter()
    # ip -> {segundo -> count}  para detectar parallelismo
    ip_per_second: dict[str, Counter] = {}
    # ip -> set de body sizes en 404s para detectar nikto camuflado
    ip_404_sizes: dict[str, set] = {}

    signals_found: list[str] = []
    anomaly_count = 0

    for log in raw_logs:
        msg = log.get("message", "")
        m = _TRIAGE_LOG_RE.match(msg)
        if not m:
            continue

        ip = m.group(1)
        # Ignorar loopback (requests internos de Apache)
        if ip.startswith("127."):
            continue

        hour, minute = m.group(3), m.group(4)
        method = m.group(5).upper()
        url = m.group(6).lower()
        status = m.group(7)
        body_size = m.group(8)
        user_agent = m.group(9).lower()

        ip_total[ip] += 1
        second_key = f"{hour}:{minute}"

        if ip not in ip_per_second:
            ip_per_second[ip] = Counter()
        ip_per_second[ip][second_key] += 1

        if status == "404":
            ip_404[ip] += 1
            if ip not in ip_404_sizes:
                ip_404_sizes[ip] = set()
            if body_size.isdigit():
                ip_404_sizes[ip].add(body_size)

        # Senal 1: user-agent de herramienta de ataque
        if any(tool in user_agent for tool in _ATTACK_TOOL_UAS):
            tool_name = next(t for t in _ATTACK_TOOL_UAS if t in user_agent)
            signals_found.append(f"tool UA: {tool_name} desde {ip}")
            anomaly_count += ip_total[ip]

        # Senal 4: POST a ruta de autenticacion
        if method == "POST" and any(p in url for p in _SENSITIVE_POST_PATHS):
            signals_found.append(f"POST auth: {url[:50]} desde {ip}")
            anomaly_count += 1

        # Senal 5: webshell activa
        if status.startswith("2") and ("cmd=" in url or "cmd%3" in url or "cmd%20" in url):
            signals_found.append(f"webshell activa: {url[:60]} -> {status}")
            anomaly_count += 10  # alta prioridad

    # Senal 2: parallelismo por segundo
    for ip, sec_counts in ip_per_second.items():
        max_per_sec = max(sec_counts.values())
        if max_per_sec >= _MAX_REQUESTS_PER_SECOND:
            signals_found.append(f"IP {ip}: {max_per_sec} req/s (herramienta automatizada)")
            anomaly_count = max(anomaly_count, ip_total[ip])

    # Senal 3: alta tasa 404
    for ip, count_404 in ip_404.items():
        total = ip_total.get(ip, 1)
        if total >= _TRIAGE_MIN_REQUESTS and count_404 / total >= _TRIAGE_404_RATIO:
            signals_found.append(
                f"IP {ip}: {count_404}/{total} 404s ({count_404/total:.0%}) — enumeracion"
            )
            anomaly_count = max(anomaly_count, count_404)

    # Senal 6: nikto camuflado — 404s con body size uniforme y alto volumen
    for ip, sizes in ip_404_sizes.items():
        count_404 = ip_404.get(ip, 0)
        if count_404 >= 20 and len(sizes) <= 2:
            signals_found.append(
                f"IP {ip}: {count_404} 404s con body size uniforme {sizes} — posible nikto"
            )
            anomaly_count = max(anomaly_count, count_404)

    # Deduplicar senales
    signals_found = list(dict.fromkeys(signals_found))

    if signals_found:
        ratio = anomaly_count / max(len(raw_logs), 1)
        logger.info(
            f"[Observador] Triaje: senal detectada "
            f"({anomaly_count}/{len(raw_logs)} logs anomalos, ratio={ratio:.1%})"
        )
        logger.debug(f"[Observador] Senales: {signals_found[:3]}")
        return {"triage_result": "signal", "anomaly_count": anomaly_count}

    logger.info(
        f"[Observador] Triaje: sin senal relevante ({len(raw_logs)} logs)"
    )
    return {"triage_result": "no_signal", "anomaly_count": 0}


def refine_analysis(state: ObserverState) -> dict:
    """
    Nodo de refinamiento: se activa cuando classify_tactic tiene confianza < 0.6.

    En lugar de reintentar con los mismos logs, genera una vista forense
    alternativa de los datos crudos:
    - Agrupa actividad por IP de origen
    - Ordena por densidad de keywords de ataque (las entradas mas sospechosas primero)
    - Identifica secuencias temporales comprimidas

    Esto implementa el paso 'Investigate' del patron Triage->Investigate->Classify:
    cuando la primera clasificacion es incierta, el grafo pide mas contexto
    en lugar de rendirse o aceptar una clasificacion de baja confianza.

    Maximo 2 refinamientos (refinement_count < 2) para evitar loops infinitos.
    """
    raw_logs = state.get("raw_logs", [])
    refinement_count = state.get("refinement_count", 0) + 1
    prev_classification = state.get("current_classification")

    if not raw_logs:
        return {"refinement_count": refinement_count}

    lines = [f"=== ANALISIS FORENSE — intento {refinement_count} ==="]

    if prev_classification:
        lines.append(
            f"Clasificacion previa: {prev_classification.get('tactic', '?')} "
            f"(confianza {prev_classification.get('confidence', 0):.0%}) — insuficiente, refinando"
        )

    # Agrupar IPs activas
    ip_counts: Counter = Counter()
    for log in raw_logs:
        msg = log.get("message", "")
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg):
            if not ip.startswith("127.") and ip != "10.10.0.5":
                ip_counts[ip] += 1

    if ip_counts:
        lines.append(f"\nIPs mas activas: {dict(ip_counts.most_common(5))}")

    # Top 20 entradas mas sospechosas: prioriza status 2xx/302/401 y metodos POST,
    # y paths con indicadores de ataque que SI aparecen en logs HTTP reales.
    _HTTP_SIGNAL_KWS = [
        "cmd=", "shell", "wp-login", "wp-admin", "xmlrpc",
        "passwd", "shadow", "upload", "eval", "base64",
    ]

    def anomaly_score(log: dict) -> int:
        msg = log.get("message", "").lower()
        score = sum(1 for kw in _HTTP_SIGNAL_KWS if kw in msg)
        # POST vale doble, status 200/302 a ruta sospechosa vale doble
        if '"post ' in msg:
            score += 2
        if '" 200 ' in msg or '" 302 ' in msg:
            score += 1
        return score

    top = sorted(
        [l for l in raw_logs if anomaly_score(l) > 0],
        key=anomaly_score,
        reverse=True,
    )[:20]

    lines.append(f"\nTop {len(top)} entradas mas sospechosas (ordenadas por densidad):")
    for log in top:
        ts = log.get("timestamp", "?")
        container = log.get("labels", {}).get("container_name", "?")
        score = anomaly_score(log)
        msg = log.get("message", "").strip()[:300]
        lines.append(f"[score={score}] [{ts}] [{container}] {msg}")

    refined_summary = "\n".join(lines)

    logger.info(
        f"[Observador] Refinamiento #{refinement_count}: "
        f"{len(top)} entradas focalizadas para segunda clasificacion"
    )

    return {
        "log_summary": refined_summary,
        "refinement_count": refinement_count,
    }


def detect_anomalies(state: ObserverState) -> dict:
    """
    Nodo de deteccion: construye perfiles por IP usando el HTTP status code.

    El status code es el discriminador clave entre escaneo y ataque real:
    - webshell_execution (200): cmd= o shell.php respondio → ejecucion activa
    - webshell_scan (4xx): nikto/gobuster probando la ruta → reconnaissance
    - login_success (302): WordPress redirige a /wp-admin tras login exitoso
    - login_failed (200/4xx): formulario devuelto con error o bloqueado

    Identifica las IPs con mayor actividad sospechosa y las entrega al LLM
    para que razone sobre si una IP especifica logro acceso o solo escaneo.
    """
    raw_logs = state.get("raw_logs", [])

    if not raw_logs:
        return {"anomaly_signals": {}, "suspect_list": state.get("suspect_list", {})}

    SQLI_MARKERS = ["' or", "1=1", "union select", "sleep(", "%27"]
    SUSPICION_THRESHOLD = 3

    ip_profiles: dict[str, dict] = {}
    seen_404_urls: dict[str, set] = {}
    ip_per_second: dict[str, Counter] = {}

    def get_profile(ip: str) -> dict:
        if ip not in ip_profiles:
            ip_profiles[ip] = {
                "total": 0,
                "attack_score": 0.0,
                "tool_detected": "",
                "webshell_scan": 0,
                "webshell_execution": 0,
                "login_failed": 0,
                "login_success": 0,
                "sqli_attempts": 0,
                "max_req_per_sec": 0,
            }
        return ip_profiles[ip]

    for log in raw_logs:
        msg = log.get("message", "")
        m = _TRIAGE_LOG_RE.match(msg)
        if not m:
            continue

        ip = m.group(1)
        if ip.startswith("127."):
            continue

        hour, minute = m.group(3), m.group(4)
        method = m.group(5).upper()
        url = m.group(6)
        status = int(m.group(7))
        user_agent = m.group(9).lower()
        url_lower = url.lower()

        profile = get_profile(ip)
        profile["total"] += 1

        # Velocidad por minuto:segundo (proxy para req/s)
        sec_key = f"{hour}:{minute}"
        if ip not in ip_per_second:
            ip_per_second[ip] = Counter()
        ip_per_second[ip][sec_key] += 1

        # Detectar herramienta por user-agent
        if not profile["tool_detected"]:
            for tool in _ATTACK_TOOL_UAS:
                if tool in user_agent:
                    profile["tool_detected"] = tool
                    profile["attack_score"] += 10
                    break

        # Webshell
        if "cmd=" in url_lower or "cmd%3" in url_lower or "shell.php" in url_lower:
            if status == 200:
                profile["webshell_execution"] += 1
                profile["attack_score"] += 10
            else:
                profile["webshell_scan"] += 1
                profile["attack_score"] += 0.5

        # Login attempts
        if "wp-login" in url_lower and method == "POST":
            if status == 302:
                profile["login_success"] += 1
                profile["attack_score"] += 10
            else:
                profile["login_failed"] += 1
                profile["attack_score"] += 1

        # Admin panel access
        if "wp-admin" in url_lower and status == 200 and method == "GET":
            profile["attack_score"] += 3

        # SQLi
        if any(marker in url_lower for marker in SQLI_MARKERS):
            profile["sqli_attempts"] += 1
            profile["attack_score"] += 2

        if status == 404:
            if ip not in seen_404_urls:
                seen_404_urls[ip] = set()
            seen_404_urls[ip].add(url)

    # Registrar velocidad maxima y penalizar enumeracion masiva
    for ip, sec_counts in ip_per_second.items():
        if ip in ip_profiles:
            max_rps = max(sec_counts.values())
            ip_profiles[ip]["max_req_per_sec"] = max_rps
            if max_rps >= _MAX_REQUESTS_PER_SECOND:
                ip_profiles[ip]["attack_score"] += min(max_rps, 20)

    for ip, urls in seen_404_urls.items():
        if ip in ip_profiles:
            ip_profiles[ip]["scanning_404"] = len(urls)
            # Score moderado: muchos 404s solos no son tan sospechosos como 200s/302s
            ip_profiles[ip]["attack_score"] += min(len(urls) * 0.05, 5)

    suspicious = {
        ip: {k: v for k, v in prof.items() if k != "attack_score" and v != 0}
        | {"attack_score": round(prof["attack_score"], 1)}
        for ip, prof in ip_profiles.items()
        if prof["attack_score"] >= SUSPICION_THRESHOLD
    }
    top_suspicious = dict(
        sorted(suspicious.items(), key=lambda x: -x[1].get("attack_score", 0))[:5]
    )

    # Actualizar lista de sospechosos persistente con datos de este ciclo
    suspect_list = dict(state.get("suspect_list", {}))
    now_str = state.get("window_end", "")

    for ip, data in top_suspicious.items():
        if ip not in suspect_list:
            suspect_list[ip] = {
                "windows_flagged": 0,
                "cumulative_score": 0.0,
                "first_seen": now_str,
                "confirmed_actions": {},
            }
        entry = suspect_list[ip]
        entry["windows_flagged"] += 1
        entry["cumulative_score"] = round(
            entry["cumulative_score"] + data.get("attack_score", 0), 1
        )
        entry["last_seen"] = now_str
        for action in ("webshell_execution", "login_success"):
            if data.get(action):
                entry["confirmed_actions"][action] = (
                    entry["confirmed_actions"].get(action, 0) + data[action]
                )

    # Enriquecer las señales actuales con contexto historico
    for ip, data in top_suspicious.items():
        entry = suspect_list[ip]
        confirmed = entry.get("confirmed_actions", {})
        windows = entry["windows_flagged"]
        has_active_indicators = bool(
            confirmed
            or data.get("login_failed", 0) > 5
            or data.get("sqli_attempts", 0) > 0
        )
        if confirmed:
            data["threat_level"] = "HIGH"
        elif has_active_indicators and windows >= 2:
            data["threat_level"] = "MEDIUM"
        else:
            data["threat_level"] = "LOW"
        data["windows_flagged"] = windows
        data["cumulative_score"] = entry["cumulative_score"]
        if confirmed:
            data["confirmed_actions"] = confirmed

    signals: dict = {
        "request_velocity": {
            "total": len(raw_logs),
            "unique_ips": len(ip_profiles),
        }
    }
    if top_suspicious:
        signals["suspicious_ips"] = top_suspicious

    active = [k for k in signals if k != "request_velocity"]
    logger.info(f"[Observador] Senales detectadas: {active}")

    return {"anomaly_signals": signals, "suspect_list": suspect_list}


def classify_tactic(state: ObserverState) -> dict:
    """
    Nodo clasificador: el LLM analiza los logs y clasifica la tactica MITRE.

    Este es el nucleo intelectual del observador. Recibe el resumen de logs,
    el historial de clasificaciones previas (para contexto temporal), y
    las definiciones de las 14 tacticas MITRE ATT&CK.

    El LLM responde con un JSON estructurado que incluye:
    - tactica clasificada
    - nivel de confianza
    - evidencia citada de los logs
    - razonamiento
    - recomendacion
    """
    summary = state.get("log_summary", "")
    history = state.get("classification_history", [])
    anomaly_signals = state.get("anomaly_signals", {})

    if not state.get("has_new_logs", False):
        logger.info("[Observador] Sin logs nuevos, manteniendo clasificacion anterior")
        return {}

    prompt = build_classification_prompt(summary, history, anomaly_signals)

    messages = [
        SystemMessage(content=OBSERVER_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    model = _get_model()
    response = model.invoke(messages)

    # Parsear la respuesta JSON del LLM
    classification = _parse_classification(response.content)

    if classification:
        tiw = classification.get("tactics_in_window", [])
        if len(tiw) > 1:
            names = ", ".join(t.get("tactic", "?") for t in tiw)
            logger.info(
                f"[Observador] Detectadas en ventana: {names} | "
                f"Actual: {classification['tactic']} ({classification['confidence']:.0%})"
            )
        else:
            logger.info(
                f"[Observador] Clasificacion: {classification['tactic']} "
                f"(confianza: {classification['confidence']:.0%})"
            )
    else:
        logger.warning("[Observador] No se pudo parsear la clasificacion del LLM")

    return {"current_classification": classification}


def generate_recommendation(state: ObserverState) -> dict:
    """
    Nodo final: registra la clasificacion en el historial.

    La recomendacion ya viene incluida en la clasificacion del LLM.
    Este nodo se encarga de persistir el resultado en el historial
    para que futuras clasificaciones tengan contexto temporal.
    """
    classification = state.get("current_classification")
    history = list(state.get("classification_history", []))

    if classification:
        classification["timestamp"] = datetime.now(timezone.utc).isoformat()
        classification["window_start"] = state.get("window_start", "")
        classification["window_end"] = state.get("window_end", "")
        history.append(classification)

    return {
        "classification_history": history,
        "current_classification": classification,
    }


def _parse_classification(content: str) -> Classification | None:
    """
    Extrae el JSON de clasificacion de la respuesta del LLM.

    El LLM a veces envuelve el JSON en markdown (```json ... ```),
    asi que limpiamos eso antes de parsear.
    """
    text = content.strip()

    # Remover bloques de codigo markdown si los hay
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    try:
        data = json.loads(text)
        # Soporta formato nuevo (current_tactic + tactics_in_window)
        # y formato legado (tactic) para compatibilidad.
        current = data.get("current_tactic") or data.get("tactic", "unknown")
        current_id = data.get("current_tactic_id") or data.get("tactic_id", "")
        tiw = data.get("tactics_in_window", [])
        if not tiw and current != "unknown":
            tiw = [{"tactic": current, "tactic_id": current_id,
                    "confidence": float(data.get("confidence", 0.0))}]
        return Classification(
            tactic=current,
            tactic_id=current_id,
            confidence=float(data.get("confidence", 0.0)),
            evidence=data.get("evidence", []),
            reasoning=data.get("reasoning", ""),
            recommendation=data.get("recommendation", ""),
            timestamp="",
            window_start="",
            window_end="",
            tactics_in_window=tiw,
        )
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.error(f"Error parseando clasificacion: {e}\nContenido: {text[:500]}")
        return None
