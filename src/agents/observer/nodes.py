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
from urllib.parse import unquote

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

# Firmas literales que SI aparecen en logs Apache reales. Verificado empiricamente:
# - gobuster default UA: "gobuster/3.8.2"
# - wpscan default UA: "WPScan v3.8.28 (https://wpscan.com/wordpress-security-scanner)"
# - nmap NSE default UA: "Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)"
# - curl (utilidad del atacante): "curl/8.19.0"
# NO incluye: nikto (randomiza UAs de navegadores reales), sqlmap/burp/zap/hydra (no usados)
_TOOL_UA_SIGNATURES = {
    "gobuster": "gobuster",
    "wpscan": "wpscan",
    "nmap_nse": "nmap scripting engine",
    "curl": "curl/",
}

# Metodos HTTP estandar. Cualquier metodo fuera de este set es un scanner.
# Nikto envia metodos aleatorios: PROPFIND, TRACK, TRACE, SEARCH, LVIG, XGFU, DEBUG, etc.
_STANDARD_HTTP_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"})

# Rutas sensibles para POST (autenticacion)
_SENSITIVE_POST_PATHS = ("/wp-login", "/login", "/admin", "/xmlrpc", "/wp-admin")

# Shellshock signature en user-agent o URL: () { :; }; o () { _; }
_SHELLSHOCK_RE = re.compile(r"\(\s*\)\s*\{\s*[:;_]")

# Una IP que genera >5 requests en el mismo segundo = herramienta automatizada
_MAX_REQUESTS_PER_SECOND = 5

# Una IP con >5 UAs distintos = rotacion de UA (nikto)
_UA_ROTATION_THRESHOLD = 5

# Una IP con >15 requests totales en la ventana es sospechosa
_TRIAGE_MIN_REQUESTS = 15

# 404 ratio: si >40% de los requests de una IP son 404 y hay al menos 8 = scanner
_TRIAGE_404_RATIO = 0.40
_TRIAGE_404_MIN = 8


# Patrones de comandos webshell ordenados por especificidad. El primer match
# determina la clasificacion. Los patrones mas especificos (acceso a recursos
# protegidos de root, exploits, credenciales) evaluan antes que los genericos.
_CMD_PRIV_ESC_PATTERNS = [
    r"setuid\s*\(\s*0",
    r"os\.setuid",
    r"os\.setgid",
    r"exec\s*['\"]?/bin/(ba)?sh",
    r"/root/(?!\.\.)[\w\-\.]+",
    r"-perm\s+-[u0]?=?[us4]",
    r"-perm\s+-?4000",
    r"\bsudo\s+",
    r"\bsu\s+-",
    r"/etc/sudoers",
    r"\bsuid\b",
    r"\bgtfobins",
    r"\bcapsh\b",
    r"linpeas",
    r"linux-exploit-suggester",
    r"pkexec",
    r"dirty(cow|pipe)",
    r"cve-\d{4}-\d{4,5}",
]

_CMD_CRED_ACCESS_PATTERNS = [
    r"/etc/shadow",
    r"password\.raw-md5",
    r"\.raw-md5",
    r"/home/\w+/password",
    r"/home/\w+/\.ssh",
    r"id_rsa",
    r"\.ssh/(?:id_|authorized_keys)",
    r"wp-config\.php",
    r"mimikatz",
    r"\bcreds?\b",
    r"(?:cat|more|less|head|tail|strings|xxd)\s+[^\s|]*(?:password|hash|credential|secret)",
    r"(?:cat|more|less|head|tail)\s+[^\s|]*\.(?:md5|sha\d+|hash)",
    r"john\s",
    r"hashcat",
    r"/etc/passwd\b",
]

_CMD_EXFIL_PATTERNS = [
    r"\bcurl\s+[^|]*(?:-X\s+)?(?:PUT|POST)",
    r"\bwget\s+[^|]*--post",
    r"\bnc\s+[\w\.]+\s+\d+",
    r"\bncat\s+[\w\.]+\s+\d+",
    r"\bftp\s+[\w\.]+",
    r"scp\s+[\w\.\-/]+\s+[^@]+@",
]

_CMD_IMPACT_PATTERNS = [
    r"\brm\s+-rf?\s+/",
    r"\bdd\s+if=.*of=/dev/",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bmkfs",
    r":\(\)\s*\{",
    r"chmod\s+-R\s+000",
]

_CMD_COLLECTION_PATTERNS = [
    r"\btar\s+.*\b(?:cz|cv)",
    r"\bzip\s+-r",
    r"\b7z\s+a",
    r"\brar\s+a",
    r"find\s+.*-exec\s+cat",
]

_CMD_DISCOVERY_PATTERNS = [
    r"\buname\b",
    r"\bwhoami\b",
    r"\bhostname\b",
    r"\bifconfig\b",
    r"\bip\s+(?:a|addr|link)\b",
    r"\bnetstat\b",
    r"\bss\s+-",
    r"\bps\s+(?:aux|-ef)",
    r"\buptime\b",
    r"\blsb_release\b",
    r"\benv\b",
    r"\bmount\b",
    r"/proc/(?:version|cpuinfo|meminfo|self)",
    r"(?:^|[\s;|])id(?:\s|$|;|\|)",
    r"(?:^|[\s;|])ls(?:\s|$|;|\|)",
    r"(?:^|[\s;|])pwd(?:\s|$|;|\|)",
    r"(?:^|[\s;|])find(?:\s|$|;|\|)",
    r"(?:cat|more|less|head|tail)\s+/etc/(?:os-release|hostname|issue|resolv\.conf)",
    r"(?:cat|ls)\s+/home",
    r"(?:cat|ls)\s+/var/www",
]


def classify_webshell_cmd(cmd: str) -> tuple[str, str]:
    """
    Mapea un comando ejecutado en webshell a la sub-tactica MITRE correspondiente.

    Evaluacion ordenada por especificidad:
      Privilege Escalation → Credential Access → Impact → Exfiltration →
      Collection → Discovery → Execution (default)

    El valor de cmd debe venir URL-decoded.
    """
    cmd_l = cmd.lower()
    for pat in _CMD_PRIV_ESC_PATTERNS:
        if re.search(pat, cmd_l):
            return ("Privilege Escalation", "TA0004")
    for pat in _CMD_CRED_ACCESS_PATTERNS:
        if re.search(pat, cmd_l):
            return ("Credential Access", "TA0006")
    for pat in _CMD_IMPACT_PATTERNS:
        if re.search(pat, cmd_l):
            return ("Impact", "TA0040")
    for pat in _CMD_EXFIL_PATTERNS:
        if re.search(pat, cmd_l):
            return ("Exfiltration", "TA0010")
    for pat in _CMD_COLLECTION_PATTERNS:
        if re.search(pat, cmd_l):
            return ("Collection", "TA0009")
    for pat in _CMD_DISCOVERY_PATTERNS:
        if re.search(pat, cmd_l):
            return ("Discovery", "TA0007")
    return ("Execution", "TA0002")


def extract_webshell_cmd(url: str) -> str | None:
    """
    Extrae y decodifica el parametro ?cmd=... de una URL de webshell.

    Retorna None si no hay cmd= en la URL.
    """
    match = re.search(r"[?&]cmd=([^&\s]+)", url)
    if not match:
        return None
    try:
        return unquote(match.group(1))
    except Exception:
        return match.group(1)


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
    Nodo de triaje: heuristicas calibradas con patrones reales de logs Apache.

    Observaciones empiricas del laboratorio mrrobot (25300+ requests analizados):
    - Gobuster/WPScan/Nmap NSE envian su nombre literal en el user-agent
    - Nikto randomiza UAs de navegadores reales (29 UAs distintos por scan)
    - Nikto usa ~18800 respuestas 404 con exactamente 488 bytes (template uniforme)
    - Nikto envia metodos HTTP no estandar (PROPFIND, TRACK, LVIG, XGFU, DEBUG)
    - Nikto incluye payloads Shellshock "() { :; };" en el user-agent
    - Nmap envia paths "/nmaplowercheck{random}" caracteristicos

    Senales (cualquiera activa el triage):

    T1. TOOL_UA: User-agent contiene firma literal de herramienta conocida
        → gobuster/, wpscan, nmap scripting engine, curl/
    T2. UA_ROTATION: Una IP usa >5 user-agents distintos en la ventana
        → rotacion de UA = nikto o scanner equivalente
    T3. WEIRD_METHODS: IP usa metodos HTTP no estandar
        → PROPFIND, TRACK, DEBUG, LVIG, etc = scanner probing
    T4. SHELLSHOCK: Payload () { :; }; en user-agent o URL
        → intento de explotacion activo
    T5. HIGH_VELOCITY: IP con >5 requests en el mismo segundo
        → paralelismo tipico de herramientas automatizadas
    T6. SCAN_404: IP con >15 requests y >40% de 404s
        → enumeracion de directorios/paths
    T7. UNIFORM_404: >20 respuestas 404 de una IP con body size uniforme
        → template de wordlist scanner
    T8. AUTH_POST: POST a ruta de autenticacion (/wp-login, /admin, etc)
        → intento de credential access
    T9. WEBSHELL_ACTIVE: URL contiene cmd=/cmd%3 y status 2xx
        → ejecucion de comandos via webshell
    """
    raw_logs = state.get("raw_logs", [])

    if not raw_logs:
        logger.info("[Observador] Triaje: sin logs, ciclo terminado")
        return {"triage_result": "no_signal", "anomaly_count": 0}

    # Perfil por IP para analisis agregado
    ip_total: Counter = Counter()
    ip_404: Counter = Counter()
    ip_per_second: dict[str, Counter] = {}
    ip_404_sizes: dict[str, Counter] = {}
    ip_uas: dict[str, set[str]] = {}
    ip_weird_methods: dict[str, set[str]] = {}
    ip_tools: dict[str, str] = {}  # ip -> firma literal detectada
    ip_shellshock: Counter = Counter()

    post_auth_count = 0
    webshell_active = False

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
        url = m.group(6).lower()
        status = m.group(7)
        body_size = m.group(8)
        user_agent = m.group(9).lower()

        ip_total[ip] += 1

        second_key = f"{hour}:{minute}"
        ip_per_second.setdefault(ip, Counter())[second_key] += 1

        if user_agent and user_agent != "-":
            ip_uas.setdefault(ip, set()).add(user_agent)

        # T1: firma literal de herramienta en UA
        if ip not in ip_tools:
            for tool_name, sig in _TOOL_UA_SIGNATURES.items():
                if sig in user_agent:
                    ip_tools[ip] = tool_name
                    break

        # T3: metodo HTTP fuera de lo estandar
        if method not in _STANDARD_HTTP_METHODS:
            ip_weird_methods.setdefault(ip, set()).add(method)

        # T4: shellshock en UA o URL
        if _SHELLSHOCK_RE.search(user_agent) or _SHELLSHOCK_RE.search(url):
            ip_shellshock[ip] += 1

        # 404 tracking
        if status == "404":
            ip_404[ip] += 1
            if body_size.isdigit():
                ip_404_sizes.setdefault(ip, Counter())[body_size] += 1

        # T8: POST a ruta de autenticacion
        if method == "POST" and any(p in url for p in _SENSITIVE_POST_PATHS):
            post_auth_count += 1

        # T9: webshell activa
        if status.startswith("2") and ("cmd=" in url or "cmd%3" in url or "cmd%20" in url):
            webshell_active = True

    signals_found: list[str] = []
    suspicious_ips: set[str] = set()

    # T1: herramientas identificadas por firma literal
    for ip, tool_name in ip_tools.items():
        signals_found.append(f"T1 tool_ua: {tool_name} desde {ip} ({ip_total[ip]} reqs)")
        suspicious_ips.add(ip)

    # T2: rotacion de user-agents (nikto)
    for ip, uas in ip_uas.items():
        if len(uas) >= _UA_ROTATION_THRESHOLD:
            signals_found.append(
                f"T2 ua_rotation: IP {ip} uso {len(uas)} UAs distintos — scanner con rotacion"
            )
            suspicious_ips.add(ip)

    # T3: metodos HTTP no estandar
    for ip, methods in ip_weird_methods.items():
        if methods:
            examples = ", ".join(sorted(methods)[:5])
            signals_found.append(
                f"T3 weird_methods: IP {ip} uso metodos no estandar: {examples}"
            )
            suspicious_ips.add(ip)

    # T4: shellshock
    for ip, count in ip_shellshock.items():
        signals_found.append(f"T4 shellshock: IP {ip} envio {count} payloads Shellshock")
        suspicious_ips.add(ip)

    # T5: alta velocidad de requests
    for ip, sec_counts in ip_per_second.items():
        max_per_sec = max(sec_counts.values())
        if max_per_sec >= _MAX_REQUESTS_PER_SECOND:
            signals_found.append(
                f"T5 velocity: IP {ip} alcanzo {max_per_sec} req/s — automatizacion"
            )
            suspicious_ips.add(ip)

    # T6: alta tasa de 404
    for ip, count_404 in ip_404.items():
        total = ip_total.get(ip, 1)
        if total >= _TRIAGE_MIN_REQUESTS and count_404 / total >= _TRIAGE_404_RATIO:
            signals_found.append(
                f"T6 scan_404: IP {ip} {count_404}/{total} 404s ({count_404/total:.0%})"
            )
            suspicious_ips.add(ip)

    # T7: body size uniforme en 404s (nikto template)
    for ip, size_counter in ip_404_sizes.items():
        total_404 = sum(size_counter.values())
        if total_404 >= 20:
            top_size, top_count = size_counter.most_common(1)[0]
            concentration = top_count / total_404
            if concentration >= 0.70:
                signals_found.append(
                    f"T7 uniform_404: IP {ip} {top_count}/{total_404} 404s "
                    f"con size={top_size} bytes ({concentration:.0%})"
                )
                suspicious_ips.add(ip)

    # T8: POST a autenticacion
    if post_auth_count > 0:
        signals_found.append(f"T8 auth_post: {post_auth_count} POSTs a rutas de login")

    # T9: webshell activa
    if webshell_active:
        signals_found.append("T9 webshell_active: cmd= con status 2xx detectado")

    # T10: IP previamente confirmada como sospechosa sigue activa en esta ventana.
    # Una vez que una IP disparo el triage, cualquier actividad posterior de esa
    # IP debe mantener el flujo activo, aunque el tráfico sea bajo.
    prior_suspects = state.get("suspect_list", {})
    for ip in ip_total:
        if ip in prior_suspects and ip not in suspicious_ips:
            signals_found.append(
                f"T10 known_attacker: IP {ip} ya marcada en ventanas previas "
                f"({ip_total[ip]} reqs en esta ventana)"
            )
            suspicious_ips.add(ip)

    anomaly_count = sum(ip_total[ip] for ip in suspicious_ips)
    anomaly_count = min(anomaly_count, len(raw_logs))

    if signals_found:
        ratio = anomaly_count / max(len(raw_logs), 1)
        logger.info(
            f"[Observador] Triaje: {len(signals_found)} senales "
            f"({anomaly_count}/{len(raw_logs)} logs anomalos, ratio={ratio:.1%})"
        )
        logger.debug(f"[Observador] Senales activas: {signals_found}")
        return {"triage_result": "signal", "anomaly_count": anomaly_count}

    logger.info(f"[Observador] Triaje: sin senal relevante ({len(raw_logs)} logs)")
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
    ip_uas: dict[str, set[str]] = {}
    ip_weird_methods: dict[str, set[str]] = {}
    ip_404_sizes: dict[str, Counter] = {}
    # Comandos ejecutados via webshell, ordenados cronologicamente
    webshell_commands: list[dict] = []

    def get_profile(ip: str) -> dict:
        if ip not in ip_profiles:
            ip_profiles[ip] = {
                "total": 0,
                "attack_score": 0.0,
                "tool_detected": "",
                "distinct_uas": 0,
                "weird_methods": 0,
                "shellshock_attempts": 0,
                "webshell_scan": 0,
                "webshell_execution": 0,
                "webshell_sub_tactics": [],
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
        body_size = m.group(8)
        user_agent = m.group(9).lower()
        url_lower = url.lower()

        profile = get_profile(ip)
        profile["total"] += 1

        sec_key = f"{hour}:{minute}"
        ip_per_second.setdefault(ip, Counter())[sec_key] += 1

        if user_agent and user_agent != "-":
            ip_uas.setdefault(ip, set()).add(user_agent)

        # Firma literal de herramienta en UA
        if not profile["tool_detected"]:
            for tool_name, sig in _TOOL_UA_SIGNATURES.items():
                if sig in user_agent:
                    profile["tool_detected"] = tool_name
                    profile["attack_score"] += 10
                    break

        # Metodo HTTP no estandar
        if method not in _STANDARD_HTTP_METHODS:
            ip_weird_methods.setdefault(ip, set()).add(method)

        # Shellshock
        if _SHELLSHOCK_RE.search(user_agent) or _SHELLSHOCK_RE.search(url_lower):
            profile["shellshock_attempts"] += 1
            profile["attack_score"] += 5

        # Webshell
        if "cmd=" in url_lower or "cmd%3" in url_lower or "shell.php" in url_lower:
            if status == 200:
                profile["webshell_execution"] += 1
                profile["attack_score"] += 10
                # Extraer comando y clasificar sub-tactica
                cmd = extract_webshell_cmd(url)
                if cmd:
                    sub_tactic, sub_id = classify_webshell_cmd(cmd)
                    profile["webshell_sub_tactics"].append(sub_tactic)
                    webshell_commands.append({
                        "timestamp": log.get("timestamp", ""),
                        "ip": ip,
                        "cmd": cmd[:120],
                        "sub_tactic": sub_tactic,
                        "sub_tactic_id": sub_id,
                    })
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
            seen_404_urls.setdefault(ip, set()).add(url)
            if body_size.isdigit():
                ip_404_sizes.setdefault(ip, Counter())[body_size] += 1

    # Rotacion de UA (nikto)
    for ip, uas in ip_uas.items():
        if ip in ip_profiles:
            ip_profiles[ip]["distinct_uas"] = len(uas)
            if len(uas) >= _UA_ROTATION_THRESHOLD:
                ip_profiles[ip]["attack_score"] += 8

    # Metodos HTTP no estandar
    for ip, methods in ip_weird_methods.items():
        if ip in ip_profiles and methods:
            ip_profiles[ip]["weird_methods"] = len(methods)
            ip_profiles[ip]["attack_score"] += 4

    # Velocidad de requests
    for ip, sec_counts in ip_per_second.items():
        if ip in ip_profiles:
            max_rps = max(sec_counts.values())
            ip_profiles[ip]["max_req_per_sec"] = max_rps
            if max_rps >= _MAX_REQUESTS_PER_SECOND:
                ip_profiles[ip]["attack_score"] += min(max_rps, 20)

    # 404 enumeration
    for ip, urls in seen_404_urls.items():
        if ip in ip_profiles:
            ip_profiles[ip]["scanning_404"] = len(urls)
            ip_profiles[ip]["attack_score"] += min(len(urls) * 0.05, 5)

    # Body size uniforme en 404s (template de wordlist scanner)
    for ip, size_counter in ip_404_sizes.items():
        total_404 = sum(size_counter.values())
        if ip in ip_profiles and total_404 >= 20:
            top_size, top_count = size_counter.most_common(1)[0]
            concentration = top_count / total_404
            if concentration >= 0.70:
                ip_profiles[ip]["uniform_404_ratio"] = round(concentration, 2)
                ip_profiles[ip]["attack_score"] += 6

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
    if webshell_commands:
        # Ordenar cronologicamente y quedarse con los mas recientes
        webshell_commands.sort(key=lambda c: c.get("timestamp", ""))
        signals["webshell_commands"] = webshell_commands[-15:]

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
        window_end = state.get("window_end", "") or datetime.now(timezone.utc).isoformat()
        classification["timestamp"] = window_end
        classification["window_start"] = state.get("window_start", "")
        classification["window_end"] = window_end
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
