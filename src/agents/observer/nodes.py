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
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import unquote

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.observer.collectors import LogCollector
from src.agents.observer.memory import (
    compute_traffic_fingerprint,
    get_prior,
)
from src.agents.observer.prompts import OBSERVER_SYSTEM_PROMPT, build_classification_prompt
from src.agents.observer.state import Classification, ObserverState
from src.llm.provider import get_observer_model
from src.ui.session import get_session

logger = logging.getLogger(__name__)

_collector = None
_model = None


# Contadores por nodo para reportar al final de la corrida.
import threading as _threading

OBSERVER_NODE_STATS = {
    "collect_calls": 0,
    "triage_signal": 0,
    "triage_no_signal": 0,
    "refine_calls": 0,
    "classify_calls": 0,
}
_OBS_STATS_LOCK = _threading.Lock()


def reset_observer_stats() -> None:
    for k in list(OBSERVER_NODE_STATS.keys()):
        OBSERVER_NODE_STATS[k] = 0


def reset_observer_singletons() -> None:
    """Limpia los singletons del observer. Usado entre runs back-to-back con
    distinto provider/modelo (ej: ablation runs)."""
    global _collector, _model
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

# Rutas sensibles para POST (autenticacion). Cubre WordPress (wp-login),
# DVWA y CMSs comunes (login.php, /login), paneles admin, OWA, Confluence
# Crowd, etc. Validado contra logs reales de mrrobot, dvwa, dc1 y bpent.
_SENSITIVE_POST_PATHS = (
    "/wp-login", "/wp-admin", "/login", "/admin", "/auth", "/signin",
    "/account/login", "/user/login", "/sso", "/xmlrpc",
)

# Endpoints de RCE/webshell por path. Detectan ejecucion sin depender del
# parametro `?cmd=` en URL (DVWA pone el payload en POST body, p.ej.
# `ip=127.0.0.1;id` a /vulnerabilities/exec/).
# Justificacion: OWASP Web Security Testing Guide v4 — categorias A03 (Injection)
# y A06 (Vulnerable Components) frecuentemente exponen endpoints predecibles.
_EXEC_ENDPOINT_PATTERNS = (
    "/vulnerabilities/exec",  # DVWA
    "/vulnerabilities/sqli",  # DVWA SQLi
    "/vulnerabilities/upload",  # DVWA upload (file inclusion / RCE)
    "/cgi-bin/",
    "/shell.php",
    "/webshell",
    "/cmd.php",
    "/exec.php",
    "/upload.php",
)

# Shellshock signature en user-agent o URL: () { :; }; o () { _; }
_SHELLSHOCK_RE = re.compile(r"\(\s*\)\s*\{\s*[:;_]")

# CVE-2021-44228 Log4Shell JNDI injection: ${jndi:ldap://...}, ${jndi:rmi://...},
# ${jndi:dns://...}. Aparece en headers (User-Agent, X-Api-Version) o URL query.
# Ref: Apache, CVE-2021-44228, NIST SP 800-155.
_LOG4SHELL_RE = re.compile(
    r"\$\{(?:jndi|lower|upper|env|sys|date|::-)[:\s\}]",
    re.IGNORECASE,
)

# CVE-2017-5638 Struts2 OGNL: payload en Content-Type con %{...}
# CVE-2022-26134 Confluence OGNL: payload en URI con ${...}
# Ambos se detectan por expresion OGNL en lugar raro del request.
_OGNL_RE = re.compile(
    r"%\{.*?(?:Runtime|ProcessBuilder|ognl|#_?memberAccess|@java\.lang)",
    re.IGNORECASE | re.DOTALL,
)
_OGNL_CONFLUENCE_RE = re.compile(
    r"\$\{.*?(?:Runtime|ProcessBuilder|ognl|getRuntime|exec\()",
    re.IGNORECASE | re.DOTALL,
)

# CVE-2014-6271 Shellshock extendido — incluye variantes con distintos
# caracteres entre () y {.
_SHELLSHOCK_EXTENDED_RE = re.compile(r"\(\s*\)\s*\{[^}]{0,20}\}[\s;]", re.IGNORECASE)

# Apache Solr Velocity RCE (CVE-2019-17558): params.resource.loader.enabled=true.
# Tambien capturamos el endpoint tipico /solr/<core>/select?wt=velocity (la
# explotacion publica usa wt=velocity con un Velocity template inline).
_SOLR_VELOCITY_RE = re.compile(
    r"params\.resource\.loader\.enabled"
    r"|VelocityResponseWriter"
    r"|/solr/[^/?]+/[^?]*\?[^ ]*wt=velocity",
    re.IGNORECASE,
)

# Spring4Shell (CVE-2022-22965): class.module.classLoader.resources...
_SPRING4SHELL_RE = re.compile(
    r"class\.module\.classLoader|class\.getResource",
    re.IGNORECASE,
)

# Una IP que genera >5 requests en el mismo segundo = herramienta automatizada
_MAX_REQUESTS_PER_SECOND = 5

# Una IP con >=5 UAs distintos = rotacion de UA (nikto). Calibrado en mrrobot:
# Nikto envia 29 UAs distintos por scan, pero queremos detectar scans parciales.
_UA_ROTATION_THRESHOLD = 5

# Una IP con >15 requests totales en la ventana es sospechosa
_TRIAGE_MIN_REQUESTS = 15

# 404 ratio: si >40% de los requests de una IP son 404 y hay al menos 8 = scanner
_TRIAGE_404_RATIO = 0.40
_TRIAGE_404_MIN = 8

# Un IP marcado como sospechoso en una ventana se mantiene en el suspect_list
# durante este numero de ventanas silenciosas. Pasado ese punto, se purga
# para evitar acumulacion infinita de estado.
_SUSPECT_TTL_WINDOWS = 5

# Marcadores SQLi compartidos entre triage y detect. Cubre payloads clasicos
# (' or 1=1, UNION SELECT, sleep()) y variantes ofuscadas: comentarios inline
# (UNION/**/SELECT) usados por sqlmap, comilla URL-encoded (%27), boolean
# blind con SLEEP/BENCHMARK, y waitfor delay (MSSQL). El match se hace tras
# urllib.parse.unquote() del URL para capturar payloads URL-encoded.
_SQLI_MARKERS = (
    "' or", "1=1", "union select", "union all select",
    "union/**/select", "union%20select",
    "sleep(", "benchmark(", "waitfor delay",
    "' and", " and 1=", " or 1=",
    "%27", "%20or%20", "%20union%20", "%2520",
    "drop table", "into outfile", "load_file(",
    "information_schema",
)


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

    Soporta tres formatos:
      1. `?cmd=id` — sin encoding
      2. `?cmd=cat%20%2Fetc%2Fpasswd` — valor URL-encoded (comun)
      3. `?cmd%3Did` — `=` doblemente encoded como `%3D` (raro pero sucede)

    Importante: matchea sobre la URL CRUDA (encoded) y solo decodifica el
    valor capturado. Decodificar la URL antes rompe el regex porque `%20`
    se vuelve espacio y `[^&\\s]+` se corta.

    Retorna None si no hay cmd= en la URL.
    """
    # Formato 1 y 2: cmd=valor (el valor puede estar URL-encoded)
    match = re.search(r"[?&]cmd=([^&\s]+)", url)
    if not match:
        # Formato 3: cmd%3D<valor> (el = esta URL-encoded como %3D)
        match = re.search(r"[?&]cmd%3[dD]([^&\s]+)", url)
    if not match:
        return None
    try:
        return unquote(match.group(1))
    except Exception:
        return match.group(1)


def _decay_suspects(
    suspect_list: dict, active_ips: set[str] | None = None
) -> dict:
    """
    Aplica TTL al suspect_list para evitar acumulacion infinita de IPs.
    IPs ausentes en la ventana actual incrementan silent_windows; cuando
    superan _SUSPECT_TTL_WINDOWS y no tienen acciones confirmadas, se purgan.
    Las IPs con confirmed_actions (webshell_execution, login_success) nunca
    expiran porque representan compromiso confirmado.
    """
    active = active_ips or set()
    out: dict = {}
    for ip, entry in suspect_list.items():
        new_entry = dict(entry)
        if ip not in active:
            new_entry["silent_windows"] = new_entry.get("silent_windows", 0) + 1
            confirmed = new_entry.get("confirmed_actions") or {}
            if not confirmed and new_entry["silent_windows"] >= _SUSPECT_TTL_WINDOWS:
                continue
        out[ip] = new_entry
    return out


def _build_ip_profiles(raw_logs: list[dict]) -> dict:
    """
    Pasada unica sobre raw_logs: construye perfiles por IP usados tanto por
    el triage como por la deteccion. Antes ambos nodos parseaban los mismos
    logs por separado (~60% codigo duplicado). Ahora comparten la pasada.

    Devuelve un dict con:
      - ip_profiles: contadores por IP (total, 404, login, webshell, sqli, etc)
      - ip_per_second: dict[ip, Counter[secondkey]]
      - ip_uas: dict[ip, set[user_agent]]
      - ip_weird_methods: dict[ip, set[method]]
      - ip_404_sizes: dict[ip, Counter[body_size]]
      - seen_404_urls: dict[ip, set[url]]
      - webshell_commands: lista cronologica de cmds ejecutados via webshell
      - post_auth_count: total de POSTs a rutas de autenticacion
      - auth_post_per_ip: Counter de POSTs a /login por IP (para detectar bruteforce)
    """
    ip_profiles: dict[str, dict] = {}
    ip_per_second: dict[str, Counter] = {}
    ip_uas: dict[str, set[str]] = {}
    ip_weird_methods: dict[str, set[str]] = {}
    ip_404_sizes: dict[str, Counter] = {}
    seen_404_urls: dict[str, set] = {}
    webshell_commands: list[dict] = []
    auth_post_per_ip: Counter = Counter()
    post_auth_count = 0

    def get_profile(ip: str) -> dict:
        if ip not in ip_profiles:
            ip_profiles[ip] = {
                "total": 0,
                "404_count": 0,
                "shellshock_attempts": 0,
                "log4shell_attempts": 0,
                "ognl_attempts": 0,
                "solr_velocity_attempts": 0,
                "spring4shell_attempts": 0,
                "tool_detected": "",
                "webshell_scan": 0,
                "webshell_execution": 0,
                "webshell_sub_tactics": [],
                "login_failed": 0,
                "login_success": 0,
                "sqli_attempts": 0,
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

        ip_per_second.setdefault(ip, Counter())[f"{hour}:{minute}"] += 1
        if user_agent and user_agent != "-":
            ip_uas.setdefault(ip, set()).add(user_agent)

        if not profile["tool_detected"]:
            for tool_name, sig in _TOOL_UA_SIGNATURES.items():
                if sig in user_agent:
                    profile["tool_detected"] = tool_name
                    break

        if method not in _STANDARD_HTTP_METHODS:
            ip_weird_methods.setdefault(ip, set()).add(method)

        if _SHELLSHOCK_RE.search(user_agent) or _SHELLSHOCK_RE.search(url_lower):
            profile["shellshock_attempts"] += 1

        # CVE-specific injection signatures en URL o User-Agent.
        # Ref: CVE-2021-44228 (Log4Shell), CVE-2017-5638 (Struts2),
        # CVE-2022-26134 (Confluence), CVE-2019-17558 (Solr), CVE-2022-22965 (Spring).
        # Buscamos tanto en la version cruda (UA suele venir plaintext) como en
        # la URL-decoded — los exploits comunmente envian payloads encoded como
        # %24%7bjndi:ldap... que solo matchean tras unquote.
        full_request = f"{url} {user_agent}"
        try:
            full_request_decoded = f"{unquote(url)} {user_agent}"
        except Exception:
            full_request_decoded = full_request
        if _LOG4SHELL_RE.search(full_request) or _LOG4SHELL_RE.search(full_request_decoded):
            profile["log4shell_attempts"] += 1
        if (_OGNL_RE.search(full_request) or _OGNL_CONFLUENCE_RE.search(full_request)
                or _OGNL_RE.search(full_request_decoded)
                or _OGNL_CONFLUENCE_RE.search(full_request_decoded)):
            profile["ognl_attempts"] += 1
        if _SOLR_VELOCITY_RE.search(full_request) or _SOLR_VELOCITY_RE.search(full_request_decoded):
            profile["solr_velocity_attempts"] += 1
        if _SPRING4SHELL_RE.search(full_request) or _SPRING4SHELL_RE.search(full_request_decoded):
            profile["spring4shell_attempts"] += 1

        # Webshell/RCE detection. Dos modos:
        # (a) `?cmd=` o `?exec=` en URL con 200 -> webshell GET clasica
        # (b) POST a endpoint de ejecucion conocido con 200 -> RCE via form
        #     (DVWA exec/, file uploads, etc). En POST el payload no esta en
        #     URL, asi que no podemos clasificar sub_tactic; se asume Execution.
        is_cmd_url = "cmd=" in url_lower or "cmd%3" in url_lower or "shell.php" in url_lower
        is_exec_endpoint = any(p in url_lower for p in _EXEC_ENDPOINT_PATTERNS)

        if is_cmd_url:
            if status == 200:
                profile["webshell_execution"] += 1
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
        elif is_exec_endpoint and method == "POST" and status == 200:
            profile["webshell_execution"] += 1
            profile["webshell_sub_tactics"].append("Execution")
            webshell_commands.append({
                "timestamp": log.get("timestamp", ""),
                "ip": ip,
                "cmd": f"POST {url[:80]} (form payload)",
                "sub_tactic": "Execution",
                "sub_tactic_id": "TA0002",
            })

        # Login success/failure. Generalizado: cualquier POST a path tipo
        # login + 302 = success (redireccion post-auth en DVWA, WordPress,
        # phpMyAdmin, Confluence Crowd, OWA, etc). 200 = formulario reenviado
        # con error o token invalido.
        is_login_path = any(p in url_lower for p in (
            "/wp-login", "/login", "/signin", "/auth/login", "/account/login",
        ))
        if is_login_path and method == "POST":
            if status == 302:
                profile["login_success"] += 1
            else:
                profile["login_failed"] += 1

        # SQLi detection contra version decodificada — sqlmap envia payloads
        # URL-encoded (' = %27, espacios = %20 o +) que serian invisibles si
        # solo miramos url_lower crudo.
        try:
            url_decoded_lower = unquote(url).lower()
        except Exception:
            url_decoded_lower = url_lower
        if any(marker in url_decoded_lower or marker in url_lower
               for marker in _SQLI_MARKERS):
            profile["sqli_attempts"] += 1

        if method == "POST" and any(p in url_lower for p in _SENSITIVE_POST_PATHS):
            post_auth_count += 1
            auth_post_per_ip[ip] += 1

        if status == 404:
            profile["404_count"] += 1
            seen_404_urls.setdefault(ip, set()).add(url)
            if body_size.isdigit():
                ip_404_sizes.setdefault(ip, Counter())[body_size] += 1

    return {
        "ip_profiles": ip_profiles,
        "ip_per_second": ip_per_second,
        "ip_uas": ip_uas,
        "ip_weird_methods": ip_weird_methods,
        "ip_404_sizes": ip_404_sizes,
        "seen_404_urls": seen_404_urls,
        "webshell_commands": webshell_commands,
        "auth_post_per_ip": auth_post_per_ip,
        "post_auth_count": post_auth_count,
    }


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

    get_session().observer_event(
        "window_start",
        window_start=start_str or "",
        window_end=end_str or "",
    )

    collector = _get_collector()
    raw_logs = collector.collect_window(start=start, end=end)
    summary = collector.summarize_logs(raw_logs)

    has_new = len(raw_logs) > 0
    with _OBS_STATS_LOCK:
        OBSERVER_NODE_STATS["collect_calls"] += 1
    logger.info(f"[Observador] Logs recolectados: {len(raw_logs)}, nuevos: {has_new}")

    # Memoria del observer: si la primera ventana tiene logs, computa el
    # fingerprint del patron de trafico y consulta el prior. Solo se hace una
    # vez por sesion (cuando traffic_fingerprint aun no esta seteado).
    update_dict = {
        "raw_logs": raw_logs,
        "log_summary": summary,
        "has_new_logs": has_new,
    }
    if has_new and not state.get("traffic_fingerprint"):
        fp = compute_traffic_fingerprint(raw_logs)
        if fp:
            prior = get_prior(fp)
            update_dict["traffic_fingerprint"] = fp
            update_dict["baseline_prior"] = prior
            if prior:
                logger.info(
                    f"[ObserverMemory] Match fp={fp}: "
                    f"{prior.get('windows_observed', 0)} ventanas previas, "
                    f"top tactica={list(prior.get('tactic_distribution', {}).items())[:1]}"
                )
                get_session().observer_event(
                    "memory_match",
                    fingerprint=fp,
                    windows_observed=prior.get("windows_observed", 0),
                )
            else:
                logger.info(f"[ObserverMemory] Target nuevo, fp={fp}")

    return update_dict


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
        with _OBS_STATS_LOCK:
            OBSERVER_NODE_STATS["triage_no_signal"] += 1
        logger.info("[Observador] Triaje: sin logs, ciclo terminado")
        return {"triage_result": "no_signal", "anomaly_count": 0}

    # Ablation: en modo pure-LLM saltamos las heuristicas T1-T10 y siempre
    # pasamos al LLM. Esto sirve como baseline para medir el aporte del triage.
    if not state.get("use_heuristics", True):
        with _OBS_STATS_LOCK:
            OBSERVER_NODE_STATS["triage_signal"] += 1
        logger.info(
            f"[Observador] Triaje (pure-LLM): {len(raw_logs)} logs, pass-through"
        )
        return {"triage_result": "signal", "anomaly_count": len(raw_logs)}

    p = _build_ip_profiles(raw_logs)
    profiles = p["ip_profiles"]

    signals_found: list[str] = []
    suspicious_ips: set[str] = set()

    # T1: herramientas identificadas por firma literal en UA
    for ip, prof in profiles.items():
        if prof["tool_detected"]:
            signals_found.append(
                f"T1 tool_ua: {prof['tool_detected']} desde {ip} ({prof['total']} reqs)"
            )
            suspicious_ips.add(ip)

    # T2: rotacion de user-agents (nikto)
    for ip, uas in p["ip_uas"].items():
        if len(uas) >= _UA_ROTATION_THRESHOLD:
            signals_found.append(
                f"T2 ua_rotation: IP {ip} uso {len(uas)} UAs distintos — scanner con rotacion"
            )
            suspicious_ips.add(ip)

    # T3: metodos HTTP no estandar
    for ip, methods in p["ip_weird_methods"].items():
        if methods:
            examples = ", ".join(sorted(methods)[:5])
            signals_found.append(
                f"T3 weird_methods: IP {ip} uso metodos no estandar: {examples}"
            )
            suspicious_ips.add(ip)

    # T4: shellshock
    for ip, prof in profiles.items():
        if prof["shellshock_attempts"]:
            signals_found.append(
                f"T4 shellshock: IP {ip} envio {prof['shellshock_attempts']} payloads Shellshock"
            )
            suspicious_ips.add(ip)

    # T4b: Log4Shell (CVE-2021-44228). Payload ${jndi:ldap://...} en cualquier
    # header o URL. Caracteristica unica: no hay falsos positivos porque ${jndi:
    # no es sintaxis valida HTTP/HTML.
    for ip, prof in profiles.items():
        if prof.get("log4shell_attempts", 0):
            signals_found.append(
                f"T4b log4shell: IP {ip} envio {prof['log4shell_attempts']} payloads JNDI "
                f"(${{jndi:...}}) — CVE-2021-44228 intento de RCE"
            )
            suspicious_ips.add(ip)

    # T4c: OGNL injection (Struts2 CVE-2017-5638, Confluence CVE-2022-26134).
    # Payload %{...Runtime} en Content-Type (Struts) o URI (Confluence).
    for ip, prof in profiles.items():
        if prof.get("ognl_attempts", 0):
            signals_found.append(
                f"T4c ognl_injection: IP {ip} envio {prof['ognl_attempts']} payloads OGNL "
                f"— CVE-2017-5638/CVE-2022-26134 RCE pre-auth"
            )
            suspicious_ips.add(ip)

    # T4d: Solr Velocity Template (CVE-2019-17558).
    for ip, prof in profiles.items():
        if prof.get("solr_velocity_attempts", 0):
            signals_found.append(
                f"T4d solr_velocity: IP {ip} habilito VelocityResponseWriter "
                f"— CVE-2019-17558 RCE Solr"
            )
            suspicious_ips.add(ip)

    # T4e: Spring4Shell (CVE-2022-22965).
    for ip, prof in profiles.items():
        if prof.get("spring4shell_attempts", 0):
            signals_found.append(
                f"T4e spring4shell: IP {ip} manipulo class.module.classLoader "
                f"— CVE-2022-22965"
            )
            suspicious_ips.add(ip)

    # T5: alta velocidad de requests
    for ip, sec_counts in p["ip_per_second"].items():
        max_per_sec = max(sec_counts.values())
        if max_per_sec >= _MAX_REQUESTS_PER_SECOND:
            signals_found.append(
                f"T5 velocity: IP {ip} alcanzo {max_per_sec} req/s — automatizacion"
            )
            suspicious_ips.add(ip)

    # T6: alta tasa de 404
    for ip, prof in profiles.items():
        total = prof["total"]
        count_404 = prof["404_count"]
        if total >= _TRIAGE_MIN_REQUESTS and count_404 / total >= _TRIAGE_404_RATIO:
            signals_found.append(
                f"T6 scan_404: IP {ip} {count_404}/{total} 404s ({count_404/total:.0%})"
            )
            suspicious_ips.add(ip)

    # T7: body size uniforme en 404s (nikto template)
    for ip, size_counter in p["ip_404_sizes"].items():
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

    # T8: POST a autenticacion (bruteforce si misma IP repite)
    if p["post_auth_count"] > 0:
        signals_found.append(
            f"T8 auth_post: {p['post_auth_count']} POSTs a rutas de login"
        )
        for ip, count in p["auth_post_per_ip"].items():
            if count >= 3:
                suspicious_ips.add(ip)

    # T9: webshell activa
    webshell_ips = [ip for ip, prof in profiles.items() if prof["webshell_execution"]]
    if webshell_ips:
        signals_found.append(
            f"T9 webshell_active: ejecucion confirmada desde {','.join(webshell_ips)}"
        )
        suspicious_ips.update(webshell_ips)

    # T10: IP previamente confirmada como sospechosa sigue activa en esta ventana.
    # Una vez que una IP disparo el triage, cualquier actividad posterior de esa
    # IP debe mantener el flujo activo, aunque el trafico sea bajo.
    prior_suspects = state.get("suspect_list", {})
    for ip, prof in profiles.items():
        if ip in prior_suspects and ip not in suspicious_ips:
            signals_found.append(
                f"T10 known_attacker: IP {ip} ya marcada en ventanas previas "
                f"({prof['total']} reqs en esta ventana)"
            )
            suspicious_ips.add(ip)

    anomaly_count = sum(profiles[ip]["total"] for ip in suspicious_ips if ip in profiles)
    anomaly_count = min(anomaly_count, len(raw_logs))

    if signals_found:
        with _OBS_STATS_LOCK:
            OBSERVER_NODE_STATS["triage_signal"] += 1
        ratio = anomaly_count / max(len(raw_logs), 1)
        logger.info(
            f"[Observador] Triaje: {len(signals_found)} senales "
            f"({anomaly_count}/{len(raw_logs)} logs anomalos, ratio={ratio:.1%})"
        )
        logger.debug(f"[Observador] Senales activas: {signals_found}")
        get_session().observer_event(
            "triage",
            result="signal",
            signals_count=len(signals_found),
            signals=signals_found[:10],
            anomaly_count=anomaly_count,
            total_logs=len(raw_logs),
        )
        return {"triage_result": "signal", "anomaly_count": anomaly_count}

    with _OBS_STATS_LOCK:
        OBSERVER_NODE_STATS["triage_no_signal"] += 1
    logger.info(f"[Observador] Triaje: sin senal relevante ({len(raw_logs)} logs)")
    get_session().observer_event(
        "triage",
        result="no_signal",
        signals_count=0,
        total_logs=len(raw_logs),
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
    with _OBS_STATS_LOCK:
        OBSERVER_NODE_STATS["refine_calls"] += 1
    get_session().observer_event(
        "refine",
        count=refinement_count,
        prev_tactic=prev_classification.get("tactic", "?") if prev_classification else "?",
        prev_confidence=prev_classification.get("confidence", 0.0) if prev_classification else 0.0,
    )

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
        return {
            "anomaly_signals": {},
            "suspect_list": _decay_suspects(state.get("suspect_list", {})),
        }

    # Ablation: en modo pure-LLM no computamos signals ni suspect_list.
    # El LLM clasifica solo con el log_summary crudo.
    if not state.get("use_heuristics", True):
        return {
            "anomaly_signals": {},
            "suspect_list": state.get("suspect_list", {}),
        }

    SUSPICION_THRESHOLD = 3

    p = _build_ip_profiles(raw_logs)
    ip_profiles = p["ip_profiles"]
    webshell_commands = p["webshell_commands"]

    # Scoring sobre los perfiles construidos en la pasada compartida
    for ip, prof in ip_profiles.items():
        score = 0.0
        if prof["tool_detected"]:
            score += 10
        score += 5 * prof["shellshock_attempts"]
        score += 10 * prof["webshell_execution"]
        score += 0.5 * prof["webshell_scan"]
        score += 10 * prof["login_success"]
        score += 1 * prof["login_failed"]
        score += 2 * prof["sqli_attempts"]

        distinct_uas = len(p["ip_uas"].get(ip, ()))
        if distinct_uas >= _UA_ROTATION_THRESHOLD:
            score += 8
        prof["distinct_uas"] = distinct_uas

        weird = p["ip_weird_methods"].get(ip, set())
        prof["weird_methods"] = len(weird)
        if weird:
            score += 4

        sec_counts = p["ip_per_second"].get(ip, {})
        max_rps = max(sec_counts.values()) if sec_counts else 0
        prof["max_req_per_sec"] = max_rps
        if max_rps >= _MAX_REQUESTS_PER_SECOND:
            score += min(max_rps, 20)

        urls_404 = p["seen_404_urls"].get(ip, set())
        if urls_404:
            prof["scanning_404"] = len(urls_404)
            score += min(len(urls_404) * 0.05, 5)

        size_counter = p["ip_404_sizes"].get(ip, Counter())
        total_404 = sum(size_counter.values())
        if total_404 >= 20:
            top_size, top_count = size_counter.most_common(1)[0]
            concentration = top_count / total_404
            if concentration >= 0.70:
                prof["uniform_404_ratio"] = round(concentration, 2)
                score += 6

        prof["attack_score"] = round(score, 1)

    suspicious = {
        ip: {k: v for k, v in prof.items() if k != "attack_score" and v != 0}
        | {"attack_score": prof["attack_score"]}
        for ip, prof in ip_profiles.items()
        if prof["attack_score"] >= SUSPICION_THRESHOLD
    }
    top_suspicious = dict(
        sorted(suspicious.items(), key=lambda x: -x[1].get("attack_score", 0))[:5]
    )

    # Decay primero: incrementa silent_windows en IPs ausentes y purga las
    # que llevan demasiadas ventanas sin actividad.
    suspect_list = _decay_suspects(state.get("suspect_list", {}), active_ips=set(top_suspicious))
    now_str = state.get("window_end", "")

    for ip, data in top_suspicious.items():
        if ip not in suspect_list:
            suspect_list[ip] = {
                "windows_flagged": 0,
                "cumulative_score": 0.0,
                "first_seen": now_str,
                "confirmed_actions": {},
                "silent_windows": 0,
            }
        entry = suspect_list[ip]
        entry["windows_flagged"] += 1
        entry["cumulative_score"] = round(
            entry["cumulative_score"] + data.get("attack_score", 0), 1
        )
        entry["last_seen"] = now_str
        entry["silent_windows"] = 0
        for action in ("webshell_execution", "login_success"):
            if data.get(action):
                entry["confirmed_actions"][action] = (
                    entry["confirmed_actions"].get(action, 0) + data[action]
                )

    # Enriquecer las senales actuales con contexto historico
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
    baseline_prior = state.get("baseline_prior")

    if not state.get("has_new_logs", False):
        logger.info("[Observador] Sin logs nuevos, manteniendo clasificacion anterior")
        return {}

    prompt = build_classification_prompt(
        summary, history, anomaly_signals, baseline_prior=baseline_prior,
    )

    from src.llm.provider import make_cacheable_system_content
    messages = [
        SystemMessage(content=make_cacheable_system_content(
            OBSERVER_SYSTEM_PROMPT, role="observer"
        )),
        HumanMessage(content=prompt),
    ]

    model = _get_model()
    _start_call = time.monotonic()
    response = model.invoke(messages)
    _latency_ms = int((time.monotonic() - _start_call) * 1000)
    with _OBS_STATS_LOCK:
        OBSERVER_NODE_STATS["classify_calls"] += 1

    # Parsear la respuesta JSON del LLM
    classification = _parse_classification(response.content)
    if classification is not None:
        classification["llm_latency_ms"] = _latency_ms

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
        get_session().observer_event(
            "classify",
            tactic=classification.get("tactic", "?"),
            confidence=classification.get("confidence", 0.0),
            tactics_in_window=[t.get("tactic", "") for t in tiw],
            evidence=classification.get("evidence", [])[:5],
            reasoning=str(classification.get("reasoning", ""))[:500],
            refinement_count=state.get("refinement_count", 0),
            llm_latency_ms=_latency_ms,
        )
    else:
        logger.warning("[Observador] No se pudo parsear la clasificacion del LLM")
        get_session().observer_event(
            "error", message="LLM no produjo JSON parseable",
        )

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
        "refinement_count": 0,
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
