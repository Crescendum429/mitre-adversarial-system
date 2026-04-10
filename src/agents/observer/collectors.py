"""
Recolectores de logs para el agente observador.

Estos modulos consultan Loki para obtener los observables disponibles.
El observador solo puede ver lo que un sistema de monitoring real veria:
logs de sistema, eventos de red, logs de aplicacion.

No tiene acceso a:
- Decisiones del agente atacante
- Estado interno de los containers
- Trafico de red en crudo (solo logs que registren eventos)
"""

import logging
import re
from datetime import datetime, timedelta, timezone

from src.infrastructure.loki_client import LokiClient

_APACHE_LOG_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(\w+)\s+(\S+)\s+HTTP/[^"]+"\s+(\d{3})'
)

logger = logging.getLogger(__name__)


class LogCollector:
    """
    Recolecta y prepara logs del lab para el agente observador.

    Consulta Loki por ventana temporal y estructura los resultados
    en un formato que el LLM pueda analizar.
    """

    def __init__(self, loki_client: LokiClient | None = None):
        self.loki = loki_client or LokiClient()

    def collect_window(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict]:
        """
        Recolecta todos los logs del lab en una ventana temporal.

        Excluye logs de infraestructura (Loki, Grafana, Promtail)
        y del container atacante (el observador no debe ver sus acciones directas).
        """
        # Query que captura logs de todos los containers target
        logs = self.loki.query_range(
            query='{job="docker"}',
            start=start,
            end=end,
        )

        # Filtrar: solo logs de containers target (excluir infra y atacante)
        infra_containers = {"loki", "grafana", "promtail", "attacker"}
        filtered = []
        for log in logs:
            container = log.get("labels", {}).get("container", "")
            # El container name puede estar en diferentes labels segun promtail
            container_name = log.get("labels", {}).get("container_name", container)
            if container_name not in infra_containers:
                filtered.append(log)

        logger.info(f"[Observador] Logs recolectados: {len(filtered)} (de {len(logs)} total)")
        return filtered

    def summarize_logs(self, logs: list[dict]) -> str:
        """
        Formatea logs para el LLM en dos secciones:
        1. Resumen agregado de TODOS los logs: colapsa entradas repetidas por patron
           (IP, metodo, ruta, status). Comunica patrones de ataque con bajo token cost.
        2. Ultimas 50 entradas verbatim: preserva la señal de la tactica actual.

        Esto acota el output a ~200-600 lineas independientemente del volumen total.
        """
        if not logs:
            return "No se encontraron logs nuevos en la ventana temporal."

        sorted_logs = sorted(logs, key=lambda l: l.get("timestamp", ""))

        lines = [f"=== RESUMEN AGREGADO ({len(sorted_logs)} entradas totales) ==="]
        lines.extend(self._aggregate_entries(sorted_logs))

        # Notable events: successful responses and POSTs (not scan noise)
        # These are the events that indicate real attacker progress
        notable = self._notable_entries(sorted_logs)
        if notable:
            lines.append(f"\n=== EVENTOS NOTABLES ({len(notable)} con status 2xx/401 o POST) ===")
            lines.append("(Estos son los unicos requests que obtuvieron respuesta real — excluye escaneo 404/403)")
            for log in notable:
                ts = log.get("timestamp", "?")
                container = log.get("labels", {}).get("container_name", "?")
                msg = log.get("message", "").strip()
                if len(msg) > 400:
                    msg = msg[:400] + "..."
                lines.append(f"[{ts}] [{container}] {msg}")

        tail_size = min(30, len(sorted_logs))
        tail = sorted_logs[-tail_size:]
        lines.append(f"\n=== ULTIMAS {tail_size} ENTRADAS CRONOLOGICAS (mas recientes al final) ===")
        for log in tail:
            ts = log.get("timestamp", "?")
            container = log.get("labels", {}).get("container_name", "?")
            msg = log.get("message", "").strip()
            if len(msg) > 300:
                msg = msg[:300] + "..."
            lines.append(f"[{ts}] [{container}] {msg}")

        return "\n".join(lines)

    def _notable_entries(self, logs: list[dict]) -> list[dict]:
        """
        Returns entries that indicate real attacker progress — not just scanner noise.

        Criteria (ordered by signal strength):
        - POST requests: actual form interaction (login attempt, data submission)
        - Status 302: redirect after login success or resource access
        - Status 401: authentication challenge (attacker hit protected resource)
        - Status 500: server error (potential vulnerability triggered)
        - GET with execution keywords in URL + status 200: webshell/RCE active

        Excludes: GET → 200 to generic pages (scanner found page, not attacker progress).
        """
        _EXECUTION_KWS = {"cmd=", "shell", "exec", "passwd", "shadow", "cmd%"}
        _HIGH_SIGNAL_STATUSES = {"302", "401", "500"}
        notable = []
        for log in logs:
            msg = log.get("message", "")
            m = _APACHE_LOG_RE.match(msg)
            if not m:
                continue
            method, url, status = m.group(2), m.group(3).lower(), m.group(4)
            if method == "POST":
                notable.append(log)
            elif status in _HIGH_SIGNAL_STATUSES:
                notable.append(log)
            elif status == "200" and any(kw in url for kw in _EXECUTION_KWS):
                # Webshell or RCE endpoint returning 200 — high signal
                notable.append(log)
        return notable[-20:]

    def _aggregate_entries(self, logs: list[dict]) -> list[str]:
        """
        Agrega logs por patron. Distingue dos categorias:
        - Patrones relevantes (status 200/302/500 o path con keywords de ataque):
          se muestran individualmente, max 150.
        - Ruido de scan (404/403 en rutas sin keywords): se colapsa en una sola
          linea por (container, ip, status) indicando conteo y paths unicos.

        Esto reduce miles de requests de nikto/gobuster a un puñado de lineas.
        """
        _ATTACK_PATH_KWS = {
            "shell", "cmd", "exec", "admin", "login", "wp-", "passwd",
            "shadow", "upload", "config", "include", "backup", "phpmyadmin",
        }
        _INTERESTING_STATUSES = {"200", "302", "500", "401"}

        groups: dict[tuple, dict] = {}

        for log in logs:
            msg = log.get("message", "")
            ts = log.get("timestamp", "")
            container = log.get("labels", {}).get("container_name", "?")

            m = _APACHE_LOG_RE.match(msg)
            if m:
                ip, method, url, status = m.group(1), m.group(2), m.group(3), m.group(4)
                path_base = url.split("?")[0]
                key = (container, ip, method, path_base, status)
            else:
                key = (container, "", "", msg[:100], "")

            if key not in groups:
                groups[key] = {"count": 0, "first": ts, "last": ts}
            g = groups[key]
            g["count"] += 1
            if ts > g["last"]:
                g["last"] = ts

        _EXECUTION_PATH_KWS = {"cmd=", "shell", "exec", "passwd", "shadow", "cmd%"}

        def is_relevant(container, ip, method, path, status):
            # 404/403 always collapse to scan noise regardless of path content.
            # A scanner probing /shell.php and getting 404 is reconnaissance, not execution.
            if status in {"404", "403"}:
                return False
            # POST = actual interaction (login attempt, form submission)
            if method == "POST":
                return True
            # Redirect (login success), auth challenge, server error = meaningful
            if status in {"302", "401", "500"}:
                return True
            # GET 200 to execution-specific paths = webshell/RCE active
            if status == "200":
                path_l = path.lower()
                return any(kw in path_l for kw in _EXECUTION_PATH_KWS)
            return False

        relevant_lines = []
        scan_noise: dict[tuple, dict] = {}  # (container, ip, status) -> {requests, paths}

        for (container, ip, method, path, status), g in groups.items():
            if method and not is_relevant(container, ip, method, path, status):
                nkey = (container, ip, status)
                if nkey not in scan_noise:
                    scan_noise[nkey] = {"requests": 0, "paths": 0,
                                        "first": g["first"], "last": g["last"]}
                n = scan_noise[nkey]
                n["requests"] += g["count"]
                n["paths"] += 1
                if g["last"] > n["last"]:
                    n["last"] = g["last"]
                continue

            count = g["count"]
            t1 = g["first"][11:19] if len(g["first"]) >= 19 else g["first"]
            t2 = g["last"][11:19] if len(g["last"]) >= 19 else g["last"]
            suffix = f"  x{count} ({t1}-{t2})" if count > 1 else f"  ({t1})"
            if method:
                relevant_lines.append(f"[{container}] {ip} {method} {path} -> {status}{suffix}")
            else:
                relevant_lines.append(f"[{container}] {path}{suffix}")

        # Cap relevant lines para casos extremos
        lines = relevant_lines[:150]
        if len(relevant_lines) > 150:
            lines.append(f"... y {len(relevant_lines) - 150} patrones relevantes adicionales")

        for (container, ip, status), n in scan_noise.items():
            t1 = n["first"][11:19] if len(n["first"]) >= 19 else n["first"]
            t2 = n["last"][11:19] if len(n["last"]) >= 19 else n["last"]
            lines.append(
                f"[{container}] {ip} scan -> {status}  "
                f"x{n['requests']} requests ({n['paths']} rutas unicas, {t1}-{t2})"
            )

        return lines
