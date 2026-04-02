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

        tail_size = min(50, len(sorted_logs))
        tail = sorted_logs[-tail_size:]
        lines.append(f"\n=== ULTIMAS {tail_size} ENTRADAS (actividad mas reciente) ===")
        for log in tail:
            ts = log.get("timestamp", "?")
            container = log.get("labels", {}).get("container_name", "?")
            msg = log.get("message", "").strip()
            if len(msg) > 300:
                msg = msg[:300] + "..."
            lines.append(f"[{ts}] [{container}] {msg}")

        return "\n".join(lines)

    def _aggregate_entries(self, logs: list[dict]) -> list[str]:
        """Agrupa logs repetitivos por patron (container, ip, method, path_base, status)."""
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

        lines = []
        for (container, ip, method, path, status), g in groups.items():
            count = g["count"]
            t1 = g["first"][11:19] if len(g["first"]) >= 19 else g["first"]
            t2 = g["last"][11:19] if len(g["last"]) >= 19 else g["last"]
            suffix = f"  x{count} ({t1}-{t2})" if count > 1 else f"  ({t1})"
            if method:
                lines.append(f"[{container}] {ip} {method} {path} -> {status}{suffix}")
            else:
                lines.append(f"[{container}] {path}{suffix}")

        return lines
