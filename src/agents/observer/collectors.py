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
        Formatea logs para el LLM con dos secciones:
        - Historico agregado: logs anteriores al ultimo minuto, comprimidos por patron
        - Actividad reciente: ultimos 60s completos, en orden cronologico

        Esto preserva la informacion critica de la tactica actual (siempre en recientes)
        mientras reduce el volumen de logs repetitivos del escaneo previo.
        """
        if not logs:
            return "No se encontraron logs nuevos en la ventana temporal."

        sorted_logs = sorted(logs, key=lambda l: l.get("timestamp", ""))

        last_ts_str = sorted_logs[-1].get("timestamp", "")
        try:
            last_dt = datetime.fromisoformat(last_ts_str)
            cutoff_str = (last_dt - timedelta(seconds=60)).isoformat()
        except (ValueError, TypeError):
            cutoff_str = ""

        historical = [l for l in sorted_logs if cutoff_str and l.get("timestamp", "") < cutoff_str]
        recent = [l for l in sorted_logs if not cutoff_str or l.get("timestamp", "") >= cutoff_str]

        lines = []

        if historical:
            lines.append(f"=== HISTORICO AGREGADO ({len(historical)} entradas) ===")
            lines.extend(self._aggregate_entries(historical))

        section_label = (
            f"=== ACTIVIDAD RECIENTE — ultimos 60s ({len(recent)} entradas) ==="
            if historical
            else f"=== LOGS ({len(recent)} entradas) ==="
        )
        lines.append(section_label)
        for log in recent:
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
