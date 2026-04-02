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
from datetime import datetime, timezone

from src.infrastructure.loki_client import LokiClient

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
            limit=1000,
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

    def summarize_logs(self, logs: list[dict], max_entries: int = 50) -> str:
        """
        Resume logs para que quepan en el contexto del LLM.

        Prioriza entradas que parecen relevantes para deteccion de ataques
        (errores, logins, conexiones, etc.) sobre entradas rutinarias.
        """
        if not logs:
            return "No se encontraron logs nuevos en la ventana temporal."

        # Priorizar logs que parecen relevantes
        priority_keywords = [
            "wp-login.php", "xmlrpc.php", "wp-admin",
            "Invalid username", "authentication failure",
            "401", "403", "404",
            "' or", "1=1", "union select", "sleep(",
            "shell.php", "cmd=", "/uploads/",
            "/etc/passwd", "suid", "python3 -c", "/root/",
            "robots.txt",
        ]

        def relevance_score(log: dict) -> int:
            msg = log.get("message", "").lower()
            return sum(1 for kw in priority_keywords if kw in msg)

        # Primero por timestamp descendente (recientes primero), luego sort estable
        # por relevancia descendente: logs recientes de alta relevancia quedan arriba,
        # desplazando el ruido residual de tacticas anteriores (ej. nikto scan).
        logs_by_recency = sorted(logs, key=lambda l: l.get("timestamp", ""), reverse=True)
        logs_sorted = sorted(logs_by_recency, key=lambda l: -relevance_score(l))
        selected = logs_sorted[:max_entries]
        # Re-ordenar cronologicamente para presentacion al LLM
        selected.sort(key=lambda l: l.get("timestamp", ""))

        lines = []
        for log in selected:
            ts = log.get("timestamp", "?")
            container = log.get("labels", {}).get("container_name", "?")
            msg = log.get("message", "").strip()
            # Truncar mensajes largos
            if len(msg) > 300:
                msg = msg[:300] + "..."
            lines.append(f"[{ts}] [{container}] {msg}")

        return "\n".join(lines)
