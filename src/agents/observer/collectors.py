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
        """Formatea todos los logs de la ventana en orden cronologico para el LLM."""
        if not logs:
            return "No se encontraron logs nuevos en la ventana temporal."

        selected = sorted(logs, key=lambda l: l.get("timestamp", ""))

        lines = []
        for log in selected:
            ts = log.get("timestamp", "?")
            container = log.get("labels", {}).get("container_name", "?")
            msg = log.get("message", "").strip()
            if len(msg) > 300:
                msg = msg[:300] + "..."
            lines.append(f"[{ts}] [{container}] {msg}")

        return "\n".join(lines)
