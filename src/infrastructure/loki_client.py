"""
Cliente para la API de Loki. El agente observador usa este modulo para consultar
logs del lab de simulacion sin tener acceso directo a los containers.

Loki expone una API HTTP con queries en LogQL (similar a PromQL pero para logs).
El observador consulta logs por ventana temporal y por labels (container, job).

Referencia API: https://grafana.com/docs/loki/latest/reference/loki-http-api/
"""

import logging
from datetime import datetime, timezone

import httpx

from src.config.settings import settings

logger = logging.getLogger(__name__)


class LokiClient:
    """
    Cliente HTTP para consultar logs en Loki via su API REST.

    Loki organiza logs con labels (key-value) y permite queries con LogQL.
    Ejemplo de query: {container="dvwa"} |= "login" para buscar logs del
    container dvwa que contengan "login".
    """

    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or settings.loki_url).rstrip("/")
        self._http = httpx.Client(timeout=30.0)

    def query_range(
        self,
        query: str,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 5000,
    ) -> list[dict]:
        """
        Ejecuta una query LogQL sobre un rango temporal.

        Retorna una lista de entradas de log, cada una con timestamp y mensaje.
        Si no se especifica rango, usa los ultimos 15 minutos.
        """
        now = datetime.now(timezone.utc)
        if end is None:
            end = now
        if start is None:
            start = now.replace(second=0, microsecond=0)
            # Default: ultimos 15 minutos
            from datetime import timedelta
            start = end - timedelta(minutes=15)

        params = {
            "query": query,
            "start": self._to_nano(start),
            "end": self._to_nano(end),
            "limit": limit,
            "direction": "backward",
        }

        try:
            resp = self._http.get(f"{self.base_url}/loki/api/v1/query_range", params=params)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            logger.error(f"Error consultando Loki: {e}")
            return []

        return self._parse_response(data)

    def query_logs_by_container(
        self,
        container: str,
        start: datetime | None = None,
        end: datetime | None = None,
        filter_text: str | None = None,
        limit: int = 500,
    ) -> list[dict]:
        """
        Consulta logs de un container especifico.

        Opcionalmente filtra por texto contenido en los logs.
        Este es el metodo principal que usa el observador para recolectar
        logs del target (ej: DVWA) sin acceso directo al container.
        """
        query = f'{{container="{container}"}}'
        if filter_text:
            query += f' |= "{filter_text}"'

        return self.query_range(query, start=start, end=end, limit=limit)

    def query_all_target_logs(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        """
        Consulta logs de todos los containers target (no el atacante ni infra).

        El observador usa esto para tener una vista completa de los observables
        sin saber de antemano que containers son targets.
        """
        # Excluir containers de infraestructura
        query = '{job="docker"} !~ "loki|grafana|promtail|attacker"'
        return self.query_range(query, start=start, end=end, limit=limit)

    def is_healthy(self) -> bool:
        """Verifica que Loki esta respondiendo."""
        try:
            resp = self._http.get(f"{self.base_url}/ready")
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def get_labels(self) -> list[str]:
        """Obtiene los labels disponibles en Loki."""
        try:
            resp = self._http.get(f"{self.base_url}/loki/api/v1/labels")
            resp.raise_for_status()
            return resp.json().get("data", [])
        except httpx.HTTPError:
            return []

    def _parse_response(self, data: dict) -> list[dict]:
        """Parsea la respuesta JSON de Loki a una lista plana de log entries."""
        entries = []
        results = data.get("data", {}).get("result", [])

        for stream in results:
            labels = stream.get("stream", {})
            for value in stream.get("values", []):
                timestamp_ns, message = value
                entries.append({
                    "timestamp": self._from_nano(int(timestamp_ns)),
                    "message": message,
                    "labels": labels,
                })

        entries.sort(key=lambda e: e["timestamp"])
        return entries

    @staticmethod
    def _to_nano(dt: datetime) -> str:
        """Convierte datetime a nanosegundos Unix (formato que espera Loki)."""
        return str(int(dt.timestamp() * 1_000_000_000))

    @staticmethod
    def _from_nano(ns: int) -> str:
        """Convierte nanosegundos Unix a string ISO 8601."""
        dt = datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc)
        return dt.isoformat()
