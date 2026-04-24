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

    def close(self) -> None:
        if self._http and not self._http.is_closed:
            self._http.close()

    def __enter__(self) -> "LokiClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

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
