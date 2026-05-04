"""
Cliente Docker para ejecutar comandos en los containers del lab.

El agente atacante no ejecuta herramientas directamente en el host. En su lugar,
usa este modulo para enviar comandos al container de Kali via Docker SDK.
Esto mantiene el aislamiento: todo el pentesting ocurre dentro de la red Docker.

El flujo es:
  1. El nodo execute_action del atacante recibe un comando (ej: "nmap -sV 10.10.0.10")
  2. Llama a docker_exec() que ejecuta ese comando dentro del container "attacker"
  3. Captura stdout/stderr y lo retorna al nodo para que el LLM lo analice
"""

import logging
import os
import threading
import time
from dataclasses import dataclass

from docker.errors import APIError, ContainerError, NotFound

import docker
from src.config.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Resultado de ejecutar un comando en un container."""

    exit_code: int
    stdout: str
    stderr: str
    command: str
    container: str
    timed_out: bool = False
    duration_ms: int = 0  # tiempo total del exec_run, incluido timeout(1)


# Contadores globales de tool execution para reportes al final de corrida.
DOCKER_STATS: dict[str, float | int] = {
    "exec_count": 0,
    "total_seconds": 0.0,
    "timed_out_count": 0,
    "error_count": 0,
}
_DOCKER_STATS_LOCK = threading.Lock()


def reset_docker_stats() -> None:
    with _DOCKER_STATS_LOCK:
        DOCKER_STATS.update(exec_count=0, total_seconds=0.0, timed_out_count=0, error_count=0)


class DockerClient:
    """
    Wrapper sobre el Docker SDK para ejecutar comandos en containers.

    Usa el socket Docker del host (/var/run/docker.sock) para comunicarse
    con el daemon. Los containers ya deben estar corriendo via docker compose.
    """

    def __init__(self):
        self._client = docker.from_env()

    def exec_in_attacker(self, command: str, timeout: int | None = None) -> ExecResult:
        """
        Ejecuta un comando en el container atacante.

        El timeout previene que comandos bloqueantes (ej: nmap sin -T4) cuelguen
        el agente indefinidamente. Por defecto usa el timeout global de settings.
        """
        return self.exec_in_container(
            container_name=settings.attacker_container,
            command=command,
            timeout=timeout or settings.tool_timeout,
        )

    def exec_in_container(
        self, container_name: str, command: str, timeout: int | None = None
    ) -> ExecResult:
        """Ejecuta un comando en cualquier container del lab."""
        timeout = timeout or settings.tool_timeout

        try:
            container = self._client.containers.get(container_name)
        except NotFound:
            logger.error(f"Container '{container_name}' no encontrado. Verificar docker compose.")
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=f"Container '{container_name}' not found",
                command=command,
                container=container_name,
            )

        logger.info(f"[{container_name}] Ejecutando: {command}")

        _t0 = time.monotonic()
        try:
            # exec_run retorna (exit_code, output). demux=True separa stdout/stderr.
            # Docker SDK exec_run no tiene parametro timeout; se aplica via
            # el binario timeout(1) de coreutils para cortar comandos lentos.
            exit_code, output = container.exec_run(
                cmd=["timeout", str(timeout), "bash", "-c", command],
                demux=True,
                environment={"TERM": "dumb"},
            )

            stdout_full = output[0].decode("utf-8", errors="replace") if output[0] else ""
            stderr_full = output[1].decode("utf-8", errors="replace") if output[1] else ""

            # Truncar output excesivo para no saturar el contexto del LLM.
            # El output completo se conserva en stdout_full para el display.
            max_output = 8000
            if len(stdout_full) > max_output:
                stdout = stdout_full[:max_output] + f"\n... [truncado, {len(stdout_full)} chars total]"
            else:
                stdout = stdout_full
            stderr = stderr_full

            # timeout(1) de coreutils devuelve exit code 124 cuando mata al hijo por tiempo
            timed_out = exit_code == 124
            _dur = time.monotonic() - _t0
            with _DOCKER_STATS_LOCK:
                DOCKER_STATS["exec_count"] = int(DOCKER_STATS["exec_count"]) + 1
                DOCKER_STATS["total_seconds"] = float(DOCKER_STATS["total_seconds"]) + _dur
                if timed_out:
                    DOCKER_STATS["timed_out_count"] = int(DOCKER_STATS["timed_out_count"]) + 1

            result = ExecResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                command=command,
                container=container_name,
                timed_out=timed_out,
                duration_ms=int(_dur * 1000),
            )

            if timed_out:
                logger.warning(
                    f"[{container_name}] Comando excedio timeout de {timeout}s: {command}"
                )

            logger.info(f"[{container_name}] Exit code: {exit_code}, output: {len(stdout_full)} chars")

            if os.getenv("SHOW_TOOL_OUTPUT"):
                # Imprimir el output COMPLETO sin truncar (para visualizacion humana).
                # El LLM sigue recibiendo la version truncada via ExecResult.stdout.
                output_to_show = stdout_full.strip() or stderr_full.strip()
                if output_to_show:
                    logger.info(f"[{container_name}] ↓↓↓ OUTPUT ({len(stdout_full)} chars) ↓↓↓\n{output_to_show}")

            return result

        except (APIError, ContainerError) as e:
            logger.error(f"[{container_name}] Error ejecutando '{command}': {e}")
            with _DOCKER_STATS_LOCK:
                DOCKER_STATS["exec_count"] = int(DOCKER_STATS["exec_count"]) + 1
                DOCKER_STATS["error_count"] = int(DOCKER_STATS["error_count"]) + 1
                DOCKER_STATS["total_seconds"] = float(DOCKER_STATS["total_seconds"]) + (time.monotonic() - _t0)
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                command=command,
                container=container_name,
                duration_ms=int((time.monotonic() - _t0) * 1000),
            )

    def is_container_running(self, container_name: str) -> bool:
        """Verifica si un container esta corriendo."""
        try:
            container = self._client.containers.get(container_name)
            return container.status == "running"
        except NotFound:
            return False
