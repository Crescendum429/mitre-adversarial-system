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
from dataclasses import dataclass

import docker
from docker.errors import APIError, ContainerError, NotFound

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

        try:
            # exec_run retorna (exit_code, output). demux=True separa stdout/stderr.
            exit_code, output = container.exec_run(
                cmd=["bash", "-c", command],
                demux=True,
                environment={"TERM": "dumb"},
            )

            stdout = output[0].decode("utf-8", errors="replace") if output[0] else ""
            stderr = output[1].decode("utf-8", errors="replace") if output[1] else ""

            # Truncar output excesivo para no saturar el contexto del LLM
            max_output = 8000
            if len(stdout) > max_output:
                stdout = stdout[:max_output] + f"\n... [truncado, {len(stdout)} chars total]"

            result = ExecResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                command=command,
                container=container_name,
            )

            logger.info(f"[{container_name}] Exit code: {exit_code}, output: {len(stdout)} chars")

            if os.getenv("SHOW_TOOL_OUTPUT"):
                output_to_show = stdout.strip() or stderr.strip()
                if output_to_show:
                    logger.info(f"[{container_name}] ↓↓↓ OUTPUT ↓↓↓\n{output_to_show}")

            return result

        except (APIError, ContainerError) as e:
            logger.error(f"[{container_name}] Error ejecutando '{command}': {e}")
            return ExecResult(
                exit_code=-1,
                stdout="",
                stderr=str(e),
                command=command,
                container=container_name,
            )

    def is_container_running(self, container_name: str) -> bool:
        """Verifica si un container esta corriendo."""
        try:
            container = self._client.containers.get(container_name)
            return container.status == "running"
        except NotFound:
            return False

    def get_container_ip(self, container_name: str, network: str = "docker_attack_net") -> str:
        """Obtiene la IP de un container en una red especifica."""
        try:
            container = self._client.containers.get(container_name)
            networks = container.attrs["NetworkSettings"]["Networks"]
            if network in networks:
                return networks[network]["IPAddress"]
        except (NotFound, KeyError):
            pass
        return ""

    def list_lab_containers(self) -> list[dict]:
        """Lista los containers del lab con su estado."""
        lab_names = {"attacker", "dvwa", "loki", "grafana", "promtail"}
        result = []
        for container in self._client.containers.list(all=True):
            if container.name in lab_names:
                result.append({
                    "name": container.name,
                    "status": container.status,
                    "image": container.image.tags[0] if container.image.tags else "unknown",
                })
        return result
