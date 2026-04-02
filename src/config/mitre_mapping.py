"""
Mapping completo del framework MITRE ATT&CK para este sistema.

Define las 14 tacticas principales, las tecnicas seleccionadas para implementacion,
y los observables esperados que cada tecnica genera en logs. El agente observador
usa estos observables como referencia para clasificar la tactica activa.

Fuente: https://attack.mitre.org/
Referencia: MITRE ATT&CK Enterprise Matrix v16 (2025)
"""

from dataclasses import dataclass, field


@dataclass
class Technique:
    """Una tecnica especifica de MITRE ATT&CK."""

    id: str
    name: str
    description: str
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    log_indicators: list[str] = field(default_factory=list)


@dataclass
class Tactic:
    """
    Una tactica MITRE ATT&CK. Representa un objetivo tactico del adversario
    (ej: obtener acceso inicial, escalar privilegios). Cada tactica contiene
    una o mas tecnicas que son los metodos concretos para lograr ese objetivo.
    """

    id: str
    name: str
    description: str
    order: int
    techniques: list[Technique] = field(default_factory=list)
    implemented: bool = False


# ---------------------------------------------------------------------------
# Definicion completa de las 14 tacticas MITRE ATT&CK
# Las marcadas con implemented=True son las que el agente atacante puede ejecutar.
# El observador clasifica entre las 14 sin importar cuales estan implementadas.
# ---------------------------------------------------------------------------

TACTICS: dict[str, Tactic] = {
    "reconnaissance": Tactic(
        id="TA0043",
        name="Reconnaissance",
        description=(
            "El adversario recopila informacion sobre el objetivo que puede usarse "
            "para planificar operaciones futuras. Incluye escaneo de puertos, "
            "enumeracion de servicios, y descubrimiento de infraestructura."
        ),
        order=1,
        implemented=True,
        techniques=[
            Technique(
                id="T1046",
                name="Network Service Discovery",
                description="Escaneo de puertos y servicios de red del objetivo.",
                tools=["nmap"],
                commands=[
                    "nmap -sV -sC {target}",
                    "nmap -p- --min-rate 1000 {target}",
                    "nmap -sU --top-ports 100 {target}",
                ],
                log_indicators=[
                    "SYN scan detected",
                    "port scan",
                    "connection to multiple ports",
                    "rapid sequential connections",
                    "nmap",
                ],
            ),
        ],
    ),
    "initial_access": Tactic(
        id="TA0001",
        name="Initial Access",
        description=(
            "El adversario intenta obtener acceso al sistema objetivo. "
            "Incluye explotacion de servicios expuestos, uso de credenciales "
            "validas, y explotacion de aplicaciones web."
        ),
        order=2,
        implemented=True,
        techniques=[
            Technique(
                id="T1078",
                name="Valid Accounts",
                description="Uso de credenciales legitimas obtenidas por fuerza bruta u otros medios.",
                tools=["hydra"],
                commands=[
                    "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} ssh",
                    "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form",
                ],
                log_indicators=[
                    "failed login",
                    "authentication failure",
                    "invalid password",
                    "brute force",
                    "multiple login attempts",
                    "successful login after failures",
                ],
            ),
            Technique(
                id="T1190",
                name="Exploit Public-Facing Application",
                description="Explotacion de vulnerabilidades en aplicaciones web (SQLi, RCE).",
                tools=["sqlmap", "curl"],
                commands=[
                    "sqlmap -u 'http://{target}/vulnerabilities/sqli/?id=1&Submit=Submit' --batch",
                ],
                log_indicators=[
                    "SQL syntax error",
                    "UNION SELECT",
                    "' OR 1=1",
                    "sqlmap",
                    "unusual query parameters",
                    "error-based injection",
                ],
            ),
        ],
    ),
    "execution": Tactic(
        id="TA0002",
        name="Execution",
        description=(
            "El adversario ejecuta codigo malicioso en el sistema comprometido. "
            "Incluye interpretes de comandos, scripts, y ejecucion de binarios."
        ),
        order=3,
        implemented=True,
        techniques=[
            Technique(
                id="T1059",
                name="Command and Scripting Interpreter",
                description="Uso de shells y scripting para ejecutar comandos en el sistema objetivo.",
                tools=["bash", "python3", "netcat"],
                commands=[
                    "bash -c 'id && whoami && uname -a'",
                    "python3 -c 'import os; os.system(\"id\")'",
                ],
                log_indicators=[
                    "command execution",
                    "shell spawned",
                    "bash -c",
                    "python -c",
                    "/bin/sh",
                    "reverse shell",
                    "netcat",
                    "process execution",
                ],
            ),
        ],
    ),
    "persistence": Tactic(
        id="TA0003",
        name="Persistence",
        description=(
            "El adversario mantiene acceso al sistema comprometido a traves de "
            "reinicios y cambios de credenciales. Incluye creacion de cuentas, "
            "tareas programadas, y backdoors."
        ),
        order=4,
        implemented=False,
        techniques=[
            Technique(
                id="T1136",
                name="Create Account",
                description="Creacion de cuentas locales para mantener acceso.",
                log_indicators=["useradd", "adduser", "new account created", "user added"],
            ),
            Technique(
                id="T1053",
                name="Scheduled Task/Job",
                description="Uso de cron o at para ejecutar codigo de forma periodica.",
                log_indicators=["crontab", "cron.d", "at job", "scheduled task"],
            ),
        ],
    ),
    "privilege_escalation": Tactic(
        id="TA0004",
        name="Privilege Escalation",
        description=(
            "El adversario obtiene permisos de mayor nivel en el sistema. "
            "Incluye explotacion de vulnerabilidades del kernel, abuso de SUID, "
            "y manipulacion de mecanismos de elevacion."
        ),
        order=5,
        implemented=True,
        techniques=[
            Technique(
                id="T1548",
                name="Abuse Elevation Control Mechanism",
                description="Abuso de binarios SUID para escalar a root. En Mr. Robot: python3 con SUID.",
                tools=["python3"],
                commands=[
                    "find / -perm -u=s -type f 2>/dev/null",
                    "python3 -c \"import os; os.setuid(0); os.system('cat /root/key-3-of-3.txt')\"",
                ],
                log_indicators=[
                    "setuid", "SUID", "privilege elevation",
                    "root shell", "escalation",
                ],
            ),
        ],
    ),
    "defense_evasion": Tactic(
        id="TA0005",
        name="Defense Evasion",
        description=(
            "El adversario evita ser detectado por sistemas de seguridad. "
            "Incluye limpieza de logs, ofuscacion, y deshabilitacion de controles."
        ),
        order=6,
        implemented=False,
        techniques=[
            Technique(
                id="T1070",
                name="Indicator Removal",
                description="Eliminacion de logs y artefactos que evidencien la intrusion.",
                log_indicators=[
                    "log deletion", "history cleared", "audit log modified",
                    "truncate", "/var/log",
                ],
            ),
        ],
    ),
    "credential_access": Tactic(
        id="TA0006",
        name="Credential Access",
        description=(
            "El adversario roba credenciales como contrasenas, tokens o hashes. "
            "Incluye dumping de credenciales del sistema, keylogging, y "
            "extraccion de credenciales de archivos."
        ),
        order=7,
        implemented=True,
        techniques=[
            Technique(
                id="T1003",
                name="OS Credential Dumping",
                description=(
                    "Extraccion de hashes de contrasena y crackeo offline. "
                    "En Mr. Robot: /home/robot/password.raw-md5 contiene MD5 crackeado con john."
                ),
                tools=["john", "python3"],
                commands=[
                    "cat /home/robot/password.raw-md5",
                    "john --format=raw-md5 --wordlist=/opt/wordlists/mrrobot.txt /tmp/hash_crack.txt",
                ],
                log_indicators=[
                    "/etc/shadow", "passwd", "hash dump",
                    "credential dump", "password.raw-md5",
                ],
            ),
        ],
    ),
    "discovery": Tactic(
        id="TA0007",
        name="Discovery",
        description=(
            "El adversario explora el entorno comprometido para entender la "
            "configuracion, procesos, usuarios y red del sistema. Esto informa "
            "decisiones para movimiento lateral y exfiltracion."
        ),
        order=8,
        implemented=True,
        techniques=[
            Technique(
                id="T1082",
                name="System Information Discovery",
                description="Recopilacion de informacion del sistema (OS, hardware, hostname).",
                tools=["bash"],
                commands=[
                    "uname -a",
                    "cat /etc/os-release",
                    "hostname",
                    "df -h",
                    "free -m",
                ],
                log_indicators=[
                    "uname", "system information", "os-release",
                    "hostname query", "system enumeration",
                ],
            ),
            Technique(
                id="T1083",
                name="File and Directory Discovery",
                description="Enumeracion de archivos y directorios del sistema.",
                tools=["bash"],
                commands=[
                    "ls -la /home/",
                    "find / -name '*.conf' -type f 2>/dev/null | head -20",
                    "cat /etc/passwd",
                ],
                log_indicators=[
                    "directory listing", "find command", "file enumeration",
                    "ls -la", "sensitive file access",
                ],
            ),
        ],
    ),
    "lateral_movement": Tactic(
        id="TA0008",
        name="Lateral Movement",
        description=(
            "El adversario se mueve entre sistemas dentro de la red comprometida. "
            "Usa credenciales o vulnerabilidades para acceder a sistemas adicionales."
        ),
        order=9,
        implemented=False,
        techniques=[
            Technique(
                id="T1021",
                name="Remote Services",
                description="Uso de SSH, RDP u otros servicios remotos para moverse lateralmente.",
                log_indicators=[
                    "SSH login from internal", "lateral movement",
                    "new session from compromised host", "remote login",
                ],
            ),
        ],
    ),
    "collection": Tactic(
        id="TA0009",
        name="Collection",
        description=(
            "El adversario recopila datos de interes del sistema comprometido. "
            "Incluye captura de pantalla, keylogging, y recoleccion de archivos."
        ),
        order=10,
        implemented=False,
        techniques=[
            Technique(
                id="T1005",
                name="Data from Local System",
                description="Recoleccion de archivos sensibles del sistema local.",
                log_indicators=[
                    "file read", "sensitive data access", "database dump",
                    "archive creation", "tar", "zip",
                ],
            ),
        ],
    ),
    "command_and_control": Tactic(
        id="TA0011",
        name="Command and Control",
        description=(
            "El adversario establece comunicacion con el sistema comprometido "
            "para controlarlo remotamente. Incluye canales encubiertos, "
            "tunneling, y protocolos no estandar."
        ),
        order=11,
        implemented=False,
        techniques=[
            Technique(
                id="T1071",
                name="Application Layer Protocol",
                description="Uso de protocolos de aplicacion (HTTP, DNS) para C2.",
                log_indicators=[
                    "beacon", "C2 communication", "unusual DNS queries",
                    "periodic outbound connections", "encoded traffic",
                ],
            ),
        ],
    ),
    "exfiltration": Tactic(
        id="TA0010",
        name="Exfiltration",
        description=(
            "El adversario extrae datos del sistema comprometido hacia el exterior. "
            "Incluye exfiltracion por canales alternativos, compresion y cifrado."
        ),
        order=12,
        implemented=False,
        techniques=[
            Technique(
                id="T1048",
                name="Exfiltration Over Alternative Protocol",
                description="Extraccion de datos usando protocolos no monitoreados.",
                log_indicators=[
                    "large outbound transfer", "data exfiltration",
                    "unusual protocol", "DNS tunneling", "encoded data transfer",
                ],
            ),
        ],
    ),
    "resource_development": Tactic(
        id="TA0042",
        name="Resource Development",
        description=(
            "El adversario prepara recursos para la operacion. Incluye compra "
            "de dominios, desarrollo de herramientas, y obtencion de cuentas."
        ),
        order=0,
        implemented=False,
        techniques=[],
    ),
    "impact": Tactic(
        id="TA0040",
        name="Impact",
        description=(
            "El adversario manipula, interrumpe o destruye sistemas y datos. "
            "Incluye ransomware, destruccion de datos, y denegacion de servicio."
        ),
        order=13,
        implemented=False,
        techniques=[
            Technique(
                id="T1485",
                name="Data Destruction",
                description="Eliminacion irreversible de datos del sistema.",
                log_indicators=[
                    "file deletion", "rm -rf", "data wipe",
                    "disk format", "service disruption",
                ],
            ),
        ],
    ),
}


def get_implemented_tactics() -> list[Tactic]:
    """Retorna las tacticas implementadas, ordenadas por secuencia de ataque."""
    return sorted(
        [t for t in TACTICS.values() if t.implemented],
        key=lambda t: t.order,
    )


def get_all_tactics() -> list[Tactic]:
    """Retorna todas las tacticas, ordenadas por secuencia de ataque."""
    return sorted(TACTICS.values(), key=lambda t: t.order)


def get_tactic_by_id(tactic_id: str) -> Tactic | None:
    """Busca una tactica por su ID MITRE (ej: 'TA0043')."""
    for tactic in TACTICS.values():
        if tactic.id == tactic_id:
            return tactic
    return None


def get_tactic_by_name(name: str) -> Tactic | None:
    """Busca una tactica por su nombre interno (ej: 'reconnaissance')."""
    return TACTICS.get(name)
