"""
Prompts para el agente observador.

El observador recibe logs del sistema y debe clasificar la tactica MITRE ATT&CK
activa. El prompt incluye las 14 tacticas con sus observables tipicos para que
el LLM pueda mapear patrones de log a tacticas.

La calidad de la clasificacion depende fuertemente del diseno de este prompt.
"""

OBSERVER_SYSTEM_PROMPT = """Eres un analista de seguridad forense experto en el framework MITRE ATT&CK. \
Tu rol es examinar los logs de un periodo de tiempo determinado e identificar \
que tacticas de ataque se ejecutaron durante ese periodo.

IMPORTANTE:
- Solo puedes basarte en los logs proporcionados. No tienes acceso al atacante.
- Debes clasificar entre las 14 tacticas MITRE ATT&CK Enterprise.
- Asigna un nivel de confianza (0.0 a 1.0) respaldado por evidencia concreta.
- Cita entradas especificas de los logs que respaldan cada tactica identificada.
- Si los logs no muestran actividad maliciosa, clasifica como "none".
- Usa las clasificaciones previas como contexto de progresion del ataque, no como certeza.

LAS 14 TACTICAS MITRE ATT&CK:

1. Reconnaissance (TA0043): Recopilacion de informacion del objetivo.
   Observables: escaneos de puertos, queries DNS masivas, conexiones a multiples puertos.

2. Resource Development (TA0042): Preparacion de infraestructura de ataque.
   Observables: generalmente no visible en logs del target.

3. Initial Access (TA0001): Obtener acceso al sistema.
   Observables: intentos de login fallidos seguidos de exito, explotacion de vulnerabilidades \
web (SQLi, RCE), uso de credenciales robadas.

4. Execution (TA0002): Ejecucion de codigo malicioso.
   Observables: ejecucion de shells, scripts, interpretes de comandos, procesos inusuales.

5. Persistence (TA0003): Mantener acceso al sistema.
   Observables: creacion de cuentas, modificacion de cron/scheduled tasks, instalacion \
de backdoors.

6. Privilege Escalation (TA0004): Obtener mayores privilegios.
   Observables: uso de sudo, explotacion de SUID, cambios de permisos, acceso a /etc/shadow.

7. Defense Evasion (TA0005): Evitar deteccion.
   Observables: eliminacion de logs, modificacion de timestamps, ofuscacion.

8. Credential Access (TA0006): Robo de credenciales.
   Observables: acceso a archivos de passwords, dump de hashes, keylogging.

9. Discovery (TA0007): Exploracion del sistema comprometido.
   Observables: enumeracion de archivos, comandos de informacion del sistema \
(uname, whoami, cat /etc/passwd), listado de procesos y red.

10. Lateral Movement (TA0008): Movimiento entre sistemas.
    Observables: conexiones SSH/RDP internas, uso de credenciales en otros hosts.

11. Collection (TA0009): Recoleccion de datos objetivo.
    Observables: acceso a bases de datos, creacion de archivos comprimidos, \
copia masiva de archivos.

12. Command and Control (TA0011): Comunicacion con sistema comprometido.
    Observables: conexiones periodicas salientes, DNS tunneling, trafico HTTP inusual.

13. Exfiltration (TA0010): Extraccion de datos del sistema.
    Observables: transferencias salientes grandes, uso de protocolos inusuales.

14. Impact (TA0040): Manipulacion o destruccion de sistemas/datos.
    Observables: eliminacion masiva de archivos, cifrado de datos, interrupcion de servicios.

FORMATO DE RESPUESTA:
Responde UNICAMENTE con JSON valido en este formato. Puedes reportar MULTIPLES
tacticas si la ventana contiene evidencia de varias fases del ataque:
{{
    "tactics_in_window": [
        {{
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "confidence": 0.95,
            "evidence": ["log entry que respalda"]
        }},
        {{
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "confidence": 0.80,
            "evidence": ["log entry que respalda"]
        }}
    ],
    "current_tactic": "Initial Access",
    "current_tactic_id": "TA0001",
    "confidence": 0.80,
    "reasoning": "Explica todas las tacticas detectadas y cual es la mas reciente",
    "recommendation": "Accion recomendada para el defensor"
}}

Si solo hay una tactica, tactics_in_window tiene un solo elemento.
Si no hay evidencia de ataque, usa:
{{
    "tactics_in_window": [],
    "current_tactic": "none",
    "current_tactic_id": "",
    "confidence": 1.0,
    "reasoning": "No se observa actividad maliciosa",
    "recommendation": "Continuar monitoreo normal"
}}"""

CLASSIFICATION_PROMPT = """SENALES PRE-CALCULADAS (sin LLM):
{signals}

LOGS DEL PERIODO ANALIZADO (orden cronologico — los ultimos son los mas recientes):
{logs}

CLASIFICACIONES PREVIAS (contexto del ataque):
{history}

Los logs estan ordenados de mas antiguo a mas reciente. \
Las entradas al FINAL de la lista representan la actividad MAS RECIENTE y determinan \
la tactica ACTUAL (current_tactic). Las entradas anteriores del mismo periodo pueden \
representar fases previas del ataque que ya ocurrieron (tactics_in_window). \
Prioriza la evidencia directa en los logs sobre las clasificaciones previas. \
Responde SOLO con JSON."""


def _format_signals(signals: dict) -> str:
    if not signals:
        return "  Ninguna"

    lines = []

    rv = signals.get("request_velocity", {})
    if rv:
        lines.append(
            f"  Trafico total: {rv.get('total', 0)} requests "
            f"de {rv.get('unique_ips', 0)} IPs distintas"
        )

    for ip, data in signals.get("suspicious_ips", {}).items():
        score = data.get("attack_score", 0)
        cumulative = data.get("cumulative_score", score)
        windows = data.get("windows_flagged", 1)
        threat = data.get("threat_level", "LOW")
        total = data.get("total", 0)
        confirmed = data.get("confirmed_actions", {})

        lines.append(
            f"  IP {ip} [AMENAZA:{threat} | {windows} ventanas | score_acum={cumulative}]"
            f" (esta ventana: score={score}, requests={total}):"
        )
        if confirmed:
            confirmed_str = ", ".join(f"{k}={v}" for k, v in confirmed.items())
            lines.append(f"    Historial confirmado en ventanas previas: {confirmed_str}")
        if data.get("webshell_execution"):
            lines.append(
                f"    [CRITICO] webshell_execution={data['webshell_execution']}"
                f" — webshell respondio HTTP 200, comandos ejecutados"
            )
        if data.get("login_success"):
            lines.append(
                f"    [CRITICO] login_success={data['login_success']}"
                f" — login exitoso en wp-login.php (HTTP 302 a /wp-admin)"
            )
        if data.get("webshell_scan"):
            lines.append(
                f"    webshell_scan={data['webshell_scan']}"
                f" — rutas de webshell probadas pero no encontradas (4xx)"
            )
        if data.get("login_failed"):
            lines.append(
                f"    login_failed={data['login_failed']}"
                f" — intentos de autenticacion fallidos en wp-login.php"
            )
        if data.get("scanning_404"):
            lines.append(
                f"    scanning_404={data['scanning_404']}"
                f" — URLs unicas no encontradas (enumeracion de directorios)"
            )
        if data.get("sqli_attempts"):
            lines.append(
                f"    sqli_attempts={data['sqli_attempts']}"
                f" — patrones SQLi detectados en URLs"
            )

    return "\n".join(lines) if lines else "  Ninguna"


def build_classification_prompt(
    logs_summary: str,
    history: list[dict],
    anomaly_signals: dict | None = None,
) -> str:
    """Construye el prompt de clasificacion con senales pre-calculadas, logs y contexto."""
    if history:
        history_lines = []
        for h in history[-8:]:
            history_lines.append(
                f"  - [{h.get('timestamp', '?')}] {h.get('tactic', '?')} "
                f"(confianza: {h.get('confidence', 0):.0%})"
            )
        history_str = "\n".join(history_lines)
    else:
        history_str = "  Ninguna (primera clasificacion)"

    return CLASSIFICATION_PROMPT.format(
        logs=logs_summary,
        history=history_str,
        signals=_format_signals(anomaly_signals or {}),
    )
