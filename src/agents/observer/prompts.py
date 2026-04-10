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

PROGRESION TIPICA DE ATAQUES (MITRE ATT&CK Kill Chain):
Un ataque real suele seguir un orden logico aproximado:
  Reconnaissance -> Initial Access -> Execution -> Discovery/Credential Access
  -> Privilege Escalation -> Persistence -> Lateral Movement -> Collection -> Exfiltration -> Impact

Esta progresion NO es rigida: algunos ataques saltan fases, otros regresan a una
fase anterior (p.ej. mas Discovery despues de Privilege Escalation), y otros ejecutan
varias fases en paralelo. Pero el patron es util como PRIOR bayesiano:

- Si tu ultima clasificacion (con >=80% confianza) fue Reconnaissance, la siguiente \
ventana muy probablemente muestra MAS Reconnaissance o transicion a Initial Access.
- Si ya viste Initial Access confirmado, la siguiente fase esperada es Execution o Discovery.
- Si ya viste webshell_execution (Execution), las siguientes fases esperadas son Discovery, \
Credential Access, o Privilege Escalation.
- Si ya viste Credential Access, las siguientes son Privilege Escalation o Lateral Movement.

COMO USAR ESTE PRIOR (balance critico):
1. Antes de analizar los logs, formula una EXPECTATIVA: "dado el historial, probablemente \
voy a ver tactica X en esta ventana".
2. Analiza los logs con esa expectativa en mente — te ayuda a reconocer las senales mas rapido.
3. PERO verifica siempre con los logs actuales. Si los logs muestran algo DIFERENTE a tu \
expectativa, confia en los logs. Las clasificaciones previas pueden estar EQUIVOCADAS.
4. Si el historial es inconsistente (confianzas bajas, brincos raros entre tacticas), \
IGNORELO y clasifica solo con los logs actuales.
5. No clasifiques una tactica solo porque "es lo que deberia venir despues". Necesitas \
evidencia en los logs de ESTA ventana.
6. Si tu clasificacion contradice el prior, explica en "reasoning" por que los logs te \
llevan a una conclusion distinta.

REGLA CRITICA DE INTERPRETACION DE HTTP STATUS CODES:
- GET/HEAD con status 404/403 a CUALQUIER ruta (incluso /shell.php, /wp-admin, /cmd.php) = \
escaneo automatico = RECONNAISSANCE. El recurso no existe. NO es Execution.
- GET con status 302 a /wp-admin/ o /wp-login.php = redireccion estructural de WordPress. \
El scanner encontro que la ruta existe, NO que el atacante accedio. Es RECONNAISSANCE.
- UNICAMENTE POST con status 302 a /wp-login.php = login exitoso = Initial Access.
- POST con cualquier status = interaccion activa (intento de login, envio de formulario).
- Webshell con status 200 = Execution (base). La sub-tactica MITRE real depende del comando ejecutado.
- Volumen masivo de 404s de una sola IP = herramienta de escaneo (nikto, gobuster) = Reconnaissance.

CLASIFICACION DE SUB-TACTICAS POR COMANDO WEBSHELL:
Cuando veas un webshell con cmd=... y status 200, la tactica MITRE depende del comando. El sistema
ya pre-clasifica cada comando (ver seccion "COMANDOS EJECUTADOS VIA WEBSHELL" en SENALES). Usa esto:
- Comandos de enumeracion (uname, whoami, id, ls, find, cat /etc/hostname) = Discovery
- Lectura de passwords/hashes (cat /etc/shadow, cat *password*, cat *hash*, id_rsa) = Credential Access
- Explotacion SUID/sudo (find -perm -u=s, sudo, su, pkexec) = Privilege Escalation
- Compresion/empaquetado (tar, zip, base64 de archivos) = Collection
- Transferencia saliente (curl PUT, wget -O, nc host port) = Exfiltration
- Destruccion (rm -rf, dd, mkfs, shutdown) = Impact
- Cualquier otro = Execution (generico)

LAS 14 TACTICAS MITRE ATT&CK:

1. Reconnaissance (TA0043): Recopilacion de informacion del objetivo ANTES de obtener acceso.
   Observables: escaneos de puertos (nmap), enumeracion web masiva (nikto/gobuster con cientos \
de rutas 404), fingerprinting de tecnologias. CLAVE: muchos 404s de una IP = Reconnaissance.

2. Resource Development (TA0042): Preparacion de infraestructura de ataque.
   Observables: generalmente no visible en logs del target.

3. Initial Access (TA0001): Primer acceso exitoso al sistema.
   Observables: POST a /wp-login.php con status 302 (login exitoso), explotacion de \
vulnerabilidad web que retorna 200/302 en ruta sensible, credenciales validas usadas.
   DISTINCION vs Reconnaissance: Initial Access requiere respuesta exitosa (200/302), \
no solo probing (404).

4. Execution (TA0002): Ejecucion de codigo malicioso en el sistema comprometido.
   Observables: webshell respondiendo HTTP 200 a requests con ?cmd= o similar, \
procesos inusuales iniciados. CLAVE: la ruta de webshell con status 200 (no 404).

5. Persistence (TA0003): Mantener acceso al sistema.
   Observables: creacion de cuentas, modificacion de cron/scheduled tasks, instalacion \
de backdoors.

6. Privilege Escalation (TA0004): Obtener mayores privilegios.
   Observables: uso de sudo, explotacion de SUID, cambios de permisos, acceso a /etc/shadow.

7. Defense Evasion (TA0005): Evitar deteccion.
   Observables: eliminacion de logs, modificacion de timestamps, ofuscacion.

8. Credential Access (TA0006): Robo de credenciales.
   Observables: acceso a archivos de passwords, dump de hashes, keylogging.

9. Discovery (TA0007): Exploracion del sistema ya comprometido para mapear el entorno.
   Observables: webshell (status 200) ejecutando comandos de sistema como uname, whoami, id, \
cat /etc/passwd, ls /home, ifconfig. DISTINCION vs Execution: si el ?cmd= contiene \
comandos de enumeracion del sistema = Discovery. Si es el primer acceso via webshell = Execution.

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

LOGS DEL PERIODO ANALIZADO:
{logs}

CLASIFICACIONES PREVIAS (contexto de progresion del ataque):
{history}

INSTRUCCIONES DE ANALISIS:
1. La seccion "EVENTOS NOTABLES" lista los unicos requests con respuesta real (2xx/401/POST). \
   Estos son los eventos que indican progreso del ataque — analigalos primero.
2. Si los eventos notables muestran solo GET a paginas generales (robots.txt, login page) con 200, \
   y no hay POSTs exitosos ni webshell activa, la tactica mas probable es Reconnaissance.
3. Un volumen masivo de 404s con pocos o ningun evento notable = Reconnaissance activo.
4. Si hay POST a wp-login.php con 302 = Initial Access exitoso. GET a wp-login.php/wp-admin/ \
   con cualquier status = solo Reconnaissance (el scanner encontro la pagina).
5. Si hay GET a una ruta de webshell (?cmd=) con 200 = Execution o Discovery segun el comando.
6. Las entradas al FINAL de las "ULTIMAS ENTRADAS CRONOLOGICAS" son la actividad MAS RECIENTE.
7. Prioriza evidencia directa en los logs sobre clasificaciones previas.
8. REGLA DE PROGRESION: Los ataques NO retroceden. Si en CLASIFICACIONES PREVIAS ya se confirmo \
   webshell_execution (Execution/Discovery) o login_success (Initial Access), la tactica actual \
   no puede ser Reconnaissance. Si ya se vio Execution, la tactica actual es como minimo Execution.
9. REGLA DE TACTICA ACTUAL (CRITICA): "current_tactic" debe ser la tactica MAS AVANZADA presente \
   en esta ventana, NO la mas voluminosa. Si hay 5000 requests de Reconnaissance y 1 sola request \
   con webshell_execution (cmd= + 200), "current_tactic" es Execution/Discovery, NO Reconnaissance. \
   El volumen alto de una tactica previa indica que aun esta en progreso, pero la presencia de UN \
   evento de tactica mas avanzada significa que el ataque ya progreso a esa fase. Cualquier senal \
   [CRITICO] en SENALES PRE-CALCULADAS determina la tactica actual.
10. USO DEL PRIOR (ver PROGRESION TIPICA en system prompt): Si el historial muestra una \
    clasificacion previa de alta confianza, usala como EXPECTATIVA (no como conclusion). Busca \
    activamente senales de la fase siguiente tipica en los logs. Pero si no las encuentras y los \
    logs muestran otra cosa, confia en los logs. Menciona en "reasoning" si tu clasificacion \
    coincide o contradice la expectativa del prior.
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

    # Comandos webshell ejecutados (con clasificacion MITRE sub-tactica)
    webshell_cmds = signals.get("webshell_commands", [])
    if webshell_cmds:
        lines.append(
            f"\n  [CRITICO] COMANDOS EJECUTADOS VIA WEBSHELL "
            f"({len(webshell_cmds)} ultimos, en orden cronologico):"
        )
        for cmd_data in webshell_cmds:
            ts = cmd_data.get("timestamp", "?")[-8:] if cmd_data.get("timestamp") else "?"
            cmd = cmd_data.get("cmd", "")
            sub_t = cmd_data.get("sub_tactic", "Execution")
            lines.append(f"    [{ts}] {sub_t} <- \"{cmd}\"")
        lines.append(
            "  Nota: la tactica mas reciente observada via webshell es la que debe "
            "guiar 'current_tactic' si no hay senales posteriores de mayor progresion."
        )

    for ip, data in signals.get("suspicious_ips", {}).items():
        score = data.get("attack_score", 0)
        cumulative = data.get("cumulative_score", score)
        windows = data.get("windows_flagged", 1)
        threat = data.get("threat_level", "LOW")
        total = data.get("total", 0)
        confirmed = data.get("confirmed_actions", {})

        tool = data.get("tool_detected", "")
        max_rps = data.get("max_req_per_sec", 0)
        distinct_uas = data.get("distinct_uas", 0)
        tool_str = f" | herramienta={tool}" if tool else ""
        rps_str = f" | max={max_rps}req/s" if max_rps >= 5 else ""
        ua_str = f" | {distinct_uas}UAs" if distinct_uas >= 5 else ""
        lines.append(
            f"  IP {ip} [AMENAZA:{threat} | {windows} ventanas | score_acum={cumulative}"
            f"{tool_str}{rps_str}{ua_str}]"
            f" (esta ventana: score={score}, requests={total}):"
        )
        if confirmed:
            confirmed_str = ", ".join(f"{k}={v}" for k, v in confirmed.items())
            lines.append(f"    Historial confirmado en ventanas previas: {confirmed_str}")
        if data.get("webshell_execution"):
            sub_ts = data.get("webshell_sub_tactics", [])
            sub_str = ""
            if sub_ts:
                seen: set[str] = set()
                unique_ts = [t for t in sub_ts if not (t in seen or seen.add(t))]
                sub_str = f" | sub-tacticas observadas: {', '.join(unique_ts)}"
            lines.append(
                f"    [CRITICO] webshell_execution={data['webshell_execution']}"
                f" — webshell respondio HTTP 200, comandos ejecutados{sub_str}"
            )
        if data.get("login_success"):
            lines.append(
                f"    [CRITICO] login_success={data['login_success']}"
                f" — login exitoso en wp-login.php (HTTP 302 a /wp-admin)"
            )
        if data.get("shellshock_attempts"):
            lines.append(
                f"    [CRITICO] shellshock_attempts={data['shellshock_attempts']}"
                f" — payloads '() {{ :; }};' detectados (CVE-2014-6271 exploit)"
            )
        if distinct_uas >= 5:
            lines.append(
                f"    distinct_uas={distinct_uas}"
                f" — la IP uso multiples user-agents distintos (rotacion = scanner tipo nikto)"
            )
        if data.get("weird_methods"):
            lines.append(
                f"    weird_methods={data['weird_methods']}"
                f" — metodos HTTP no estandar detectados (PROPFIND/TRACK/LVIG = nikto probing)"
            )
        if data.get("uniform_404_ratio"):
            lines.append(
                f"    uniform_404_ratio={data['uniform_404_ratio']}"
                f" — >70% de los 404s tienen el mismo body size (wordlist scanner)"
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


_NEXT_TACTIC_HINTS = {
    "Reconnaissance": "Initial Access (requiere POST exitoso) o mas Reconnaissance",
    "Initial Access": "Execution (webshell) o Discovery",
    "Execution": "Discovery, Credential Access, o Privilege Escalation",
    "Discovery": "Credential Access, Privilege Escalation, o Lateral Movement",
    "Credential Access": "Privilege Escalation o Lateral Movement",
    "Privilege Escalation": "Persistence, Lateral Movement, o Defense Evasion",
    "Persistence": "Lateral Movement, Collection, o Command and Control",
    "Defense Evasion": "Credential Access, Discovery, o Exfiltration",
    "Lateral Movement": "Collection, Credential Access, o mas Discovery",
    "Collection": "Exfiltration o Command and Control",
    "Command and Control": "Exfiltration o Impact",
    "Exfiltration": "Impact o fin del ataque",
    "Impact": "Fin del ataque",
}


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
        # Resumen del prior: que esperar en esta ventana dado el historial
        last_high_conf = next(
            (h for h in reversed(history) if h.get("confidence", 0) >= 0.80),
            None,
        )
        if last_high_conf:
            last_tactic = last_high_conf.get("tactic", "")
            next_hint = _NEXT_TACTIC_HINTS.get(last_tactic, "cualquier tactica posterior")
            history_lines.append("")
            history_lines.append(
                f"  PRIOR: La ultima clasificacion de alta confianza fue '{last_tactic}' "
                f"({last_high_conf.get('confidence', 0):.0%})."
            )
            history_lines.append(
                f"  EXPECTATIVA por defecto para esta ventana: mas '{last_tactic}' o "
                f"transicion a {next_hint}."
            )
            history_lines.append(
                "  RECUERDA: verifica con los logs actuales. Si contradicen la expectativa, "
                "confia en los logs."
            )
        history_str = "\n".join(history_lines)
    else:
        history_str = "  Ninguna (primera clasificacion) — sin prior, clasifica solo con logs."

    return CLASSIFICATION_PROMPT.format(
        logs=logs_summary,
        history=history_str,
        signals=_format_signals(anomaly_signals or {}),
    )
