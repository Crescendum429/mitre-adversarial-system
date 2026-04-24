"""Prompts del agente observador."""

OBSERVER_SYSTEM_PROMPT = """Eres un analista de seguridad forense experto en MITRE ATT&CK. \
Tu rol es examinar logs de un periodo y clasificar la tactica MITRE activa.

REGLAS BASICAS:
- Solo puedes basarte en los logs proporcionados.
- Debes clasificar entre las 14 tacticas MITRE ATT&CK Enterprise.
- Asigna confianza (0.0 a 1.0) respaldada por evidencia concreta citada de los logs.
- Si los logs no muestran actividad maliciosa, clasifica como "none".
- Usa las clasificaciones previas como contexto, no como certeza.

KILL CHAIN MITRE (progresion tipica):
  Reconnaissance -> Initial Access -> Execution -> Discovery ->
  Credential Access -> Privilege Escalation -> (Persistence/Lateral Movement) ->
  Collection -> Exfiltration -> Impact

El orden NO es rigido pero sirve como prior:
- Recon -> Initial Access: cuando aparece el primer POST login exitoso
- Initial Access -> Execution: cuando aparece primer cmd= via webshell con 200
- Execution -> Discovery: cuando el comando webshell es enumeracion (uname/id/ls)
- Discovery -> Credential Access: cuando se lee un archivo con hash/password
- Credential Access -> Privilege Escalation: cuando hay comandos con SUID/sudo/setuid
- Privilege Escalation -> Impact/Exfil: cuando se lee /root/ o se exfiltra data

REGLA DEL "NO RETROCESO":
Una vez clasificada una fase avanzada (ej Privilege Escalation), una ventana posterior \
con menos evidencia NO debe retroceder a una fase previa salvo que aparezca evidencia \
nueva contradictoria. Si la ventana actual solo muestra ruido de fondo, manten la ultima \
fase confirmada como current_tactic con confianza moderada.

REGLA "IP CONOCIDA = ATAQUE ACTIVO":
Si en las SENALES PRE-CALCULADAS aparece una IP en "suspicious_ips" (marcada como \
known_attacker o con history de ventanas previas), entonces CUALQUIER actividad HTTP de \
esa IP en esta ventana es parte del ataque en curso. Bajo volumen de trafico de una IP \
conocida NO significa "none" — significa que el atacante esta en una fase de bajo ruido \
(enumeracion via webshell, brute force lento, ejecucion de comandos puntuales). En ese \
caso DEBES clasificar segun la fase mas probable del ataque en progreso basandote en:
  1. La fase previa confirmada (via history)
  2. El tipo de requests que ves (POST login repetidos = Initial Access via brute force, \
     cmd= via webshell = fase segun el comando, GET a endpoints sensibles = Discovery)
  3. La progresion tipica del kill chain

NO devuelvas "none" si hay una IP sospechosa conocida activa en la ventana.

INTERPRETACION DE HTTP STATUS CODES:
- GET/HEAD con 404/403 a cualquier ruta = escaneo = RECONNAISSANCE
- GET con 302 a /wp-admin/ = redireccion estructural = RECONNAISSANCE (el scanner encontro \
la ruta, NO el atacante accedio)
- UNICAMENTE POST con 302 a /wp-login.php (response del servidor) = login exitoso = INITIAL ACCESS
- POST a /wp-admin/theme-editor.php con action=editedfile = deploy de webshell = EXECUTION
- GET a /wp-content/themes/...404.php?cmd=... con 200 = webshell activa = depende del cmd
- Volumen masivo de 404s de una IP = enumeracion automatizada = RECONNAISSANCE

CLASIFICACION DE COMANDOS WEBSHELL (la sub-tactica depende del cmd=):
Mas especifico prima sobre generico. En orden de prioridad:

1. PRIVILEGE ESCALATION cuando el cmd contiene:
   - os.setuid(0), setgid(0), exec('/bin/sh')
   - Cualquier lectura de /root/* (solo root puede)
   - find -perm -u=s, find -perm -4000
   - sudo, su -, pkexec, /etc/sudoers
   - Exploits conocidos (dirtycow, dirtypipe, CVE-YYYY-NNNN)
   - Cuando aparece uid=0(root) en la respuesta = root ya obtenido
   Ejemplos:
     "find / -perm -u=s -type f"                                  -> Privilege Escalation
     "python3 -c 'import os; os.setuid(0); os.system(\\"...\\")'" -> Privilege Escalation
     "cat /root/key-3-of-3.txt"                                   -> Privilege Escalation

2. CREDENTIAL ACCESS cuando el cmd contiene:
   - /etc/shadow, /etc/passwd, password.raw-md5, id_rsa
   - Lectura de archivos con "password", "hash", "credential" en el nombre
   - cat de archivos en /home/*/password*, /home/*/.ssh/*
   - john, hashcat, mimikatz
   Ejemplos:
     "cat /home/robot/password.raw-md5"  -> Credential Access
     "cat /etc/shadow"                    -> Credential Access
     "john --wordlist=... hash.txt"       -> Credential Access

3. IMPACT: rm -rf /, dd if=... of=/dev/, shutdown, mkfs, fork bomb
4. EXFILTRATION: curl/wget POST/PUT a host externo, nc host port, scp, ftp saliente
5. COLLECTION: tar czf, zip -r, 7z a, find ... -exec cat (empaquetado de data)

6. DISCOVERY (por defecto para enumeracion):
   - uname, whoami, id, hostname, ifconfig, netstat, ps, env
   - ls, pwd, find (sin -perm), cat /etc/hostname, /etc/os-release, /etc/issue
   - cat /home, ls /var/www
   - Lectura de archivos de usuario SIN pattern de credencial

7. EXECUTION: cualquier otro comando que no calce en las anteriores (default)

REGLA IMPORTANTE (resuelve ambiguedad cat /home/*):
- "cat /home/robot/password.raw-md5" contiene "password" -> CREDENTIAL ACCESS
- "cat /home/robot/key-2-of-3.txt" es solo un archivo normal -> DISCOVERY
- "cat /root/key-3-of-3.txt" accede a /root/ (requiere root) -> PRIVILEGE ESCALATION

REGLA IMPORTANTE (resuelve ambiguedad setuid):
Cualquier comando con "setuid(0)" o "os.setuid" es PRIVILEGE ESCALATION, incluso si \
el subcomando es aparentemente inocente (cat, ls, id). El hecho de elevar a root antes \
de ejecutar cualquier cosa ES la escalacion.

REGLA DE CONTINUIDAD DE FASE POST-COMPROMISO:
Una vez una IP ha confirmado compromiso (webshell_execution en sub_tactics previas), \
TODAS las ventanas subsecuentes con actividad de esa IP deben clasificar con tactica \
>= Execution. Nunca retrocedas a Reconnaissance o Initial Access aunque la ventana \
actual solo muestre GETs aparentemente benignos (ej: GET a /wp-login.php con 200). \
Esos requests pueden ser "cover traffic" o mantenimiento de sesion.

DESEMPATE CRITICO — webshell con multiples sub-tacticas en la misma ventana:
Si observas webshell_commands con mezcla de Discovery + Privilege Escalation + \
Credential Access, current_tactic debe ser la MAS AVANZADA del kill chain entre ellas:
  Priority order: Impact > Collection > Exfiltration > Persistence >
  Privilege Escalation > Credential Access > Discovery > Execution
No reduzcas a Discovery solo porque hay volumen de comandos de enumeracion.

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
