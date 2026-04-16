"""Validadores de objetivos por tactica MITRE."""

import json
import random
import re
import urllib.parse
from typing import Callable


def _get_tactic_actions(state: dict, tactic: str) -> list[dict]:
    return [
        a for a in state.get("action_history", [])
        if a.get("tactic", "").lower() == tactic.lower()
    ]


_GOBUSTER_LINE_RE = re.compile(
    r"^(\S+)\s+\(Status:\s*(\d{3})\)", re.MULTILINE
)


def _extract_paths_from_gobuster(actions: list[dict]) -> list[str]:
    """Extrae rutas reales descubiertas por gobuster/run_gobuster_recursive.

    Solo considera rutas con status distinto de 404, lo que evita reportar como
    descubiertas rutas que el servidor negó. No depende de substring matching
    sobre HTML (que confunde paths reales con referencias a assets estáticos).
    """
    found: set[str] = set()
    for a in actions:
        if a.get("technique") not in {"run_gobuster", "run_gobuster_recursive"}:
            continue
        for path, status in _GOBUSTER_LINE_RE.findall(a.get("output_preview", "")):
            if status in {"200", "301", "302", "401", "403"}:
                found.add(path.lstrip("/"))
    return sorted(found)


def _extract_paths_from_curl_redirects(actions: list[dict]) -> list[str]:
    """Extrae rutas desde respuestas HTTP con código 2xx/3xx en run_curl."""
    found: set[str] = set()
    for a in actions:
        if a.get("technique") not in {"run_curl", "run_command"}:
            continue
        out = a.get("output_preview", "")
        if re.search(r"HTTP/[\d.]+\s+(?:200|301|302)", out):
            cmd_args = _parse_tool_args(a.get("command", ""))
            url = cmd_args.get("url", "")
            m = re.search(r"https?://[^/]+(/\S*)", url)
            if m:
                path = m.group(1).split("?")[0].rstrip("/")
                if path and path != "/":
                    found.add(path.lstrip("/"))
    return sorted(found)


def _all_outputs(actions: list[dict]) -> str:
    return "\n".join(a.get("output_preview", "") for a in actions)


def _parse_tool_args(command_json: str) -> dict:
    try:
        return json.loads(command_json)
    except Exception:
        return {}


def _is_echo_command(cmd: str) -> bool:
    cmd_l = cmd.strip().lower()
    return (
        cmd_l.startswith("echo ")
        or cmd_l.startswith("echo\t")
        or cmd_l.startswith("printf ")
        or cmd_l.startswith("/bin/echo ")
        or " | echo " in cmd_l
        or cmd_l == "echo"
    )


def _verify_webshell_live(webshell_url: str) -> tuple[bool, str]:
    try:
        from src.infrastructure.docker_client import DockerClient
    except Exception:
        return False, "no se pudo importar DockerClient"

    a, b = random.randint(100, 999), random.randint(100, 999)
    expected = str(a + b)
    marker = f"v{random.randint(10000, 99999)}"
    cmd = f"echo -n {marker}; expr {a} + {b}"
    encoded = urllib.parse.quote(cmd)
    docker = DockerClient()
    result = docker.exec_in_attacker(f"curl -s '{webshell_url}?cmd={encoded}'", timeout=15)
    if result.exit_code != 0:
        return False, f"webshell no respondio (exit={result.exit_code})"
    out = result.stdout.strip()
    if marker not in out or expected not in out:
        return False, (
            f"output no contiene marker+suma esperados "
            f"(esperaba '{marker}'+'{expected}', obtuvo '{out[:80]}')"
        )
    return True, f"webshell operativa (marker={marker})"


def _verify_root_live(webshell_url: str) -> tuple[bool, str]:
    try:
        from src.infrastructure.docker_client import DockerClient
    except Exception:
        return False, "no se pudo importar DockerClient"

    cmd = "python3 -c 'import os; os.setuid(0); os.system(\"head -1 /etc/shadow\")'"
    encoded = urllib.parse.quote(cmd)
    docker = DockerClient()
    result = docker.exec_in_attacker(f"curl -s '{webshell_url}?cmd={encoded}'", timeout=15)
    if result.exit_code != 0:
        return False, f"webshell no respondio (exit={result.exit_code})"
    out = result.stdout.strip()
    if out.startswith("root:") and len(out) > 10:
        return True, "root confirmado (/etc/shadow leido)"
    return False, f"lectura de /etc/shadow fallo (obtuvo: {out[:80]})"


def verify_reconnaissance(state: dict) -> tuple[bool, str, dict]:
    actions = _get_tactic_actions(state, "reconnaissance")
    evidence = {}
    missing = []

    nmap_actions = [a for a in actions if a.get("technique") == "run_nmap"]
    if not nmap_actions:
        missing.append("nmap no invocado")
    else:
        nmap_out = _all_outputs(nmap_actions)
        if re.search(r"80/tcp\s+open", nmap_out):
            evidence["port_80_open"] = True
        else:
            missing.append("nmap ejecutado pero no se confirmo 80/tcp open")

    web_tools = {"run_nikto", "run_gobuster", "run_curl", "run_wpscan", "run_command"}
    web_actions = [a for a in actions if a.get("technique") in web_tools]
    if not web_actions:
        missing.append("ninguna herramienta de enumeracion web invocada")

    all_out = _all_outputs(actions)
    web_tech = []
    for pattern, name in [
        (r"\bApache\b", "Apache"),
        (r"\bnginx\b", "nginx"),
        (r"\bIIS\b", "IIS"),
        (r"wordpress|wp-login|wp-admin|wp-content", "WordPress"),
        (r"\bDVWA\b|dvwa", "DVWA"),
        (r"\bDrupal\b", "Drupal"),
        (r"\bJoomla\b", "Joomla"),
        (r"\bPHP\b", "PHP"),
        (r"\bMySQL\b", "MySQL"),
    ]:
        if re.search(pattern, all_out, re.IGNORECASE):
            web_tech.append(name)
    if web_tech:
        evidence["web_technologies"] = web_tech
    else:
        missing.append("no se identifico tecnologia web")

    paths = _extract_paths_from_gobuster(web_actions)
    if not paths:
        paths = _extract_paths_from_curl_redirects(web_actions)
    if paths:
        evidence["discovered_paths"] = sorted(paths)[:15]
    else:
        missing.append("no se descubrio ninguna ruta via gobuster u otros tools web")

    if missing:
        return False, "; ".join(missing), evidence

    return True, f"Puerto 80 open, tech={web_tech}, paths={sorted(paths)[:3]}", evidence


def verify_initial_access(state: dict) -> tuple[bool, str, dict]:
    actions = _get_tactic_actions(state, "initial_access")
    evidence = {}
    missing = []

    outputs = _all_outputs(actions)
    creds_user = None
    creds_pass = None
    credentials_source = None

    m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", outputs, re.IGNORECASE)
    if m:
        creds_user = m.group(1)
        creds_pass = m.group(2)
        credentials_source = "hydra"

    if not creds_user:
        for action in actions:
            cmd = action.get("command", "")
            out = action.get("output_preview", "")
            args = _parse_tool_args(cmd)
            if args.get("login_url") and args.get("login_data"):
                if _is_login_success(out):
                    extracted = _extract_post_credentials(args.get("login_data", ""))
                    if extracted:
                        creds_user, creds_pass = extracted
                        credentials_source = "http_session"
                        break
            if not _is_login_post(cmd):
                continue
            if not _is_login_success(out):
                continue
            extracted = _extract_post_credentials(cmd)
            if extracted:
                creds_user, creds_pass = extracted
                credentials_source = "direct_verify"
                break

    if not creds_user:
        missing.append(
            "credenciales no verificadas (usa hydra contra el login "
            "o verifica credenciales descubiertas con un POST autenticado)"
        )
    else:
        evidence["username"] = creds_user
        evidence["password"] = creds_pass
        evidence["credentials_source"] = credentials_source

    login_verified = False
    for action in actions:
        cmd = action.get("command", "")
        out = action.get("output_preview", "")
        if _is_login_post(cmd) and _is_login_success(out):
            login_verified = True
            break
        args = _parse_tool_args(cmd)
        if args.get("login_url") and _is_login_success(out):
            login_verified = True
            break
        if "hydra" in cmd and re.search(r"login:.*password:", out):
            login_verified = True
            break

    if login_verified:
        evidence["login_verified"] = True
    else:
        missing.append(
            "login no verificado (POST con credenciales debe retornar 302 "
            "o respuesta indicando sesion exitosa)"
        )

    if missing:
        return False, "; ".join(missing), evidence

    return (
        True,
        f"Credenciales {creds_user}:{creds_pass} verificadas via {credentials_source}",
        evidence,
    )


def _is_login_post(cmd: str) -> bool:
    """Detecta un comando que hace POST a un endpoint de login."""
    cmd_l = cmd.lower()
    if "post" not in cmd_l and "-d " not in cmd_l and "-d'" not in cmd_l:
        return False
    login_hints = [
        "wp-login", "/login", "login.php", "signin", "authenticate",
        "log=", "username=", "user=", "email=",
    ]
    pass_hints = ["pwd=", "password=", "passwd=", "pass="]
    has_login = any(h in cmd_l for h in login_hints)
    has_pass = any(h in cmd_l for h in pass_hints)
    return has_login and has_pass


def _is_login_success(response: str) -> bool:
    """Detecta evidencia HTTP de login exitoso en el output de una peticion.

    Distincion clave: apps como DVWA retornan 302 Location: login.php en fallo,
    no solo en exito. Un 302 cuyo destino es el mismo endpoint de login NO es
    evidencia de autenticacion exitosa.
    """
    if re.search(r"HTTP/[\d.]+\s+30[12]", response):
        # Redirect de vuelta al propio login = fallo (DVWA, Drupal, etc.)
        if re.search(
            r"Location:\s*[^\r\n]*(?:login|signin|signon|auth|session)(?:\.php|\.html|\.asp|/)?\b",
            response,
            re.IGNORECASE,
        ):
            return False
        # Redirect a pagina protegida/interna = exito
        if re.search(
            r"Location:\s*/?(wp-admin|admin|dashboard|home|index|user|profile|vulnerabilities)",
            response,
            re.IGNORECASE,
        ):
            return True
        # Cualquier otro 302 a ruta distinta de login tambien cuenta como exito
        if re.search(r"Location:\s*\S+", response):
            return True
    # Set-Cookie con session token indica sesion creada
    if re.search(r"Set-Cookie:\s*[^\n]*session[^\n]*=[^\s;]+", response, re.IGNORECASE):
        if not re.search(r"(invalid|error|incorrect|denied)", response, re.IGNORECASE):
            return True
    return False


def _extract_post_credentials(cmd: str) -> tuple[str, str] | None:
    """Extrae username + password del body de un POST de login."""
    for user_key, pass_key in [
        ("log", "pwd"),
        ("username", "password"),
        ("user", "pass"),
        ("email", "password"),
    ]:
        pattern = rf"{user_key}=([^&'\"\s]+)[^&]*&{pass_key}=([^&'\"\s]+)"
        m = re.search(pattern, cmd, re.IGNORECASE)
        if m:
            return m.group(1), m.group(2)
    return None


def verify_execution(state: dict) -> tuple[bool, str, dict]:
    """
    Acepta RCE verificada por cualquier tool (web_shell, curl, command, sqlmap)
    cuyo output muestre ejecucion real de comandos en el target.
    """
    actions = _get_tactic_actions(state, "execution")
    evidence = {}
    missing = []

    target = state.get("target", "")

    def _has_real_system_output(text: str) -> bool:
        """Detecta evidencia de ejecucion real en el target.

        Acepta tanto output crudo (webshell/curl directo) como output dentro
        de HTML (apps con form vulnerable que reflejan el resultado del comando
        en un <pre>, ej: DVWA, command injection en formularios web).
        """
        patterns = [
            r"\buid=\d+\([^)]+\)\s+gid=\d+",
            r"^Linux\s+\S+\s+[\d.]+",
            r"^\w+\s+\d+\s+\d+:\d+:\d+",
            r"^PID\s+TTY",
            r"^root:[^:]*:0:0:",
            r"\bGNU/Linux\b",
        ]
        return any(re.search(p, text, re.MULTILINE) for p in patterns)

    webshell_url = None
    rce_via_tool = False
    rce_source = None

    for action in actions:
        tool_name = action.get("technique", "")
        cmd = action.get("command", "")
        out = action.get("output_preview", "")

        if tool_name == "run_web_shell":
            args = _parse_tool_args(cmd)
            if _is_echo_command(args.get("cmd", "")):
                continue
            if _has_real_system_output(out):
                webshell_url = args.get("url", "")
                rce_source = "run_web_shell"
                break
            continue

        if tool_name in {"run_curl", "run_command", "run_sqlmap", "run_http_session"}:
            if target and target not in cmd and target not in out:
                continue
            if _has_real_system_output(out):
                rce_via_tool = True
                rce_source = tool_name
                break

    if rce_source is None:
        missing.append(
            "RCE no verificada: ninguna herramienta retorno output real del sistema "
            "(uid=, Linux kernel version, /etc/passwd, etc). Intenta un vector de "
            "command injection, file upload, o deploy de webshell."
        )
        return False, "; ".join(missing), evidence

    if webshell_url:
        evidence["webshell_url"] = webshell_url
        live_ok, live_reason = _verify_webshell_live(webshell_url)
        if live_ok:
            evidence["webshell_live_verified"] = True
            return True, f"Webshell operativa en {webshell_url}", evidence
        missing.append(f"verificacion live de webshell fallo: {live_reason}")
        return False, "; ".join(missing), evidence

    if rce_via_tool:
        evidence["rce_via"] = rce_source
        evidence["rce_verified"] = True
        return True, f"RCE verificada via {rce_source}", evidence

    return False, "RCE no verificada", evidence


_EXECUTION_VECTORS = {"run_web_shell", "run_http_session", "run_curl", "run_command", "run_sqlmap"}
_ENUM_KEYWORDS = ["uname", "whoami", " id ", "/etc/passwd", "/home", "hostname", "ifconfig", "ip a", "ls /"]


def _real_execution_actions(actions: list[dict]) -> list[dict]:
    """Devuelve acciones que ejecutaron comandos reales en el target.

    Acepta cualquier vector de ejecucion: webshell, command injection via
    run_http_session, run_curl con RCE por parametro, etc. Filtra comandos echo
    y comandos shell que no tocaron el target.
    """
    real = []
    for action in actions:
        tool = action.get("technique", "")
        if tool not in _EXECUTION_VECTORS:
            continue
        args = _parse_tool_args(action.get("command", ""))
        user_cmd = args.get("cmd") or args.get("target_data") or args.get("data") or ""
        if _is_echo_command(user_cmd):
            continue
        real.append(action)
    return real


def verify_discovery(state: dict) -> tuple[bool, str, dict]:
    """Discovery es versatil: acepta enumeracion del sistema via cualquier
    vector de ejecucion (webshell, command injection, RCE por curl).
    """
    actions = _get_tactic_actions(state, "discovery")
    evidence = {}
    missing = []

    real_exec_actions = _real_execution_actions(actions)
    if not real_exec_actions:
        missing.append("discovery requiere ejecutar comandos en el target (via webshell, command injection, o RCE)")
        return False, "; ".join(missing), evidence

    all_out = _all_outputs(real_exec_actions)

    uname_match = re.search(r"Linux\s+\S+\s+[\d.]+", all_out)
    if uname_match:
        evidence["target_uname"] = uname_match.group(0)[:100]

    user_match = re.search(r"uid=\d+\(([^)]+)\)", all_out)
    if user_match:
        evidence["target_user"] = user_match.group(1)

    passwd_match = re.search(r"^(root:x:0:0:|[a-z_][a-z0-9_-]*:x:\d+:\d+:)", all_out, re.MULTILINE)
    if passwd_match:
        evidence["etc_passwd_read"] = True

    enum_done = (
        "target_uname" in evidence
        or "target_user" in evidence
        or "etc_passwd_read" in evidence
    )
    if not enum_done:
        for action in real_exec_actions:
            args = _parse_tool_args(action.get("command", ""))
            user_cmd = (args.get("cmd") or args.get("target_data") or args.get("data") or "").lower()
            if any(k in user_cmd for k in _ENUM_KEYWORDS):
                out = action.get("output_preview", "")
                if out.strip() and len(out.strip()) > 20:
                    enum_done = True
                    evidence["system_enumerated"] = True
                    break

    if not enum_done:
        missing.append(
            "enumeracion del sistema no verificada: ejecuta uname -a, id, "
            "whoami o cat /etc/passwd y confirma que la respuesta contiene output real"
        )

    hash_match = re.search(
        r"\b([a-z_][a-z0-9_]+):\$?[a-z0-9]{1,4}\$?([a-zA-Z0-9./$]{16,})\b",
        all_out,
    )
    if not hash_match:
        hash_match = re.search(
            r"\b([a-z_][a-z0-9_]+):([a-f0-9]{16,128})\b",
            all_out,
            re.IGNORECASE,
        )
    if hash_match:
        evidence["discovered_user"] = hash_match.group(1)
        evidence["discovered_hash"] = hash_match.group(2)

    if missing:
        return False, "; ".join(missing), evidence

    parts = []
    if "target_user" in evidence:
        parts.append(f"user={evidence['target_user']}")
    if "target_uname" in evidence:
        parts.append("uname ok")
    if "etc_passwd_read" in evidence:
        parts.append("passwd leido")
    if "discovered_hash" in evidence:
        parts.append(f"hash={evidence['discovered_user']}:{evidence['discovered_hash'][:12]}...")
    return True, "Sistema enumerado (" + ", ".join(parts) + ")", evidence


def verify_credential_access(state: dict) -> tuple[bool, str, dict]:
    actions = _get_tactic_actions(state, "credential_access")
    evidence = {}
    missing = []

    john_actions = [a for a in actions if a.get("technique") == "run_john"]
    if not john_actions:
        missing.append("run_john no invocado")
        return False, "; ".join(missing), evidence

    prior_hashes = set()
    for a in state.get("action_history", []):
        if a.get("tactic") == "discovery":
            matches = re.findall(r"\b[a-f0-9]{16,128}\b", a.get("output_preview", ""))
            prior_hashes.update(matches)

    hash_used = None
    for action in john_actions:
        args = _parse_tool_args(action.get("command", ""))
        hash_content = args.get("hash_content", "")
        m = re.search(r"([a-f0-9]{16,128})", hash_content)
        if m:
            hash_used = m.group(1)
            break

    if not hash_used:
        missing.append("run_john llamado pero sin hash valido en hash_content")
    elif prior_hashes and hash_used not in prior_hashes:
        missing.append(
            f"el hash pasado a john no coincide con el descubierto en Discovery "
            f"(usaste {hash_used[:12]}...)"
        )
    else:
        evidence["hash_cracked_input"] = hash_used

    cracked = None
    outputs = _all_outputs(john_actions)
    m = re.search(r"^(\w+):([^\s:]+)::?", outputs, re.MULTILINE)
    if m and m.group(2) not in ("!", "", "*"):
        cracked = m.group(2)
    if not cracked:
        m = re.search(r"([^\s]+)\s*\(\w+\)\s*$", outputs, re.MULTILINE)
        if m:
            cracked = m.group(1)
    if not cracked:
        missing.append("password no crackeado")
    else:
        evidence["cracked_password"] = cracked

    if missing:
        return False, "; ".join(missing), evidence

    return True, f"Hash crackeado: {cracked}", evidence


def verify_privilege_escalation(state: dict) -> tuple[bool, str, dict]:
    """Privilege escalation es versatil: acepta cualquier evidencia de uid=0
    en output real del target, sin importar el vector (webshell, command
    injection, SUID, sudo).
    """
    actions = _get_tactic_actions(state, "privilege_escalation")
    evidence = {}
    missing = []

    real_exec_actions = _real_execution_actions(actions)
    all_out = _all_outputs(real_exec_actions)

    suid_enumerated = False
    for action in real_exec_actions:
        args = _parse_tool_args(action.get("command", ""))
        user_cmd = (args.get("cmd") or args.get("target_data") or args.get("data") or "")
        if "-perm" in user_cmd and ("u=s" in user_cmd or "4000" in user_cmd):
            suid_enumerated = True
            break
    if suid_enumerated:
        evidence["suid_enumerated"] = True

    root_confirmed = False
    if re.search(r"uid=0\(root\)", all_out):
        root_confirmed = True
        evidence["uid_0_observed"] = True
    elif re.search(r"^root:[^:]*:0:0:", all_out, re.MULTILINE):
        shadow_match = re.search(r"^root:[^\s:]{10,}:", all_out, re.MULTILINE)
        if shadow_match:
            root_confirmed = True
            evidence["shadow_root_hash"] = True

    webshell_url = ""
    tactic_evidence = state.get("tactic_evidence", {})
    webshell_url = tactic_evidence.get("execution", {}).get("webshell_url", "")
    if not root_confirmed and webshell_url:
        live_ok, live_reason = _verify_root_live(webshell_url)
        if live_ok:
            root_confirmed = True
            evidence["root_live_verified"] = True
            try:
                from src.infrastructure.docker_client import DockerClient
                key_cmd = "python3 -c 'import os; os.setuid(0); os.system(\"cat /root/key-3-of-3.txt\")'"
                docker = DockerClient()
                res = docker.exec_in_attacker(
                    f"curl -s '{webshell_url}?cmd={urllib.parse.quote(key_cmd)}'",
                    timeout=15,
                )
                m = re.search(r"\b([a-f0-9]{32})\b", res.stdout)
                if m:
                    evidence["key_3"] = m.group(1)
            except Exception:
                pass

    if not root_confirmed:
        missing.append(
            "escalacion no verificada: se requiere uid=0(root) en output real, "
            "lectura de /etc/shadow con hash de root, o verificacion live via webshell"
        )

    if missing:
        return False, "; ".join(missing), evidence

    parts = []
    if evidence.get("uid_0_observed"):
        parts.append("uid=0 confirmado")
    if evidence.get("shadow_root_hash"):
        parts.append("/etc/shadow leido")
    if evidence.get("root_live_verified"):
        parts.append("root live verificado")
    if evidence.get("key_3"):
        parts.append(f"key-3={evidence['key_3'][:12]}...")
    return True, "Root confirmado (" + ", ".join(parts) + ")", evidence


OBJECTIVE_VALIDATORS: dict[str, Callable[[dict], tuple[bool, str, dict]]] = {
    "reconnaissance": verify_reconnaissance,
    "initial_access": verify_initial_access,
    "execution": verify_execution,
    "discovery": verify_discovery,
    "credential_access": verify_credential_access,
    "privilege_escalation": verify_privilege_escalation,
}


def check_tactic_objective(state: dict) -> tuple[bool, str, dict]:
    """
    Verifica el objetivo de la tactica actual.

    Returns: (cumplido, razon, evidencia)
    """
    tactic = state.get("current_tactic", "")
    validator = OBJECTIVE_VALIDATORS.get(tactic)
    if validator is None:
        return True, f"No hay validador para {tactic}, aceptando juicio del LLM", {}
    return validator(state)
