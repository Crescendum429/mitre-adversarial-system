"""
Validadores de objetivos por tactica MITRE.

Cada tactica tiene un criterio concreto de exito que se verifica en codigo
(no por el LLM) contra el action_history y collected_data del atacante.

Si el objetivo NO se cumple, el grafo fuerza replanificacion con feedback
especifico sobre lo que falta. Esto evita que el LLM declare tacticas como
"completas" despues de 1-2 acciones superficiales.

Cada validador retorna:
  (success: bool, reason: str, extracted_evidence: dict)

extracted_evidence se agrega a collected_data automaticamente.
"""

import re
from typing import Callable


def _get_tactic_actions(state: dict, tactic: str) -> list[dict]:
    """Retorna las acciones ejecutadas durante una tactica especifica."""
    return [
        a for a in state.get("action_history", [])
        if a.get("tactic", "").lower() == tactic.lower()
    ]


def _all_outputs(actions: list[dict]) -> str:
    """Concatena los outputs de todas las acciones (para buscar patrones)."""
    return "\n".join(a.get("output_preview", "") for a in actions)


def verify_reconnaissance(state: dict) -> tuple[bool, str, dict]:
    """
    Reconnaissance requiere:
      1. Puerto 80 confirmado abierto via nmap
      2. Tecnologia web identificada (Apache, WordPress, etc)
      3. Al menos una ruta interesante descubierta (wp-login, wp-admin, etc)
    """
    actions = _get_tactic_actions(state, "reconnaissance")
    outputs = _all_outputs(actions)

    evidence = {}
    missing = []

    # 1. Puerto 80 abierto
    if re.search(r"80/tcp\s+open", outputs):
        evidence["port_80_open"] = True
    else:
        missing.append("nmap no confirmo puerto 80/tcp abierto (ejecuta run_nmap con -p-)")

    # 2. Tecnologia web
    web_tech = []
    if "Apache" in outputs:
        web_tech.append("Apache")
    if re.search(r"wordpress|wp-login|wp-admin|wp-content", outputs, re.IGNORECASE):
        web_tech.append("WordPress")
    if "PHP" in outputs:
        web_tech.append("PHP")
    if web_tech:
        evidence["web_technologies"] = web_tech
    else:
        missing.append("no se identifico tecnologia web (ejecuta run_nikto o run_gobuster)")

    # 3. Rutas interesantes
    interesting_paths = set()
    for path in ["/robots.txt", "/wp-login.php", "/wp-admin", "/license.txt", "/wp-content"]:
        if path in outputs:
            interesting_paths.add(path)
    if interesting_paths:
        evidence["discovered_paths"] = sorted(interesting_paths)
    else:
        missing.append("no se descubrio ninguna ruta sensible (ejecuta run_gobuster)")

    # Extra: si el output contiene key-1-of-3.txt (mencionado en robots.txt),
    # lo dejamos anotado pero NO lo contamos como key capturada aun — lo es
    # cuando efectivamente se lee el contenido.
    key1_match = re.search(r"^([0-9a-f]{32})\s*$", outputs, re.MULTILINE)
    if key1_match and "key-1-of-3" in outputs:
        evidence["key_1"] = key1_match.group(1)

    if missing:
        return False, "; ".join(missing), evidence

    return (
        True,
        f"Puerto 80 abierto, tech={web_tech}, paths={sorted(interesting_paths)}",
        evidence,
    )


def verify_initial_access(state: dict) -> tuple[bool, str, dict]:
    """
    Initial Access requiere:
      1. Credenciales WordPress encontradas (usuario + password)
      2. Login exitoso via POST a /wp-login.php con respuesta 302 a /wp-admin/
    """
    actions = _get_tactic_actions(state, "initial_access")
    outputs = _all_outputs(actions)

    evidence = {}
    missing = []

    # 1. Credenciales
    # Patron 1: formato user:password (sin espacios alrededor de :)
    creds_match = re.search(
        r"\b(elliot|admin|robot)[:\s]+([A-Za-z0-9\-!@#\$%^&*()_]{4,})",
        outputs,
    )
    if creds_match:
        evidence["wp_user"] = creds_match.group(1)
        evidence["wp_password"] = creds_match.group(2)
    else:
        # Patron 2: busqueda en base64 decodificado
        import base64
        b64_matches = re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", outputs)
        for b64 in b64_matches:
            try:
                decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
                m = re.search(r"\b(\w+)\s*:\s*([A-Za-z0-9\-!@#\$%^&*()_]{4,})", decoded)
                if m:
                    evidence["wp_user"] = m.group(1)
                    evidence["wp_password"] = m.group(2).strip()
                    break
            except Exception:
                continue
    # Patron 3: si hay un POST a wp-login con log= y pwd=, extraer de ahi
    if "wp_user" not in evidence:
        for action in actions:
            cmd = action.get("command", "")
            m = re.search(r"log=(\w+)[^&]*&pwd=([^&'\"]+)", cmd)
            if m:
                evidence["wp_user"] = m.group(1)
                evidence["wp_password"] = m.group(2)
                break
    if "wp_user" not in evidence:
        missing.append("no se encontraron credenciales (revisa /robots.txt y /license.txt)")

    # 2. Login exitoso: busca una peticion POST a wp-login.php cuya respuesta
    # contenga status 302. WordPress SIEMPRE redirige a /wp-admin/ cuando el login
    # es exitoso (200 = formulario de error, 302 = exito). No necesitamos verificar
    # el header Location explicitamente porque puede estar truncado en el preview.
    login_success = False
    login_action_cmd = ""
    for action in actions:
        out = action.get("output_preview", "")
        cmd = action.get("command", "")
        # Patrones que indican un POST curl con credenciales al login de WordPress
        is_wp_login_post = (
            "wp-login" in cmd
            and "log=" in cmd
            and "pwd=" in cmd
        )
        if is_wp_login_post and ("302 Found" in out or "HTTP/1.1 302" in out or "HTTP/2 302" in out):
            login_success = True
            login_action_cmd = cmd[:120]
            break
        # Alternativa: login con hydra — busca "host:port login: X password: Y"
        if "hydra" in cmd and re.search(r"login:\s*\S+.*password:\s*\S+", out):
            login_success = True
            login_action_cmd = cmd[:120]
            break

    if login_success:
        evidence["wp_login_verified"] = True
    else:
        missing.append(
            "no se verifico login exitoso (necesitas POST a /wp-login.php "
            "con respuesta 302 Location: /wp-admin/)"
        )

    if missing:
        return False, "; ".join(missing), evidence

    return (
        True,
        f"Credenciales {evidence.get('wp_user')}:{evidence.get('wp_password')}, login 302 confirmado",
        evidence,
    )


def verify_execution(state: dict) -> tuple[bool, str, dict]:
    """
    Execution requiere:
      1. Webshell desplegada via theme-editor (POST con action=editedfile + _wpnonce)
      2. Webshell verificada: run_web_shell con cmd=id o uname retorna output real
         del sistema (uid=, Linux, etc), NO HTML 404
    """
    actions = _get_tactic_actions(state, "execution")
    evidence = {}
    missing = []

    # 1. Deploy via theme-editor
    deployed = any(
        "theme-editor" in a.get("command", "") and "action=editedfile" in a.get("command", "")
        for a in actions
    )
    if deployed:
        evidence["webshell_deploy_attempted"] = True

    # 2. Webshell operativa: algun run_web_shell con output real del sistema
    webshell_verified = False
    webshell_url = None
    for action in actions:
        if action.get("technique") != "run_web_shell":
            continue
        out = action.get("output_preview", "")
        # Output tipico de id: uid=33(www-data) gid=33(www-data)
        # Output tipico de uname: Linux ...
        # Output NO valido: contiene "<!DOCTYPE" o "<html" (es un error 404 HTML)
        is_html_error = "<!DOCTYPE" in out or "<html" in out.lower()
        has_system_output = bool(
            re.search(r"\buid=\d+", out)
            or re.search(r"^Linux\s+", out, re.MULTILINE)
            or re.search(r"\bgid=\d+", out)
        )
        if has_system_output and not is_html_error:
            webshell_verified = True
            # Extraer URL de la webshell del comando
            cmd = action.get("command", "")
            url_match = re.search(r'"url":\s*"([^"]+)"', cmd)
            if url_match:
                webshell_url = url_match.group(1)
            evidence["webshell_verified_output"] = out[:200]
            break

    if webshell_verified:
        evidence["webshell_operational"] = True
        if webshell_url:
            evidence["webshell_url"] = webshell_url
    else:
        missing.append(
            "webshell no verificada (run_web_shell debe retornar output real "
            "del sistema como uid=33 o Linux, NO HTML 404)"
        )

    if missing:
        return False, "; ".join(missing), evidence

    return (
        True,
        f"Webshell operativa en {webshell_url or 'desconocido'}",
        evidence,
    )


def verify_discovery(state: dict) -> tuple[bool, str, dict]:
    """
    Discovery requiere:
      1. Enumeracion basica del sistema (uname, whoami, id)
      2. Lectura de /etc/passwd o enumeracion de /home
      3. Descubrimiento del hash de robot (formato MD5 de 32 chars hex)
    """
    actions = _get_tactic_actions(state, "discovery")
    outputs = _all_outputs(actions)
    evidence = {}
    missing = []

    # 1. Enumeracion del sistema
    enum_commands = {"uname", "whoami", "id"}
    enum_done = any(
        any(cmd in a.get("command", "").lower() for cmd in enum_commands)
        for a in actions
    )
    if enum_done:
        evidence["system_enumerated"] = True
        # Extraer info
        uname_match = re.search(r"Linux\s+\S+\s+[\d.]+", outputs)
        if uname_match:
            evidence["target_uname"] = uname_match.group(0)[:100]
        user_match = re.search(r"uid=\d+\(([^)]+)\)", outputs)
        if user_match:
            evidence["target_user"] = user_match.group(1)
    else:
        missing.append(
            "no se ejecuto enumeracion basica (corre uname, whoami o id via webshell)"
        )

    # 2. Descubrimiento de /home
    home_explored = any(
        "/home" in a.get("command", "") or "/etc/passwd" in a.get("command", "")
        for a in actions
    )
    if home_explored:
        evidence["home_explored"] = True
    else:
        missing.append("no se exploro /home ni /etc/passwd")

    # 3. Hash MD5 de robot descubierto
    # Buscar patron robot:<32 hex chars>
    hash_match = re.search(r"robot\s*:\s*([a-f0-9]{32})", outputs, re.IGNORECASE)
    if hash_match:
        evidence["robot_md5_hash"] = hash_match.group(1)
    else:
        missing.append(
            "hash MD5 de robot no encontrado (lee /home/robot/password.raw-md5 via webshell)"
        )

    # Extra: si al listar /home se encontro y leyo key-1 o key-2, capturarlo
    for action in actions:
        cmd = action.get("command", "")
        out = action.get("output_preview", "")
        if "key-1-of-3" in cmd:
            m = re.search(r"\b([a-f0-9]{32})\b", out)
            if m and m.group(1) != evidence.get("robot_md5_hash"):
                evidence["key_1"] = m.group(1)
        if "key-2-of-3" in cmd:
            m = re.search(r"\b([a-f0-9]{32})\b", out)
            if m and m.group(1) != evidence.get("robot_md5_hash"):
                evidence["key_2"] = m.group(1)

    if missing:
        return False, "; ".join(missing), evidence

    return (
        True,
        f"Sistema enumerado, hash robot:{evidence.get('robot_md5_hash', '?')[:12]}...",
        evidence,
    )


def verify_credential_access(state: dict) -> tuple[bool, str, dict]:
    """
    Credential Access requiere:
      1. Ejecucion de john contra el hash descubierto
      2. Hash crackeado (password en texto plano)
    """
    actions = _get_tactic_actions(state, "credential_access")
    outputs = _all_outputs(actions)
    evidence = {}
    missing = []

    # 1. john ejecutado
    john_run = any(a.get("technique") == "run_john" for a in actions)
    if not john_run:
        missing.append("john no ejecutado (usa run_john con el hash descubierto)")

    # 2. Password crackeado
    # Output tipico de john --show: "robot:abcdefghijklmnopqrstuvwxyz:..."
    # O: "robot         (abcdefghijklmnopqrstuvwxyz)"
    cracked = None
    # Patron 1: john --show
    m = re.search(r"robot:([^\s:]+)(?::|$)", outputs)
    if m and m.group(1) not in ("!", ""):
        cracked = m.group(1)
    # Patron 2: john durante crack
    if not cracked:
        m = re.search(r"([\w]+)\s+\(robot\)", outputs)
        if m:
            cracked = m.group(1)
    # Patron 3: "password hash cracked" — buscar palabras del wordlist
    if not cracked:
        # john imprime "1 password hash cracked"
        if "password hash cracked" in outputs.lower():
            # Buscar en las acciones por algo con formato "robot : <something>"
            m = re.search(r"robot[:\s]+([a-z]+)\b", outputs)
            if m:
                cracked = m.group(1)

    if cracked:
        evidence["robot_password"] = cracked
    else:
        missing.append("password no crackeado (john debe retornar la contrasena en texto plano)")

    # Extra: si durante la tactica se leyo /home/robot/key-2-of-3.txt, capturarlo
    for action in actions:
        cmd = action.get("command", "")
        out = action.get("output_preview", "")
        if "key-2-of-3" in cmd:
            m = re.search(r"\b([a-f0-9]{32})\b", out)
            if m:
                evidence["key_2"] = m.group(1)

    if missing:
        return False, "; ".join(missing), evidence

    return True, f"Password de robot crackeado: {cracked}", evidence


def verify_privilege_escalation(state: dict) -> tuple[bool, str, dict]:
    """
    Privilege Escalation requiere:
      1. Binarios SUID enumerados
      2. Explotacion exitosa: comando ejecutado como root (uid=0)
         O lectura de /root/key-3-of-3.txt
    """
    actions = _get_tactic_actions(state, "privilege_escalation")
    outputs = _all_outputs(actions)
    evidence = {}
    missing = []

    # 1. SUID enumerados
    suid_enumerated = any(
        "-perm" in a.get("command", "") and "u=s" in a.get("command", "")
        for a in actions
    )
    if suid_enumerated:
        evidence["suid_enumerated"] = True
        # Extraer binarios SUID encontrados
        suid_bins = re.findall(r"^(/\S+(?:python|nmap|perl|ruby|php|bash|vi|less|find|cp)\S*)", outputs, re.MULTILINE)
        if suid_bins:
            evidence["suid_binaries"] = suid_bins[:10]

    # 2. Root obtenido: buscar uid=0(root) en algun output, O contenido del key-3
    root_gained = False
    if re.search(r"uid=0\(root\)", outputs):
        root_gained = True
        evidence["root_uid_confirmed"] = True

    # Lectura de /root/key-3-of-3.txt
    key3_read = False
    if re.search(r"/root/key-3-of-3\.txt", " ".join(a.get("command", "") for a in actions)):
        # Verificar que el output tiene contenido plausible de un flag (hash de 32 chars)
        for action in actions:
            if "/root/key-3" in action.get("command", ""):
                out = action.get("output_preview", "")
                # Flag tipico es hash MD5 (32 hex chars) o string similar
                if re.search(r"[a-f0-9]{32}", out) or (out.strip() and "Permission denied" not in out and "<!DOCTYPE" not in out):
                    key3_read = True
                    m = re.search(r"([a-f0-9]{32})", out)
                    if m:
                        evidence["key_3"] = m.group(1)
                    break

    if not root_gained and not key3_read:
        if not suid_enumerated:
            missing.append("SUID binaries no enumerados (corre find / -perm -u=s -type f)")
        else:
            missing.append(
                "escalacion no verificada: ejecuta python3 -c \"import os; os.setuid(0); "
                "os.system('cat /root/key-3-of-3.txt')\" via webshell"
            )

    if missing:
        return False, "; ".join(missing), evidence

    return (
        True,
        f"Root obtenido, key-3={evidence.get('key_3', 'leido')[:16]}...",
        evidence,
    )


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

    Returns: (objetivo_cumplido, razon_detallada, evidencia_extraida)
    """
    tactic = state.get("current_tactic", "")
    validator = OBJECTIVE_VALIDATORS.get(tactic)
    if validator is None:
        # Sin validador: aceptar el juicio del LLM por defecto
        return True, f"No hay validador para {tactic}, aceptando juicio del LLM", {}
    return validator(state)
