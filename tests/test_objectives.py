"""Tests unitarios de los validadores de objetivos.

Estos tests son clave para la defensa de tesis: demuestran que los validadores
rechazan evidencia falsa (hallucination del LLM) y aceptan solo evidencia
observable. Cada test documenta un escenario con su resultado esperado.
"""

import pytest

from src.agents.attacker.objectives import (
    _extract_cracked_password,
    _extract_paths_from_gobuster,
    _is_login_post,
    _is_login_success,
    verify_credential_access,
    verify_discovery,
    verify_execution,
    verify_initial_access,
    verify_privilege_escalation,
    verify_reconnaissance,
)


# ---------------------------------------------------------------------------
# _is_login_success: bug critico que antes aceptaba 302→login como exito
# ---------------------------------------------------------------------------

class TestIsLoginSuccess:
    def test_302_to_login_is_failure(self):
        """DVWA retorna 302 Location: login.php en login fallido."""
        response = "HTTP/1.1 302 Found\nLocation: login.php\nContent-Length: 0"
        assert _is_login_success(response) is False

    def test_302_to_wp_login_is_failure(self):
        """WordPress retorna 302 a wp-login.php en fallido."""
        response = "HTTP/1.1 302 Found\nLocation: /wp-login.php?error=1"
        assert _is_login_success(response) is False

    def test_302_to_index_is_success(self):
        """DVWA redirige a index.php tras login exitoso."""
        response = "HTTP/1.1 302 Found\nLocation: index.php"
        assert _is_login_success(response) is True

    def test_302_to_wp_admin_is_success(self):
        """WordPress redirige a wp-admin tras login exitoso."""
        response = "HTTP/1.1 302 Found\nLocation: /wp-admin/"
        assert _is_login_success(response) is True

    def test_302_to_dashboard_is_success(self):
        response = "HTTP/1.1 302 Found\nLocation: /dashboard"
        assert _is_login_success(response) is True

    def test_302_to_signin_is_failure(self):
        response = "HTTP/1.1 302 Found\nLocation: /signin"
        assert _is_login_success(response) is False

    def test_200_without_session_is_failure(self):
        """Respuesta 200 sin cookie de sesion NO es login exitoso."""
        response = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<form>..."
        assert _is_login_success(response) is False

    def test_set_cookie_with_session_is_success(self):
        response = "HTTP/1.1 200 OK\nSet-Cookie: sessionid=abc123; path=/"
        assert _is_login_success(response) is True

    def test_set_cookie_with_error_keyword_is_failure(self):
        """Si la respuesta contiene 'invalid' o 'error', no es exitoso."""
        response = "HTTP/1.1 200 OK\nSet-Cookie: session=x\n\ninvalid credentials"
        assert _is_login_success(response) is False


# ---------------------------------------------------------------------------
# _is_login_post
# ---------------------------------------------------------------------------

class TestIsLoginPost:
    def test_wp_login_post(self):
        cmd = 'curl -d "log=admin&pwd=hunter2" http://target/wp-login.php'
        assert _is_login_post(cmd) is True

    def test_dvwa_login_post(self):
        cmd = 'curl -X POST -d "username=admin&password=x" http://target/login.php'
        assert _is_login_post(cmd) is True

    def test_get_is_not_login_post(self):
        cmd = 'curl http://target/login.php'
        assert _is_login_post(cmd) is False

    def test_post_without_login_fields(self):
        cmd = 'curl -d "ip=127.0.0.1" http://target/vulnerabilities/exec/'
        assert _is_login_post(cmd) is False


# ---------------------------------------------------------------------------
# _extract_paths_from_gobuster
# ---------------------------------------------------------------------------

class TestExtractPathsFromGobuster:
    def test_extracts_200_paths(self):
        gobuster_output = (
            "/admin              (Status: 200) [Size: 1234]\n"
            "/login.php          (Status: 302) [Size: 0]\n"
            "/private            (Status: 403) [Size: 256]\n"
            "/nonexistent        (Status: 404) [Size: 0]\n"
        )
        actions = [{"technique": "run_gobuster", "output_preview": gobuster_output}]
        paths = _extract_paths_from_gobuster(actions)
        assert "admin" in paths
        assert "login.php" in paths
        assert "private" in paths  # 403 tambien cuenta
        assert "nonexistent" not in paths  # 404 excluido

    def test_ignores_non_gobuster_actions(self):
        actions = [{"technique": "run_curl", "output_preview": "/admin (Status: 200)"}]
        assert _extract_paths_from_gobuster(actions) == []


# ---------------------------------------------------------------------------
# _extract_cracked_password: bug del john regex anterior
# ---------------------------------------------------------------------------

class TestExtractCrackedPassword:
    def test_john_show_format(self):
        """john --show output: user:password:::"""
        text = "robot:ilovebob:::"
        password, user = _extract_cracked_password(text)
        assert password == "ilovebob"
        assert user == "robot"

    def test_john_cracking_format(self):
        """john cracking: password       (user)"""
        text = "mypassword       (elliot)\n1g 0:00:00 done"
        password, user = _extract_cracked_password(text)
        assert password == "mypassword"
        assert user == "elliot"

    def test_hashcat_format(self):
        """hashcat: hash:password"""
        text = "5f4dcc3b5aa765d61d8327deb882cf99:password"
        password, user = _extract_cracked_password(text)
        assert password == "password"

    def test_no_password_found(self):
        text = "No password hashes loaded"
        password, user = _extract_cracked_password(text)
        assert password is None
        assert user is None

    def test_rejects_known_noise(self):
        """john --show con ! o * NO es un password real."""
        text = "root:!:::"
        password, user = _extract_cracked_password(text)
        assert password is None


# ---------------------------------------------------------------------------
# verify_reconnaissance: requiere nmap + tech + paths
# ---------------------------------------------------------------------------

class TestVerifyReconnaissance:
    def _state(self, actions):
        return {
            "current_tactic": "reconnaissance",
            "action_history": actions,
        }

    def test_rejects_empty_history(self):
        ok, reason, _ = verify_reconnaissance(self._state([]))
        assert ok is False
        assert "nmap no invocado" in reason

    def test_accepts_complete_recon(self):
        actions = [
            {
                "tactic": "reconnaissance",
                "technique": "run_nmap",
                "output_preview": "80/tcp open http Apache httpd\n443/tcp open",
            },
            {
                "tactic": "reconnaissance",
                "technique": "run_gobuster",
                "output_preview": (
                    "/admin (Status: 200) [Size: 1234]\n"
                    "/login.php (Status: 302)\n"
                    "/robots.txt (Status: 200)\n"
                ),
            },
        ]
        ok, reason, evidence = verify_reconnaissance(self._state(actions))
        assert ok is True, reason
        assert evidence.get("http_port_open") == 80
        assert "Apache" in evidence.get("web_technologies", [])
        assert "admin" in evidence.get("discovered_paths", [])

    def test_detects_non_standard_http_port(self):
        """Ports 8983 (Solr), 8080 (Tomcat) etc. deben contar."""
        actions = [
            {
                "tactic": "reconnaissance",
                "technique": "run_nmap",
                "output_preview": "8983/tcp open solr Apache Solr 7.7.0",
            },
            {
                "tactic": "reconnaissance",
                "technique": "run_gobuster",
                "output_preview": "/solr (Status: 200)",
            },
        ]
        ok, reason, evidence = verify_reconnaissance(self._state(actions))
        assert ok is True, reason
        assert evidence.get("http_port_open") == 8983
        assert "Apache Solr" in evidence.get("web_technologies", [])


# ---------------------------------------------------------------------------
# verify_execution: debe detectar uid= en HTML (bug critico del audit)
# ---------------------------------------------------------------------------

class TestVerifyExecution:
    def _state(self, actions, target="10.10.0.10"):
        return {
            "current_tactic": "execution",
            "target": target,
            "action_history": actions,
        }

    def test_accepts_uid_in_html_response(self):
        """DVWA retorna uid=33(www-data) embebido en HTML del form."""
        html_response = (
            "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
            "<!DOCTYPE html>\n<html>...\n"
            "<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n</pre>\n"
            "</html>"
        )
        actions = [
            {
                "tactic": "execution",
                "technique": "run_http_session",
                "command": '{"target_url": "http://10.10.0.10/vulnerabilities/exec/"}',
                "output_preview": html_response,
            }
        ]
        ok, reason, evidence = verify_execution(self._state(actions))
        assert ok is True, reason
        assert evidence.get("rce_verified") is True

    def test_accepts_webshell_with_uid(self):
        actions = [
            {
                "tactic": "execution",
                "technique": "run_web_shell",
                "command": '{"url": "http://10.10.0.20/shell.php", "cmd": "id"}',
                "output_preview": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            }
        ]
        ok, reason, evidence = verify_execution(self._state(actions))
        assert ok is True, reason

    def test_rejects_html_without_uid(self):
        actions = [
            {
                "tactic": "execution",
                "technique": "run_http_session",
                "command": '{"target_url": "http://10.10.0.10/"}',
                "output_preview": "<html><body>Welcome</body></html>",
            }
        ]
        ok, _, _ = verify_execution(self._state(actions))
        assert ok is False

    def test_rejects_echo_webshell(self):
        """run_web_shell con cmd='echo foo' NO es evidencia de RCE."""
        actions = [
            {
                "tactic": "execution",
                "technique": "run_web_shell",
                "command": '{"url": "http://10.10.0.20/shell.php", "cmd": "echo hello"}',
                "output_preview": "hello",
            }
        ]
        ok, _, _ = verify_execution(self._state(actions))
        assert ok is False


# ---------------------------------------------------------------------------
# verify_discovery: requiere evidencia real (no fallback laxo)
# ---------------------------------------------------------------------------

class TestVerifyDiscovery:
    def _state(self, actions):
        return {"current_tactic": "discovery", "action_history": actions}

    def test_accepts_uname_output(self):
        actions = [
            {
                "tactic": "discovery",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "uname -a"}',
                "output_preview": "Linux mrrobot 6.19.6 #1 SMP Debian x86_64",
            }
        ]
        ok, reason, evidence = verify_discovery(self._state(actions))
        assert ok is True, reason
        assert "target_uname" in evidence

    def test_rejects_404_html(self):
        """Bug previo: HTML 404 pasaba la validacion de discovery."""
        actions = [
            {
                "tactic": "discovery",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "uname"}',
                "output_preview": "<html><title>404 Not Found</title></html>",
            }
        ]
        ok, _, _ = verify_discovery(self._state(actions))
        assert ok is False

    def test_accepts_etc_passwd(self):
        actions = [
            {
                "tactic": "discovery",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "cat /etc/passwd"}',
                "output_preview": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            }
        ]
        ok, _, evidence = verify_discovery(self._state(actions))
        assert ok is True
        assert evidence.get("etc_passwd_read") is True

    def test_extracts_hash_from_output(self):
        actions = [
            {
                "tactic": "discovery",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "cat /home/robot/password.raw-md5"}',
                "output_preview": "robot:c3fcd3d76192e4007dfb496cca67e13b",
            }
        ]
        # Aunque no valide solo por hash, si hay uname tambien debe aceptar + capturar hash
        actions.append({
            "tactic": "discovery",
            "technique": "run_web_shell",
            "command": '{"url": "http://x/shell.php", "cmd": "uname -a"}',
            "output_preview": "Linux mrrobot 6.19.6",
        })
        ok, _, evidence = verify_discovery(self._state(actions))
        assert ok is True
        assert evidence.get("discovered_user") == "robot"
        assert evidence.get("discovered_hash") == "c3fcd3d76192e4007dfb496cca67e13b"


# ---------------------------------------------------------------------------
# verify_credential_access: versatil (hydra/hashcat/lectura directa)
# ---------------------------------------------------------------------------

class TestVerifyCredentialAccess:
    def _state(self, cred_actions, discovery_actions=None):
        actions = []
        if discovery_actions:
            actions.extend(discovery_actions)
        actions.extend(cred_actions)
        return {"current_tactic": "credential_access", "action_history": actions}

    def test_accepts_john_crack_output(self):
        actions = [
            {
                "tactic": "credential_access",
                "technique": "run_john",
                "command": '{"hash_content": "robot:5f4dcc3b5aa765d61d8327deb882cf99"}',
                "output_preview": "password         (robot)\n1g 0:00:00 done",
            }
        ]
        ok, reason, evidence = verify_credential_access(self._state(actions))
        assert ok is True, reason
        assert evidence.get("cracked_password") == "password"

    def test_accepts_hashcat_output(self):
        actions = [
            {
                "tactic": "credential_access",
                "technique": "run_command",
                "command": '{"command": "hashcat -m 0 hash.txt wordlist"}',
                "output_preview": "5f4dcc3b5aa765d61d8327deb882cf99:password",
            }
        ]
        ok, _, evidence = verify_credential_access(self._state(actions))
        assert ok is True
        assert evidence.get("cracked_password") == "password"

    def test_rejects_empty_actions(self):
        ok, _, _ = verify_credential_access(self._state([]))
        assert ok is False

    def test_rejects_only_echo_commands(self):
        """El LLM podria tratar de fabricar output con echo."""
        actions = [
            {
                "tactic": "credential_access",
                "technique": "run_command",
                "command": '{"command": "echo password (admin)"}',
                "output_preview": "password (admin)",
            }
        ]
        ok, reason, _ = verify_credential_access(self._state(actions))
        assert ok is False
        assert "echo" in reason.lower()


# ---------------------------------------------------------------------------
# verify_privilege_escalation: uid=0 O /etc/shadow O /root flag
# ---------------------------------------------------------------------------

class TestVerifyPrivilegeEscalation:
    def _state(self, actions):
        return {
            "current_tactic": "privilege_escalation",
            "action_history": actions,
            "tactic_evidence": {},
        }

    def test_accepts_uid_0(self):
        actions = [
            {
                "tactic": "privilege_escalation",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "python3 -c \'import os; os.setuid(0); os.system(\\"id\\")\'"}',
                "output_preview": "uid=0(root) gid=0(root) groups=0(root)",
            }
        ]
        ok, reason, evidence = verify_privilege_escalation(self._state(actions))
        assert ok is True, reason
        assert evidence.get("uid_0_observed") is True

    def test_accepts_etc_shadow_with_root_hash(self):
        actions = [
            {
                "tactic": "privilege_escalation",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "cat /etc/shadow"}',
                "output_preview": (
                    "root:$6$saltsalt$hashhashhashhashhashhashhash:19340:0:99999:7:::\n"
                    "daemon:*:19340:0:99999:7:::\n"
                ),
            }
        ]
        ok, _, evidence = verify_privilege_escalation(self._state(actions))
        assert ok is True
        assert evidence.get("shadow_root_hash") is True

    def test_accepts_root_flag_capture(self):
        """Acceso a /root/<archivo>.txt con hash = prueba de root."""
        actions = [
            {
                "tactic": "privilege_escalation",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "cat /root/key-3-of-3.txt"}',
                "output_preview": "04787ddef27c3dee1ee161b21670b4e4",
            }
        ]
        ok, _, evidence = verify_privilege_escalation(self._state(actions))
        assert ok is True
        assert evidence.get("root_flag_captured") == "04787ddef27c3dee1ee161b21670b4e4"

    def test_rejects_when_no_root_evidence(self):
        """Enum de SUID sin escalacion real NO es priv-esc."""
        actions = [
            {
                "tactic": "privilege_escalation",
                "technique": "run_web_shell",
                "command": '{"url": "http://x/shell.php", "cmd": "find / -perm -u=s -type f 2>/dev/null"}',
                "output_preview": "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/python3.10",
            }
        ]
        ok, _, _ = verify_privilege_escalation(self._state(actions))
        assert ok is False
