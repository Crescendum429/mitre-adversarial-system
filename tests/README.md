# Tests unitarios

Suite de tests para validar correctitud de los componentes deterministicos del
sistema (validadores de objetivos, memoria, heuristicas de observador, metricas).

**Estos tests no requieren Docker ni acceso a APIs LLM** — son puros y rapidos
(~1 segundo total). Se enfocan en la logica determinista que respalda al LLM.

## Como correr

```bash
poetry run pytest tests/
# o, mas verboso
poetry run pytest tests/ -v --tb=short
```

## Cobertura

| Archivo | # Tests | Que cubre |
|---------|---------|-----------|
| `test_objectives.py` | 30 | Validadores de las 6 tacticas MITRE: aceptan evidencia observable, rechazan hallucination (echo, HTML sin uid, 302→login). |
| `test_memory.py` | 14 | Fingerprint de target (estable, target-agnostic), persistencia atomica de playbooks, sanitizacion de credenciales. |
| `test_observer_heuristics.py` | 27 | Patrones de detection de CVEs: Log4Shell, Struts/Confluence OGNL, Solr Velocity, Spring4Shell, Shellshock, webshell sub-tactica. |
| `test_metrics.py` | 28 | Metricas P/R/F1 micro/macro, multi-label, accuracy estricta vs ventana. |

**Total: 99 tests, todos passing.**

## Filosofia

Los tests documentan *contratos* de los componentes deterministicos. Cuando el
LLM produce output ambiguo, los validadores son la fuente de verdad sobre si
una tactica se cumplio. Los tests aseguran que esa fuente de verdad no tiene
falsos positivos (acepta evidencia observable) ni falsos negativos (rechaza
output fabricado).

Ejemplos clave:

- `TestIsLoginSuccess::test_302_to_login_is_failure`: documenta que DVWA
  retorna 302 → login.php en login fallido. El bug previo aceptaba esto como
  exito y validaba `admin:.bash_history` como credencial real.
- `TestExtractWebshellCmd::test_url_encoded`: documenta que `?cmd%3Did`
  (URL-encoded) debe extraerse como `id`, no perderse silenciosamente.
- `TestVerifyExecution::test_accepts_uid_in_html_response`: DVWA retorna
  `uid=33(www-data)` embebido en `<pre>` dentro del HTML del form. El
  validator debe encontrarlo aun con el wrapping HTML.

## Tests futuros (no criticos para defensa)

- Tests de integracion que requieren Docker: skipear si no hay daemon.
- Tests de los wrappers de tools (mocking del DockerClient).
- Property-based tests con Hypothesis para regex de extraccion.
