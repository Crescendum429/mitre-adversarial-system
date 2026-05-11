# Sistema Adversarial MITRE ATT&CK

Banco de pruebas adversarial controlado para medir empíricamente la capacidad de agentes LLM de inferir tácticas MITRE ATT&CK a partir únicamente de telemetría de red y logs del sistema. Dos agentes autónomos —uno ofensivo y uno defensivo— operan en paralelo sin comunicación directa; el agente defensivo solo observa los efectos del ataque a través del stack de observabilidad. Proyecto Integrador, USFQ Ingeniería en Ciencias de la Computación, mayo 2026.

## Pregunta de investigación

¿En qué medida pueden agentes LLM autónomos simular cadenas de ataque siguiendo el framework MITRE ATT&CK, y qué tan eficazmente puede un agente observador inferir la táctica activa a partir únicamente de telemetría de red y logs del sistema, en un entorno adversarial controlado y reproducible?

El trabajo se enmarca como **measurement paper, no system paper**: la contribución central no es proponer una arquitectura agéntica nueva, sino medir empíricamente la precisión de inferencia táctica MITRE ATT&CK por un observer LLM dentro del régimen documentado por benchmarks recientes (PentestEval 2025: 31 % pipeline completion; Cyber Defense Benchmark 2026: 3,8 % event labeling) como techo actual del estado del arte.

## Arquitectura

![Arquitectura del sistema](paper/Arquitectura.png)

> Documento final del proyecto integrador: [`paper/SISTEMA_ADVERSARIAL_MITRE_ATTACK_Alarcon.pdf`](paper/SISTEMA_ADVERSARIAL_MITRE_ATTACK_Alarcon.pdf)

Tres capas con responsabilidades estrictamente separadas:

| Capa | Implementación | Propósito |
|------|----------------|-----------|
| Orquestación | `src/main.py` (Python host) | Lanza atacante y observer en threads separados; persiste reportes |
| Agentes LLM | `src/agents/` (LangGraph) | Atacante grafo ReAct (5 nodos) + Observer pipeline condicional (6 nodos) |
| Infraestructura Docker | `docker/` (11 contenedores en 2 redes aisladas) | Targets vulnerables + stack de observabilidad |

| Agente | Patrón | Rol |
|--------|--------|-----|
| Atacante | ReAct con validators code-based, replans con feedback, memoria por SHA-256 fingerprint del target | Ejecuta cadenas de ataque MITRE ATT&CK contra targets vulnerables |
| Observador | Grafo condicional con triaje heurístico (T1-T10) + firmas CVE + clasificación LLM con calibración bayesiana cost-sensitive | Clasifica la táctica activa por ventana de 5 s a partir solo de logs |

**Decisión clave del setup**: los agentes NO se comunican directamente. El atacante interactúa con los targets; el observer consulta Loki. El único canal de información del observer es el efecto del ataque sobre los logs HTTP — simulando la perspectiva real de un analista SOC.

Modelo configurable por agente vía `.env`: soporta siete proveedores intercambiables (OpenAI, Anthropic, Google, Groq, OpenRouter, Cerebras, DeepSeek). Stack ganador operacional del Eje B (generalización a 7 escenarios): atacante `gpt-4.1` + observer `deepseek-chat`. Para escenarios complejos con credenciales no canónicas (bpent), atacante `claude-sonnet-4-5-20250929` completa 6/6 tácticas donde GPT-4.1 se atasca en Initial Access por sesgo de frecuencia.

**Reproducibilidad**: el sistema fija `LLM_SEED=42` y temperaturas separadas por rol (atacante 0.2 para exploración, observer 0.0 para clasificación determinista). El parámetro seed es respetado a nivel API por OpenAI, Google, Groq, Cerebras y OpenRouter; **Anthropic no expone seed determinista en su API actual**. Para corridas Anthropic la reproducibilidad estadística depende del `model_snapshot` fijo, `temperature=0.0` para el observer y reporte explícito de varianza inter-corrida (μ ± σ + IC 95 % bootstrap) sobre n ≥ 3.

## Componentes

```
src/
  agents/
    attacker/        # Grafo ReAct: plan → exec → valid → check → advance
    observer/        # Pipeline condicional: collect → triage → detect → classify → refine → recommend
  config/            # Settings tipados con Pydantic
  evaluation/        # metrics.py — macro/micro F1, bootstrap CI 95 %, matriz de confusión
  infrastructure/    # Cliente Docker SDK, queries LogQL a Loki
  llm/               # Capa multi-proveedor con reintentos backoff
  ui/                # Dashboard live (Rich) + reporte HTML autocontenido (asistido por Claude Design)
docker/
  docker-compose.yml # 11 contenedores en attack_net + monitor_net
data/
  matrix_aggregate.json    # 38 corridas consolidadas (4 ejes)
  observer_baselines.json  # Prior bayesiano por fingerprint de target
  attack_playbooks.json    # Memoria persistente del atacante (gitignored)
```

### Agente Atacante — grafo ReAct con validators code-based

Ciclo `plan_tactic → execute_tools → validate_result → check_objective → advance_tactic` sobre **30 herramientas de pentesting** ejecutadas dentro de un contenedor Kali Linux aislado. Implementado con LangGraph (Sapkota et al. 2025: el único framework Python que soporta nativamente grafos de estado con ciclos condicionales). El diseño del prompt sigue la metodología **Pentest Task Tree (PTT)** propuesta en PentestGPT (Deng et al., USENIX Security 2024).

Cada táctica tiene un **validator determinista** en `src/agents/attacker/objectives.py` que revisa el historial de acciones y decide si el objetivo fue cumplido (credenciales verificadas vía POST live, RCE con evidencia `uid=`, hash crackeado en texto plano, root confirmado por `uid=0` o lectura de `/etc/shadow` o `/root/`). Si el validator rechaza el avance, el grafo replanifica con feedback explícito hasta 15 veces antes de aceptar la táctica como fallida.

**Anti-cheating**: el principio anti-trampa del prompt prohíbe invocar credenciales, paths o procedimientos memorizados de writeups públicos del corpus de pre-entrenamiento. Cualquier acción debe estar justificada por evidencia recolectada en la corrida actual (output de tools, no conocimiento previo del LLM). Los validators complementan este principio rechazando como evidencia salida fabricada por `echo`, `printf` o `python -c print()`. La diferencia empírica entre régimen pre-anti-cheating y post-anti-cheating cuantifica cuánto del desempeño aparente del agente se debe a memorización del corpus vs razonamiento genuino.

**Memoria de playbooks** (`data/attack_playbooks.json`): tras Recon el sistema computa un fingerprint SHA-256 del target (puertos + tech anchor + paths normalizados) y consulta memoria. Si hay match, inyecta el playbook previo en los prompts de las tácticas siguientes como hipótesis a verificar. Reducción empírica observada cold→warm: −31,6 % de tool_calls (Eje D, 19 → 13 acciones; coherente con Eje C −48 % en corridas Sonnet 4.5/dvwa).

Catálogo de herramientas (fuente única de verdad: `src.agents.attacker.tools.TOOL_CATEGORIES`):

| Categoría | Tools |
|-----------|-------|
| Reconocimiento (13) | `run_nmap`, `run_whatweb`, `run_nikto`, `run_gobuster`, `run_gobuster_recursive`, `run_dirsearch`, `run_spider`, `run_wpscan`, `run_dns_enum`, `run_enum4linux`, `run_smbclient`, `run_ftp`, `run_searchsploit` |
| Explotación (10) | `run_hydra_http_form`, `run_hydra`, `run_john`, `run_http_session`, `run_sqlmap`, `run_curl`, `run_command`, `run_web_shell`, `run_ssh_exec`, `run_file_upload` |
| Payloads y listeners (4) | `write_exploit_file`, `run_msfvenom`, `start_reverse_listener`, `serve_http` |
| Escalada de privilegios (2) | `run_priv_esc_enum`, `run_linpeas` |
| Utilitarios (1) | `decode_string` (base64/hex/url/rot13) |

Tácticas implementadas end-to-end con validator: Reconnaissance, Initial Access, Execution, Discovery, Credential Access, Privilege Escalation. Prompts extendidos (sin validator code-based) para Persistence y Lateral Movement.

### Agente Observador — pipeline condicional con triaje y refinamiento

Pipeline de seis nodos (patrón Triage → Investigate → Classify de Vinay 2025):

1. **collect_logs** — consulta Loki vía LogQL hasta 1500 entradas por ventana de 5 s.
2. **triage_anomalies** — diez heurísticas T1-T10 sin LLM (firmas literales en User-Agent, rotación de UAs, métodos HTTP no estándar, Shellshock, velocidad de requests, ratios de 404, body-size uniforme, POST a rutas de autenticación, webshell activa, IPs sospechosas conocidas). Si no hay señal, el grafo termina sin invocar al LLM (40-60 % de calls ahorradas en ventanas vacías).
3. **detect_anomalies** — perfila IPs por status code HTTP sin LLM (webshell_execution, login_success, brute_force_4xx, scan_burst); pre-clasifica con regex MITRE.
4. **classify_tactic** — única invocación al LLM. Construye prompt con señales pre-calculadas + resumen deduplicado de logs + historial de últimas 8 clasificaciones + firmas CVE detectadas. Phase lock evita regresión hacia tácticas tempranas.
5. **refine_analysis** — si la confianza < umbral cost-sensitive, invoca al LLM con vista forense alternativa (max 2 iteraciones).
6. **generate_recommendation** — persiste la clasificación, genera recomendación accionable.

Firmas CVE pre-calculadas: Log4Shell `${jndi:ldap://...}`, Confluence OGNL `${@Runtime@exec}`, Struts2 OGNL, Solr Velocity, Spring4Shell. La calibración bayesiana adaptativa ajusta el umbral por táctica vía Elkan 2001 (cost-sensitive) y Platt 1999 (probability calibration); umbrales por defecto: Reconnaissance 0,55; Initial Access 0,60; Privilege Escalation 0,75.

## Infraestructura Docker

Topología en dos redes aisladas (`docker/docker-compose.yml`):

| Contenedor | Red | Función |
|------------|-----|---------|
| `attacker` | attack_net (10.10.0.5) | Kali Linux con catálogo de herramientas |
| `dvwa` | attack_net (10.10.0.10) + monitor_net | Damn Vulnerable Web Application |
| `mrrobot` | attack_net (10.10.0.20) + monitor_net | Réplica del CTF Mr. Robot (Apache + WordPress) |
| `dc1` | attack_net (10.10.0.30) + monitor_net | DC-1 inspirado (Drupal + SUID find) |
| `bpent` | attack_net (10.10.0.40) + monitor_net | Basic Pentesting (user `marlinspike` + SUID `vim.tiny`) |
| `log4shell` | attack_net (10.10.0.50) + monitor_net | Apache Solr 8.11.0 vulnerable a CVE-2021-44228 |
| `confluence` | attack_net (10.10.0.60) + monitor_net | Atlassian Confluence 7.13.6 vulnerable a CVE-2022-26134 |
| `phpunit` | attack_net (10.10.0.70) + monitor_net | PHPUnit 5.6.2 vulnerable a CVE-2017-9841 |
| `loki` | monitor_net (10.10.1.10) | Almacenamiento y consulta de logs |
| `promtail` | monitor_net (10.10.1.20) | Recolección de logs vía Docker socket autodiscovery |
| `grafana` | monitor_net (10.10.1.30) | Dashboard de visualización auxiliar |

El contenedor atacante **solo ve `attack_net`**; la infraestructura de observabilidad vive en `monitor_net` y no es alcanzable desde el atacante. El orquestador es un proceso Python en el host, no un contenedor — esto garantiza que el observer simule la perspectiva real de un analista SOC sin acceso al estado interno del atacante.

## Escenarios de evaluación

Siete escenarios con perfiles distintos:

- **`basic`** — cadena corta de cuatro tácticas sobre DVWA: Recon, Initial Access, Execution, Discovery. Escenario base de la matriz Eje A.
- **`dvwa`** — seis tácticas sobre DVWA: añade Credential Access y Privilege Escalation.
- **`mrrobot`** — seis tácticas sobre la réplica Mr. Robot. Contraseñas y hashes se generan aleatoriamente en cada build (no hardcoded).
- **`dc1`** — seis tácticas sobre DC-1 (Drupal + SUID find priv-esc). Mejor caso de generalización: 6/6 tácticas, mF1=0,529.
- **`bpent`** — seis tácticas sobre Basic Pentesting (Apache + brute-force SSH a `marlinspike` + SUID `vim.tiny`). Control empírico: sin walkthrough público en internet.
- **`log4shell`** — tres tácticas sobre Apache Solr 8.11.0 (CVE-2021-44228 JNDI o CVE-2019-17558 Velocity). RCE pre-auth directo, sin Initial Access ni brute force.
- **`confluence`** — tres tácticas sobre Confluence 7.13.6 (CVE-2022-26134 OGNL injection).
- **`phpunit`** — tres tácticas sobre PHPUnit 5.6.2 (CVE-2017-9841 eval-stdin RCE). Validación de generalización: vector POST único, distinto a los anteriores.

## Decisiones metodológicas (mayo 2026)

### Sincronización atacante-ventana (1:N táctica/ventana)

`settings.attacker_tactic_per_window=True` (default ON). Antes de iniciar la primera acción de cada nueva táctica, `execute_tools` espera al inicio de la siguiente ventana del observer. El razonamiento del LLM, replans y acciones intra-táctica **no** se bloquean — solo se difiere el `docker exec` del primer tool de cada táctica nueva.

Consecuencia metodológica: cada ventana del observer contiene **a lo más una táctica del kill chain** (1:N — una táctica puede ocupar varias ventanas, pero ninguna ventana abarca dos). Esto fortalece la separabilidad temporal del ground truth y convierte la clasificación del observer de multi-label genuino a single-label / multi-class por ventana, simplificando `strict_accuracy` y la matriz de confusión.

Para comparar con corridas previas a este cambio (sin sincronización):

```bash
ATTACKER_TACTIC_PER_WINDOW=0 poetry run python -m src.main --scenario basic
```

### Procesamiento secuencial del observer (sin saltos de ventana)

El loop principal del observer (`src/main.py`) y la flush phase incrementan el cursor temporal `last_end` exactamente en `interval_delta` (5 s) por iteración. Cuando la latencia LLM > polling, las ventanas se acumulan en backlog lógico — pero **nunca se descartan ni se saltan**. La flush phase explícita procesa todas las ventanas pendientes hasta cubrir el último evento del atacante + un intervalo de seguridad.

Prioridad: **cobertura completa sobre latencia** (régimen forense, no SOC reactivo). Saltar ventanas introduciría sesgo no observado en la matriz de confusión: las ventanas saltadas serían sistemáticamente las que coinciden con tácticas rápidas del atacante, sub-representando dichas clases. El `observer_backlog_ratio = (latencia avg / poll_interval) − 1.0` es métrica diagnóstica del retraso acumulado, **no de ventanas perdidas**.

## Métricas

- **macro-F1** (primaria): media no ponderada del F1 por táctica (Sokolova & Lapalme 2009). Se prefiere a micro-F1 por la distribución desbalanceada de tácticas en las ventanas (Reconnaissance domina por volumen de tráfico).
- **strict_accuracy**: porcentaje de ventanas con táctica predicha = táctica real. Bajo régimen 1:N es directamente interpretable.
- **per-tactic precision / recall / F1 + support**: dónde falla el observer.
- **matriz de confusión consolidada**: confusiones sistemáticas (Discovery clasificado como Execution, etc.).
- **bootstrap CI 95 %** (Efron 1979): 1 000 re-muestras, justifica n=1 single-run.
- **evaluable_windows (ew)**: cualifica mF1 (ew<5 marca outliers).
- **wall-clock total, latencia avg observer, tool_calls, replans**: métricas operacionales (viabilidad, no calidad).

## Requisitos

- Python 3.11+
- Docker y Docker Compose
- API key de al menos un proveedor LLM (OpenAI, Anthropic, Google, Groq, OpenRouter, Cerebras o DeepSeek)

## Instalación

```bash
git clone https://github.com/Crescendum429/mitre-adversarial-system
cd mitre-adversarial-system
poetry install
cp .env.example .env
# Editar .env con las API keys y los modelos elegidos
```

Variables principales de `.env`:

```
LLM_PROVIDER=openai
OPENAI_MODEL=gpt-4.1
OBSERVER_PROVIDER=deepseek
OBSERVER_MODEL=deepseek-chat

LLM_SEED=42
ATTACKER_TEMPERATURE=0.2
OBSERVER_TEMPERATURE=0.0
```

## Uso

```bash
docker compose -f docker/docker-compose.yml up -d

# Corrida estándar
poetry run python -m src.main --scenario basic
poetry run python -m src.main --scenario dvwa
poetry run python -m src.main --scenario mrrobot

# Solo el atacante, sin observer
poetry run python -m src.main --scenario basic --attacker-only

# Ver output raw de las herramientas
poetry run python -m src.main --scenario basic --tool-output

# Dashboard live en terminal (split-screen atacante + observer)
poetry run python -m src.main --scenario basic --dashboard

# Frontend HTML (browser, modo live polling)
poetry run python -m src.main --scenario basic --open-frontend

# Ablation regex-only del observer (sin LLM)
OBSERVER_REGEX_ONLY=1 poetry run python -m src.main --scenario basic --no-memory

# Ablation pure-LLM (sin heurísticas T1-T10)
poetry run python -m src.main --scenario basic --no-heuristics

# Benchmark reproducible n=3 cold
poetry run python scripts/run_benchmark.py --scenarios basic --runs-per-scenario 3 --cold-all
```

### Reproducir el audit de la sesión de resultados

```bash
poetry run python scripts/audit_runs.py            # audit sobre data/matrix_aggregate.json
poetry run python scripts/build_results_report.py  # regenera informe
```

## Diseño experimental — sesión de resultados (mayo 2026)

Cuatro ejes documentados en `data/matrix_aggregate.json` (38 corridas, ~12 h wall-clock):

- **Eje A — matriz cross-modelo 5×5 sobre `basic`** (cold por celda): cinco atacantes × cinco observers. Reset de memoria entre runs. 19 corridas válidas (6 falladas por cuota free tier Cerebras).
- **Eje B — generalización a 7 escenarios** (stack ganador): GPT-4.1 atacante + DeepSeek observer sobre dvwa, mrrobot, dc1, bpent, log4shell, confluence, phpunit. Run B08: replicación bpent con Sonnet 4.5 atacante.
- **Eje C — ablation regex-only** (sin LLM observer) sobre basic + log4shell.
- **Eje D — efecto memoria warm**: tres corridas consecutivas sin reset sobre `basic`.

**Hallazgos principales**:

| Métrica | Valor |
|---------|-------|
| μ macro-F1 Eje A (matriz cross-modelo, 19 válidas) | 0,441 |
| μ macro-F1 Eje B (Niveles 1+2 evaluables, n=4) | 0,429 |
| Top observer Eje A (operacional) | DeepSeek-chat μ=0,479 |
| Mejor escenario Eje B (cadena completa) | dc1 6/6 tácticas, mF1=0,529 |
| Eje C: regex-only basic vs LLM hybrid basic | 0,492 vs 0,441 |
| Eje D: efecto memoria cold→warm | −31,6 % tool_calls; +29,9 % mF1 acumulado |

Los runs donde el atacante se atasca en Initial Access (mrrobot y bpent con GPT-4.1, 1/6 tácticas) se reportan como **scope conditions** dentro del régimen del frequency bias documentado por Carlini et al. 2023, no como métrica del observer (en esos runs el observer fue ejercitado solo sobre Reconnaissance).

## Frontend

Dos componentes de visualización en `src/ui/`:

- **`dashboard.py`** — dashboard live en terminal (Rich Layout) con split-screen del estado del atacante (táctica activa, última acción, replans) y del observer (ventana actual, última clasificación, señales de triaje). Activable con `--dashboard`.
- **`report.py`** — reporte HTML autosuficiente post-corrida con CSS embebido (sin dependencias externas) en `data/reports/<scenario>_<timestamp>.html`. Cuatro vistas: Batalla en Paralelo, Resumen (CI 95 %, matriz de confusión, métricas por táctica), Tácticas (cards colapsables con evidencia), Timeline.

**Modo live**: cada corrida reescribe el JSON cada 2 s (atómico vía tmp+rename). El frontend hace polling configurable y actualiza las cuatro vistas mientras avanza el run. Activar con `--open-frontend`.

```bash
# Visor manual (sin --open-frontend)
poetry run python -m http.server 8765
# abrir http://127.0.0.1:8765/web/frontend.html
# luego "Cargar session.json" → seleccionar data/reports/<run>.json
```

Los componentes visuales se diseñaron con asistencia de **Claude Design** (Anthropic) para mantener una estética sobria coherente con la naturaleza forense del reporte.

## Stack tecnológico

- **LangGraph** — orquestación de grafos de agentes con ciclos condicionales
- **LangChain (multi-proveedor)** — capa LLM con reintentos backoff
- **Docker SDK + Docker Compose** — ejecución de herramientas en contenedor aislado
- **Loki + Promtail** — log aggregation y consultas LogQL
- **Pydantic Settings** — configuración tipada
- **Rich** — dashboard live en terminal
- **pytest** — 261 tests unitarios

## Documentación adicional

- [`paper/SISTEMA_ADVERSARIAL_MITRE_ATTACK_Alarcon.pdf`](paper/SISTEMA_ADVERSARIAL_MITRE_ATTACK_Alarcon.pdf) — documento final del proyecto integrador (USFQ, mayo 2026)
- [`paper/Arquitectura.png`](paper/Arquitectura.png) — diagrama Eraser del sistema completo
- `data/AUDIT_RUNS.md` — audit completo de las 38 corridas
- `data/INFORME_RESULTADOS_FINALES.md` — informe consolidado de resultados

## Declaración sobre uso de tecnologías generativas y asistidas por IA

Para la elaboración de este proyecto integrador (sistema, documento final y componentes visuales) el autor declara haber utilizado herramientas de IA generativa (Claude de Anthropic y modelos de OpenAI) para tareas de asistencia en la implementación, refinamiento de redacción, corrección gramatical y tipográfica, y diseño de los componentes visuales del frontend (Claude Design). El autor revisó y editó exhaustivamente todo el contenido generado y asume plena responsabilidad por la versión final del documento, el código publicado y los resultados experimentales reportados.

---

**Autor**: Francisco Jesús Alarcón Aguirre · **Tutor**: Roberto Andrade · USFQ, 2026
