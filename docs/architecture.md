# Arquitectura del Sistema Adversarial MITRE ATT&CK

## Resumen

El sistema implementa dos agentes autonomos basados en LLMs que operan en un entorno de simulacion controlado:

- **Agente Atacante**: ejecuta cadenas de ataque reales siguiendo las tacticas MITRE ATT&CK. Usa el patron ReAct (Reasoning + Acting) para decidir que tecnica ejecutar en cada paso.
- **Agente Observador**: analiza logs del sistema en tiempo real y clasifica la tactica MITRE ATT&CK activa. Solo tiene acceso a observables (logs, eventos), simulando la perspectiva real de un SIEM o endpoint.

Los agentes no se comunican entre si. El atacante genera actividad maliciosa que produce artefactos en logs, y el observador intenta clasificar esa actividad analizando los logs via Loki.

## Justificacion del Framework: LangGraph

Se selecciono LangGraph (v1.0+) como framework de orquestacion por las siguientes razones:

1. **Checkpointing nativo**: cada paso del agente se persiste automaticamente. Esto permite reproducir exactamente una ejecucion de ataque para analisis y evaluacion, lo cual es critico para la metodologia de la tesis.

2. **Soporte nativo para ReAct**: el patron razonar-actuar-observar se implementa naturalmente con nodos y edges condicionales. El LLM razona, emite tool_calls, LangGraph ejecuta las herramientas, y el resultado vuelve al LLM.

3. **Grafos independientes**: cada agente es un grafo compilado separado con su propio estado. No hay acoplamiento entre atacante y observador.

4. **Madurez**: es el framework de agentes mas usado en produccion (Uber, LinkedIn, Klarna). Version estable 1.0+ desde octubre 2025.

**Alternativas descartadas**:
- CrewAI: impone roles fijos y comunicacion entre agentes. Nuestros agentes son independientes.
- AutoGen: orientado a conversaciones multi-agente. Nuestro flujo es unidireccional.
- n8n: no disenado para agentes LLM con razonamiento iterativo.

## Capas de la Arquitectura

### Capa 1: Infraestructura (Docker Compose)

Todos los componentes corren en containers Docker con redes aisladas:

| Container | Imagen | Red | Proposito |
|-----------|--------|-----|-----------|
| attacker | Kali Linux minimal | attack_net (10.10.0.5) | Ejecuta herramientas de pentesting |
| dvwa | vulnerables/web-dvwa | attack_net (10.10.0.10) + monitor_net | Aplicacion web vulnerable |
| loki | grafana/loki:3.4.2 | monitor_net (10.10.1.10) | Agregacion de logs |
| promtail | grafana/promtail:3.4.2 | monitor_net | Recoleccion de logs Docker |
| grafana | grafana/grafana:11.5.2 | monitor_net | Dashboard de visualizacion |

**Redes**:
- `attack_net` (10.10.0.0/24): conecta atacante con targets. El atacante solo ve esta red.
- `monitor_net` (10.10.1.0/24): conecta targets con logging. El atacante no puede acceder a esta red.

Esta separacion garantiza que el atacante no puede manipular directamente la infraestructura de logging.

**Logging**: Promtail lee los archivos de log JSON de Docker y los envia a Loki. El observador consulta Loki via API HTTP (LogQL). Loki opera en modo monolitico para minimizar recursos (~200MB RAM vs ~3GB de Elasticsearch).

### Capa 2: Agentes (Python + LangGraph)

#### Agente Atacante (Patron ReAct)

El patron ReAct (Reasoning and Acting) permite al LLM intercalar razonamiento con ejecucion de acciones. En cada iteracion:

1. El LLM analiza la situacion y decide que herramienta usar
2. LangGraph ejecuta la herramienta
3. El resultado vuelve al LLM para analisis
4. El LLM decide si continuar o cambiar de tactica

**Grafo**:
```
START -> plan_tactic -> execute_tools -> validate_result -+
              ^                                           |
              |              [has tool_calls]              |
              +------ execute_tools <---------------------+
              |              [no tool_calls]               |
              +------ advance_tactic <--------------------+
                           |                |
                     [mas tacticas]    [terminado]
                           |                |
                     plan_tactic           END
```

**Estado** (`AttackerState`):
- `target`: IP del objetivo
- `tactic_sequence`: lista ordenada de tacticas a ejecutar
- `current_tactic`: tactica en curso
- `collected_data`: datos acumulados (puertos, credenciales, archivos)
- `action_history`: historial completo de acciones (ground truth)
- `messages`: historial de mensajes LLM (para contexto)

**Herramientas** (LangChain Tools):
- `run_nmap`: escaneo de red y servicios
- `run_hydra`: fuerza bruta de credenciales
- `run_sqlmap`: deteccion y explotacion de SQLi
- `run_command`: ejecucion de comandos shell arbitrarios
- `run_curl`: peticiones HTTP

Cada herramienta ejecuta el comando dentro del container atacante via Docker SDK.

#### Agente Observador (Pipeline de Clasificacion)

El observador implementa un pipeline lineal que se ejecuta periodicamente:

```
START -> collect_logs -> classify_tactic -> generate_recommendation -> END
```

**Nodos**:
1. `collect_logs`: consulta Loki via API LogQL, filtra logs de containers target, prioriza entradas relevantes para deteccion.
2. `classify_tactic`: el LLM recibe los logs y las 14 definiciones de tacticas MITRE. Clasifica con nivel de confianza y evidencia citada.
3. `generate_recommendation`: registra la clasificacion en el historial temporal.

**Estado** (`ObserverState`):
- `raw_logs`: logs crudos de Loki
- `log_summary`: resumen priorizado para el LLM
- `current_classification`: {tactic, confidence, evidence, reasoning, recommendation}
- `classification_history`: historial de clasificaciones previas (contexto temporal)

**Restriccion clave**: el observador NO tiene acceso a las decisiones del atacante ni al estado de los containers. Solo ve logs, simulando un SIEM real.

### Capa 3: Orquestacion

El orquestador (`main.py`) coordina la ejecucion:

1. Verifica que la infraestructura Docker esta activa
2. Define el escenario (que tacticas ejecutar)
3. Lanza el observador en un thread separado (polling periodico)
4. Ejecuta el atacante en el thread principal
5. Al finalizar, compara ground truth vs clasificaciones
6. Genera reporte con accuracy, timeline, y analisis

## Tacticas MITRE ATT&CK Implementadas

### Fase 1 (Entregable 30%)

| Tactica | ID | Tecnicas | Herramientas |
|---------|----|----------|-------------|
| Reconnaissance | TA0043 | T1046 Network Service Discovery | nmap |
| Initial Access | TA0001 | T1078 Valid Accounts, T1190 Exploit Public-Facing App | hydra, sqlmap |
| Execution | TA0002 | T1059 Command and Scripting Interpreter | bash, python, netcat |
| Discovery | TA0007 | T1082 System Info, T1083 File/Dir Discovery | comandos shell |

### Fase 2 (Entregable 60%)

| Tactica | ID | Tecnicas | Herramientas |
|---------|----|----------|-------------|
| Persistence | TA0003 | T1136 Create Account, T1053 Scheduled Task | useradd, crontab |
| Privilege Escalation | TA0004 | T1548 Abuse Elevation Control | SUID, sudo |
| Credential Access | TA0006 | T1003 OS Credential Dumping | /etc/shadow |
| Lateral Movement | TA0008 | T1021 Remote Services | SSH pivoting |

## Metodologia de Evaluacion

Para cada escenario de ataque:

1. **Ground truth**: el atacante registra cada accion con {tactica, tecnica, timestamp}
2. **Clasificaciones**: el observador registra {tactica_clasificada, confianza, timestamp}
3. **Metricas**:
   - Accuracy por tactica
   - Precision, Recall, F1 por tactica
   - Confusion matrix 14x14
   - Latencia de deteccion (tiempo desde inicio de tactica hasta clasificacion correcta)
   - Confianza promedio en clasificaciones correctas vs incorrectas

## Alineacion con Estandares

- **ISO/IEC 23053:2022**: Framework for AI Systems Using ML. El sistema sigue la arquitectura de referencia: datos de entrada (logs), modulo de inferencia (LLM), y modulo de decision (clasificacion).
- **ISO/IEC 22989:2022**: AI Concepts and Terminology. Adopta terminologia estandar para agentes autonomos y sistemas de IA.
- **MITRE ATT&CK Enterprise v16**: Taxonomia de tacticas y tecnicas como base del sistema de clasificacion.

## Decisiones de Diseno

### Por que Docker en lugar de VMs

- Reproducibilidad: `docker compose up` replica el entorno exacto en cualquier maquina
- Recursos: <2GB RAM para todo el lab vs >8GB para VMs
- Aislamiento: redes Docker proporcionan segmentacion suficiente para simulacion
- CI/CD: el entorno se puede integrar en pipelines de testing automatizado

### Por que Loki en lugar de ELK Stack

- Recursos: ~500MB RAM vs ~3-4GB para Elasticsearch + Logstash + Kibana
- Simplicidad: una config YAML vs multiples archivos de configuracion
- Suficiencia: para el volumen de logs de un lab (MB/dia), Loki es mas que adecuado
- Integracion Docker nativa: Promtail descubre containers automaticamente

### Por que separar atacante y observador en grafos independientes

- Realismo: en un escenario real, el defensor no tiene acceso al atacante
- Evaluacion: permite medir objetivamente la capacidad de clasificacion
- Modularidad: cada agente se puede desarrollar, testear y mejorar independientemente
- Reproducibilidad: se puede re-ejecutar el observador contra los mismos logs
