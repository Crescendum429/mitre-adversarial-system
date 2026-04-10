# Arquitectura Micro-Nivel — Sistema Adversarial MITRE ATT&CK

Para visualizar: pega cada bloque en https://mermaid.live

---

## Diagrama 1 — Vista General del Sistema

```mermaid
flowchart TD

    subgraph CLI["Orquestador · main.py"]
        cli["--scenario mrrobot\nverify_infrastructure → run_attacker"]
    end

    subgraph GRAPH["Grafo · graph.py + state.py"]
        graph["StateGraph(AttackerState)\ngraph.stream(state, recursion_limit=100)"]
    end

    subgraph LLM_B["Proveedor LLM · provider.py"]
        llm["ChatOpenAI gpt-4-turbo\nbind_tools(10 tools) · temp=0.3"]
    end

    subgraph REACT_B["Loop ReAct · nodes.py"]
        direction LR
        plan["plan_tactic"]
        exec["execute_tools"]
        vali["validate_result"]
        adva["advance_tactic"]
        plan --> exec --> vali --> adva
        adva -->|siguiente táctica| plan
    end

    subgraph TOOLS_B["Herramientas · tools.py"]
        tools["nmap · nikto · hydra · wpscan\ncurl · gobuster · web_shell\njohn · command · sqlmap"]
    end

    subgraph SDK_B["Docker SDK · docker_client.py"]
        sdk["exec_run(cmd, demux=True)\n→ ExecResult(exit_code, stdout, stderr)"]
    end

    subgraph INFRA_B["Infraestructura · docker-compose.yml"]
        direction LR
        subgraph ANET["attack_net · 10.10.0.0/24"]
            atk["attacker\n10.10.0.5 · 1GB · Kali"]
            mrr["mrrobot\n10.10.0.20 · 256MB · PHP:8.1"]
        end
        subgraph MNET["monitor_net · 10.10.1.0/24"]
            lok["loki · :3100"]
            pmt["promtail · 128MB"]
            grf["grafana · :3000"]
        end
        pmt --> lok --> grf
        mrr -. logs .-> lok
    end

    cli --> graph --> plan
    llm -. modelo .-> plan
    llm -. modelo .-> vali
    exec --> tools --> sdk
    sdk -->|ExecResult| exec
    sdk -. docker exec .-> atk
```

---

## Diagrama 2 — Loop ReAct: Algoritmo Detallado

```mermaid
flowchart TD

    START([INICIO · nueva táctica])

    plan["plan_tactic\nbuild_prompt(tactic, target, collected_data)\nllm.invoke(messages) → AIMessage + tool_calls"]

    exec["execute_tools\n∀ tool_call → tool.invoke(args)\naction_history.append(tactic, technique, output, ts)"]

    vali["validate_result\nllm.invoke(messages + ToolMessages)\n→ AIMessage"]

    adva["advance_tactic\ncurrent_tactic_index++\nnext_tactic | attack_finished = True"]

    sc{{"¿AIMessage\ncon tool_calls?"}}
    sl{{"¿attack\n_finished?"}}
    END_N([FIN · 6/6 tácticas])

    START --> plan
    plan --> exec
    exec --> vali
    vali --> sc
    sc -->|sí · más herramientas| exec
    sc -->|no · táctica completa| adva
    adva --> sl
    sl -->|no · quedan tácticas| plan
    sl -->|sí| END_N
```

---

## Diagrama 3 — Infraestructura Docker

```mermaid
flowchart TD

    HOST["Host Linux\n/var/run/docker.sock\nDocker SDK → docker.from_env()"]

    subgraph ANET["attack_net · 10.10.0.0/24"]
        ATK["attacker · 10.10.0.5\nKali Linux · 1GB · NET_RAW NET_ADMIN\nnmap · hydra · sqlmap · gobuster · wpscan · john\nnikto via git clone sullo/nikto\n/opt/wordlists/mrrobot.txt"]

        MRR["mrrobot · 10.10.0.20\nPHP:8.1-Apache · 256MB\nrobot user · SUID python3\nkey-1-of-3 · key-2-of-3 · key-3-of-3\npassword.raw-md5 · shell.php (runtime)"]
    end

    subgraph MNET["monitor_net · 10.10.1.0/24"]
        PMT["promtail · 128MB\nautodiscovery via docker.sock\n→ push a loki:3100"]

        LOK["loki · 10.10.1.10:3100\ngrafana/loki:3.4.2 · 512MB\nrecibe logs de todos los containers"]

        GRF["grafana · :3000 · 256MB\ngrafana/grafana:11.5.2\nadmin/admin · datasource Loki pre-provisionado"]
    end

    HOST -->|docker exec| ATK
    ATK <-->|attack_net| MRR
    MRR -. "dual-homed · genera logs" .-> LOK
    PMT --> LOK --> GRF
```
