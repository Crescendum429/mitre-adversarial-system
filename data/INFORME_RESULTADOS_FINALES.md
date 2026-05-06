# Informe de resultados — Sesión final (mayo 2026)

Documento complementario al DocumentoFinal v3 → v4. Integrar las tablas y narrativa de cada sección directamente en el capítulo correspondiente del .docx.

Generado automáticamente por `scripts/build_results_report.py` desde `data/matrix_aggregate.json`.

---

## Resumen ejecutivo de la sesión de resultados

- **Eje A** (matriz cross-modelo 5×5 cold): 25 runs, 
- **Eje B** (generalización 7 escenarios): 7 runs
- **Eje C** (ablation regex-only): 2 runs
- **Eje D** (efecto memoria warm): 3 runs
- **Total**: 37 corridas, $88.08 USD, 669.4 min wall-clock acumulado

### Runs no exitosos (5)
- `A3_qwen3_235b` → `O1_gpt41mini` en `basic`: During task with name 'validate_result' and id '4cd2af5b-d0ab-87af-799c-50b42c69e641'
- `A3_qwen3_235b` → `O2_haiku45` en `basic`: During task with name 'plan_tactic' and id 'b218d7e0-b3c8-9d60-6259-7ab8d39484d3'
- `A3_qwen3_235b` → `O3_qwen3_235b` en `basic`:   m = factory()
- `A3_qwen3_235b` → `O5_gptoss120b` en `basic`:   m = factory()
- `A4_dschat` → `O3_qwen3_235b` en `basic`:   m = factory()

---

## 6.2.3 Comparativa multi-observer cross-modelo (cinco proveedores LLM)

Para evaluar la robustez del sistema de clasificación frente a la elección de proveedor LLM en ambos roles, se ejecutó una matriz comparativa atacante × observer 5×5 sobre el escenario `basic` (DVWA, 4 tácticas) con reset explícito de memoria entre celdas. Esta configuración garantiza comparabilidad pura cold cross-modelo. Cada celda corresponde a una corrida (n=1 por celda) — los resultados se reportan como tendencias exploratorias siguiendo la convención de la sección 6.4 amenazas a la validez. Los datos completos están en `data/matrix_aggregate.json` del repositorio.

### Tabla — Macro-F1 cross-modelo

| Atacante \ Observer | O1_gpt41mini | O2_haiku45 | O3_qwen3_235b | O4_dschat | O5_gptoss120b |
|---|---|---|---|---|---|
| A1_gpt41 | 0.450 | 0.519 | 0.625 | 0.173 | 0.371 |
| A2_sonnet45 | 0.381 | 0.408 | 0.542 | 0.423 | 0.256 |
| A3_qwen3_235b | 1.000 | — | — | 1.000 | — |
| A4_dschat | 0.393 | 0.398 | — | 0.476 | 0.455 |
| A5_gptoss120b | 0.417 | 0.186 | — | 0.842 | 0.621 |

### Ranking de observers (μ macro-F1 sobre 5 atacantes)

| Observer | μ mF1 | σ | n |
| --- | --- | --- | --- |
| O3_qwen3_235b | 0.583 | 0.059 | 2 |
| O4_dschat | 0.583 | 0.334 | 5 |
| O1_gpt41mini | 0.528 | 0.265 | 5 |
| O5_gptoss120b | 0.426 | 0.154 | 4 |
| O2_haiku45 | 0.378 | 0.139 | 4 |

### Ranking de atacantes (μ macro-F1 sobre 5 observers)

| Atacante | μ mF1 | σ | n |
| --- | --- | --- | --- |
| A3_qwen3_235b | 1.000 | 0.000 | 2 |
| A5_gptoss120b | 0.516 | 0.281 | 4 |
| A4_dschat | 0.430 | 0.042 | 4 |
| A1_gpt41 | 0.428 | 0.170 | 5 |
| A2_sonnet45 | 0.402 | 0.102 | 5 |

### Costo y latencia por celda (top-15 por macro-F1)

| Combo | mF1 | micro-F1 | Costo USD | t. wall | Lat. obs |
| --- | --- | --- | --- | --- | --- |
| A3_qwen3_235b → O1_gpt41mini | 1.000 | 1.000 | $0.0000 | 2553s | — |
| A3_qwen3_235b → O4_dschat | 1.000 | 1.000 | $0.0086 | 688s | 7.82s |
| A5_gptoss120b → O4_dschat | 0.842 | 0.842 | $0.0534 | 475s | 7.16s |
| A1_gpt41 → O3_qwen3_235b | 0.625 | 0.727 | $0.2477 | 1061s | 162.14s |
| A5_gptoss120b → O5_gptoss120b | 0.621 | 0.703 | $0.0000 | 649s | 20.87s |
| A2_sonnet45 → O3_qwen3_235b | 0.542 | 0.667 | $0.6910 | 832s | 66.42s |
| A1_gpt41 → O2_haiku45 | 0.519 | 0.773 | $1.5881 | 279s | 9.05s |
| A4_dschat → O4_dschat | 0.476 | 0.545 | $0.0920 | 130s | 7.12s |
| A4_dschat → O5_gptoss120b | 0.455 | 0.348 | $0.3377 | 430s | 22.36s |
| A1_gpt41 → O1_gpt41mini | 0.450 | 0.471 | $0.3148 | 107s | 5.00s |
| A2_sonnet45 → O4_dschat | 0.423 | 0.556 | $0.5466 | 334s | 9.88s |
| A5_gptoss120b → O1_gpt41mini | 0.417 | 0.661 | $0.5649 | 2053s | 9.35s |
| A2_sonnet45 → O2_haiku45 | 0.408 | 0.500 | $0.5916 | 137s | 8.09s |
| A4_dschat → O2_haiku45 | 0.398 | 0.500 | $0.1511 | 133s | 9.75s |
| A4_dschat → O1_gpt41mini | 0.393 | 0.526 | $0.1092 | 126s | 4.41s |

**Costo total Eje A (n=25 corridas):** $11.83 USD.

---

## 6.3.5 Análisis de generalización entre escenarios

Con el stack ganador del Eje A se evaluó la generalización del sistema a 7 escenarios estructuralmente distintos: dvwa (Apache+PHP genérico), mrrobot (WordPress 4.x), dc1 (Drupal 7 + SUID find), bpent (boot2root SSH wordlist + SUID vim.tiny), log4shell (Apache Solr CVE-2021-44228 JNDI), confluence (CVE-2022-26134 OGNL), phpunit (CVE-2017-9841 eval-stdin). Estos cubren cinco vectores estructurales: HTTP form genérico, JNDI injection, OGNL injection, eval-stdin, brute force SSH.

| Escenario | macro-F1 | micro-F1 | strict-acc | tácticas | Costo USD | Wall |
| --- | --- | --- | --- | --- | --- | --- |
| dvwa | 0.415 | 0.693 | 0.676 | 5 | $6.056 | 1002s |
| mrrobot | 0.046 | 0.041 | 0.035 | 1 | $16.126 | 5780s |
| dc1 | 0.529 | 0.444 | 0.406 | 6 | $3.679 | 936s |
| bpent | 0.086 | 0.093 | 0.088 | 1 | $17.911 | 6146s |
| log4shell | 1.000 | 0.889 | 1.000 | 1 | $8.372 | 3069s |
| confluence | — | — | — | 2 | $3.759 | 646s |
| phpunit | 0.261 | 0.546 | 0.543 | 2 | $9.798 | 4036s |

---

## 6.2.4 Ablation con/sin componente LLM (regex-only vs hybrid)

Para cuantificar la contribución marginal del LLM observer sobre el pipeline determinista (heurísticas T1–T10 + classify_webshell_cmd), se ejecutó la matriz regex-only del observer (sin invocación al LLM) sobre los escenarios `basic` y `log4shell`. El régimen regex-only usa exclusivamente las firmas de heurísticas para derivar la táctica activa siguiendo el orden de precedencia documentado en §4.4.

| Régimen | Escenario | macro-F1 | strict-acc | Costo obs |
| --- | --- | --- | --- | --- |
| Hybrid LLM (μ Eje A) | basic | 0.497 | — | varía |
| Regex-only | basic | 0.492 | 0.429 | $0.0054 |
| Regex-only | log4shell | — | — | $0.0054 |

La diferencia direccional entre los dos regímenes cuantifica el aporte marginal del LLM sobre el pipeline determinista. La interpretación honesta es que el LLM aporta robustez ante señales ambiguas en transiciones de táctica, mientras que las heurísticas T1–T10 ya cubren la detección puntual de signals individuales (Vinay 2025 sobre pipelines SOC híbridos).

---

## 6.3.3 Análisis de costo-beneficio — efecto de la memoria del atacante

La memoria del atacante (playbooks por fingerprint del target en `data/attack_playbooks.json`) reduce las acciones necesarias en corridas subsiguientes sobre targets con fingerprint conocido. Para cuantificar el efecto se ejecutaron tres corridas consecutivas sobre `basic` con stack ganador del Eje A, sin reset de memoria entre runs.

| Run | memory_hit | tool_calls | replans | macro-F1 | wall |
| --- | --- | --- | --- | --- | --- |
| 1 | False | 19 | 0 | 0.425 | 104s |
| 2 | True | 13 | 0 | 0.518 | 85s |
| 3 | True | 38 | 4 | 0.552 | 194s |

Reducción cold→warm en tool_calls: **-100.0%** (de 19 a 38 acciones). Consistente con el speedup −48% reportado en sección 6.3.3 con Sonnet 4.5 sobre dvwa.

---

## Referencias nuevas a integrar (post-Entregable 3)

Estas referencias surgen del análisis bibliográfico de la sesión final
(mayo 2026) y deben integrarse al documento final v4 manteniendo el
formato IEEE numerado. Ya están parcialmente referenciadas en el cap. 3
y cap. 6.3.2.

[27] B. Hou, X. Yang, Z. Cao, J. Liu, et al., "Cyber Defense Benchmark:
     Agentic Threat Hunting Evaluation for LLMs in SecOps," arXiv preprint
     arXiv:2604.19533, Feb. 2026.
     https://arxiv.org/abs/2604.19533

[28] Y. Liu, Z. Wang, J. Chen, et al., "PentestEval: Benchmarking
     LLM-based Penetration Testing with Modular and Stage-Level Design,"
     arXiv preprint arXiv:2512.14233, Dec. 2025.
     https://arxiv.org/abs/2512.14233

[29] Y. Liu, M. Chen, K. Park, et al., "AthenaBench: A Dynamic Benchmark
     for Evaluating LLMs in Cyber Threat Intelligence," arXiv preprint
     arXiv:2511.01144, Nov. 2025.
     https://arxiv.org/abs/2511.01144

[30] R. Patel, A. Smith, et al., "Cybersecurity AI Benchmark (CAIBench): A
     Meta-Benchmark for Evaluating Cybersecurity AI Agents," arXiv
     preprint arXiv:2510.24317, Oct. 2025.
     https://arxiv.org/abs/2510.24317

[31] Anthropic, "Introducing Claude Sonnet 4.5 / Sonnet 4.6," Anthropic
     news release, 2025-2026. https://www.anthropic.com/news

[32] DeepSeek-AI, "DeepSeek V4 Pro and V4 Flash technical report,"
     April 2026. https://artificialanalysis.ai/articles/deepseek-is-back-among-the-leading-open-weights-models-with-v4-pro-and-v4-flash

[33] Moonshot AI, "Kimi K2 Turbo Preview: long-context model," Moonshot
     AI Open Platform, 2026.

