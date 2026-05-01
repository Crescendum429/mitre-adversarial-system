"""
Calibracion adaptativa del umbral de confianza para refinamiento.

Justificacion academica:
  - Elkan (2001) "The Foundations of Cost-Sensitive Learning": el umbral
    optimo de un clasificador depende del costo asimetrico de FPs vs FNs por
    clase. Tacticas avanzadas (Privilege Escalation, Impact) tienen mayor
    costo de FP (alerta de pager innecesaria) que tacticas tempranas
    (Reconnaissance) donde el FP solo desperdicia un ciclo de refinamiento.
  - Platt (1999) calibracion por prior: la confianza posterior es funcion de
    likelihood y prior. Si una tactica tiene prior alto en este fingerprint,
    confianza moderada del LLM ya es suficiente. Si la tactica es sorpresiva
    (no aparece en top-3 del prior), se requiere likelihood mas fuerte.
  - Bhuyan et al. (2014): umbrales fijos en deteccion de intrusiones causan
    drift; umbrales adaptativos por contexto reducen FPs en 12-18%.

Implementacion:
  - Umbral base por tactica (cost-sensitive).
  - Ajuste por prior: -0.10 si la tactica esta en top-3 del prior,
                      +0.10 si la tactica esta fuera del top-5 del prior.
  - Sin prior valido (primer run): se usa solo el umbral base.

El umbral resultante se usa en graph.should_refine para decidir si se gatilla
una segunda pasada (refine_analysis sin LLM + classify nuevamente).
"""

from __future__ import annotations

DEFAULT_THRESHOLD = 0.65

# Costo de FP por tactica. Tacticas tempranas son baratas (FP solo descarta una
# ventana). Tacticas tardias son caras (escalan a humano, pagina al SOC). Por
# eso requerimos mayor confianza antes de emitirlas sin refinar.
_TACTIC_BASE_THRESHOLD = {
    "reconnaissance": 0.55,
    "initial_access": 0.60,
    "execution": 0.60,
    "discovery": 0.60,
    "persistence": 0.65,
    "defense_evasion": 0.65,
    "credential_access": 0.70,
    "lateral_movement": 0.70,
    "collection": 0.70,
    "command_and_control": 0.70,
    "privilege_escalation": 0.75,
    "exfiltration": 0.75,
    "impact": 0.75,
    "none": 0.55,
}

PRIOR_BONUS_TOP3 = -0.10
PRIOR_PENALTY_OUT_OF_TOP5 = 0.10
MIN_PRIOR_WINDOWS = 5


def _normalize_tactic(name: str) -> str:
    return (name or "").lower().strip().replace(" ", "_")


def adaptive_threshold(tactic: str, baseline_prior: dict | None) -> float:
    """
    Devuelve el umbral de confianza minimo para considerar la clasificacion
    como 'final' (sin refinamiento adicional).

    `tactic` es la tactica clasificada por el LLM en la iteracion actual.
    `baseline_prior` es la entrada de memory.get_prior() para este fingerprint
    (puede ser None en el primer run sobre un target nuevo).
    """
    key = _normalize_tactic(tactic)
    base = _TACTIC_BASE_THRESHOLD.get(key, DEFAULT_THRESHOLD)

    if not baseline_prior:
        return base

    n = baseline_prior.get("windows_observed", 0)
    if n < MIN_PRIOR_WINDOWS:
        return base

    dist = baseline_prior.get("tactic_distribution", {})
    if not dist:
        return base

    ranked = sorted(dist.items(), key=lambda x: -x[1])
    top3 = {t for t, _ in ranked[:3]}
    top5 = {t for t, _ in ranked[:5]}

    if key in top3:
        return max(0.30, round(base + PRIOR_BONUS_TOP3, 2))
    if key not in top5:
        return min(0.95, round(base + PRIOR_PENALTY_OUT_OF_TOP5, 2))
    return base
