"""
Metricas academicas para evaluacion del observador.

Implementa precision/recall/F1 (micro y macro) sobre clasificacion multi-label
de tacticas MITRE ATT&CK, siguiendo la literatura estandar de IDS/SOC:

  - Sokolova & Lapalme (2009). "A systematic analysis of performance measures
    for classification tasks". Information Processing & Management.
  - Manning et al. (2008). "Introduction to Information Retrieval". Cambridge
    University Press. Chapter 8 (evaluation).
  - Sharafaldin et al. (2018). "Toward Generating a New Intrusion Detection
    Dataset and Intrusion Traffic Characterization". ICISSP. (CICIDS2017)

El modulo es deliberadamente independiente de main.py para que pueda usarse
en analisis post-hoc sobre resultados guardados (ej: agregar experimentos,
reproducir tablas del paper).
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class TacticMetrics:
    """Metricas por tactica individual."""

    tactic: str
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def support(self) -> int:
        """Numero real de ventanas donde esta tactica estaba activa (tp + fn)."""
        return self.tp + self.fn

    @property
    def precision(self) -> float:
        """De lo que el modelo dijo que era esta tactica, cuanto acerto."""
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        """De lo que era esta tactica, cuanto detecto el modelo."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        """Media armonica de precision y recall."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class EvaluationReport:
    """Reporte completo de evaluacion de una corrida del observador."""

    per_tactic: dict[str, TacticMetrics]
    confusion: dict[str, dict[str, int]]
    strict_accuracy: float
    window_accuracy: float
    evaluable_windows: int
    total_windows: int
    # Metadata reproducibilidad
    attacker_model: str = ""
    observer_model: str = ""
    seed: int | None = None
    scenario: str = ""
    timestamp: str = ""

    @property
    def total_tp(self) -> int:
        return sum(m.tp for m in self.per_tactic.values())

    @property
    def total_fp(self) -> int:
        return sum(m.fp for m in self.per_tactic.values())

    @property
    def total_fn(self) -> int:
        return sum(m.fn for m in self.per_tactic.values())

    @property
    def micro_precision(self) -> float:
        denom = self.total_tp + self.total_fp
        return self.total_tp / denom if denom else 0.0

    @property
    def micro_recall(self) -> float:
        denom = self.total_tp + self.total_fn
        return self.total_tp / denom if denom else 0.0

    @property
    def micro_f1(self) -> float:
        p, r = self.micro_precision, self.micro_recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def macro_precision(self) -> float:
        """Promedio no ponderado de precision por tactica (solo con support > 0)."""
        ms = [m for m in self.per_tactic.values() if m.support > 0]
        return sum(m.precision for m in ms) / len(ms) if ms else 0.0

    @property
    def macro_recall(self) -> float:
        ms = [m for m in self.per_tactic.values() if m.support > 0]
        return sum(m.recall for m in ms) / len(ms) if ms else 0.0

    @property
    def macro_f1(self) -> float:
        ms = [m for m in self.per_tactic.values() if m.support > 0]
        return sum(m.f1 for m in ms) / len(ms) if ms else 0.0


def _normalize(name: str) -> str:
    if not name:
        return ""
    return name.lower().strip().replace(" ", "_")


def evaluate(
    observer_classifications: list[dict],
    attacker_timeline: list[dict],
    *,
    attacker_model: str = "",
    observer_model: str = "",
    seed: int | None = None,
    scenario: str = "",
) -> EvaluationReport:
    """
    Calcula metricas estandar comparando clasificaciones del observer con
    ground truth del atacante.

    Args:
        observer_classifications: lista de dicts con keys: timestamp,
            window_start, window_end, tactic, tactics_in_window.
        attacker_timeline: lista de dicts con keys: timestamp, tactic.
        attacker_model, observer_model, seed, scenario: metadata de
            reproducibilidad (se guarda en el reporte, critico para tesis).

    Returns:
        EvaluationReport con metricas agregadas por tactica, micro y macro,
        accuracy estricta, accuracy por ventana, matriz de confusion.
    """
    per_tactic: dict[str, TacticMetrics] = defaultdict(lambda: TacticMetrics(tactic=""))
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    strict_correct = 0
    window_correct = 0
    evaluable = 0

    # Rango real del ataque (primera accion → ultima)
    attack_end = max(
        (_parse_ts(a.get("timestamp", "")) for a in attacker_timeline if a.get("timestamp")),
        default=None,
    )

    sorted_cls = sorted(
        observer_classifications,
        key=lambda c: _parse_ts(c.get("window_end", "")) or datetime.min.replace(tzinfo=timezone.utc),
    )

    for cls in sorted_cls:
        ws = _parse_ts(cls.get("window_start", ""))
        we = _parse_ts(cls.get("window_end", ""))
        if ws is None or we is None:
            continue

        real_in_window = _tactics_in_window(ws, we, attacker_timeline)
        observed_current = _normalize(cls.get("tactic", ""))
        observed_in_window_raw = [
            _normalize(t.get("tactic", ""))
            for t in cls.get("tactics_in_window", [])
            if isinstance(t, dict)
        ]
        observed_in_window = {t for t in observed_in_window_raw if t}
        if not observed_in_window and observed_current and observed_current != "none":
            observed_in_window = {observed_current}

        is_pre_attack = not real_in_window or real_in_window[-1] in ("unknown", "")
        is_post_attack = bool(attack_end) and ws > attack_end
        if is_pre_attack or is_post_attack:
            continue

        evaluable += 1
        last_real = real_in_window[-1]

        if _match(last_real, observed_current):
            strict_correct += 1

        real_set = {_normalize(t) for t in real_in_window if t}
        if all(any(_match(r, o) for o in observed_in_window) for r in real_set):
            window_correct += 1

        # Confusion matrix (current tactic)
        obs_key = observed_current if observed_current != "none" else "none"
        confusion[last_real][obs_key] += 1

        # TP/FP/FN multi-label
        for t in real_set:
            m = per_tactic[t]
            m.tactic = t
            if t in observed_in_window:
                m.tp += 1
            else:
                m.fn += 1
        for t in observed_in_window:
            if t not in real_set:
                m = per_tactic[t]
                m.tactic = t
                m.fp += 1

    return EvaluationReport(
        per_tactic=dict(per_tactic),
        confusion={k: dict(v) for k, v in confusion.items()},
        strict_accuracy=strict_correct / evaluable if evaluable else 0.0,
        window_accuracy=window_correct / evaluable if evaluable else 0.0,
        evaluable_windows=evaluable,
        total_windows=len(observer_classifications),
        attacker_model=attacker_model,
        observer_model=observer_model,
        seed=seed,
        scenario=scenario,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        normalized = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _tactics_in_window(
    ws: datetime,
    we: datetime,
    timeline: list[dict],
) -> list[str]:
    """Tacticas activas durante una ventana de observacion."""
    if not timeline:
        return ["unknown"]
    tactics = []
    # La tactica activa AL INICIO de la ventana es la mas reciente <= ws
    tactic_at_start = "unknown"
    for entry in timeline:
        ts = _parse_ts(entry.get("timestamp", ""))
        if ts is None:
            continue
        if ts <= ws:
            tactic_at_start = _normalize(entry.get("tactic", "unknown"))
        else:
            break
    if tactic_at_start not in ("unknown", ""):
        tactics.append(tactic_at_start)
    # Mas las que iniciaron durante la ventana
    for entry in timeline:
        ts = _parse_ts(entry.get("timestamp", ""))
        if ts is None:
            continue
        if ws < ts <= we:
            t = _normalize(entry.get("tactic", ""))
            if t and t not in tactics:
                tactics.append(t)
    return tactics or ["unknown"]


def _match(real: str, observed: str) -> bool:
    if not real or not observed:
        return False
    return _normalize(real) == _normalize(observed)


def dump_as_json(report: EvaluationReport) -> dict:
    """Serializa el reporte a dict JSON-friendly para guardar resultados."""
    return {
        "metadata": {
            "attacker_model": report.attacker_model,
            "observer_model": report.observer_model,
            "seed": report.seed,
            "scenario": report.scenario,
            "timestamp": report.timestamp,
        },
        "aggregate": {
            "strict_accuracy": round(report.strict_accuracy, 4),
            "window_accuracy": round(report.window_accuracy, 4),
            "micro_precision": round(report.micro_precision, 4),
            "micro_recall": round(report.micro_recall, 4),
            "micro_f1": round(report.micro_f1, 4),
            "macro_precision": round(report.macro_precision, 4),
            "macro_recall": round(report.macro_recall, 4),
            "macro_f1": round(report.macro_f1, 4),
            "evaluable_windows": report.evaluable_windows,
            "total_windows": report.total_windows,
        },
        "per_tactic": {
            t: {
                "tp": m.tp, "fp": m.fp, "fn": m.fn,
                "support": m.support,
                "precision": round(m.precision, 4),
                "recall": round(m.recall, 4),
                "f1": round(m.f1, 4),
            }
            for t, m in report.per_tactic.items()
        },
        "confusion_matrix": report.confusion,
    }
