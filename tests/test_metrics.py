"""Tests del modulo de metricas academicas."""

from datetime import datetime, timedelta, timezone

from src.evaluation.metrics import (
    TacticMetrics,
    _match,
    _normalize,
    _tactics_in_window,
    dump_as_json,
    evaluate,
)


class TestTacticMetrics:
    def test_perfect_classification(self):
        m = TacticMetrics(tactic="execution", tp=10, fp=0, fn=0)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0
        assert m.support == 10

    def test_no_predictions(self):
        """TP=0, FP=0, FN=0: no hubo clasificaciones — metricas son 0."""
        m = TacticMetrics(tactic="x", tp=0, fp=0, fn=0)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0

    def test_only_false_positives(self):
        """El modelo predijo pero siempre estaba mal."""
        m = TacticMetrics(tactic="x", tp=0, fp=5, fn=0)
        assert m.precision == 0.0
        assert m.recall == 0.0  # recall = tp/(tp+fn) = 0/0 = 0 por convencion

    def test_f1_harmonic_mean(self):
        m = TacticMetrics(tactic="x", tp=3, fp=1, fn=2)
        assert abs(m.precision - 0.75) < 1e-6
        assert abs(m.recall - 0.6) < 1e-6
        assert abs(m.f1 - 2/3) < 1e-3


class TestNormalize:
    def test_removes_spaces(self):
        assert _normalize("Initial Access") == "initial_access"

    def test_lowercases(self):
        assert _normalize("EXECUTION") == "execution"

    def test_handles_empty(self):
        assert _normalize("") == ""
        assert _normalize(None) == ""


class TestMatch:
    def test_same_string(self):
        assert _match("execution", "execution")

    def test_case_insensitive(self):
        assert _match("EXECUTION", "execution")

    def test_space_vs_underscore(self):
        assert _match("Initial Access", "initial_access")

    def test_different(self):
        assert not _match("execution", "discovery")


class TestTacticsInWindow:
    def _ts(self, seconds_offset: int) -> str:
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        return (base + timedelta(seconds=seconds_offset)).isoformat()

    def test_single_tactic_in_window(self):
        ws = datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 0, 20, tzinfo=timezone.utc)
        timeline = [
            {"timestamp": self._ts(15), "tactic": "execution"},
        ]
        assert _tactics_in_window(ws, we, timeline) == ["execution"]

    def test_tactic_active_at_window_start(self):
        """La tactica que empezo antes de ws sigue activa."""
        ws = datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 0, 40, tzinfo=timezone.utc)
        timeline = [
            {"timestamp": self._ts(10), "tactic": "reconnaissance"},
            {"timestamp": self._ts(20), "tactic": "initial_access"},
            # Ningun nuevo evento en [30, 40)
        ]
        assert _tactics_in_window(ws, we, timeline) == ["initial_access"]

    def test_multiple_tactics_in_window(self):
        ws = datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc)
        we = datetime(2026, 1, 1, 0, 0, 50, tzinfo=timezone.utc)
        timeline = [
            {"timestamp": self._ts(0), "tactic": "reconnaissance"},
            {"timestamp": self._ts(20), "tactic": "initial_access"},
            {"timestamp": self._ts(40), "tactic": "execution"},
        ]
        result = _tactics_in_window(ws, we, timeline)
        assert "reconnaissance" in result
        assert "initial_access" in result
        assert "execution" in result

    def test_empty_timeline(self):
        ws = datetime(2026, 1, 1, tzinfo=timezone.utc)
        we = ws + timedelta(seconds=10)
        assert _tactics_in_window(ws, we, []) == ["unknown"]


class TestEvaluate:
    def _make_classification(self, ws: str, we: str, tactic: str, window: list = None):
        return {
            "window_start": ws,
            "window_end": we,
            "tactic": tactic,
            "tactics_in_window": [{"tactic": t} for t in (window or [tactic])],
        }

    def _ts(self, offset: int) -> str:
        return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset)).isoformat()

    def test_perfect_run(self):
        """Todas las clasificaciones aciertan exactamente — incluyendo
        tacticas carry-over (la tactica previa sigue considerada activa en
        ventanas posteriores hasta que el atacante avanza).
        """
        timeline = [
            {"timestamp": self._ts(10), "tactic": "reconnaissance"},
            {"timestamp": self._ts(30), "tactic": "initial_access"},
            {"timestamp": self._ts(50), "tactic": "execution"},
        ]
        # Para perfect score, observer debe reportar TODAS las tacticas
        # activas en tactics_in_window (no solo la current_tactic).
        cls = [
            self._make_classification(self._ts(5), self._ts(15),
                "reconnaissance", ["reconnaissance"]),
            self._make_classification(self._ts(25), self._ts(35),
                "initial_access", ["reconnaissance", "initial_access"]),
            self._make_classification(self._ts(45), self._ts(55),
                "execution", ["initial_access", "execution"]),
        ]
        report = evaluate(cls, timeline)
        assert report.strict_accuracy == 1.0
        assert report.micro_f1 == 1.0
        assert report.macro_f1 == 1.0
        assert report.evaluable_windows == 3

    def test_current_tactic_only_degrades_multilabel(self):
        """Si el observer solo reporta current_tactic (no carry-over), la
        accuracy estricta es 1.0 pero el F1 multi-label degrada porque las
        tacticas previas que siguen activas cuentan como FN.
        """
        timeline = [
            {"timestamp": self._ts(10), "tactic": "reconnaissance"},
            {"timestamp": self._ts(30), "tactic": "initial_access"},
            {"timestamp": self._ts(50), "tactic": "execution"},
        ]
        cls = [
            self._make_classification(self._ts(5), self._ts(15), "reconnaissance"),
            self._make_classification(self._ts(25), self._ts(35), "initial_access"),
            self._make_classification(self._ts(45), self._ts(55), "execution"),
        ]
        report = evaluate(cls, timeline)
        assert report.strict_accuracy == 1.0  # current_tactic siempre acerto
        # Pero F1 degrada por tacticas carry-over no detectadas
        assert report.micro_f1 < 1.0

    def test_includes_metadata(self):
        report = evaluate(
            [], [], attacker_model="gpt-4.1", observer_model="gpt-4.1-mini",
            seed=42, scenario="basic",
        )
        assert report.attacker_model == "gpt-4.1"
        assert report.seed == 42
        assert report.scenario == "basic"
        assert report.timestamp  # no vacio

    def test_dump_as_json_roundtrip(self):
        """El dump debe ser JSON-serializable y tener las keys esperadas."""
        import json as _json
        timeline = [{"timestamp": self._ts(10), "tactic": "execution"}]
        cls = [self._make_classification(self._ts(5), self._ts(15), "execution")]
        report = evaluate(cls, timeline, scenario="basic", seed=42)
        data = dump_as_json(report)
        # Debe ser JSON-serializable (incluye defaultdict si no conversion)
        text = _json.dumps(data)
        assert "strict_accuracy" in text
        assert "micro_f1" in text
        assert "confusion_matrix" in text
        assert data["metadata"]["seed"] == 42

    def test_false_positive_penalizes_precision(self):
        """Observer predice execution en una ventana de recon → FP para execution."""
        timeline = [{"timestamp": self._ts(10), "tactic": "reconnaissance"}]
        cls = [self._make_classification(self._ts(5), self._ts(15), "execution")]
        report = evaluate(cls, timeline)
        # Recon tiene FN (real pero no predicho), Execution tiene FP (predicho pero no real)
        assert report.per_tactic["reconnaissance"].fn == 1
        assert report.per_tactic["execution"].fp == 1
        assert report.strict_accuracy == 0.0
