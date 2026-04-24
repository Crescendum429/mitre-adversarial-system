"""Modulo de evaluacion academica — metricas P/R/F1 multi-label para observer."""

from src.evaluation.metrics import (
    EvaluationReport,
    TacticMetrics,
    dump_as_json,
    evaluate,
)

__all__ = ["EvaluationReport", "TacticMetrics", "dump_as_json", "evaluate"]
