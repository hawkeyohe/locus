from __future__ import annotations

import random
import uuid
from datetime import UTC, datetime

from .classifier import FEATURE_NAMES, GaussianNB, explain
from .models import FAILURE_TYPES, Span, Trace


BASELINES = {
    "healthy": (0.90, 0.94, 0.04, 0.97, 720, 0.08),
    "retrieval_failure": (0.25, 0.45, 0.06, 0.95, 780, 0.12),
    "prompt_injection": (0.72, 0.62, 0.91, 0.82, 880, 0.18),
    "hallucination": (0.76, 0.19, 0.08, 0.94, 820, 0.14),
    "wrong_tool": (0.82, 0.75, 0.08, 0.12, 910, 0.16),
    "latency_spike": (0.86, 0.87, 0.05, 0.94, 4200, 0.11),
    "data_drift": (0.61, 0.71, 0.10, 0.89, 1050, 0.89),
}

QUERIES = (
    "Summarize the evidence for retrieval regressions.",
    "Which deployment introduced the quality drop?",
    "Compare the healthy run with the latest incident.",
    "Find the source supporting the latency claim.",
)


def _sample_features(scenario: str, rng: random.Random) -> list[float]:
    base = BASELINES[scenario]
    sampled = []
    for index, value in enumerate(base):
        spread = 130 if FEATURE_NAMES[index] == "latency_ms" else 0.045
        sampled.append(rng.gauss(value, spread))
    for index in range(len(sampled)):
        if FEATURE_NAMES[index] != "latency_ms":
            sampled[index] = min(1.0, max(0.0, sampled[index]))
        else:
            sampled[index] = max(100, sampled[index])
    return sampled


def training_data(seed: int = 90210, samples_per_class: int = 100):
    rng = random.Random(seed)
    rows: list[list[float]] = []
    labels: list[str] = []
    for scenario in FAILURE_TYPES:
        for _ in range(samples_per_class):
            rows.append(_sample_features(scenario, rng))
            labels.append(scenario)
    return rows, labels


class IncidentLab:
    def __init__(self) -> None:
        rows, labels = training_data()
        self.classifier = GaussianNB().fit(rows, labels)
        self.traces: list[Trace] = []
        self.run("healthy", seed=11)
        self.run("retrieval_failure", seed=12)

    def run(self, scenario: str, seed: int | None = None) -> Trace:
        if scenario not in FAILURE_TYPES:
            raise ValueError(f"Unknown scenario: {scenario}")
        rng = random.Random(seed)
        features = _sample_features(scenario, rng)
        metrics = dict(zip(FEATURE_NAMES, features, strict=True))
        probabilities = self.classifier.predict_proba(features)
        ranking = sorted(probabilities.items(), key=lambda item: item[1], reverse=True)
        best_label, confidence = ranking[0]
        predicted = best_label if confidence >= 0.55 else "unknown"

        latency = int(metrics["latency_ms"])
        retrieval_ms = min(260, int(latency * 0.22))
        tool_status = "ok" if metrics["tool_correctness"] > 0.7 else "error"
        answer = (
            "The latest evaluation indicates a measurable regression. "
            "Inspect the cited trace evidence before promoting the release."
        )
        trace = Trace(
            id=str(uuid.uuid4())[:8],
            created_at=datetime.now(UTC).isoformat(),
            scenario=scenario,
            query=rng.choice(QUERIES),
            answer=answer,
            model_version="local-simulator-v1",
            prompt_version="research-agent-v3",
            metrics={key: round(value, 3) for key, value in metrics.items()},
            spans=[
                Span("retrieve", retrieval_ms, "ok", "Top-4 document retrieval"),
                Span("tool_call", 95, tool_status, "Search incident index"),
                Span(
                    "generate",
                    max(120, latency - retrieval_ms - 95),
                    "ok",
                    "Compose cited response",
                ),
            ],
            evidence=explain(features, best_label),
            diagnosis={
                "predicted": predicted,
                "confidence": round(confidence, 3),
                "ground_truth": scenario,
                "correct": predicted == scenario,
                "ranking": [
                    {"label": label, "probability": round(probability, 3)}
                    for label, probability in ranking[:3]
                ],
            },
        )
        self.traces.insert(0, trace)
        self.traces = self.traces[:100]
        return trace

    def summary(self) -> dict:
        incidents = [trace for trace in self.traces if trace.scenario != "healthy"]
        correct = sum(trace.diagnosis["correct"] for trace in self.traces)
        return {
            "total_runs": len(self.traces),
            "incidents": len(incidents),
            "diagnosis_accuracy": round(correct / len(self.traces), 3),
            "avg_latency_ms": round(
                sum(trace.metrics["latency_ms"] for trace in self.traces)
                / len(self.traces)
            ),
        }

