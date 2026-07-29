from __future__ import annotations

import math
from collections import Counter, defaultdict


FEATURE_NAMES = (
    "retrieval_relevance",
    "citation_coverage",
    "injection_score",
    "tool_correctness",
    "latency_ms",
    "distribution_shift",
)


class GaussianNB:
    """Small, inspectable Gaussian Naive Bayes implementation."""

    def __init__(self) -> None:
        self.classes: list[str] = []
        self.priors: dict[str, float] = {}
        self.means: dict[str, list[float]] = {}
        self.variances: dict[str, list[float]] = {}

    def fit(self, rows: list[list[float]], labels: list[str]) -> "GaussianNB":
        grouped: dict[str, list[list[float]]] = defaultdict(list)
        for row, label in zip(rows, labels, strict=True):
            grouped[label].append(row)

        counts = Counter(labels)
        self.classes = sorted(grouped)
        for label, samples in grouped.items():
            self.priors[label] = counts[label] / len(labels)
            columns = list(zip(*samples, strict=True))
            means = [sum(column) / len(column) for column in columns]
            self.means[label] = means
            self.variances[label] = [
                max(sum((value - mean) ** 2 for value in column) / len(column), 1e-6)
                for column, mean in zip(columns, means, strict=True)
            ]
        return self

    def predict_proba(self, row: list[float]) -> dict[str, float]:
        log_scores: dict[str, float] = {}
        for label in self.classes:
            score = math.log(self.priors[label])
            for value, mean, variance in zip(
                row, self.means[label], self.variances[label], strict=True
            ):
                score += -0.5 * (
                    math.log(2 * math.pi * variance)
                    + ((value - mean) ** 2 / variance)
                )
            log_scores[label] = score

        ceiling = max(log_scores.values())
        exponentials = {
            label: math.exp(score - ceiling) for label, score in log_scores.items()
        }
        total = sum(exponentials.values())
        return {label: value / total for label, value in exponentials.items()}


def explain(row: list[float], predicted: str) -> list[str]:
    values = dict(zip(FEATURE_NAMES, row, strict=True))
    explanations = {
        "healthy": ["All monitored signals remain within their expected ranges."],
        "retrieval_failure": [
            f"Retrieval relevance fell to {values['retrieval_relevance']:.2f}.",
            f"Citation coverage is {values['citation_coverage']:.0%}.",
        ],
        "prompt_injection": [
            f"Injection detector score reached {values['injection_score']:.2f}.",
            "Retrieved context contains instruction-like language.",
        ],
        "hallucination": [
            f"Only {values['citation_coverage']:.0%} of claims are supported.",
            "The answer contains claims absent from retrieved evidence.",
        ],
        "wrong_tool": [
            f"Tool-call correctness measured {values['tool_correctness']:.0%}.",
            "The selected tool does not match the requested operation.",
        ],
        "latency_spike": [
            f"End-to-end latency rose to {values['latency_ms']:.0f} ms.",
            "The generation span dominates total execution time.",
        ],
        "data_drift": [
            f"Distribution-shift score reached {values['distribution_shift']:.2f}.",
            "Input characteristics differ from the training baseline.",
        ],
    }
    return explanations[predicted]

