from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


FAILURE_TYPES = (
    "healthy",
    "retrieval_failure",
    "prompt_injection",
    "hallucination",
    "wrong_tool",
    "latency_spike",
    "data_drift",
)


@dataclass
class Span:
    name: str
    duration_ms: int
    status: str
    detail: str


@dataclass
class Trace:
    id: str
    created_at: str
    scenario: str
    query: str
    answer: str
    model_version: str
    prompt_version: str
    metrics: dict[str, float]
    spans: list[Span]
    evidence: list[str]
    diagnosis: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

