# Locus

Locus is an AI-agent reliability testing application. It injects controlled
failures into an agent, observes how the agent responds, and reports which
tests passed or failed, why they failed, and how critical each failure is.

The current MVP generates healthy and failing research-agent traces, trains a
probabilistic root-cause classifier, and explains each diagnosis using the
observed evidence.

The project is intentionally runnable with only Python's standard library.

## Run it

```bash
python3 -m sentinel.server
```

Open [http://localhost:8000](http://localhost:8000).

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

## What the MVP demonstrates

- Reproducible injection of retrieval, prompt-injection, hallucination,
  tool-selection, latency, and data-drift failures
- Structured traces with spans, metrics, model version, and evidence
- A Gaussian Naive Bayes classifier trained on generated labeled incidents
- Confidence-aware diagnoses with an explicit `unknown` outcome
- A dashboard for running experiments and comparing incidents

## Product direction

Locus will let developers connect their own AI agents and run a configurable
reliability test suite against them. Each evaluation will:

- Inject realistic retrieval, security, reasoning, tool-use, latency, and
  distribution-shift failures
- Measure whether the agent detects, contains, recovers from, or amplifies the
  injected failure
- Report pass/fail results with supporting trace evidence
- Assign severity and criticality based on user impact and failure behavior
- Produce an actionable reliability report that can be compared across agent,
  model, prompt, and tool versions

## Architecture

```text
Browser dashboard
      |
      v
Standard-library JSON API
      |
      +--> Agent trace simulator
      +--> Failure injectors
      +--> Feature extraction
      +--> Root-cause classifier
      +--> In-memory trace store
```

This first milestone uses controlled simulation so every failure has known
ground truth. The next milestone will connect the same trace contract to a real
retrieval pipeline and persist experiments in SQLite.
