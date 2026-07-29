const state = { traces: [], selected: null };
const labels = {
  healthy: "Healthy baseline",
  retrieval_failure: "Retrieval failure",
  prompt_injection: "Prompt injection",
  hallucination: "Unsupported claims",
  wrong_tool: "Wrong tool selected",
  latency_spike: "Latency spike",
  data_drift: "Data drift",
};

const pct = value => `${Math.round(value * 100)}%`;
const title = value => labels[value] || value.replaceAll("_", " ");

async function load(selectNewest = false) {
  const response = await fetch("/api/traces");
  const data = await response.json();
  state.traces = data.traces;
  if (selectNewest || !state.selected) state.selected = state.traces[0]?.id;
  renderSummary(data.summary);
  renderList();
  renderDetail();
  const picker = document.querySelector("#scenario");
  if (!picker.children.length) {
    data.scenarios.filter(item => item !== "healthy").forEach(scenario => {
      picker.add(new Option(title(scenario), scenario));
    });
  }
}

function renderSummary(summary) {
  const items = [
    ["TOTAL RUNS", summary.total_runs],
    ["INCIDENTS", summary.incidents],
    ["DIAGNOSIS ACCURACY", pct(summary.diagnosis_accuracy)],
    ["MEAN LATENCY", `${summary.avg_latency_ms} ms`],
  ];
  document.querySelector("#metrics").innerHTML = items
    .map(([label, value]) => `<div class="metric"><small>${label}</small><strong>${value}</strong></div>`)
    .join("");
}

function renderList() {
  const list = document.querySelector("#trace-list");
  list.innerHTML = "";
  document.querySelector("#run-count").textContent = `${state.traces.length} traces`;
  state.traces.forEach(trace => {
    const row = document.querySelector("#trace-template").content.firstElementChild.cloneNode(true);
    row.classList.toggle("healthy", trace.scenario === "healthy");
    row.classList.toggle("active", trace.id === state.selected);
    row.querySelector("strong").textContent = title(trace.scenario);
    row.querySelector("small").textContent = `${trace.id} · ${Math.round(trace.metrics.latency_ms)}ms`;
    row.querySelector(".confidence").textContent = pct(trace.diagnosis.confidence);
    row.onclick = () => { state.selected = trace.id; renderList(); renderDetail(); };
    list.append(row);
  });
}

function renderDetail() {
  const trace = state.traces.find(item => item.id === state.selected);
  if (!trace) return;
  const ranking = trace.diagnosis.ranking.map(item => `
    <div class="bar-line"><span>${title(item.label)}</span>
    <div class="bar"><i style="width:${pct(item.probability)}"></i></div>
    <b>${pct(item.probability)}</b></div>`).join("");
  const spans = trace.spans.map(span => `
    <div class="span"><b>${span.name}</b><small>${span.duration_ms} ms · ${span.status}</small></div>`).join("");
  document.querySelector("#detail").innerHTML = `
    <div class="detail-top">
      <div><span class="tag ${trace.scenario === "healthy" ? "healthy" : ""}">${trace.scenario === "healthy" ? "BASELINE" : "INCIDENT DETECTED"}</span>
      <h2>${title(trace.diagnosis.predicted)}</h2></div>
      <div class="score"><strong>${pct(trace.diagnosis.confidence)}</strong><small>MODEL CONFIDENCE</small></div>
    </div>
    <div class="query">${trace.query}</div>
    <div class="section-label">EXECUTION TIMELINE</div><div class="timeline">${spans}</div>
    <div class="section-label">DIAGNOSTIC EVIDENCE</div>
    <ul class="evidence">${trace.evidence.map(item => `<li>↳ ${item}</li>`).join("")}</ul>
    <div class="section-label">ROOT-CAUSE PROBABILITIES</div><div class="bars">${ranking}</div>
  `;
}

document.querySelector("#run").onclick = async () => {
  const button = document.querySelector("#run");
  const status = document.querySelector("#run-status");
  button.disabled = true;
  status.textContent = "Injecting failure and collecting trace…";
  try {
    const response = await fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: document.querySelector("#scenario").value }),
    });
    if (!response.ok) throw new Error("Experiment failed");
    await load(true);
    status.textContent = "Trace captured. Root-cause analysis complete.";
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

load();

