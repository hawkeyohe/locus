const state = { agents: [], suites: [], runs: [], selectedRun: null, pendingAgent: null, poller: null };
const api = async (path, options = {}) => {
  const response = await fetch(path, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
};
const esc = value => String(value ?? "").replace(/[&<>"']/g, character => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]));
const human = value => String(value || "").replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase());
const fmtDate = value => value ? new Date(value).toLocaleString() : "—";

function credentials() {
  const type = document.querySelector("#auth-type").value;
  if (type === "bearer") return { token: document.querySelector("#credential-token").value };
  if (type === "api_key") return { headerName: document.querySelector("#credential-header").value, value: document.querySelector("#credential-value").value };
  if (type === "basic") return { username: document.querySelector("#credential-user").value, password: document.querySelector("#credential-password").value };
  return {};
}
function agentPayload() {
  return { name: document.querySelector("#agent-name").value, description: document.querySelector("#agent-description").value, endpointUrl: document.querySelector("#endpoint").value, authenticationType: document.querySelector("#auth-type").value, credentials: credentials(), requestHeaders: JSON.parse(document.querySelector("#headers").value), requestTemplate: JSON.parse(document.querySelector("#request-template").value), responsePath: document.querySelector("#response-path").value, timeoutMs: Number(document.querySelector("#timeout").value) };
}
document.querySelector("#auth-type").onchange = event => {
  const box = document.querySelector("#credentials"), type = event.target.value; box.hidden = type === "none";
  box.innerHTML = type === "bearer" ? '<label class="field-label">Bearer token</label><input class="text-input" id="credential-token" type="password" required>' : type === "api_key" ? '<div class="form-grid"><div><label class="field-label">Header name</label><input class="text-input" id="credential-header" value="X-API-Key"></div><div><label class="field-label">API key</label><input class="text-input" id="credential-value" type="password"></div></div>' : type === "basic" ? '<div class="form-grid"><div><label class="field-label">Username</label><input class="text-input" id="credential-user"></div><div><label class="field-label">Password</label><input class="text-input" id="credential-password" type="password"></div></div>' : "";
};

document.querySelector("#agent-form").onsubmit = async event => {
  event.preventDefault(); const status = document.querySelector("#connection-result"); status.hidden = false; status.className = "connection-result"; status.textContent = "Saving encrypted connection…";
  try { const agent = await api("/api/agents", { method: "POST", body: JSON.stringify(agentPayload()) }); state.pendingAgent = agent; status.className += " success"; status.textContent = "Agent saved. Run a connection test to activate it."; await load(); }
  catch (error) { status.className += " error"; status.textContent = error.message; }
};
document.querySelector("#test-connection").onclick = async () => {
  const status = document.querySelector("#connection-result"); status.hidden = false; status.className = "connection-result";
  try {
    if (!state.pendingAgent) state.pendingAgent = await api("/api/agents", { method: "POST", body: JSON.stringify(agentPayload()) });
    status.textContent = "Testing reachability, authentication, JSON, and response path…";
    const result = await api(`/api/agents/${state.pendingAgent.id}/test`, { method: "POST", body: "{}" });
    status.className += result.success ? " success" : " error"; status.innerHTML = result.success ? `<strong>Connection verified</strong><span>HTTP ${result.httpStatus} · ${result.latencyMs} ms · ${esc(result.parsedResponse)}</span>` : `<strong>Connection failed</strong><span>${esc(result.error)}</span>`; await load();
  } catch (error) { status.className += " error"; status.textContent = error.message; }
};

async function load() {
  const [dashboard, agents, suites, runs] = await Promise.all([api("/api/dashboard"), api("/api/agents"), api("/api/test-suites"), api("/api/test-runs")]);
  state.agents = agents.agents; state.suites = suites.testSuites; state.runs = runs.testRuns;
  renderDashboard(dashboard); renderSelectors(); renderRuns();
  if (state.selectedRun) await showRun(state.selectedRun, false);
}
function renderDashboard(data) {
  document.querySelector("#health-score").innerHTML = data.averageScore ? `${Math.round(data.averageScore)}<small>/100</small>` : "—";
  document.querySelector("#metrics").innerHTML = [["ACTIVE AGENTS",data.activeAgents],["TEST RUNS",data.totalRuns],["FAILED TESTS",data.failedTests],["CRITICAL",data.criticalFindings]].map(([label,value]) => `<div class="metric"><small>${label}</small><strong>${value}</strong></div>`).join("");
}
function renderSelectors() {
  const agentSelect = document.querySelector("#agent-select"), suiteSelect = document.querySelector("#suite-select"); const oldAgent = agentSelect.value, oldSuite = suiteSelect.value;
  agentSelect.innerHTML = state.agents.length ? state.agents.map(agent => `<option value="${agent.id}" ${agent.status !== "active" ? "disabled" : ""}>${esc(agent.name)} · ${human(agent.status)}</option>`).join("") : '<option value="">Connect an agent first</option>';
  suiteSelect.innerHTML = state.suites.map(suite => `<option value="${suite.id}">${esc(suite.name)} · ${suite.testCases.length} tests</option>`).join("");
  if ([...agentSelect.options].some(option => option.value === oldAgent)) agentSelect.value = oldAgent; if ([...suiteSelect.options].some(option => option.value === oldSuite)) suiteSelect.value = oldSuite; renderCases();
}
function renderCases() { const suite = state.suites.find(item => item.id === document.querySelector("#suite-select").value); document.querySelector("#suite-cases").innerHTML = suite ? suite.testCases.map(test => `<label class="case-row"><input type="checkbox" checked disabled><span><strong>${esc(test.name)}</strong><small>${human(test.category)} · ${human(test.default_severity)}</small></span></label>`).join("") : '<div class="empty-small">No tests in this suite.</div>'; }
document.querySelector("#suite-select").onchange = renderCases;
document.querySelector("#run").onclick = async () => { const status = document.querySelector("#run-status"); try { status.textContent = "Queueing test run…"; const run = await api("/api/test-runs", { method: "POST", body: JSON.stringify({ agentId: document.querySelector("#agent-select").value, testSuiteId: document.querySelector("#suite-select").value, configuration: { concurrency: 2 } }) }); state.selectedRun = run.id; status.textContent = "Run started. Results update automatically."; startPolling(); await load(); } catch (error) { status.textContent = error.message; } };
function renderRuns() {
  const list = document.querySelector("#trace-list"); document.querySelector("#run-count").textContent = `${state.runs.length} runs`; list.innerHTML = "";
  if (!state.runs.length) { list.innerHTML = '<div class="empty-small">No runs yet. Start your first reliability test.</div>'; return; }
  state.runs.forEach(run => { const row = document.querySelector("#trace-template").content.firstElementChild.cloneNode(true); row.classList.toggle("healthy", run.status === "completed" && run.overall_score >= 90); row.classList.toggle("active", run.id === state.selectedRun); row.querySelector("strong").textContent = `${run.agent_name} · ${run.suite_name}`; row.querySelector("small").textContent = `${human(run.status)} · ${fmtDate(run.created_at)}`; row.querySelector(".confidence").textContent = run.status === "running" ? `${run.progress}%` : run.overall_score == null ? "—" : `${Math.round(run.overall_score)}/100`; row.onclick = () => showRun(run.id); list.append(row); });
}
async function showRun(runId, rerender = true) { state.selectedRun = runId; const run = await api(`/api/test-runs/${runId}`); if (rerender) renderRuns(); document.querySelector("#export-report").disabled = run.status !== "completed"; if (run.status === "queued" || run.status === "running") { document.querySelector("#detail").innerHTML = `<div class="progress-view"><span class="eyebrow">${human(run.status)}</span><h2>Running deterministic checks</h2><div class="progress-track"><i style="width:${run.progress}%"></i></div><strong>${run.progress}% complete</strong><button class="secondary-button" onclick="cancelRun('${run.id}')">Cancel run</button></div>`; return; } const report = await api(`/api/reports/${runId}`); renderReport(report); }
function renderReport(report) { const run = report.run, regression = report.regression; document.querySelector("#detail").innerHTML = `<div class="detail-top"><div><span class="tag ${run.overall_score >= 90 ? "healthy" : ""}">${run.overall_score >= 90 ? "BASELINE PASSED" : "FINDINGS DETECTED"}</span><h2>${esc(report.agent.name)}</h2><p>${esc(report.testSuite.name)} · ${fmtDate(run.completed_at)}</p></div><div class="score"><strong>${Math.round(run.overall_score)}/100</strong><small>OVERALL SCORE</small></div></div><div class="score-grid"><div><small>SECURITY</small><strong>${Math.round(run.security_score)}</strong></div><div><small>RELIABILITY</small><strong>${Math.round(run.reliability_score)}</strong></div><div><small>COMPLIANCE</small><strong>${Math.round(run.compliance_score)}</strong></div><div><small>FAILURES</small><strong>${report.counts.failed + report.counts.error}</strong></div></div>${regression.available ? `<div class="regression-card"><span class="eyebrow">Regression comparison</span><strong>${regression.baselineScore} → ${regression.currentScore}</strong><p>${regression.newFailures} new failures · ${regression.resolvedFailures} resolved · ${regression.latencyChangePercent}% latency change</p></div>` : ""}<div class="section-label">FINDINGS</div><div class="findings">${report.results.map(result => `<details class="finding ${result.status}"><summary><span class="severity-pill">${human(result.severity)}</span><strong>${esc(result.test_name)}</strong><span>${human(result.status)}</span></summary><div><b>Input</b><p>${esc(result.input)}</p><b>Expected behavior</b><p>${esc(result.expected_behavior)}</p><b>Actual behavior</b><p>${esc(result.actual_behavior || result.error_type || "No response")}</p><b>Evidence</b><ul>${result.evidence.map(item => `<li>${esc(item)}</li>`).join("")}</ul><b>Remediation</b><ul>${result.remediation.map(item => `<li>${esc(item)}</li>`).join("")}</ul><small>HTTP ${result.http_status || "—"} · ${result.latency_ms || 0} ms</small></div></details>`).join("") || '<div class="empty-small">No results stored.</div>'}</div>`; }
window.cancelRun = async runId => { await api(`/api/test-runs/${runId}/cancel`, { method: "POST", body: "{}" }); await load(); };
function startPolling() { clearInterval(state.poller); state.poller = setInterval(async () => { await load(); const run = state.runs.find(item => item.id === state.selectedRun); if (!run || ["completed","failed","cancelled"].includes(run.status)) clearInterval(state.poller); }, 1000); }
document.querySelector("#export-report").onclick = () => { if (state.selectedRun) window.location = `/api/reports/${state.selectedRun}/export`; };
document.querySelector("#new-test").onclick = () => document.querySelector("#test-dialog").showModal();
document.querySelector("#test-form").onsubmit = async event => { if (event.submitter?.value === "cancel") return; event.preventDefault(); const form = new FormData(event.currentTarget); try { await api(`/api/test-suites/${document.querySelector("#suite-select").value}/test-cases`, { method: "POST", body: JSON.stringify({ name: form.get("name"), description: "Custom business-rule test", category: "business_rule", input: form.get("input"), expectedBehavior: form.get("expectedBehavior"), defaultSeverity: form.get("defaultSeverity"), evaluatorType: form.get("evaluatorType"), evaluatorConfig: JSON.parse(form.get("evaluatorConfig")), timeoutMs: 10000, enabled: true }) }); document.querySelector("#test-dialog").close(); await load(); } catch (error) { alert(error.message); } };
load().catch(error => { document.querySelector("#detail").innerHTML = `<div class="empty"><strong>${esc(error.message)}</strong></div>`; });
