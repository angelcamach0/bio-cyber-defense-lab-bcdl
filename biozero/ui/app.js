// SPDX-License-Identifier: AGPL-3.0-only
// Reviewer session stays in an HttpOnly cookie; CSRF stays in memory.
const byId = (id) => document.getElementById(id);
let csrf = "";
let catalog = [];
let pollingGeneration = 0;
let signedIn = false;
let sessionGeneration = 0;
let authOperation = 0;
let authPending = false;
const terminal = new Set(["succeeded", "incomplete", "rejected", "failed", "timed_out"]);

function message(value) { byId("statusMessage").textContent = value; }
function currentSession(generation) { return signedIn && generation === sessionGeneration; }
function currentAction(sessionEpoch, pollingEpoch) {
  return currentSession(sessionEpoch) && pollingEpoch === pollingGeneration;
}
async function api(path, options = {}) {
  const sessionEpoch = sessionGeneration;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 35000);
  const headers = { ...options.headers };
  if (options.method === "POST") {
    headers["Content-Type"] = "application/json";
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  try {
    const response = await fetch(path, { ...options, headers, credentials: "same-origin", signal: controller.signal });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 401 && path !== "/api/sign-in" && sessionEpoch === sessionGeneration) {
        showSignedOut();
        message("Your session ended. Sign in to begin.");
      }
      throw new Error(data.error || `Request failed (${response.status})`);
    }
    return data;
  } finally { clearTimeout(timeout); }
}
function showSignedOut() {
  sessionGeneration += 1;
  signedIn = false;
  csrf = "";
  pollingGeneration += 1;
  byId("loginPanel").hidden = false;
  byId("workspace").hidden = true;
  byId("reportPanel").hidden = true;
  byId("executionReport").textContent = "";
  byId("evaluationReport").textContent = "";
  byId("executionStatus").textContent = "—";
  byId("scientificStatus").textContent = "—";
  byId("releaseBadge").textContent = "Not assessed";
  byId("releaseBadge").className = "badge";
  byId("accessCode").value = "";
  catalog = [];
  byId("experimentSelect").replaceChildren();
  byId("experimentScope").textContent = "";
  byId("runSelect").replaceChildren();
  byId("identityLabel").textContent = "Review workspace";
  byId("jobLabel").textContent = "";
  byId("runBtn").disabled = true;
  byId("viewRunBtn").disabled = true;
}
function selectionScope() {
  const experiment = catalog.find((item) => item.id === byId("experimentSelect").value);
  byId("experimentScope").textContent = experiment ? `${experiment.scope} · input SHA-256 ${experiment.input_sha256}` : "No prepared experiments available.";
}
async function refreshRuns(sessionEpoch = sessionGeneration, pollingEpoch = null) {
  if (!currentSession(sessionEpoch)) return;
  const runs = await api("/api/runs");
  if (!currentSession(sessionEpoch) || (pollingEpoch !== null && pollingEpoch !== pollingGeneration)) return;
  byId("runSelect").replaceChildren();
  for (const run of runs) {
    const option = document.createElement("option");
    option.value = run.job_id;
    option.textContent = `${run.experiment_id} · ${run.job_id}`;
    byId("runSelect").append(option);
  }
  byId("viewRunBtn").disabled = runs.length === 0;
}
async function loadWorkspace(session, expectedGeneration = sessionGeneration) {
  if (expectedGeneration !== sessionGeneration) return;
  const generation = ++sessionGeneration;
  pollingGeneration += 1;
  try {
    csrf = session.csrf_token;
    signedIn = true;
    byId("identityLabel").textContent = `Reviewer ${session.reviewer}`;
    const prepared = await api("/api/experiments");
    if (!currentSession(generation)) return;
    catalog = prepared;
    byId("experimentSelect").replaceChildren();
    for (const experiment of catalog) {
      const option = document.createElement("option");
      option.value = experiment.id;
      option.textContent = experiment.label;
      byId("experimentSelect").append(option);
    }
    selectionScope();
    await refreshRuns(generation);
    if (!currentSession(generation)) return;
    byId("loginPanel").hidden = true;
    byId("workspace").hidden = false;
    byId("runBtn").disabled = catalog.length === 0;
    message("Choose a prepared experiment or review one of your previous runs.");
  } catch (error) {
    if (generation === sessionGeneration) { showSignedOut(); message(error.message); }
  }
}
function renderReport(report) {
  const data = report.data || {};
  const release = data.release_status || "unassessed";
  const approved = report.status === "succeeded" && release === "evaluated_passed";
  byId("reportPanel").hidden = false;
  byId("jobLabel").textContent = `${report.experiment_id} · ${report.job_id}`;
  byId("executionStatus").textContent = report.status;
  byId("scientificStatus").textContent = release;
  byId("releaseBadge").textContent = approved ? "Evaluation passed" : release === "withheld" ? "Release withheld" : "Not scientifically assessed";
  byId("releaseBadge").className = approved ? "badge passed" : "badge";
  byId("evaluationReport").textContent = data.scientific_evaluation ? JSON.stringify(data.scientific_evaluation, null, 2) : "No scientific evaluation is available. Execution success alone does not validate scientific results.";
  const { scientific_evaluation, ...execution } = data;
  byId("executionReport").textContent = JSON.stringify({ status: report.status, error_code: report.error_code || "", ...execution }, null, 2);
}
async function pollRun(job, sessionEpoch = sessionGeneration, pollingEpoch = null) {
  if (!currentSession(sessionEpoch)) return;
  const generation = pollingEpoch === null ? ++pollingGeneration : pollingEpoch;
  const deadline = Date.now() + 12 * 60 * 1000;
  while (currentAction(sessionEpoch, generation) && Date.now() < deadline) {
    const report = await api(`/api/results/${encodeURIComponent(job)}`);
    if (!currentAction(sessionEpoch, generation)) return;
    renderReport(report);
    if (terminal.has(report.status)) {
      const approved = report.status === "succeeded" && report.data?.release_status === "evaluated_passed";
      message(approved ? "The prepared experiment passed scientific evaluation. Its scope remains synthetic." : `Execution ended as ${report.status}. Inspect the separate scientific release decision.`);
      await refreshRuns(sessionEpoch, generation);
      return;
    }
    message(`Worker status: ${report.status}`);
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  if (currentAction(sessionEpoch, generation)) message("Stopped waiting after 12 minutes. Use Previous runs to check the report later.");
}
function finishAction(sessionEpoch, pollingEpoch) {
  if (!currentAction(sessionEpoch, pollingEpoch)) return;
  byId("runBtn").disabled = catalog.length === 0;
  byId("viewRunBtn").disabled = byId("runSelect").options.length === 0;
}
byId("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (authPending) return;
  const reviewer = byId("reviewerId").value.trim();
  const access = byId("accessCode").value.trim();
  // A deliberate sign-in supersedes initial session recovery immediately.
  showSignedOut();
  const generation = sessionGeneration;
  const operation = ++authOperation;
  authPending = true;
  byId("signInBtn").disabled = true;
  try {
    const session = await api("/api/sign-in", { method: "POST", body: JSON.stringify({ id: reviewer, access_code: access }) });
    if (generation === sessionGeneration) await loadWorkspace(session, generation);
  } catch (error) { if (generation === sessionGeneration) { showSignedOut(); message(error.message); } }
  finally {
    if (operation === authOperation) { authPending = false; byId("signInBtn").disabled = false; }
  }
});
byId("signOutBtn").addEventListener("click", async () => {
  if (!signedIn || authPending) return;
  const operation = ++authOperation;
  authPending = true;
  // Start the request with the current CSRF token, then invalidate local views.
  // Wait for its cookie deletion before admitting another sign-in.
  const logout = api("/api/sign-out", { method: "POST", body: "{}" });
  showSignedOut();
  const generation = sessionGeneration;
  byId("signInBtn").disabled = true;
  try {
    await logout;
    if (generation === sessionGeneration) message("Signed out. Existing worker jobs continue and remain owned by your identity.");
  } catch (error) { if (generation === sessionGeneration) message(error.message); }
  finally {
    if (operation === authOperation) { authPending = false; byId("signInBtn").disabled = false; }
  }
});
byId("experimentSelect").addEventListener("change", selectionScope);
byId("runBtn").addEventListener("click", async () => {
  if (!signedIn || authPending || byId("runBtn").disabled) return;
  const sessionEpoch = sessionGeneration;
  const pollingEpoch = ++pollingGeneration;
  const experiment = byId("experimentSelect").value;
  byId("runBtn").disabled = true;
  byId("viewRunBtn").disabled = true;
  try {
    message("Submitting the prepared encrypted and signed input…");
    const run = await api(`/api/experiments/${encodeURIComponent(experiment)}/runs`, { method: "POST", body: "{}" });
    if (!currentAction(sessionEpoch, pollingEpoch)) return;
    await pollRun(run.job_id, sessionEpoch, pollingEpoch);
  } catch (error) { if (currentAction(sessionEpoch, pollingEpoch)) message(error.message); }
  finally { finishAction(sessionEpoch, pollingEpoch); }
});
byId("viewRunBtn").addEventListener("click", async () => {
  if (!signedIn || authPending || byId("viewRunBtn").disabled) return;
  const sessionEpoch = sessionGeneration;
  const pollingEpoch = ++pollingGeneration;
  const job = byId("runSelect").value;
  byId("runBtn").disabled = true;
  byId("viewRunBtn").disabled = true;
  try { await pollRun(job, sessionEpoch, pollingEpoch); }
  catch (error) { if (currentAction(sessionEpoch, pollingEpoch)) message(error.message); }
  finally { finishAction(sessionEpoch, pollingEpoch); }
});
(async () => {
  const generation = sessionGeneration;
  try {
    const session = await api("/api/session");
    if (generation === sessionGeneration) await loadWorkspace(session, generation);
  } catch (error) {
    if (generation === sessionGeneration) { showSignedOut(); message(error.message === "session_required" ? "Sign in to begin." : error.message); }
  }
})();
