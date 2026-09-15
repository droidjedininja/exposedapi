const findings = [
  {
    id: "f-001",
    severity: "high",
    confidence: 96,
    title: "Cross-account order access via predictable object ID",
    shortTitle: "Cross-account order access",
    type: "BOLA / IDOR",
    endpoint: "GET /api/v1/orders/{order_id}",
    proof: "Account A → Account B data",
    status: "Verified",
    cvss: "8.1",
    impact: "An authenticated user can retrieve another customer's order record, including redacted contact and shipping details, by changing the order identifier.",
    evidence: [
      "Account A requested its own order ord_7c20 and received customer_id acct_A.",
      "Only the path identifier was changed to ord_8f31 while keeping Account A's token.",
      "The API returned HTTP 200 with customer_id acct_B, confirming missing object-level authorization."
    ],
    request: "GET /api/v1/orders/ord_8f31 HTTP/1.1\nHost: api.demo-marketplace.test\nAuthorization: Bearer <ACCOUNT_A_TOKEN>\nAccept: application/json",
    response: "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  \"order_id\": \"ord_8f31\",\n  \"customer_id\": \"acct_B\",\n  \"email\": \"b•••@example.test\",\n  \"ship_to\": \"[REDACTED]\"\n}",
    steps: [
      "Sign in as Account A and request its own order to confirm the expected authorization context.",
      "Replay the request with Account A's token and replace the path value with Account B's order ID.",
      "Observe HTTP 200 and confirm the response belongs to Account B."
    ],
    remediation: "Enforce server-side ownership checks for every order lookup. Resolve the order through the authenticated account relationship instead of trusting the client-supplied order ID.",
    rationale: "Three-request replay produced a stable cross-account response. The customer identifier and record ownership changed while the authenticated principal did not."
  },
  {
    id: "f-002",
    severity: "medium",
    confidence: 89,
    title: "Credentialed CORS origin reflection on profile endpoint",
    shortTitle: "Credentialed CORS origin reflection",
    type: "CORS misconfiguration",
    endpoint: "GET /api/v1/profile",
    proof: "Arbitrary Origin reflected",
    status: "Verified",
    cvss: "6.5",
    impact: "A malicious origin may be able to read authenticated profile data in a victim's browser when cookies are accepted cross-site.",
    evidence: ["Sent Origin: https://attacker.example.", "Response reflected the origin and enabled credentials.", "Preflight and actual request behavior matched."],
    request: "GET /api/v1/profile HTTP/1.1\nHost: api.demo-marketplace.test\nOrigin: https://attacker.example\nCookie: session=<VICTIM_SESSION>",
    response: "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://attacker.example\nAccess-Control-Allow-Credentials: true\n\n{\"email\":\"v•••@example.test\",\"tier\":\"seller\"}",
    steps: ["Host a page on an untrusted origin.", "Issue a credentialed fetch to /api/v1/profile.", "Confirm the browser exposes the JSON response to the untrusted page."],
    remediation: "Use an exact allowlist of trusted origins and never reflect arbitrary Origin values when credentials are enabled.",
    rationale: "Both access-control headers were reproduced across preflight and response, but final severity depends on production cookie behavior."
  },
  {
    id: "f-003",
    severity: "medium",
    confidence: 82,
    title: "GraphQL resolver exposes unpublished seller metadata",
    shortTitle: "Unpublished seller metadata exposed",
    type: "Broken access control",
    endpoint: "POST /graphql → sellerDraft(id)",
    proof: "Draft fields returned to buyer role",
    status: "Verified",
    cvss: "5.7",
    impact: "A buyer-role account can query unpublished seller metadata intended for the seller dashboard, including internal inventory notes.",
    evidence: ["Schema discovery identified sellerDraft(id).", "Buyer token returned draft-only fields.", "Unauthenticated request was correctly rejected."],
    request: "POST /graphql HTTP/1.1\nHost: api.demo-marketplace.test\nAuthorization: Bearer <BUYER_TOKEN>\nContent-Type: application/json\n\n{\"query\":\"query { sellerDraft(id: \\\"s_204\\\") { id internalNotes } }\"}",
    response: "HTTP/1.1 200 OK\n\n{\"data\":{\"sellerDraft\":{\"id\":\"s_204\",\"internalNotes\":\"[REDACTED]\"}}}",
    steps: ["Authenticate with a buyer-role account.", "Query sellerDraft using another seller's public identifier.", "Observe draft-only metadata in the response."],
    remediation: "Add resolver-level role and ownership authorization before returning draft seller fields.",
    rationale: "Role mismatch is reproducible. The exposed sample is limited, so impact remains medium pending confirmation of additional sensitive fields."
  },
  {
    id: "f-004",
    severity: "low",
    confidence: 71,
    title: "Verbose API error discloses internal service route",
    shortTitle: "Internal route in verbose error",
    type: "Information disclosure",
    endpoint: "POST /api/v1/exports",
    proof: "Internal hostname in 500 response",
    status: "Needs review",
    cvss: "3.1",
    impact: "Malformed input reveals an internal service name and handler path, which can improve attacker reconnaissance but does not provide direct access.",
    evidence: ["A schema-valid but unsupported format produced HTTP 500.", "The body contained export-worker.svc.cluster.local.", "No secrets or stack trace were present."],
    request: "POST /api/v1/exports HTTP/1.1\nHost: api.demo-marketplace.test\nAuthorization: Bearer <ACCOUNT_A_TOKEN>\nContent-Type: application/json\n\n{\"format\":\"legacy_xml\"}",
    response: "HTTP/1.1 500 Internal Server Error\n\n{\"error\":\"upstream export-worker.svc.cluster.local/convert unavailable\"}",
    steps: ["Authenticate normally.", "Request the unsupported legacy_xml format.", "Observe the internal service route in the error body."],
    remediation: "Return a generic client-facing error and keep upstream routing details in server-side logs.",
    rationale: "Disclosure is consistent, but no direct exploitation path was found. ExposedAPI keeps it below the submission threshold by default."
  }
];

const state = {
  activeView: "scan",
  scanComplete: false,
  scanRunning: false,
  severity: "all",
  minConfidence: 0,
  sort: "risk",
  selectedIds: new Set(),
  drawerFinding: null,
  mission: { scope: true, scan: false, inspect: false, report: false, export: false }
};

const missionSteps = [
  { id: "scope", title: "Confirm authorization", detail: "Read the target, profile, and rate limits.", action: "Review scope", view: "scan" },
  { id: "scan", title: "Run the verification pipeline", detail: "Watch 27 signals become 4 verified findings.", action: "Run scan", view: "scan" },
  { id: "inspect", title: "Interrogate the top signal", detail: "Read the rationale, request, and response evidence.", action: "Inspect evidence", view: "findings" },
  { id: "report", title: "Build the submission", detail: "Open the report and check its evidence controls.", action: "Open report", view: "report" },
  { id: "export", title: "Export a defensible report", detail: "Copy or download the completed Markdown report.", action: "Export report", view: "report" }
];

const severityRank = { high: 3, medium: 2, low: 1 };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("show"), 2100);
}

function navigate(view) {
  state.activeView = view;
  $$(".view").forEach(el => {
    const active = el.dataset.view === view;
    el.hidden = !active;
    el.classList.toggle("active", active);
  });
  $$(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.viewTarget === view));
  history.replaceState(null, "", `#${view}`);
  $(".sidebar").classList.remove("open");
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (view === "report" && state.scanComplete) completeMissionStep("report");
}

function loadMission() {
  try {
    const saved = JSON.parse(localStorage.getItem("exposedapi-mission-01") || "null");
    if (saved && typeof saved === "object") state.mission = { ...state.mission, ...saved, scope: true };
  } catch (_) { /* Device-local progress is optional. */ }
}

function completeMissionStep(id) {
  if (!Object.hasOwn(state.mission, id) || state.mission[id]) return;
  state.mission[id] = true;
  try { localStorage.setItem("exposedapi-mission-01", JSON.stringify(state.mission)); } catch (_) { /* no-op */ }
  renderAcademy();
}

function missionProgress(mission) {
  const complete = missionSteps.filter(step => mission[step.id]).length;
  return { complete, total: missionSteps.length, percent: Math.round((complete / missionSteps.length) * 100) };
}

function renderAcademy() {
  const progress = missionProgress(state.mission);
  $("#navAcademyCount").textContent = `${progress.complete}/${progress.total}`;
  $("#academyPercent").textContent = `${progress.percent}%`;
  $("#academyRing").style.setProperty("--progress", `${progress.percent}%`);
  $("#academyProgress").style.width = `${progress.percent}%`;
  $("#academyStatus").textContent = progress.percent === 100
    ? "Mission complete. Repeat the loop until you can explain every decision without prompts."
    : `${progress.complete} of ${progress.total} operator actions complete.`;
  $("#debriefPanel").classList.toggle("ready", progress.percent === 100);
  $("#missionList").innerHTML = missionSteps.map((step, index) => `
    <div class="mission-step ${state.mission[step.id] ? "complete" : ""}">
      <i>${state.mission[step.id] ? "✓" : index + 1}</i>
      <div><strong>${step.title}</strong><small>${step.detail}</small></div>
      <button type="button" data-mission-action="${step.id}" data-mission-view="${step.view}">${state.mission[step.id] ? "Review" : step.action}</button>
    </div>`).join("");
  $$('[data-mission-action]').forEach(button => button.addEventListener("click", () => {
    const id = button.dataset.missionAction;
    if (id === "scan" && !state.scanComplete) return runSampleScan("academy");
    navigate(button.dataset.missionView);
    if (id === "inspect") {
      if (!state.scanComplete) return runSampleScan("findings");
      setTimeout(() => openFinding("f-001"), 260);
    }
  }));
}

async function runSampleScan(destination = null) {
  if (state.scanRunning) return;
  navigate("scan");
  state.scanRunning = true;
  state.scanComplete = false;
  $("#runScanButton").disabled = true;
  $("#runScanButton span:last-child").textContent = "Scanning…";
  $("#scanState").textContent = "Running";
  $("#scanState").className = "scan-state running";
  $("#resultsBlock").className = "results-block locked";
  $("#verifiedMetric").textContent = "0";
  $$(".pipeline-step").forEach(step => step.className = "pipeline-step");
  ["discoverResult", "analyzeResult", "verifyResult", "prioritizeResult"].forEach(id => $("#" + id).textContent = "—");
  $("#scanProgress").style.width = "3%";

  const stages = [
    { key: "discover", progress: 25, result: "43 routes", log: "Parsed OpenAPI hints, JavaScript routes, and GraphQL operations." },
    { key: "analyze", progress: 52, result: "27 signals", log: "Compared guest, buyer, and seller authorization boundaries." },
    { key: "verify", progress: 78, result: "4 verified", log: "Replayed candidate issues and suppressed non-reproducible noise." },
    { key: "prioritize", progress: 100, result: "1 high", log: "Ranked findings by demonstrated impact and evidence confidence." }
  ];

  for (let i = 0; i < stages.length; i++) {
    const stage = stages[i];
    const el = $(`.pipeline-step[data-stage="${stage.key}"]`);
    el.classList.add("running");
    $("#pipelineLog").innerHTML = `<span class="log-time">00:0${i + 1}</span><span>${stage.log}</span>`;
    await delay(720);
    el.classList.remove("running");
    el.classList.add("done");
    el.querySelector(".stage-marker span").textContent = "✓";
    $("#" + stage.key + "Result").textContent = stage.result;
    $("#scanProgress").style.width = stage.progress + "%";
  }

  state.scanComplete = true;
  state.scanRunning = false;
  state.selectedIds.add("f-001");
  $("#runScanButton").disabled = false;
  $("#runScanButton span:last-child").textContent = "Replay sample scan";
  $("#scanState").textContent = "Complete";
  $("#scanState").className = "scan-state complete";
  $("#resultsBlock").className = "results-block unlocked";
  $("#verifiedMetric").textContent = "4";
  $("#pipelineLog").innerHTML = '<span class="log-time">00:04</span><span>Complete — 4 verified findings promoted from 27 raw signals.</span>';
  updateUnlockedViews();
  renderFindings();
  renderReport();
  completeMissionStep("scan");
  showToast("Scan complete: 4 verified findings, 23 signals suppressed");
  if (destination) { await delay(450); navigate(destination); }
}

function updateUnlockedViews() {
  $("#navFindingCount").textContent = state.scanComplete ? findings.length : "—";
  $("#navReportCount").textContent = state.selectedIds.size;
  $("#findingsEmpty").hidden = state.scanComplete;
  $("#findingsWorkspace").hidden = !state.scanComplete;
  const reportReady = state.scanComplete && state.selectedIds.size > 0;
  $("#reportEmpty").hidden = reportReady;
  $("#reportWorkspace").hidden = !reportReady;
  $("#downloadReport").disabled = !reportReady;
  $("#copyReport").disabled = !reportReady;
}

function rankAndFilterFindings(items, filters) {
  return [...items]
    .filter(f => filters.severity === "all" || f.severity === filters.severity)
    .filter(f => f.confidence >= filters.minConfidence)
    .sort((a, b) => {
      if (filters.sort === "confidence") return b.confidence - a.confidence;
      if (filters.sort === "status") return a.status.localeCompare(b.status);
      return severityRank[b.severity] - severityRank[a.severity] || b.confidence - a.confidence;
    });
}

function filteredFindings() {
  return rankAndFilterFindings(findings, {
    severity: state.severity,
    minConfidence: state.minConfidence,
    sort: state.sort
  });
}

function renderFindings() {
  if (!state.scanComplete) return;
  const list = filteredFindings();
  $("#resultCount").textContent = `${list.length} finding${list.length === 1 ? "" : "s"}`;
  $("#findingList").innerHTML = list.length ? list.map(f => `
    <article class="finding-card" data-id="${f.id}">
      <span class="severity-badge ${f.severity}">${f.severity.toUpperCase()}</span>
      <div class="finding-main"><strong>${f.shortTitle}</strong><code>${f.endpoint}</code></div>
      <div class="finding-proof"><span>Verified signal</span><strong>${f.proof}</strong></div>
      <div class="finding-confidence"><span>Confidence</span><div class="mini-track"><i style="--score:${f.confidence}%"></i></div><strong>${f.confidence}%</strong></div>
      <div class="finding-actions">
        <button class="icon-button inspect-button" type="button" data-id="${f.id}" title="Inspect evidence" aria-label="Inspect ${f.shortTitle}">↗</button>
        <button class="icon-button report-button ${state.selectedIds.has(f.id) ? "added" : ""}" type="button" data-id="${f.id}" title="${state.selectedIds.has(f.id) ? "Remove from" : "Add to"} report" aria-label="Add ${f.shortTitle} to report">${state.selectedIds.has(f.id) ? "✓" : "+"}</button>
      </div>
    </article>`).join("") : '<div class="empty-state"><div class="empty-glyph">◇</div><h2>No matches</h2><p>Lower the confidence threshold or choose another severity.</p></div>';

  $$(".inspect-button").forEach(button => button.addEventListener("click", () => openFinding(button.dataset.id)));
  $$(".report-button").forEach(button => button.addEventListener("click", () => toggleReportFinding(button.dataset.id)));
}

function openFinding(id) {
  const f = findings.find(item => item.id === id);
  if (!f) return;
  state.drawerFinding = f;
  $("#drawerTitle").textContent = f.shortTitle;
  $("#drawerBody").innerHTML = `
    <div class="drawer-summary">
      <div class="drawer-stat"><span>Severity</span><strong class="severity-text">${f.severity.toUpperCase()}</strong></div>
      <div class="drawer-stat"><span>Confidence</span><strong>${f.confidence}%</strong></div>
      <div class="drawer-stat"><span>Status</span><strong>${f.status}</strong></div>
    </div>
    <div class="drawer-risk"><strong>${f.type}</strong><br>${f.impact}</div>
    <details class="drawer-section" open><summary>Why ExposedAPI promoted it</summary><div><p>${f.rationale}</p><div class="evidence-chain">${f.evidence.map((event, i) => `<div class="evidence-event"><i>${i + 1}</i><span>${event}</span></div>`).join("")}</div></div></details>
    <details class="drawer-section" open><summary>Proof-of-concept request</summary><div><pre class="code-block">${escapeHtml(f.request)}</pre></div></details>
    <details class="drawer-section"><summary>Verified response excerpt</summary><div><pre class="code-block">${escapeHtml(f.response)}</pre></div></details>
    <details class="drawer-section"><summary>Recommended remediation</summary><div><p>${f.remediation}</p></div></details>`;
  $("#drawerAddReport").textContent = state.selectedIds.has(f.id) ? "Remove from report" : "Add to report";
  $("#drawerBackdrop").hidden = false;
  $("#findingDrawer").classList.add("open");
  $("#findingDrawer").setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  completeMissionStep("inspect");
}

function closeDrawer() {
  $("#findingDrawer").classList.remove("open");
  $("#findingDrawer").setAttribute("aria-hidden", "true");
  $("#drawerBackdrop").hidden = true;
  document.body.style.overflow = "";
}

function toggleReportFinding(id) {
  if (state.selectedIds.has(id)) state.selectedIds.delete(id); else state.selectedIds.add(id);
  if (!state.selectedIds.size) {
    const fallback = findings.find(f => f.id === id)?.id;
    if (fallback && state.activeView === "report") showToast("Select at least one finding to keep the report preview active");
  }
  updateUnlockedViews();
  renderFindings();
  renderReport();
  if (state.drawerFinding?.id === id) $("#drawerAddReport").textContent = state.selectedIds.has(id) ? "Remove from report" : "Add to report";
  showToast(state.selectedIds.has(id) ? "Finding added to report" : "Finding removed from report");
}

function selectedFinding() {
  const select = $("#reportFindingSelect");
  const available = findings.filter(f => state.selectedIds.has(f.id));
  return available.find(f => f.id === select.value) || available[0];
}

function renderReport() {
  updateUnlockedViews();
  const selected = findings.filter(f => state.selectedIds.has(f.id));
  if (!selected.length) return;
  const select = $("#reportFindingSelect");
  const previous = select.value;
  select.innerHTML = selected.map(f => `<option value="${f.id}">${f.shortTitle}</option>`).join("");
  if (selected.some(f => f.id === previous)) select.value = previous;
  const f = selectedFinding();
  if (!f) return;
  const requestOn = $("#includeRequest").checked;
  const responseOn = $("#includeResponse").checked;
  const remediationOn = $("#includeRemediation").checked;
  const score = calculateReadiness({ requestOn, responseOn, remediationOn });
  $("#readinessScore").textContent = score + "%";
  $("#readinessBar").style.width = score + "%";
  $("#readinessList").innerHTML = `<li class="complete">Impact demonstrated</li><li class="${requestOn ? "complete" : "pending"}">Reproduction ${requestOn ? "included" : "omitted"}</li><li class="${responseOn ? "complete" : "pending"}">Response evidence ${responseOn ? "included" : "omitted"}</li>`;
  $("#reportPreview").innerHTML = `
    <div class="report-meta"><span class="report-brand">EXPOSEDAPI / REPORT PREVIEW</span><span>Draft • Synthetic evidence</span></div>
    <h2>${f.title}</h2>
    <div class="report-badges"><span class="paper-badge ${f.severity}">${f.severity.toUpperCase()} SEVERITY</span><span class="paper-badge">${f.confidence}% CONFIDENCE</span><span class="paper-badge">${f.type}</span></div>
    <h3>Summary</h3><p>${f.impact}</p>
    <h3>Affected endpoint</h3><p><code>${f.endpoint}</code></p>
    <h3>Steps to reproduce</h3><ol>${f.steps.map(step => `<li>${step}</li>`).join("")}</ol>
    ${requestOn ? `<h3>Proof-of-concept request</h3><pre class="report-code">${escapeHtml(f.request)}</pre>` : ""}
    ${responseOn ? `<h3>Evidence</h3><pre class="report-code">${escapeHtml(f.response)}</pre>` : ""}
    <h3>Impact</h3><p class="impact-box">${f.impact} This demonstrates a broken trust boundary with a reproducible, cross-account result.</p>
    ${remediationOn ? `<h3>Suggested remediation</h3><p>${f.remediation}</p>` : ""}
    <h3>Testing notes</h3><p>All identifiers, tokens, and personal data in this preview are synthetic or redacted. No destructive actions were performed.</p>`;
}

function reportMarkdown() {
  const f = selectedFinding();
  if (!f) return "";
  return buildReportMarkdown(f, {
    requestOn: $("#includeRequest").checked,
    responseOn: $("#includeResponse").checked,
    remediationOn: $("#includeRemediation").checked
  });
}

function calculateReadiness({ requestOn, responseOn, remediationOn }) {
  return 55 + (requestOn ? 15 : 0) + (responseOn ? 15 : 0) + (remediationOn ? 15 : 0);
}

function buildReportMarkdown(f, { requestOn, responseOn, remediationOn }) {
  return `# ${f.title}\n\n**Severity:** ${f.severity.toUpperCase()}  \n**Confidence:** ${f.confidence}%  \n**Type:** ${f.type}\n\n## Summary\n\n${f.impact}\n\n## Affected endpoint\n\n\`${f.endpoint}\`\n\n## Steps to reproduce\n\n${f.steps.map((s,i) => `${i+1}. ${s}`).join("\n")}${requestOn ? `\n\n## Proof of concept\n\n\`\`\`http\n${f.request}\n\`\`\`` : ""}${responseOn ? `\n\n## Evidence\n\n\`\`\`http\n${f.response}\n\`\`\`` : ""}\n\n## Impact\n\n${f.impact} This demonstrates a broken trust boundary with a reproducible, cross-account result.${remediationOn ? `\n\n## Suggested remediation\n\n${f.remediation}` : ""}\n\n## Testing notes\n\nAll identifiers, tokens, and personal data in this preview are synthetic or redacted. No destructive actions were performed.\n`;
}

function escapeHtml(text) { const div = document.createElement("div"); div.textContent = text; return div.innerHTML; }

function bindEvents() {
  $$(".nav-item").forEach(button => button.addEventListener("click", () => navigate(button.dataset.viewTarget)));
  $$("[data-route]").forEach(link => link.addEventListener("click", event => { event.preventDefault(); navigate(link.dataset.route); }));
  $("#mobileMenu").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
  $("#runScanButton").addEventListener("click", () => runSampleScan());
  $("#findingsRunScan").addEventListener("click", () => runSampleScan("findings"));
  $("#emptyRunScan").addEventListener("click", () => runSampleScan("findings"));
  $("#reportRunScan").addEventListener("click", () => runSampleScan("report"));
  $("#reviewTopFinding").addEventListener("click", () => { navigate("findings"); setTimeout(() => openFinding("f-001"), 260); });
  $$(".open-finding").forEach(button => button.addEventListener("click", () => openFinding(button.dataset.findingId)));
  $("#closeDrawer").addEventListener("click", closeDrawer);
  $("#drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", event => { if (event.key === "Escape") closeDrawer(); });
  $("#drawerCopyPoc").addEventListener("click", async () => { if (state.drawerFinding) { await navigator.clipboard.writeText(state.drawerFinding.request); showToast("PoC copied"); } });
  $("#drawerAddReport").addEventListener("click", () => { if (state.drawerFinding) toggleReportFinding(state.drawerFinding.id); });
  $$(".filter-chip").forEach(button => button.addEventListener("click", () => { state.severity = button.dataset.severity; $$(".filter-chip").forEach(b => b.classList.toggle("active", b === button)); renderFindings(); }));
  $("#confidenceRange").addEventListener("input", event => { state.minConfidence = Number(event.target.value); $("#confidenceValue").textContent = state.minConfidence + "%"; renderFindings(); });
  $("#sortFindings").addEventListener("change", event => { state.sort = event.target.value; renderFindings(); });
  $("#reportFindingSelect").addEventListener("change", renderReport);
  ["includeRequest", "includeResponse", "includeRemediation"].forEach(id => $("#" + id).addEventListener("change", renderReport));
  $("#copyReport").addEventListener("click", async () => { await navigator.clipboard.writeText(reportMarkdown()); completeMissionStep("export"); showToast("HackerOne-ready report copied"); });
  $("#downloadReport").addEventListener("click", () => { const blob = new Blob([reportMarkdown()], {type: "text/markdown"}); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "exposedapi-hackerone-report.md"; a.click(); URL.revokeObjectURL(url); completeMissionStep("export"); showToast("Markdown report downloaded"); });
  $("#resetMission").addEventListener("click", () => { state.mission = { scope: true, scan: false, inspect: false, report: false, export: false }; try { localStorage.removeItem("exposedapi-mission-01"); } catch (_) { /* no-op */ } renderAcademy(); showToast("Mission progress reset"); });
}

if (typeof document !== "undefined") {
  loadMission();
  bindEvents();
  updateUnlockedViews();
  renderAcademy();
  navigate(["scan", "findings", "report", "academy"].includes(location.hash.slice(1)) ? location.hash.slice(1) : "academy");
}

if (typeof module !== "undefined") {
  module.exports = { findings, rankAndFilterFindings, calculateReadiness, buildReportMarkdown, missionProgress };
}
