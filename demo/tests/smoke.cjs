const assert = require("node:assert/strict");
const {
  findings,
  rankAndFilterFindings,
  calculateReadiness,
  buildReportMarkdown,
  missionProgress
} = require("../app.js");

assert.equal(findings.length, 4, "Sample scan should promote four verified findings");

const prioritized = rankAndFilterFindings(findings, {
  severity: "all",
  minConfidence: 0,
  sort: "risk"
});
assert.equal(prioritized[0].id, "f-001", "Verified IDOR should be highest priority");
assert.equal(prioritized[0].confidence, 96);

const mediumOnly = rankAndFilterFindings(findings, {
  severity: "medium",
  minConfidence: 85,
  sort: "confidence"
});
assert.deepEqual(mediumOnly.map(f => f.id), ["f-002"], "Severity and confidence filters should combine");

assert.equal(calculateReadiness({ requestOn: true, responseOn: true, remediationOn: true }), 100);
assert.equal(calculateReadiness({ requestOn: true, responseOn: false, remediationOn: true }), 85);

const completeReport = buildReportMarkdown(prioritized[0], {
  requestOn: true,
  responseOn: true,
  remediationOn: true
});
assert.match(completeReport, /## Steps to reproduce/);
assert.match(completeReport, /Authorization: Bearer <ACCOUNT_A_TOKEN>/);
assert.match(completeReport, /customer_id/);
assert.match(completeReport, /## Suggested remediation/);

const redactedReport = buildReportMarkdown(prioritized[0], {
  requestOn: true,
  responseOn: false,
  remediationOn: false
});
assert.doesNotMatch(redactedReport, /## Evidence/);
assert.doesNotMatch(redactedReport, /## Suggested remediation/);

assert.deepEqual(missionProgress({ scope: true, scan: true, inspect: false, report: false, export: false }), { complete: 2, total: 5, percent: 40 });
assert.deepEqual(missionProgress({ scope: true, scan: true, inspect: true, report: true, export: true }), { complete: 5, total: 5, percent: 100 });

console.log("PASS sample scan → priority queue");
console.log("PASS severity + confidence filtering");
console.log("PASS expandable finding evidence model");
console.log("PASS HackerOne report composition controls");
console.log("PASS operator mission progress");
