import assert from "node:assert/strict";
import test from "node:test";

import type { Finding, McpServer } from "../lib/audit-engine.ts";
import {
  createGovernedAuditReport,
  createGovernedSarifReport,
  createRiskException,
  findActiveRiskException,
  openFindingEntries,
  parseRiskExceptions,
  revokeRiskException,
  riskExceptionStatus,
} from "../lib/finding-exceptions.ts";

const finding: Finding = {
  id: "remote-transport",
  severity: "critical",
  title: "Transport non chiffré",
  description: "Le serveur utilise HTTP.",
  remediation: "Passez le serveur en HTTPS.",
  snippet: '"url": "https://mcp.example.test"',
  rule: "MCP-NET-01",
};

const server: McpServer = {
  id: "remote",
  name: "Remote MCP",
  owner: "Platform",
  transport: "HTTP",
  source: "Test",
  score: 72,
  status: "critical",
  controls: 10,
  findings: [finding],
  lastScan: "à l’instant",
};

const now = new Date("2026-07-30T10:00:00.000Z");

function exception() {
  return createRiskException(
    {
      id: "exception-1",
      server,
      finding,
      reason: "Migration TLS planifiée et suivie dans SEC-42.",
      owner: "Équipe Platform",
      expiresAt: "2026-08-15T23:59:59.999Z",
    },
    now,
  );
}

test("creates a documented, bounded and dated risk exception", () => {
  const created = exception();

  assert.equal(created.serverId, server.id);
  assert.equal(created.rule, finding.rule);
  assert.equal(created.createdAt, now.toISOString());
  assert.equal(riskExceptionStatus(created, now), "active");
  assert.throws(
    () =>
      createRiskException(
        {
          id: "too-long",
          server,
          finding,
          reason: "Migration TLS planifiée.",
          owner: "Platform",
          expiresAt: "2028-01-01T00:00:00.000Z",
        },
        now,
      ),
    /366 jours/,
  );
});

test("automatically reopens expired or revoked findings", () => {
  const created = exception();
  assert.equal(findActiveRiskException(server, finding, [created], now), created);
  assert.equal(openFindingEntries([server], [created], now).length, 0);

  const afterExpiry = new Date("2026-08-16T00:00:00.000Z");
  assert.equal(riskExceptionStatus(created, afterExpiry), "expired");
  assert.equal(openFindingEntries([server], [created], afterExpiry).length, 1);

  const revoked = revokeRiskException(
    created,
    new Date("2026-08-01T08:00:00.000Z"),
  );
  assert.equal(riskExceptionStatus(revoked, afterExpiry), "revoked");
  assert.equal(openFindingEntries([server], [revoked], afterExpiry).length, 1);
});

test("ignores malformed exception data loaded from browser storage", () => {
  const created = exception();
  const parsed = parseRiskExceptions(
    JSON.stringify([
      created,
      { ...created, id: "", owner: "x" },
      { arbitrary: true },
    ]),
  );

  assert.deepEqual(parsed, [created]);
  assert.deepEqual(parseRiskExceptions("{"), []);
});

test("exports accepted risk in JSON and SARIF without hiding the finding", () => {
  const created = exception();
  const report = createGovernedAuditReport([server], [created], now);
  const sarif = createGovernedSarifReport([server], [created], now);
  const exportedFinding = report.servers[0].findings[0];
  const sarifResult = sarif.runs[0].results[0];

  assert.equal(report.schemaVersion, "1.1");
  assert.equal(report.summary.toFix, 1);
  assert.equal(report.summary.openFindings, 0);
  assert.equal(report.summary.acceptedFindings, 1);
  assert.equal(report.riskExceptions[0].status, "active");
  assert.ok("riskException" in exportedFinding);
  assert.ok("suppressions" in sarifResult);
  if ("suppressions" in sarifResult) {
    assert.equal(sarifResult.suppressions[0].status, "accepted");
    assert.match(sarifResult.suppressions[0].justification, /SEC-42/);
  }
});
