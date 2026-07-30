import assert from "node:assert/strict";
import test from "node:test";

import type { Finding, McpServer } from "../lib/audit-engine.ts";
import { createRiskException } from "../lib/finding-exceptions.ts";
import { createAuditPdfReport } from "../lib/pdf-report.ts";

const generatedAt = new Date("2026-07-30T12:00:00.000Z");

function finding(index: number): Finding {
  return {
    id: `finding-${index}`,
    severity: index % 3 === 0 ? "critical" : index % 2 === 0 ? "high" : "medium",
    title: `Écart de sécurité numéro ${index}`,
    description:
      "Ce contrôle décrit un risque concret pouvant affecter la confidentialité ou l’intégrité du serveur MCP.",
    remediation:
      "Appliquez une configuration dédiée, réduisez les permissions et vérifiez le résultat avant la mise en production.",
    snippet: `"security": {\n  "leastPrivilege": true,\n  "audit": "metadata-only"\n}`,
    rule: `MCP-TEST-${String(index).padStart(2, "0")}`,
  };
}

const findings = Array.from({ length: 9 }, (_, index) => finding(index + 1));

const server: McpServer = {
  id: "test-server",
  name: "Serveur MCP de validation",
  owner: "Équipe Platform",
  transport: "HTTPS",
  source: "Test",
  score: 34,
  status: "critical",
  controls: 12,
  findings,
  lastScan: "à l’instant",
};

test("creates a paginated PDF audit with actionable and accepted risks", () => {
  const riskException = createRiskException(
    {
      id: "exception-1",
      server,
      finding: findings[0],
      reason: "Migration planifiée dans SEC-42 avec une mesure compensatoire.",
      owner: "Équipe Platform",
      expiresAt: "2026-08-30T23:59:59.999Z",
    },
    generatedAt,
  );
  const report = createAuditPdfReport(
    [server],
    [riskException],
    generatedAt,
  );
  const prefix = new TextDecoder("latin1").decode(report.bytes.slice(0, 8));
  const suffix = new TextDecoder("latin1").decode(report.bytes.slice(-16));

  assert.match(prefix, /^%PDF-/);
  assert.match(suffix, /%%EOF/);
  assert.ok(report.bytes.length > 8_000);
  assert.ok(report.pages >= 2);
  assert.equal(report.fileName, "mcp-trustmap-audit-2026-07-30.pdf");
  assert.deepEqual(report.summary, {
    servers: 1,
    score: 34,
    findings: 9,
    openFindings: 8,
    activeExceptions: 1,
  });
});

test("creates a valid empty-scope report without inventing findings", () => {
  const report = createAuditPdfReport([], [], generatedAt);
  const prefix = new TextDecoder("latin1").decode(report.bytes.slice(0, 8));

  assert.match(prefix, /^%PDF-/);
  assert.equal(report.summary.findings, 0);
  assert.equal(report.summary.openFindings, 0);
  assert.ok(report.pages >= 1);
});
