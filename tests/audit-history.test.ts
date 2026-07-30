import assert from "node:assert/strict";
import test from "node:test";
import type {
  AuditHistoryRecord,
  AuditRuleSummary,
} from "../lib/audit-history.ts";
import {
  AuditHistoryValidationError,
  compareAuditHistory,
  createAuditHistoryCsv,
  createAuditHistoryPayload,
  parseAuditHistoryPayload,
  parseAuditHistoryRecords,
} from "../lib/audit-history.ts";
import type { Finding, McpServer, Severity } from "../lib/audit-engine.ts";

function finding(
  id: string,
  rule: string,
  severity: Severity,
  secret = "",
): Finding {
  return {
    id,
    rule,
    severity,
    title: `Constat ${id}`,
    description: "Description.",
    impact: "Impact.",
    remediation: "Correction.",
    snippet: `{"token":"${secret}"}`,
  };
}

function server(
  id: string,
  name: string,
  score: number,
  findings: Finding[],
): McpServer {
  return {
    id,
    name,
    owner: "Équipe confidentielle",
    transport: "Stdio",
    source: "Chemin confidentiel",
    score,
    status: findings.some((entry) => entry.severity === "critical")
      ? "critical"
      : findings.length
        ? "attention"
        : "secure",
    controls: 12,
    findings,
    lastScan: "à l’instant",
  };
}

function record(
  id: string,
  score: number,
  rules: AuditRuleSummary[],
): AuditHistoryRecord {
  const critical = rules
    .filter((rule) => rule.severity === "critical")
    .reduce((sum, rule) => sum + rule.count, 0);
  const high = rules
    .filter((rule) => rule.severity === "high")
    .reduce((sum, rule) => sum + rule.count, 0);
  const medium = rules
    .filter((rule) => rule.severity === "medium")
    .reduce((sum, rule) => sum + rule.count, 0);
  return {
    id,
    createdAt: "2026-07-30T10:00:00.000Z",
    source: "manual",
    score,
    servers: 2,
    critical,
    high,
    medium,
    toFix: critical + high + medium,
    secure: 0,
    rules,
  };
}

test("creates an aggregate history payload without infrastructure metadata", () => {
  const concreteSecret = "history-secret-that-must-not-leak";
  const payload = createAuditHistoryPayload(
    [
      server("private-id", "Serveur secret", 42, [
        finding("one", "MCP-SEC-01", "critical", concreteSecret),
        finding("two", "MCP-SEC-01", "high", concreteSecret),
      ]),
    ],
    "import",
  );
  const serialized = JSON.stringify(payload);

  assert.equal(payload.servers, 1);
  assert.equal(payload.critical, 1);
  assert.equal(payload.high, 1);
  assert.deepEqual(payload.rules, [
    { rule: "MCP-SEC-01", severity: "critical", count: 2 },
  ]);
  assert.doesNotMatch(serialized, /Serveur secret/);
  assert.doesNotMatch(serialized, /private-id/);
  assert.doesNotMatch(serialized, /Équipe confidentielle/);
  assert.doesNotMatch(serialized, new RegExp(concreteSecret));
});

test("validates counters and rejects duplicate or malformed rules", () => {
  assert.throws(
    () =>
      parseAuditHistoryPayload({
        source: "manual",
        score: 70,
        servers: 1,
        critical: 1,
        high: 0,
        medium: 0,
        toFix: 0,
        secure: 0,
        rules: [],
      }),
    AuditHistoryValidationError,
  );
  assert.throws(
    () =>
      parseAuditHistoryPayload({
        source: "manual",
        score: 70,
        servers: 1,
        critical: 0,
        high: 2,
        medium: 0,
        toFix: 2,
        secure: 0,
        rules: [
          { rule: "MCP-NET-01", severity: "high", count: 1 },
          { rule: "MCP-NET-01", severity: "high", count: 1 },
        ],
      }),
    AuditHistoryValidationError,
  );
});

test("compares introduced and resolved findings by rule", () => {
  const previous = record("00000000-0000-4000-8000-000000000001", 55, [
    { rule: "MCP-SEC-01", severity: "critical", count: 2 },
    { rule: "MCP-NET-01", severity: "high", count: 1 },
  ]);
  const current = record("00000000-0000-4000-8000-000000000002", 72, [
    { rule: "MCP-SEC-01", severity: "critical", count: 1 },
    { rule: "MCP-SUP-02", severity: "medium", count: 2 },
  ]);

  assert.deepEqual(compareAuditHistory(current, previous), {
    scoreDelta: 17,
    findingDelta: 0,
    criticalDelta: -1,
    introducedFindings: 2,
    resolvedFindings: 2,
  });
});

test("parses bounded API history records", () => {
  const entry = record("00000000-0000-4000-8000-000000000003", 80, []);
  const [parsed] = parseAuditHistoryRecords([entry]);

  assert.equal(parsed.id, entry.id);
  assert.equal(parsed.score, 80);
  assert.throws(
    () => parseAuditHistoryRecords([{ ...entry, createdAt: "invalid" }]),
    AuditHistoryValidationError,
  );
});

test("exports chronological CSV trends without infrastructure metadata", () => {
  const previous = {
    ...record("00000000-0000-4000-8000-000000000010", 55, [
      { rule: "MCP-SEC-01", severity: "critical" as const, count: 2 },
    ]),
    createdAt: "2026-07-29T10:00:00.000Z",
  };
  const current = {
    ...record("00000000-0000-4000-8000-000000000011", 75, [
      { rule: "MCP-SEC-01", severity: "critical" as const, count: 1 },
      { rule: "MCP-NET-01", severity: "high" as const, count: 1 },
    ]),
    createdAt: "2026-07-30T10:00:00.000Z",
  };

  const csv = createAuditHistoryCsv([current, previous]);

  assert.ok(csv.startsWith("\uFEFFsep=;\r\n"));
  assert.match(csv, /audit_id;created_at;source;score/);
  assert.ok(csv.indexOf(previous.id) < csv.indexOf(current.id));
  assert.match(csv, /;20;0;1;1;MCP-NET-01:high:1\|MCP-SEC-01:critical:1/);
  assert.doesNotMatch(csv, /Équipe confidentielle|Chemin confidentiel/);
});
