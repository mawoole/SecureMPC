import assert from "node:assert/strict";
import test from "node:test";

import {
  applyRiskExceptionDecision,
  EnterpriseAuthorizationError,
  prepareRiskExceptionForSync,
  resolveEnterpriseRole,
  roleCapabilities,
} from "../lib/enterprise-authorization.ts";
import {
  createRiskException,
  riskExceptionStatus,
} from "../lib/finding-exceptions.ts";
import type { Finding, McpServer } from "../lib/audit-engine.ts";

const requester = "1".repeat(64);
const auditorOne = "2".repeat(64);
const auditorTwo = "3".repeat(64);
const admin = "4".repeat(64);
const now = new Date("2026-07-30T10:00:00.000Z");

const finding: Finding = {
  id: "critical-secret",
  severity: "critical",
  title: "Secret exposé",
  description: "Un secret est présent.",
  remediation: "Utiliser un coffre.",
  snippet: "${TOKEN}",
  rule: "MCP-SEC-01",
};

const server: McpServer = {
  id: "alpha",
  name: "Alpha MCP",
  owner: "Platform",
  transport: "Stdio",
  source: "Test",
  score: 50,
  status: "critical",
  controls: 13,
  findings: [finding],
  lastScan: "maintenant",
};

function incomingException() {
  return createRiskException(
    {
      id: "critical-exception",
      server,
      finding,
      reason: "Rotation du secret suivie dans SEC-42.",
      owner: "Platform",
      expiresAt: "2026-08-30T10:00:00.000Z",
    },
    now,
  );
}

test("résout les rôles de façon fermée et rend l’aperçu local administrateur", () => {
  const runtime = {
    TRUSTMAP_ROLE_BINDINGS: JSON.stringify({
      "admin@example.test": "admin",
      "audit@example.test": "auditor",
    }),
  };
  assert.equal(
    resolveEnterpriseRole("admin@example.test", runtime, false),
    "admin",
  );
  assert.equal(
    resolveEnterpriseRole("audit@example.test", runtime, false),
    "auditor",
  );
  assert.equal(
    resolveEnterpriseRole("unknown@example.test", runtime, false),
    "reader",
  );
  assert.equal(resolveEnterpriseRole(null, {}, true), "admin");
  assert.equal(roleCapabilities("reader").canSync, false);
  assert.equal(roleCapabilities("auditor").canReject, false);
  assert.equal(roleCapabilities("admin").canReject, true);
});

test("ignore les approbations clientes et ouvre une demande critique", () => {
  const spoofed = {
    ...incomingException(),
    approval: {
      status: "approved" as const,
      requiredApprovals: 2 as const,
      requestedBy: requester,
      requestedAt: now.toISOString(),
      approvals: [
        { actorRef: auditorOne, approvedAt: now.toISOString() },
        { actorRef: auditorTwo, approvedAt: now.toISOString() },
      ],
    },
  };
  const prepared = prepareRiskExceptionForSync(spoofed, requester);
  assert.equal(prepared.approval?.status, "pending");
  assert.deepEqual(prepared.approval?.approvals, []);
  assert.equal(prepared.approval?.requestedBy, requester);
  assert.equal(riskExceptionStatus(prepared, now), "pending");
});

test("impose deux approbateurs distincts du demandeur", () => {
  const pending = prepareRiskExceptionForSync(incomingException(), requester);
  assert.throws(
    () =>
      applyRiskExceptionDecision(
        pending,
        { actorHash: requester, role: "admin" },
        "approve",
        now,
      ),
    (error) =>
      error instanceof EnterpriseAuthorizationError && error.status === 409,
  );
  const first = applyRiskExceptionDecision(
    pending,
    { actorHash: auditorOne, role: "auditor" },
    "approve",
    now,
  );
  assert.equal(first.approval?.status, "pending");
  assert.equal(first.approval?.approvals.length, 1);
  assert.throws(
    () =>
      applyRiskExceptionDecision(
        first,
        { actorHash: auditorOne, role: "auditor" },
        "approve",
        now,
      ),
    (error) =>
      error instanceof EnterpriseAuthorizationError && error.status === 409,
  );
  const approved = applyRiskExceptionDecision(
    first,
    { actorHash: auditorTwo, role: "auditor" },
    "approve",
    now,
  );
  assert.equal(approved.approval?.status, "approved");
  assert.equal(riskExceptionStatus(approved, now), "active");
});

test("réserve le rejet à l’administrateur", () => {
  const pending = prepareRiskExceptionForSync(incomingException(), requester);
  assert.throws(
    () =>
      applyRiskExceptionDecision(
        pending,
        { actorHash: auditorOne, role: "auditor" },
        "reject",
        now,
      ),
    (error) =>
      error instanceof EnterpriseAuthorizationError && error.status === 403,
  );
  const rejected = applyRiskExceptionDecision(
    pending,
    { actorHash: admin, role: "admin" },
    "reject",
    now,
  );
  assert.equal(riskExceptionStatus(rejected, now), "rejected");
});
