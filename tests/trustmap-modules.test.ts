import assert from "node:assert/strict";
import test from "node:test";
import type { McpServer } from "../lib/audit-engine.ts";
import type { RiskException } from "../lib/finding-exceptions.ts";
import {
  createCiCommand,
  createDiscoverSummary,
  createEnterprisePolicyPack,
  createEnterpriseSummary,
  createGithubActionsWorkflow,
  evaluateCiGate,
  type TrustMapCiOptions,
} from "../lib/trustmap-modules.ts";

const servers: McpServer[] = [
  {
    id: "alpha",
    name: "Alpha MCP",
    owner: "Platform",
    transport: "Stdio",
    source: "Claude Desktop",
    score: 50,
    status: "critical",
    controls: 4,
    lastScan: "maintenant",
    findings: [
      {
        id: "alpha-secret",
        severity: "critical",
        title: "Secret exposé",
        description: "Un secret est présent.",
        remediation: "Utiliser un coffre.",
        snippet: "${TOKEN}",
        rule: "MCP-SEC-01",
      },
    ],
    components: [
      {
        id: "npm:alpha@1.0.0",
        ecosystem: "npm",
        name: "alpha",
        version: "1.0.0",
        reference: "alpha@1.0.0",
        componentType: "library",
        pinStatus: "pinned",
        evidence: "package-lock.json",
        provenance: {
          provider: "npm-registry-sigstore",
          checkedAt: "2026-07-30T10:00:00.000Z",
          registrySignature: "verified",
          slsaProvenance: "verified",
          subjectDigest: "matched",
          identityPolicy: "matched",
          message: "Preuves valides.",
        },
      },
    ],
  },
  {
    id: "beta",
    name: "Beta MCP",
    owner: "Produit",
    transport: "HTTPS",
    source: "VS Code",
    score: 90,
    status: "secure",
    controls: 4,
    lastScan: "maintenant",
    findings: [],
  },
];

const ciOptions: TrustMapCiOptions = {
  configPath: "./configs/MCP production.json",
  failOn: "high",
  sarif: true,
  sbom: true,
  osv: true,
  provenance: true,
  requireServers: true,
};

test("TrustMap CI génère une commande déterministe et sûre", () => {
  const command = createCiCommand(ciOptions);
  assert.match(command, /--path "\.\/configs\/MCP production\.json"/);
  assert.match(command, /--fail-on high/);
  assert.match(command, /--require-servers/);
  assert.match(command, /--osv/);
  assert.match(command, /--provenance/);
  assert.match(command, /mcp-trustmap\.cdx\.json/);
  assert.match(command, /mcp-trustmap\.sarif/);
});

test("TrustMap CI produit un workflow GitHub Actions avec SARIF", () => {
  const workflow = createGithubActionsWorkflow(ciOptions);
  assert.match(workflow, /name: MCP TrustMap/);
  assert.match(workflow, /security-events: write/);
  assert.match(workflow, /github\/codeql-action\/upload-sarif@v4/);
  assert.match(workflow, /npm run collect/);
});

test("TrustMap CI simule les constats ouverts et les exceptions actives", () => {
  const blocked = evaluateCiGate(servers, [], "high");
  assert.equal(blocked.passed, false);
  assert.equal(blocked.blockingFindings, 1);

  const exception: RiskException = {
    schemaVersion: "1.0",
    id: "exception-alpha",
    serverId: "alpha",
    serverName: "Alpha MCP",
    findingId: "alpha-secret",
    rule: "MCP-SEC-01",
    findingTitle: "Secret exposé",
    reason: "Migration du coffre planifiée.",
    owner: "Platform",
    createdAt: "2026-07-30T10:00:00.000Z",
    expiresAt: "2099-08-30T10:00:00.000Z",
  };
  assert.equal(evaluateCiGate(servers, [exception], "high").passed, true);
});

test("TrustMap Discover agrège les sources, transports et preuves", () => {
  const summary = createDiscoverSummary(servers);
  assert.equal(summary.servers, 2);
  assert.equal(summary.sources.length, 2);
  assert.equal(summary.transports.length, 2);
  assert.equal(summary.components, 1);
  assert.equal(summary.pinnedComponents, 1);
  assert.equal(summary.provenanceVerified, 1);
});

test("TrustMap Enterprise calcule la gouvernance et exporte un pack minimal", () => {
  const now = new Date("2026-07-30T12:00:00.000Z");
  const summary = createEnterpriseSummary(servers, [], now);
  assert.equal(summary.ownershipCoverage, 100);
  assert.equal(summary.provenanceCoverage, 100);
  assert.equal(summary.openCritical, 1);
  assert.deepEqual(
    summary.owners.map((owner) => owner.owner),
    ["Platform", "Produit"],
  );

  const pack = createEnterprisePolicyPack(servers, [], now);
  assert.equal(pack.generator.name, "MCP TrustMap");
  assert.equal(pack.policy.maximumOpenCritical, 0);
  assert.equal(pack.generatedAt, now.toISOString());
});
