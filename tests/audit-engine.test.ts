import assert from "node:assert/strict";
import test from "node:test";
import {
  auditConfiguration,
  calculateAuditMetrics,
  createAuditReport,
  createSarifReport,
  SECURITY_RULES,
} from "../lib/audit-engine.ts";

function config(servers: Record<string, unknown>) {
  return JSON.stringify({ mcpServers: servers });
}

test("accepts MCP server containers used by common clients", () => {
  const claude = auditConfiguration(
    config({
      filesystem: {
        command: "npx",
        args: [
          "-y",
          "@modelcontextprotocol/server-filesystem@1.0.0",
          "/workspace/project",
        ],
      },
    }),
  );
  const vscode = auditConfiguration(
    JSON.stringify({
      servers: {
        remote: {
          url: "https://mcp.example.test/v1",
          headers: { Authorization: "Bearer ${MCP_ACCESS_TOKEN}" },
        },
      },
    }),
  );
  const cursor = auditConfiguration(
    JSON.stringify({
      mcp: {
        servers: {
          direct: {
            command: "/opt/mcp/server",
            args: ["--readonly"],
          },
        },
      },
    }),
  );

  assert.equal(claude.length, 1);
  assert.equal(vscode.length, 1);
  assert.equal(cursor.length, 1);
  assert.equal(claude[0].findings.length, 0);
  assert.equal(vscode[0].findings.length, 0);
  assert.equal(cursor[0].findings.length, 0);
});

test("detects a concrete secret without returning its value", () => {
  const exposedSecret = "example-secret-that-must-never-leak";
  const servers = auditConfiguration(
    config({
      github: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github@1.2.3"],
        env: { GITHUB_TOKEN: exposedSecret },
      },
    }),
  );

  assert.ok(
    servers[0].findings.some((finding) => finding.rule === "MCP-SEC-01"),
  );

  const report = JSON.stringify(
    createAuditReport(servers, new Date("2026-07-29T12:00:00.000Z")),
  );
  const sarif = JSON.stringify(
    createSarifReport(servers, new Date("2026-07-29T12:00:00.000Z")),
  );
  assert.doesNotMatch(report, new RegExp(exposedSecret));
  assert.doesNotMatch(sarif, new RegExp(exposedSecret));
});

test("does not treat environment placeholders as exposed secrets", () => {
  const servers = auditConfiguration(
    config({
      remote: {
        url: "https://mcp.example.test/v1",
        headers: {
          Authorization: "Bearer ${MCP_ACCESS_TOKEN}",
          "X-API-Key": "{{MCP_API_KEY}}",
        },
      },
    }),
  );

  assert.equal(servers[0].status, "secure");
  assert.equal(servers[0].findings.length, 0);
});

test("prioritizes transport, execution and isolation failures", () => {
  const servers = auditConfiguration(
    config({
      unsafe: {
        command: "bash",
        args: ["-c", "mcp-server", "--no-sandbox", "/"],
        url: "http://mcp.example.test/v1",
      },
    }),
  );
  const rules = new Set(
    servers[0].findings.map((finding) => finding.rule),
  );

  assert.equal(servers[0].status, "critical");
  assert.ok(servers[0].score < 50);
  assert.ok(rules.has("MCP-NET-01"));
  assert.ok(rules.has("MCP-EXEC-01"));
  assert.ok(rules.has("MCP-EXEC-02"));
  assert.ok(rules.has("MCP-AUTHZ-03"));
});

test("detects unpinned packages but accepts exact semantic versions", () => {
  const servers = auditConfiguration(
    config({
      unpinned: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github"],
      },
      pinned: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github@1.2.3"],
      },
    }),
  );

  assert.ok(
    servers[0].findings.some((finding) => finding.rule === "MCP-SUP-02"),
  );
  assert.ok(
    servers[1].findings.every((finding) => finding.rule !== "MCP-SUP-02"),
  );
  assert.equal(servers[0].components?.[0].ecosystem, "npm");
  assert.equal(servers[1].components?.[0].pinStatus, "pinned");
});

test("flags mutable OCI images and unpinned Python packages", () => {
  const servers = auditConfiguration(
    config({
      container: {
        command: "docker",
        args: ["run", "--rm", "ghcr.io/acme/mcp-server:1.4.0"],
      },
      python: {
        command: "uvx",
        args: ["mcp-server-fetch"],
      },
    }),
  );

  assert.equal(servers[0].components?.[0].pinStatus, "mutable");
  assert.equal(servers[1].components?.[0].pinStatus, "unpinned");
  assert.ok(
    servers.every((server) =>
      server.findings.some((finding) => finding.rule === "MCP-SUP-02"),
    ),
  );
});

test("flags privileged database identities without exposing connection data", () => {
  const connection =
    "postgresql://postgres:example-password@db.example.test/analytics";
  const servers = auditConfiguration(
    config({
      analytics: {
        command: "npx",
        args: ["-y", "@acme/postgres-mcp@2.4.1"],
        env: { DATABASE_URL: connection },
      },
    }),
  );

  assert.ok(
    servers[0].findings.some(
      (finding) => finding.rule === "MCP-AUTHZ-01",
    ),
  );
  assert.doesNotMatch(JSON.stringify(servers), /example-password/);
});

test("exports deterministic JSON and SARIF reports", () => {
  const generatedAt = new Date("2026-07-29T12:00:00.000Z");
  const servers = auditConfiguration(
    config({
      remote: {
        url: "http://mcp.example.test/v1?token=hidden-token-value",
      },
    }),
  );
  const report = createAuditReport(servers, generatedAt);
  const sarif = createSarifReport(servers, generatedAt);

  assert.equal(report.schemaVersion, "1.0");
  assert.equal(report.generatedAt, generatedAt.toISOString());
  assert.equal(report.summary.servers, 1);
  assert.equal(report.summary.critical, 2);
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results.length, 2);
  assert.doesNotMatch(JSON.stringify(sarif), /hidden-token-value/);
});

test("calculates portfolio metrics from sanitized server results", () => {
  const servers = auditConfiguration(
    config({
      secure: {
        command: "/opt/mcp/server",
        args: ["--readonly"],
      },
      insecure: {
        url: "http://mcp.example.test/v1",
      },
    }),
  );
  const metrics = calculateAuditMetrics(servers);

  assert.equal(metrics.secure, 1);
  assert.equal(metrics.critical, 1);
  assert.equal(metrics.toFix, 1);
  assert.equal(metrics.controls, SECURITY_RULES.length * 2);
});

test("rejects malformed JSON and invalid server entries", () => {
  assert.throws(
    () => auditConfiguration("{"),
    /configuration JSON n’est pas valide/,
  );
  assert.throws(
    () => auditConfiguration(JSON.stringify({ mcpServers: { broken: true } })),
    /serveur « broken » est invalide/,
  );
});

test("imports a redacted collector inventory with passive probe evidence", () => {
  const servers = auditConfiguration(
    JSON.stringify({
      schemaVersion: "1.0",
      generatedAt: "2026-07-29T12:00:00.000Z",
      collector: {
        name: "Secure MPC Collector",
        version: "1.0.0",
        platform: "linux",
      },
      sources: [],
      servers: [
        {
          id: "abc123",
          name: "remote",
          source: {
            client: "VS Code",
            path: "~/.config/Code/User/mcp.json",
          },
          configuration: {
            url: "https://mcp.example.test/v1",
            headers: { Authorization: "${REDACTED}" },
          },
          redactions: [
            {
              path: "configuration.headers.Authorization",
              kind: "secret",
            },
          ],
          probe: {
            status: "auth-required",
            checkedAt: "2026-07-29T12:00:00.000Z",
            durationMs: 24,
            httpStatus: 401,
            message: "Authentification requise.",
          },
        },
      ],
    }),
  );

  assert.equal(servers.length, 1);
  assert.equal(servers[0].id, "collected-abc123");
  assert.equal(servers[0].probe?.status, "auth-required");
  assert.match(servers[0].source, /VS Code/);
  assert.ok(
    servers[0].findings.some((finding) => finding.rule === "MCP-SEC-01"),
  );
  assert.ok(
    servers[0].findings.every(
      (finding) => finding.rule !== "MCP-AUTHN-01",
    ),
  );
});

test("turns OSV advisories into scored findings and SARIF rules", () => {
  const servers = auditConfiguration(
    JSON.stringify({
      schemaVersion: "1.0",
      generatedAt: "2026-07-29T12:00:00.000Z",
      collector: {
        name: "Secure MPC Collector",
        version: "1.2.0",
        platform: "linux",
      },
      vulnerabilityScan: {
        provider: "OSV.dev",
        status: "complete",
        checkedAt: "2026-07-29T12:00:00.000Z",
        queriedComponents: 1,
        skippedComponents: 0,
        vulnerabilities: 1,
        message: "Analyse OSV terminée.",
      },
      sources: [],
      servers: [
        {
          id: "vulnerable",
          name: "vulnerable-server",
          source: {
            client: "VS Code",
            path: "~/.config/Code/User/mcp.json",
          },
          configuration: {
            command: "npx",
            args: ["-y", "@acme/mcp-server@1.2.3"],
          },
          redactions: [],
          components: [
            {
              id: "npm-acme-mcp",
              name: "@acme/mcp-server",
              ecosystem: "npm",
              componentType: "library",
              version: "1.2.3",
              purl: "pkg:npm/%40acme/mcp-server@1.2.3",
              pinStatus: "pinned",
              reference: "@acme/mcp-server@1.2.3",
              evidence: "npx",
              scope: "direct",
              dependencies: ["pkg:npm/helper@2.0.0"],
              lockfile: "package-lock.json",
              integrityStatus: "recorded",
              vulnerabilities: [],
            },
            {
              id: "npm-helper",
              name: "helper",
              ecosystem: "npm",
              componentType: "library",
              version: "2.0.0",
              purl: "pkg:npm/helper@2.0.0",
              pinStatus: "pinned",
              reference: "helper@2.0.0",
              evidence: "Version verrouillée dans package-lock.json.",
              scope: "transitive",
              dependencies: [],
              lockfile: "package-lock.json",
              integrityStatus: "recorded",
              vulnerabilities: [
                {
                  id: "GHSA-test-1234",
                  aliases: ["CVE-2026-1234"],
                  summary: "Injection de commande",
                  severity: "high",
                  advisoryUrl: "javascript:alert('unsafe')",
                  fixedVersion: "1.2.4",
                },
              ],
            },
          ],
          componentGraph: {
            direct: 1,
            transitive: 1,
            truncated: false,
            lockfiles: ["package-lock.json"],
          },
          probe: {
            status: "skipped-stdio",
            checkedAt: "2026-07-29T12:00:00.000Z",
            durationMs: 0,
            message: "Serveur stdio non exécuté.",
          },
        },
      ],
    }),
  );

  const finding = servers[0].findings.find(
    (entry) => entry.rule === "MCP-VULN-01",
  );
  assert.equal(finding?.severity, "high");
  assert.match(finding?.remediation ?? "", /1\.2\.4/);
  assert.match(finding?.remediation ?? "", /@acme\/mcp-server/);
  assert.match(finding?.description ?? "", /Dépendance transitive/);
  assert.equal(
    finding?.snippet,
    "https://osv.dev/vulnerability/GHSA-test-1234",
  );
  assert.equal(servers[0].vulnerabilityScan?.status, "complete");
  assert.equal(servers[0].componentGraph?.transitive, 1);
  assert.ok(servers[0].score < 100);

  const sarif = createSarifReport(
    servers,
    new Date("2026-07-29T12:00:00.000Z"),
  );
  assert.ok(
    sarif.runs[0].tool.driver.rules.some(
      (rule) => rule.id === "MCP-VULN-01",
    ),
  );
});

test("turns invalid SLSA or registry proofs into a critical finding", () => {
  const servers = auditConfiguration(
    JSON.stringify({
      schemaVersion: "1.0",
      generatedAt: "2026-07-30T12:00:00.000Z",
      collector: {
        name: "Secure MPC Collector",
        version: "1.5.0",
        platform: "linux",
      },
      provenanceScan: {
        provider: "npm-registry-sigstore",
        status: "partial",
        checkedAt: "2026-07-30T12:00:00.000Z",
        packages: 1,
        registrySignaturesVerified: 0,
        slsaProvenanceVerified: 0,
        missing: 0,
        failed: 1,
        message: "Une preuve est invalide.",
      },
      sources: [],
      servers: [
        {
          id: "invalid-proof",
          name: "invalid-proof",
          source: { client: "VS Code", path: ".vscode/mcp.json" },
          configuration: {
            command: "npx",
            args: ["@acme/mcp-server@1.2.3"],
          },
          redactions: [],
          components: [
            {
              id: "npm-acme-mcp",
              name: "@acme/mcp-server",
              ecosystem: "npm",
              componentType: "library",
              version: "1.2.3",
              purl: "pkg:npm/%40acme/mcp-server@1.2.3",
              pinStatus: "pinned",
              reference: "@acme/mcp-server@1.2.3",
              evidence: "npx",
              scope: "direct",
              lockfile: "pnpm-lock.yaml",
              integrityStatus: "recorded",
              integrity: "sha512-Zml4dHVyZQ==",
              provenance: {
                provider: "npm-registry-sigstore",
                checkedAt: "2026-07-30T12:00:00.000Z",
                registrySignature: "failed",
                slsaProvenance: "failed",
                subjectDigest: "mismatched",
                identityPolicy: "mismatched",
                sourceRepository: "https://github.com/acme/mcp-server",
                message: "Le digest ne correspond pas.",
              },
            },
          ],
          probe: {
            status: "skipped-stdio",
            checkedAt: "2026-07-30T12:00:00.000Z",
            durationMs: 0,
            message: "Serveur stdio non exécuté.",
          },
        },
      ],
    }),
  );

  const finding = servers[0].findings.find(
    (entry) => entry.rule === "MCP-SUP-03",
  );
  assert.equal(finding?.severity, "critical");
  assert.match(finding?.remediation ?? "", /lockfile/);
  assert.equal(servers[0].provenanceScan?.failed, 1);
  assert.equal(
    servers[0].components?.[0].provenance?.subjectDigest,
    "mismatched",
  );
});

test("imports a verified GitHub OCI attestation without inventing a supply-chain failure", () => {
  const digest =
    "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  const servers = auditConfiguration(
    JSON.stringify({
      schemaVersion: "1.0",
      generatedAt: "2026-07-30T12:00:00.000Z",
      collector: {
        name: "Secure MPC Collector",
        version: "1.4.0",
        platform: "linux",
      },
      ociVerification: {
        provider: "oci-provenance",
        backend: "github-attestations",
        status: "complete",
        checkedAt: "2026-07-30T12:00:00.000Z",
        images: 1,
        policies: 1,
        matched: 1,
        unmatched: 0,
        signaturesVerified: 0,
        slsaProvenanceVerified: 1,
        missing: 0,
        failed: 0,
        message: "Attestation vérifiée.",
      },
      sources: [],
      servers: [
        {
          id: "oci-proof",
          name: "oci-proof",
          source: { client: "VS Code", path: ".vscode/mcp.json" },
          configuration: {
            command: "docker",
            args: ["run", `ghcr.io/acme/mcp@${digest}`],
          },
          redactions: [],
          components: [
            {
              id: "oci-acme-mcp",
              name: "ghcr.io/acme/mcp",
              ecosystem: "oci",
              componentType: "container",
              version: digest,
              purl: `pkg:docker/ghcr.io/acme/mcp@${encodeURIComponent(digest)}`,
              pinStatus: "pinned",
              reference: `ghcr.io/acme/mcp@${digest}`,
              evidence: "Image OCI verrouillée.",
              scope: "direct",
              provenance: {
                provider: "oci-github-attestation",
                checkedAt: "2026-07-30T12:00:00.000Z",
                registrySignature: "not-applicable",
                slsaProvenance: "verified",
                subjectDigest: "matched",
                identityPolicy: "matched",
                policyId: "github-acme",
                sourceRepository: "https://github.com/acme/mcp",
                message: "Attestation et digest vérifiés.",
              },
            },
          ],
          probe: {
            status: "skipped-stdio",
            checkedAt: "2026-07-30T12:00:00.000Z",
            durationMs: 0,
            message: "Serveur stdio non exécuté.",
          },
        },
      ],
    }),
  );

  assert.equal(servers[0].ociVerification?.status, "complete");
  assert.equal(
    servers[0].components?.[0].provenance?.provider,
    "oci-github-attestation",
  );
  assert.equal(
    servers[0].components?.[0].provenance?.policyId,
    "github-acme",
  );
  assert.equal(
    servers[0].findings.some((finding) => finding.rule === "MCP-SUP-03"),
    false,
  );
});

test("turns an unmatched OCI policy into a critical actionable finding", () => {
  const digest =
    "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
  const servers = auditConfiguration(
    JSON.stringify({
      schemaVersion: "1.0",
      generatedAt: "2026-07-30T12:00:00.000Z",
      collector: {
        name: "Secure MPC Collector",
        version: "1.5.0",
        platform: "linux",
      },
      ociVerification: {
        provider: "oci-provenance",
        backend: "mixed",
        status: "partial",
        checkedAt: "2026-07-30T12:00:00.000Z",
        images: 1,
        policies: 2,
        matched: 0,
        unmatched: 1,
        signaturesVerified: 0,
        slsaProvenanceVerified: 0,
        missing: 0,
        failed: 1,
        message: "Une image n’a aucune politique.",
      },
      sources: [],
      servers: [
        {
          id: "oci-unmatched",
          name: "oci-unmatched",
          source: { client: "VS Code", path: ".vscode/mcp.json" },
          configuration: {
            command: "docker",
            args: ["run", `quay.io/unknown/mcp@${digest}`],
          },
          redactions: [],
          components: [
            {
              id: "oci-unmatched-component",
              name: "quay.io/unknown/mcp",
              ecosystem: "oci",
              componentType: "container",
              version: digest,
              purl: `pkg:docker/quay.io/unknown/mcp@${encodeURIComponent(digest)}`,
              pinStatus: "pinned",
              reference: `quay.io/unknown/mcp@${digest}`,
              evidence: "Image OCI verrouillée.",
              scope: "direct",
              provenance: {
                provider: "oci-policy",
                checkedAt: "2026-07-30T12:00:00.000Z",
                registrySignature: "not-applicable",
                slsaProvenance: "failed",
                subjectDigest: "unavailable",
                identityPolicy: "not-configured",
                message: "Aucune politique OCI correspondante.",
              },
            },
          ],
          probe: {
            status: "skipped-stdio",
            checkedAt: "2026-07-30T12:00:00.000Z",
            durationMs: 0,
            message: "Serveur stdio non exécuté.",
          },
        },
      ],
    }),
  );

  const finding = servers[0].findings.find(
    (entry) => entry.rule === "MCP-SUP-03",
  );
  assert.equal(finding?.severity, "critical");
  assert.match(finding?.snippet ?? "", /--oci-policy-file/);
  assert.equal(servers[0].ociVerification?.backend, "mixed");
  assert.equal(servers[0].ociVerification?.unmatched, 1);
});
