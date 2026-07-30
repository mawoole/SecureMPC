import assert from "node:assert/strict";
import test from "node:test";
import {
  createCycloneDxReport,
  extractSupplyChainComponents,
} from "../lib/supply-chain.ts";

test("extracts pinned and unpinned npm packages with PURLs", () => {
  const pinned = extractSupplyChainComponents({
    command: "npx.cmd",
    args: ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"],
  });
  const unpinned = extractSupplyChainComponents({
    command: "pnpm",
    args: ["dlx", "@modelcontextprotocol/server-github@latest"],
  });

  assert.equal(pinned.length, 1);
  assert.equal(pinned[0].ecosystem, "npm");
  assert.equal(pinned[0].pinStatus, "pinned");
  assert.equal(pinned[0].version, "1.2.3");
  assert.equal(
    pinned[0].purl,
    "pkg:npm/%40modelcontextprotocol/server-filesystem@1.2.3",
  );
  assert.equal(unpinned[0].pinStatus, "unpinned");
  assert.equal(unpinned[0].version, undefined);
});

test("extracts Python packages launched by uvx and pipx", () => {
  const uvx = extractSupplyChainComponents({
    command: "uvx",
    args: ["mcp-server-fetch==2.4.0"],
  });
  const pipx = extractSupplyChainComponents({
    command: "pipx",
    args: ["run", "mcp-server-git"],
  });

  assert.equal(uvx[0].ecosystem, "pypi");
  assert.equal(uvx[0].pinStatus, "pinned");
  assert.equal(uvx[0].purl, "pkg:pypi/mcp-server-fetch@2.4.0");
  assert.equal(pipx[0].pinStatus, "unpinned");

  const wildcard = extractSupplyChainComponents({
    command: "uvx",
    args: ["mcp-server-fetch==2.*"],
  });
  assert.equal(wildcard[0].pinStatus, "unpinned");
});

test("requires OCI digests because tags remain mutable", () => {
  const tagged = extractSupplyChainComponents({
    command: "docker",
    args: [
      "run",
      "--rm",
      "-e",
      "MCP_MODE=readonly",
      "ghcr.io/acme/mcp-server:1.4.0",
    ],
  });
  const digest = `sha256:${"a".repeat(64)}`;
  const immutable = extractSupplyChainComponents({
    command: "podman",
    args: ["run", `ghcr.io/acme/mcp-server@${digest}`],
  });

  assert.equal(tagged[0].ecosystem, "oci");
  assert.equal(tagged[0].version, "1.4.0");
  assert.equal(tagged[0].pinStatus, "mutable");
  assert.equal(immutable[0].pinStatus, "pinned");
  assert.equal(immutable[0].version, digest);
});

test("records local executables without inventing a version", () => {
  const components = extractSupplyChainComponents({
    command: "C:\\Program Files\\MCP\\server.exe",
    args: ["--readonly"],
  });

  assert.equal(components.length, 1);
  assert.equal(components[0].ecosystem, "executable");
  assert.equal(components[0].name, "server.exe");
  assert.equal(components[0].pinStatus, "unknown");
  assert.doesNotMatch(JSON.stringify(components), /Program Files/);
});

test("generates a deduplicated CycloneDX 1.7 dependency graph", () => {
  const components = extractSupplyChainComponents({
    command: "npx",
    args: ["-y", "@modelcontextprotocol/server-filesystem@1.2.3"],
  });
  components[0].vulnerabilities = [
    {
      id: "GHSA-test-1234",
      aliases: ["CVE-2026-1234"],
      summary: "Avis de sécurité de test",
      severity: "high",
      modified: "2026-07-28T10:00:00Z",
      advisoryUrl:
        "https://osv.dev/vulnerability/GHSA-test-1234",
      fixedVersion: "1.2.4",
    },
  ];
  components[0].provenance = {
    provider: "npm-registry-sigstore",
    checkedAt: "2026-07-29T12:00:00.000Z",
    registrySignature: "verified",
    slsaProvenance: "verified",
    subjectDigest: "matched",
    identityPolicy: "matched",
    policyId: "release-policy",
    message: "Preuve vérifiée.",
  };
  const report = createCycloneDxReport(
    [
      {
        id: "server-a",
        name: "Filesystem A",
        transport: "Stdio",
        source: "VS Code",
        score: 100,
        findings: [],
        components,
      },
      {
        id: "server-b",
        name: "Filesystem B",
        transport: "Stdio",
        source: "Cursor",
        score: 100,
        findings: [],
        components,
      },
    ],
    new Date("2026-07-29T12:00:00.000Z"),
    "00000000-0000-4000-8000-000000000001",
  );

  assert.equal(report.bomFormat, "CycloneDX");
  assert.equal(report.specVersion, "1.7");
  assert.equal(
    report.serialNumber,
    "urn:uuid:00000000-0000-4000-8000-000000000001",
  );
  assert.equal(report.metadata.timestamp, "2026-07-29T12:00:00.000Z");
  assert.equal(report.components.length, 3);
  assert.equal(
    report.components.filter(
      (component) =>
        "purl" in component &&
        component.purl ===
          "pkg:npm/%40modelcontextprotocol/server-filesystem@1.2.3",
    ).length,
    1,
  );
  assert.equal(report.dependencies.length, 4);
  assert.equal(report.vulnerabilities?.length, 1);
  assert.equal(report.vulnerabilities?.[0].id, "GHSA-test-1234");
  assert.equal(report.vulnerabilities?.[0].affects.length, 1);
  assert.match(
    JSON.stringify(report),
    /secure-mpc:provenance-policy/,
  );
  assert.match(
    report.vulnerabilities?.[0].recommendation ?? "",
    /1\.2\.4/,
  );
});
