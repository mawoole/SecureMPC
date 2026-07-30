import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import type { Finding, McpServer, Severity } from "../lib/audit-engine.ts";
import {
  evaluateSecurityGate,
  formatSecurityGateSummary,
  severityAtOrAbove,
} from "../lib/ci-gate.ts";

function finding(id: string, severity: Severity): Finding {
  return {
    id,
    rule: `MCP-${id}`,
    severity,
    title: `Constat ${id}`,
    description: "Description de test.",
    impact: "Impact de test.",
    remediation: "Correction de test.",
    snippet: '{"secret":"${REDACTED}"}',
  };
}

function server(name: string, findings: Finding[]): McpServer {
  return {
    id: name.toLowerCase(),
    name,
    owner: "Équipe test",
    transport: "Stdio",
    source: "Fixture",
    score: 50,
    status: findings.some((entry) => entry.severity === "critical")
      ? "critical"
      : findings.length
        ? "attention"
        : "secure",
    controls: 10,
    findings,
    lastScan: "à l’instant",
  };
}

test("compares severity thresholds inclusively", () => {
  assert.equal(severityAtOrAbove("critical", "high"), true);
  assert.equal(severityAtOrAbove("high", "high"), true);
  assert.equal(severityAtOrAbove("medium", "high"), false);
});

test("blocks findings at or above the configured threshold", () => {
  const result = evaluateSecurityGate(
    [
      server("Serveur B", [finding("003", "medium")]),
      server("Serveur A", [
        finding("002", "high"),
        finding("001", "critical"),
      ]),
    ],
    { threshold: "high", requireServers: true },
  );

  assert.equal(result.passed, false);
  assert.equal(result.servers, 2);
  assert.deepEqual(result.findings, {
    critical: 1,
    high: 1,
    medium: 1,
  });
  assert.deepEqual(
    result.blockingFindings.map(({ finding: entry }) => entry.severity),
    ["critical", "high"],
  );
});

test("can require at least one discovered server", () => {
  const result = evaluateSecurityGate([], {
    threshold: "critical",
    requireServers: true,
  });

  assert.equal(result.passed, false);
  assert.equal(result.missingRequiredServers, true);
  assert.match(
    formatSecurityGateSummary(result),
    /Aucun serveur MCP n’a été découvert/,
  );
});

test("summary excludes configuration snippets and concrete secrets", () => {
  const concreteSecret = "must-not-appear-in-ci-logs";
  const unsafeFinding = {
    ...finding("004", "critical"),
    snippet: `{"token":"${concreteSecret}"}`,
  };
  const result = evaluateSecurityGate(
    [server("Serveur sensible", [unsafeFinding])],
    { threshold: "critical" },
  );
  const summary = formatSecurityGateSummary(result);

  assert.match(summary, /Serveur sensible · MCP-004 · Constat 004/);
  assert.doesNotMatch(summary, new RegExp(concreteSecret));
  assert.doesNotMatch(summary, /snippet/);
});

test("collector CLI writes SARIF and returns code 3 for a blocked audit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-sentinel-gate-"));
  const configuration = join(directory, "unsafe.json");
  const inventory = join(directory, "inventory.json");
  const sarif = join(directory, "results.sarif");
  const concreteSecret = "must-not-appear-in-cli-output";

  try {
    await writeFile(
      configuration,
      JSON.stringify({
        mcpServers: {
          "unsafe-shell": {
            command: "powershell.exe",
            args: ["-Command", "Write-Output test"],
            env: { ACCESS_TOKEN: concreteSecret },
          },
        },
      }),
      "utf8",
    );
    const result = spawnSync(
      process.execPath,
      [
        "--experimental-strip-types",
        resolve("tools/collector.ts"),
        "--no-default-paths",
        "--no-lockfiles",
        "--path",
        configuration,
        "--output",
        inventory,
        "--sarif",
        sarif,
        "--fail-on",
        "high",
        "--require-servers",
      ],
      { encoding: "utf8" },
    );

    assert.equal(result.status, 3, result.stderr);
    assert.match(result.stderr, /Contrôle CI : ÉCHEC/);
    assert.match(result.stderr, /MCP-EXEC-01/);
    assert.doesNotMatch(result.stderr, new RegExp(concreteSecret));

    const report = JSON.parse(await readFile(sarif, "utf8")) as {
      version: string;
      runs: Array<{ results: unknown[] }>;
    };
    assert.equal(report.version, "2.1.0");
    assert.ok(report.runs[0].results.length >= 1);

    const storedInventory = await readFile(inventory, "utf8");
    assert.doesNotMatch(storedInventory, new RegExp(concreteSecret));
    assert.match(storedInventory, /\$\{REDACTED\}/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
