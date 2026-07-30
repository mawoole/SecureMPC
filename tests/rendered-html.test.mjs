import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const developmentPreviewMeta =
  /<meta(?=[^>]*\bname=["']codex-preview["'])(?=[^>]*\bcontent=["']development["'])[^>]*>/i;

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the MCP Sentinel application", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<html lang="fr">/i);
  assert.match(html, /<title>MCP Sentinel — Audit de sécurité MCP<\/title>/i);
  assert.match(html, /MCP Sentinel/);
  assert.match(html, /Vue d’ensemble/);
  assert.match(html, /Lancer un audit/);
  assert.match(html, /Exporter/);
  assert.match(html, /Rapport PDF/);
  assert.match(html, /SBOM CycloneDX/);
  assert.doesNotMatch(html, developmentPreviewMeta);
  assert.doesNotMatch(html, /react-loading-skeleton/i);
  assert.doesNotMatch(html, /Your site is taking shape/i);
});

test("keeps the audit engine separate from the interface", async () => {
  const [
    page,
    layout,
    auditEngine,
    findingExceptions,
    supplyChain,
    lockfiles,
    kubernetesAdmission,
    kubernetesAdmissionValidation,
    ociProvenance,
    osv,
    provenance,
    pdfReport,
    workspaces,
    packageJson,
    ciWorkflow,
  ] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../lib/audit-engine.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/finding-exceptions.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/supply-chain.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/lockfiles.ts", import.meta.url), "utf8"),
    readFile(
      new URL("../lib/kubernetes-admission.ts", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../lib/kubernetes-admission-validation.ts", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../lib/oci-provenance.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/osv.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/provenance.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/pdf-report.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/workspaces.ts", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8"),
  ]);

  assert.match(page, /from "\.\.\/lib\/audit-engine"/);
  assert.match(page, /createGovernedAuditReport/);
  assert.match(page, /createGovernedSarifReport/);
  assert.match(auditEngine, /export function auditConfiguration/);
  assert.match(auditEngine, /export function createSarifReport/);
  assert.match(findingExceptions, /export function createRiskException/);
  assert.match(findingExceptions, /status: "accepted" as const/);
  assert.match(supplyChain, /export function createCycloneDxReport/);
  assert.match(lockfiles, /export async function analyzeLockfile/);
  assert.match(lockfiles, /export function enrichComponentsFromLockfiles/);
  assert.match(
    kubernetesAdmission,
    /export function generateKubernetesAdmissionBundle/,
  );
  assert.match(
    kubernetesAdmissionValidation,
    /export function validateKubernetesAdmissionBundle/,
  );
  assert.match(ociProvenance, /export async function verifyOciProvenance/);
  assert.match(
    ociProvenance,
    /export function parseOciVerificationPolicyDocument/,
  );
  assert.match(page, /POLITIQUE ABSENTE/);
  assert.match(osv, /export async function scanComponentsWithOsv/);
  assert.match(provenance, /export async function verifyComponentProvenance/);
  assert.match(pdfReport, /export function createAuditPdfReport/);
  assert.match(workspaces, /export async function discoverWorkspacePackages/);
  assert.match(page, /npm run collect:security/);
  assert.match(page, /Claude Desktop classique ou Microsoft/);
  assert.match(page, /<code>\.mcp\.json<\/code>/);
  assert.match(packageJson, /generate:admission/);
  assert.match(packageJson, /validate:admission/);
  assert.match(ciWorkflow, /Generate Kubernetes admission bundle/);
  assert.match(ciWorkflow, /npm run validate:admission/);
  assert.match(ciWorkflow, /npm audit --omit=dev --audit-level=high/);
  assert.match(layout, /MCP Sentinel — Audit de sécurité MCP/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  let previewFiles = [];
  try {
    previewFiles = await readdir(
      new URL("../app/_sites-preview/", import.meta.url),
    );
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  assert.deepEqual(previewFiles, []);
});
