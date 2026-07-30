import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Miniflare } from "miniflare";
import test from "node:test";

const developmentPreviewMeta =
  /<meta(?=[^>]*\bname=["']codex-preview["'])(?=[^>]*\bcontent=["']development["'])[^>]*>/i;

function createWorker() {
  const serverDirectory = fileURLToPath(
    new URL("../dist/server/", import.meta.url),
  );
  return new Miniflare({
    modules: true,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    modulesRoot: serverDirectory,
    scriptPath: fileURLToPath(
      new URL("../dist/server/index.js", import.meta.url),
    ),
    compatibilityDate: "2026-07-29",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: { DB: `render-test-${process.pid}-${Date.now()}` },
    bindings: {
      TRUSTMAP_KMS_KEY_ID: "render-test-key:v1",
      TRUSTMAP_KMS_MASTER_KEY:
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
      TRUSTMAP_WORKSPACE_ID: "render-test-workspace",
    },
  });
}

async function render() {
  const worker = createWorker();
  try {
    const response = await worker.dispatchFetch("http://localhost/", {
      headers: { accept: "text/html" },
    });
    return new Response(await response.arrayBuffer(), {
      status: response.status,
      headers: response.headers,
    });
  } finally {
    await worker.dispose();
  }
}

test("server-renders the MCP TrustMap application", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<html lang="fr">/i);
  assert.match(
    html,
    /<title>MCP TrustMap — Cartographie, audit et gouvernance MCP<\/title>/i,
  );
  assert.match(html, /MCP TrustMap/);
  assert.match(html, /Vue d’ensemble/);
  assert.match(html, /Lancer un audit/);
  assert.match(html, /Exporter/);
  assert.match(html, /Rapport PDF/);
  assert.match(html, /SBOM CycloneDX/);
  assert.doesNotMatch(html, developmentPreviewMeta);
  assert.doesNotMatch(html, /react-loading-skeleton/i);
  assert.doesNotMatch(html, /Your site is taking shape/i);
});

test("persists aggregate audit history in the Worker runtime", async () => {
  const worker = createWorker();
  try {
    const audit = {
      source: "manual",
      score: 82,
      servers: 2,
      critical: 0,
      high: 1,
      medium: 1,
      toFix: 2,
      secure: 1,
      rules: [
        { rule: "MCP-NET-01", severity: "high", count: 1 },
        { rule: "MCP-AUTHN-01", severity: "medium", count: 1 },
      ],
    };
    const unauthenticated = await worker.dispatchFetch(
      "https://secure.example/api/audit-history",
    );
    assert.equal(unauthenticated.status, 401);

    const crossOrigin = await worker.dispatchFetch(
      "http://localhost/api/audit-history",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: "https://attacker.example",
        },
        body: JSON.stringify(audit),
      },
    );
    assert.equal(crossOrigin.status, 403);

    const created = await worker.dispatchFetch(
      "http://localhost/api/audit-history",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: "http://localhost",
        },
        body: JSON.stringify(audit),
      },
    );
    assert.equal(created.status, 201, await created.text());
    assert.equal(created.headers.get("cache-control"), "no-store");

    const listed = await worker.dispatchFetch(
      "http://localhost/api/audit-history",
    );
    assert.equal(listed.status, 200);
    const body = await listed.json();
    assert.equal(body.history.length, 1);
    assert.equal(body.history[0].score, 82);
    assert.deepEqual(body.history[0].rules, audit.rules);
    assert.equal(JSON.stringify(body).includes("configuration"), false);

    const deleted = await worker.dispatchFetch(
      "http://localhost/api/audit-history",
      {
        method: "DELETE",
        headers: { Origin: "http://localhost" },
      },
    );
    assert.equal(deleted.status, 200);
  } finally {
    await worker.dispose();
  }
});

test("synchronizes SSO-attributed exceptions as KMS envelopes", async () => {
  const worker = createWorker();
  try {
    const exception = {
      schemaVersion: "1.0",
      id: "exception-sync-1",
      serverId: "remote",
      serverName: "Remote MCP",
      findingId: "remote-transport",
      rule: "MCP-NET-01",
      findingTitle: "Transport non chiffré",
      reason: "Migration TLS planifiée et suivie dans SEC-42.",
      owner: "Équipe Platform",
      createdAt: "2026-07-30T10:00:00.000Z",
      expiresAt: "2026-08-15T23:59:59.999Z",
    };
    const unauthenticated = await worker.dispatchFetch(
      "https://secure.example/api/exception-sync",
    );
    assert.equal(unauthenticated.status, 401);

    const crossOrigin = await worker.dispatchFetch(
      "http://localhost/api/exception-sync",
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Origin: "https://attacker.example",
        },
        body: JSON.stringify({ exceptions: [exception] }),
      },
    );
    assert.equal(crossOrigin.status, 403);

    const created = await worker.dispatchFetch(
      "http://localhost/api/exception-sync",
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Origin: "http://localhost",
        },
        body: JSON.stringify({ exceptions: [exception] }),
      },
    );
    const createdText = await created.text();
    assert.equal(created.status, 200, createdText);
    const createdBody = JSON.parse(createdText);
    assert.equal(createdBody.changed, 1);
    assert.equal(createdBody.exceptions.length, 1);
    assert.equal(createdBody.sync.kms.keyId, "render-test-key:v1");
    assert.equal(createdBody.sync.identity, "Aperçu local");

    const revoked = {
      ...exception,
      revokedAt: "2026-08-01T08:00:00.000Z",
    };
    const updated = await worker.dispatchFetch(
      "http://localhost/api/exception-sync",
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Origin: "http://localhost",
        },
        body: JSON.stringify({ exceptions: [revoked] }),
      },
    );
    const updatedText = await updated.text();
    assert.equal(updated.status, 200, updatedText);
    const updatedBody = JSON.parse(updatedText);
    assert.equal(updatedBody.exceptions[0].revokedAt, revoked.revokedAt);

    const ssoListed = await worker.dispatchFetch(
      "https://secure.example/api/exception-sync",
      {
        headers: {
          "oai-authenticated-user-email": "auditor@example.test",
          "oai-authenticated-user-full-name": "Auditrice%20MCP",
          "oai-authenticated-user-full-name-encoding":
            "percent-encoded-utf-8",
        },
      },
    );
    assert.equal(ssoListed.status, 200);
    const ssoBody = await ssoListed.json();
    assert.equal(ssoBody.sync.identity, "Auditrice MCP");
    assert.equal(ssoBody.exceptions[0].revokedAt, revoked.revokedAt);

    const database = await worker.getD1Database("DB");
    const stored = await database
      .prepare(
        "SELECT record_key, envelope, actor_hash FROM exception_sync_records LIMIT 1",
      )
      .first();
    assert.match(stored.record_key, /^record:[a-f0-9]{64}$/);
    assert.match(stored.actor_hash, /^[a-f0-9]{64}$/);
    assert.doesNotMatch(
      stored.envelope,
      /Remote MCP|SEC-42|exception-sync-1/u,
    );
  } finally {
    await worker.dispose();
  }
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
    auditHistory,
    auditHistoryRoute,
    exceptionSync,
    exceptionSyncRoute,
    keyManagement,
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
    readFile(new URL("../lib/audit-history.ts", import.meta.url), "utf8"),
    readFile(
      new URL("../app/api/audit-history/route.ts", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../lib/enterprise-sync.ts", import.meta.url), "utf8"),
    readFile(
      new URL("../app/api/exception-sync/route.ts", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../lib/key-management.ts", import.meta.url), "utf8"),
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
  assert.match(auditHistory, /export function createAuditHistoryPayload/);
  assert.match(auditHistory, /export function compareAuditHistory/);
  assert.match(auditHistoryRoute, /oai-authenticated-user-email/);
  assert.match(auditHistoryRoute, /sameOrigin/);
  assert.doesNotMatch(auditHistoryRoute, /serverName|configuration|snippet/);
  assert.match(exceptionSync, /encryptSyncedRiskException/);
  assert.match(exceptionSyncRoute, /oai-authenticated-user-email/);
  assert.match(exceptionSyncRoute, /sameOrigin/);
  assert.match(keyManagement, /createKeyManagementProvider/);
  assert.match(keyManagement, /AES-GCM/);
  assert.match(page, /\/api\/audit-history/);
  assert.match(page, /\/api\/exception-sync/);
  assert.doesNotMatch(page, /branchement à un historique persistant/);
  assert.match(page, /npm run collect:security/);
  assert.match(page, /Claude Desktop classique ou Microsoft/);
  assert.match(page, /<code>\.mcp\.json<\/code>/);
  assert.match(packageJson, /generate:admission/);
  assert.match(packageJson, /validate:admission/);
  assert.match(ciWorkflow, /Generate Kubernetes admission bundle/);
  assert.match(ciWorkflow, /npm run validate:admission/);
  assert.match(ciWorkflow, /npm audit --omit=dev --audit-level=high/);
  assert.match(ciWorkflow, /npm run audit:ci/);
  assert.match(
    layout,
    /MCP TrustMap — Cartographie, audit et gouvernance MCP/,
  );
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
