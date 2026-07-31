import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { Log, LogLevel, Miniflare } from "miniflare";
import test from "node:test";

const developmentPreviewMeta =
  /<meta(?=[^>]*\bname=["']codex-preview["'])(?=[^>]*\bcontent=["']development["'])[^>]*>/i;

function collectJavaScriptModules(directory, prefix = "") {
  const modules = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      modules.push(
        ...collectJavaScriptModules(join(directory, entry.name), relativePath),
      );
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      modules.push({
        type: "ESModule",
        path: join(directory, entry.name),
        relativePath,
      });
    }
  }
  return modules;
}

function createWorker() {
  const serverDirectory = fileURLToPath(
    new URL("../dist/server/", import.meta.url),
  );
  const modules = collectJavaScriptModules(serverDirectory);
  modules.sort((left, right) => {
    if (left.relativePath === "index.js") return -1;
    if (right.relativePath === "index.js") return 1;
    return left.relativePath.localeCompare(right.relativePath);
  });
  const moduleDefinitions = modules.map(({ path, type }) => ({ path, type }));
  return new Miniflare({
    modules: moduleDefinitions,
    modulesRoot: serverDirectory,
    log: new Log(LogLevel.NONE),
    compatibilityDate: "2026-07-29",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: { DB: `render-test-${process.pid}-${Date.now()}` },
    bindings: {
      BETTER_AUTH_URL: "http://localhost",
      BETTER_AUTH_SECRET:
        "render-test-auth-secret-with-at-least-thirty-two-characters",
      TRUSTMAP_ENVIRONMENT: "development",
      TRUSTMAP_DEV_EMAIL_LOG: "true",
      TRUSTMAP_KMS_KEY_ID: "render-test-key:v1",
      TRUSTMAP_KMS_MASTER_KEY:
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    },
  });
}

async function applyMigrations(worker) {
  const database = await worker.getD1Database("DB");
  for (const filename of [
    "0000_tranquil_forge.sql",
    "0001_slim_speed_demon.sql",
    "0002_curious_vermin.sql",
  ]) {
    const migration = await readFile(
      new URL(`../drizzle/${filename}`, import.meta.url),
      "utf8",
    );
    for (const statement of migration.split("--> statement-breakpoint")) {
      const sql = statement.trim();
      if (sql) await database.prepare(sql).run();
    }
  }
  return database;
}

async function render(path = "/login") {
  const worker = createWorker();
  try {
    const response = await worker.dispatchFetch(`http://localhost${path}`, {
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

test("server-renders the autonomous MCP TrustMap login", async () => {
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
  assert.match(html, /Se connecter/);
  assert.match(html, /Adresse e-mail/);
  assert.match(html, /Mot de passe oublié/);
  assert.match(html, /Créer un compte/);
  assert.doesNotMatch(html, developmentPreviewMeta);
  assert.doesNotMatch(html, /react-loading-skeleton/i);
  assert.doesNotMatch(html, /Your site is taking shape/i);
});

test("protects organization data APIs without an application session", async () => {
  const worker = createWorker();
  try {
    for (const path of ["/api/audit-history", "/api/exception-sync"]) {
      const response = await worker.dispatchFetch(`http://localhost${path}`, {
        headers: { Origin: "http://localhost" },
      });
      assert.equal(response.status, 401, `${path}: ${await response.text()}`);
      assert.equal(response.headers.get("cache-control"), "no-store");
    }

    const crossOrigin = await worker.dispatchFetch(
      "http://localhost/api/exception-sync",
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Origin: "https://attacker.example",
        },
        body: JSON.stringify({ exceptions: [] }),
      },
    );
    assert.equal(crossOrigin.status, 403);
  } finally {
    await worker.dispose();
  }
});

test("creates a native account and requires e-mail verification", async () => {
  const worker = createWorker();
  try {
    const database = await applyMigrations(worker);
    const originalConsoleInfo = console.info;
    let response;
    try {
      console.info = () => {};
      response = await worker.dispatchFetch(
        "http://localhost/api/auth/sign-up/email",
        {
          method: "POST",
          headers: {
            "CF-Connecting-IP": "127.0.0.1",
            "Content-Type": "application/json",
            Origin: "http://localhost",
          },
          body: JSON.stringify({
            email: "admin@example.test",
            name: "Admin Test",
            password: "Correct-Horse-Battery-Staple-2026",
          }),
        },
      );
    } finally {
      console.info = originalConsoleInfo;
    }
    assert.equal(response.status, 200, await response.text());

    const user = await database
      .prepare(
        "SELECT email, email_verified AS emailVerified FROM user WHERE email = ?",
      )
      .bind("admin@example.test")
      .first();
    assert.equal(user.email, "admin@example.test");
    assert.equal(user.emailVerified, 0);

    const credential = await database
      .prepare(
        "SELECT password FROM account WHERE provider_id = 'credential' LIMIT 1",
      )
      .first();
    assert.equal(typeof credential.password, "string");
    assert.doesNotMatch(
      credential.password,
      /Correct-Horse-Battery-Staple-2026/,
    );
    assert.equal(response.headers.get("set-cookie"), null);
  } finally {
    await worker.dispose();
  }
});

test("keeps the audit engine separate from the interface", async () => {
  const [
    page,
    dashboard,
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
    enterpriseAuthorization,
    keyManagement,
    authServer,
    authPermissions,
    schema,
    packageJson,
    ciWorkflow,
  ] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/dashboard.tsx", import.meta.url), "utf8"),
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
    readFile(
      new URL("../lib/enterprise-authorization.ts", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../lib/key-management.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/auth/server.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/auth/permissions.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8"),
  ]);

  assert.match(dashboard, /from "\.\.\/lib\/audit-engine"/);
  assert.match(dashboard, /createGovernedAuditReport/);
  assert.match(dashboard, /createGovernedSarifReport/);
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
  assert.match(dashboard, /POLITIQUE ABSENTE/);
  assert.match(osv, /export async function scanComponentsWithOsv/);
  assert.match(provenance, /export async function verifyComponentProvenance/);
  assert.match(pdfReport, /export function createAuditPdfReport/);
  assert.match(workspaces, /export async function discoverWorkspacePackages/);
  assert.match(auditHistory, /export function createAuditHistoryPayload/);
  assert.match(auditHistory, /export function compareAuditHistory/);
  assert.match(auditHistoryRoute, /getAuthContext/);
  assert.match(auditHistoryRoute, /organizationId/);
  assert.match(auditHistoryRoute, /sameOrigin/);
  assert.doesNotMatch(auditHistoryRoute, /oai-authenticated-user-email/);
  assert.doesNotMatch(auditHistoryRoute, /serverName|configuration|snippet/);
  assert.match(exceptionSync, /encryptSyncedRiskException/);
  assert.match(exceptionSyncRoute, /getAuthContext/);
  assert.match(exceptionSyncRoute, /organizationId/);
  assert.match(exceptionSyncRoute, /sameOrigin/);
  assert.doesNotMatch(exceptionSyncRoute, /oai-authenticated-user-email/);
  assert.match(exceptionSyncRoute, /export async function PATCH/);
  assert.match(enterpriseAuthorization, /applyRiskExceptionDecision/);
  assert.match(keyManagement, /createKeyManagementProvider/);
  assert.match(keyManagement, /AES-GCM/);
  assert.match(page, /getAuthContext/);
  assert.match(page, /redirect\("\/login"\)/);
  assert.match(authServer, /requireEmailVerification: true/);
  assert.match(authServer, /twoFactor\(/);
  assert.match(authServer, /organization\(/);
  assert.match(authPermissions, /adminRole/);
  assert.match(authPermissions, /auditorRole/);
  assert.match(authPermissions, /readerRole/);
  assert.match(schema, /export const organization/);
  assert.match(schema, /export const member/);
  assert.match(schema, /export const invitation/);
  assert.match(dashboard, /\/api\/audit-history/);
  assert.match(dashboard, /\/api\/exception-sync/);
  assert.doesNotMatch(dashboard, /branchement à un historique persistant/);
  assert.match(dashboard, /npm run collect:security/);
  assert.match(dashboard, /Claude Desktop classique ou Microsoft/);
  assert.match(dashboard, /<code>\.mcp\.json<\/code>/);
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
