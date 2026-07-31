import assert from "node:assert/strict";
import test from "node:test";

import type { Finding, McpServer } from "../lib/audit-engine.ts";
import { createRiskException } from "../lib/finding-exceptions.ts";
import {
  createExceptionRecordKey,
  createExceptionSpaceId,
  decryptSyncedRiskException,
  encryptSyncedRiskException,
  parseExceptionEnvelope,
  serializeExceptionEnvelope,
} from "../lib/enterprise-sync.ts";
import {
  createKeyManagementProvider,
  createPlatformSecretKeyProvider,
} from "../lib/key-management.ts";

const masterKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

const finding: Finding = {
  id: "remote-transport",
  severity: "critical",
  title: "Transport non chiffré",
  description: "Le serveur utilise HTTP.",
  remediation: "Passez le serveur en HTTPS.",
  snippet: '"url": "https://mcp.example.test"',
  rule: "MCP-NET-01",
};

const server: McpServer = {
  id: "remote",
  name: "Remote MCP",
  owner: "Platform",
  transport: "HTTP",
  source: "Test",
  score: 72,
  status: "critical",
  controls: 10,
  findings: [finding],
  lastScan: "à l’instant",
};

const exception = createRiskException(
  {
    id: "exception-1",
    server,
    finding,
    reason: "Migration TLS planifiée et suivie dans SEC-42.",
    owner: "Équipe Platform",
    expiresAt: "2026-08-15T23:59:59.999Z",
  },
  new Date("2026-07-30T10:00:00.000Z"),
);

test("envelope-encrypts each synced exception with a wrapped data key", async () => {
  const provider = createPlatformSecretKeyProvider(masterKey, "test-key:v1");
  const spaceId = await createExceptionSpaceId("workspace-test");
  const recordKey = await createExceptionRecordKey(spaceId, exception.id);
  const envelope = await encryptSyncedRiskException(
    exception,
    provider,
    spaceId,
    recordKey,
  );
  const serialized = serializeExceptionEnvelope(envelope);

  assert.equal(envelope.provider, "platform-secret");
  assert.equal(envelope.keyId, "test-key:v1");
  assert.doesNotMatch(serialized, /SEC-42|Remote MCP|exception-1/u);
  assert.deepEqual(
    await decryptSyncedRiskException(
      parseExceptionEnvelope(serialized),
      provider,
      spaceId,
      recordKey,
    ),
    exception,
  );
});

test("binds wrapped and encrypted keys to their workspace record", async () => {
  const provider = createPlatformSecretKeyProvider(masterKey, "test-key:v1");
  const spaceId = await createExceptionSpaceId("workspace-test");
  const otherSpaceId = await createExceptionSpaceId("other-workspace");
  const recordKey = await createExceptionRecordKey(spaceId, exception.id);
  const envelope = await encryptSyncedRiskException(
    exception,
    provider,
    spaceId,
    recordKey,
  );

  await assert.rejects(
    decryptSyncedRiskException(
      envelope,
      provider,
      otherSpaceId,
      await createExceptionRecordKey(otherSpaceId, exception.id),
    ),
    /fournisseur de clés|déchiffrée/u,
  );
});

test("requires a complete KMS configuration and rejects clear-text endpoints", () => {
  assert.throws(
    () => createKeyManagementProvider({}),
    /clé d’enveloppe/u,
  );
  assert.throws(
    () =>
      createKeyManagementProvider({
        TRUSTMAP_KMS_ENDPOINT: "http://kms.example.test",
        TRUSTMAP_KMS_KEY_ID: "enterprise-key",
        TRUSTMAP_KMS_BEARER_TOKEN: "a".repeat(32),
      }),
    /HTTPS/u,
  );
  assert.equal(
    createKeyManagementProvider({
      TRUSTMAP_KMS_MASTER_KEY: masterKey,
      TRUSTMAP_KMS_KEY_ID: "sites-key:v1",
    }).status().label,
    "Clé d’enveloppe gérée par l’hébergeur",
  );
});

test("can unwrap records during a bounded platform-key rotation", async () => {
  const oldProvider = createPlatformSecretKeyProvider(masterKey, "sites-key:v1");
  const rotatedRuntime = {
    TRUSTMAP_KMS_MASTER_KEY:
      "Hh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0",
    TRUSTMAP_KMS_KEY_ID: "sites-key:v2",
    TRUSTMAP_KMS_PREVIOUS_KEYS: JSON.stringify({
      "sites-key:v1": masterKey,
    }),
  };
  const historicalProvider = createKeyManagementProvider(
    rotatedRuntime,
    "platform-secret",
    "sites-key:v1",
  );
  const spaceId = await createExceptionSpaceId("workspace-test");
  const recordKey = await createExceptionRecordKey(spaceId, exception.id);
  const envelope = await encryptSyncedRiskException(
    exception,
    oldProvider,
    spaceId,
    recordKey,
  );

  assert.deepEqual(
    await decryptSyncedRiskException(
      envelope,
      historicalProvider,
      spaceId,
      recordKey,
    ),
    exception,
  );
});
