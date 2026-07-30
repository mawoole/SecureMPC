import assert from "node:assert/strict";
import test from "node:test";

import type { Finding, McpServer } from "../lib/audit-engine.ts";
import {
  createRiskException,
  revokeRiskException,
} from "../lib/finding-exceptions.ts";
import {
  createEncryptedRiskExceptionBundle,
  createPolicySigningIdentity,
  decryptRiskExceptionBundle,
  mergeRiskExceptions,
  signCiPolicyProfiles,
  verifySignedCiPolicy,
} from "../lib/trustmap-governance.ts";
import { DEFAULT_TRUSTMAP_CI_PROFILES } from "../lib/trustmap-modules.ts";

const passphrase = "une phrase secrete de test robuste";
const now = new Date("2026-07-30T10:00:00.000Z");

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

function riskException() {
  return createRiskException(
    {
      id: "exception-1",
      server,
      finding,
      reason: "Migration TLS planifiée et suivie dans SEC-42.",
      owner: "Équipe Platform",
      expiresAt: "2026-08-15T23:59:59.999Z",
    },
    now,
  );
}

test("signs CI profiles with a protected identity and verifies its fingerprint", async () => {
  const identity = await createPolicySigningIdentity(
    "Équipe sécurité",
    passphrase,
    now,
  );
  const signed = await signCiPolicyProfiles(
    DEFAULT_TRUSTMAP_CI_PROFILES,
    JSON.stringify(identity),
    passphrase,
    now,
  );
  const verified = await verifySignedCiPolicy(
    JSON.stringify(signed),
    identity.keyId,
  );

  assert.equal(verified.trusted, true);
  assert.equal(verified.keyId, identity.keyId);
  assert.equal(verified.profiles.length, 3);
  assert.equal(
    (
      await verifySignedCiPolicy(
        JSON.stringify(signed),
        `sha256:${"0".repeat(64)}`,
      )
    ).trusted,
    false,
  );
  await assert.rejects(
    signCiPolicyProfiles(
      DEFAULT_TRUSTMAP_CI_PROFILES,
      JSON.stringify(identity),
      "une autre phrase secrete robuste",
      now,
    ),
    /phrase secrète incorrecte|fichier altéré/u,
  );
});

test("rejects a signed CI policy altered after signature", async () => {
  const identity = await createPolicySigningIdentity(
    "Équipe sécurité",
    passphrase,
    now,
  );
  const signed = await signCiPolicyProfiles(
    DEFAULT_TRUSTMAP_CI_PROFILES,
    JSON.stringify(identity),
    passphrase,
    now,
  );
  signed.profiles[0].failOn = "medium";

  await assert.rejects(
    verifySignedCiPolicy(JSON.stringify(signed), identity.keyId),
    /signature/u,
  );
});

test("encrypts and decrypts an exception bundle without plaintext findings", async () => {
  const exception = riskException();
  const bundle = await createEncryptedRiskExceptionBundle(
    [exception],
    passphrase,
    now,
  );
  const serialized = JSON.stringify(bundle);

  assert.doesNotMatch(serialized, /SEC-42|Remote MCP/u);
  assert.deepEqual(
    await decryptRiskExceptionBundle(serialized, passphrase),
    [exception],
  );
  await assert.rejects(
    decryptRiskExceptionBundle(
      serialized,
      "une autre phrase secrete robuste",
    ),
    /phrase secrète incorrecte|fichier altéré/u,
  );
});

test("propagates revocation when encrypted exception registers are merged", () => {
  const active = riskException();
  const revoked = revokeRiskException(
    active,
    new Date("2026-08-01T08:00:00.000Z"),
  );

  assert.deepEqual(mergeRiskExceptions([active], [revoked]), [revoked]);
  assert.deepEqual(mergeRiskExceptions([revoked], [active]), [revoked]);
});
