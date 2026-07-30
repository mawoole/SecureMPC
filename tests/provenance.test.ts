import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign as signCryptographicPayload,
} from "node:crypto";
import test from "node:test";
import {
  verifyComponentProvenance,
  verifyNpmRegistrySignature,
} from "../lib/provenance.ts";
import type { SupplyChainComponent } from "../lib/supply-chain.ts";

function fixtureComponent(): SupplyChainComponent {
  return {
    id: "npm:fixture@1.0.0",
    ecosystem: "npm",
    name: "fixture",
    version: "1.0.0",
    reference: "fixture@1.0.0",
    purl: "pkg:npm/fixture@1.0.0",
    componentType: "library",
    pinStatus: "pinned",
    evidence: "Test",
    scope: "direct",
    integrity: "sha512-Zml4dHVyZQ==",
    integrityStatus: "recorded",
  };
}

test("verifies an npm registry ECDSA signature over name, version and integrity", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const component = fixtureComponent();
  const payload = `${component.name}@${component.version}:${component.integrity}`;
  const signature = signCryptographicPayload(
    "sha256",
    Buffer.from(payload),
    privateKey,
  ).toString("base64");

  assert.equal(
    verifyNpmRegistrySignature(
      component.name,
      component.version ?? "",
      component.integrity ?? "",
      [{ keyid: "fixture-key", sig: signature }],
      [
        {
          keyid: "fixture-key",
          key: publicKey
            .export({ type: "spki", format: "der" })
            .toString("base64"),
        },
      ],
    ),
    true,
  );
});

test("verifies a SLSA subject only when the Sigstore bundle and lockfile digest match", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const component = fixtureComponent();
  const payload = `${component.name}@${component.version}:${component.integrity}`;
  const signature = signCryptographicPayload(
    "sha256",
    Buffer.from(payload),
    privateKey,
  ).toString("base64");
  const digest = Buffer.from("Zml4dHVyZQ==", "base64").toString("hex");
  const bundle = {
    dsseEnvelope: {
      payload: Buffer.from(
        JSON.stringify({
          _type: "https://in-toto.io/Statement/v1",
          subject: [
            {
              name: "pkg:npm/fixture@1.0.0",
              digest: { sha512: digest },
            },
          ],
          predicateType: "https://slsa.dev/provenance/v1",
          predicate: {
            buildDefinition: {
              externalParameters: {
                workflow: {
                  repository: "https://github.com/acme/fixture",
                },
              },
            },
            runDetails: {
              builder: {
                id: "https://github.com/actions/runner/github-hosted",
              },
            },
          },
        }),
      ).toString("base64"),
    },
  };
  const fetchImpl: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/-/npm/v1/keys")) {
      return new Response(
        JSON.stringify({
          keys: [
            {
              keyid: "fixture-key",
              key: publicKey.export({ type: "spki", format: "pem" }).toString(),
            },
          ],
        }),
        { status: 200 },
      );
    }
    if (url.endsWith("/fixture/1.0.0")) {
      return new Response(
        JSON.stringify({
          dist: {
            integrity: component.integrity,
            signatures: [{ keyid: "fixture-key", sig: signature }],
            attestations: {
              url: "https://registry.npmjs.org/-/npm/v1/attestations/fixture@1.0.0",
              provenance: { predicateType: "https://slsa.dev/provenance/v1" },
            },
          },
        }),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        attestations: [
          {
            predicateType: "https://slsa.dev/provenance/v1",
            bundle,
          },
        ],
      }),
      { status: 200 },
    );
  };

  const verification = await verifyComponentProvenance([component], {
    fetchImpl,
    now: () => new Date("2026-07-30T12:00:00.000Z"),
    policy: {
      certificateIssuer: "https://token.actions.githubusercontent.com",
      certificateIdentityURI: "^https://github\\.com/acme/fixture/",
    },
    verifyBundleImpl: async () => undefined,
  });

  assert.equal(
    verification.components[0].provenance?.registrySignature,
    "verified",
    JSON.stringify(verification.components[0].provenance),
  );
  assert.equal(
    verification.components[0].provenance?.slsaProvenance,
    "verified",
  );
  assert.equal(
    verification.components[0].provenance?.identityPolicy,
    "matched",
  );
  assert.equal(verification.summary.status, "complete");
});
