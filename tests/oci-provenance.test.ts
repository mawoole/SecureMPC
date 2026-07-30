import assert from "node:assert/strict";
import test from "node:test";
import {
  parseOciVerificationPolicyDocument,
  verifyOciProvenance,
  type VerificationCommandRunner,
} from "../lib/oci-provenance.ts";
import type { SupplyChainComponent } from "../lib/supply-chain.ts";

const DIGEST =
  "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

function imageComponent(
  version: string = DIGEST,
  name = "ghcr.io/acme/mcp",
): SupplyChainComponent {
  return {
    id: `oci:${name}@${version}`,
    ecosystem: "oci",
    name,
    version,
    reference: `${name}@${version}`,
    purl: `pkg:docker/${name}@${encodeURIComponent(version)}`,
    componentType: "container",
    pinStatus: version.startsWith("sha256:") ? "pinned" : "mutable",
    evidence: "Test OCI",
    scope: "direct",
  };
}

function slsaStatement() {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: "ghcr.io/acme/mcp",
        digest: { sha256: DIGEST.replace("sha256:", "") },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: { repository: "https://github.com/acme/mcp" },
        },
      },
      runDetails: {
        builder: {
          id: "https://github.com/actions/runner/github-hosted",
        },
      },
    },
  };
}

test("verifies a digest-pinned OCI signature and SLSA attestation with Cosign", async () => {
  const calls: Array<{ executable: string; args: string[] }> = [];
  const runner: VerificationCommandRunner = async (executable, args) => {
    calls.push({ executable, args });
    if (args[0] === "verify") {
      return {
        code: 0,
        stdout: JSON.stringify([
          {
            critical: {
              image: { "docker-manifest-digest": DIGEST },
            },
          },
        ]),
        stderr: "",
      };
    }
    return {
      code: 0,
      stdout: JSON.stringify([
        {
          payload: Buffer.from(JSON.stringify(slsaStatement())).toString(
            "base64",
          ),
        },
      ]),
      stderr: "",
    };
  };

  const verification = await verifyOciProvenance([imageComponent()], {
    policy: {
      kind: "cosign",
      certificateIssuer: "https://token.actions.githubusercontent.com",
      certificateIdentityURI:
        "^https://github\\.com/acme/mcp/.github/workflows/release\\.yml@refs/tags/.+$",
    },
    commandRunner: runner,
    now: () => new Date("2026-07-30T12:00:00.000Z"),
  });

  assert.equal(verification.summary.status, "complete");
  assert.equal(verification.summary.signaturesVerified, 1);
  assert.equal(verification.summary.slsaProvenanceVerified, 1);
  assert.equal(
    verification.components[0].provenance?.provider,
    "oci-cosign",
  );
  assert.equal(
    verification.components[0].provenance?.subjectDigest,
    "matched",
  );
  assert.equal(calls.length, 2);
  assert.equal(calls.every((call) => call.executable === "cosign"), true);
  assert.equal(
    calls.every(
      (call) =>
        call.args.includes(imageComponent().reference) &&
        call.args.includes("--certificate-identity-regexp") &&
        !call.args.includes("--insecure-ignore-tlog") &&
        !call.args.includes("--check-claims=false"),
    ),
    true,
  );
});

test("verifies a GitHub OCI attestation against the expected repository", async () => {
  const calls: string[][] = [];
  const runner: VerificationCommandRunner = async (_executable, args) => {
    calls.push(args);
    return {
      code: 0,
      stdout: JSON.stringify([
        {
          verificationResult: {
            statement: slsaStatement(),
          },
        },
      ]),
      stderr: "",
    };
  };
  const verification = await verifyOciProvenance([imageComponent()], {
    policy: { kind: "github", repository: "acme/mcp" },
    commandRunner: runner,
  });

  assert.equal(
    verification.components[0].provenance?.provider,
    "oci-github-attestation",
  );
  assert.equal(
    verification.components[0].provenance?.registrySignature,
    "not-applicable",
  );
  assert.equal(
    verification.components[0].provenance?.slsaProvenance,
    "verified",
  );
  assert.deepEqual(calls[0], [
    "attestation",
    "verify",
    `oci://${imageComponent().reference}`,
    "--repo",
    "acme/mcp",
    "--format",
    "json",
  ]);
});

test("fails closed on a mismatched SLSA subject and skips mutable tags", async () => {
  let calls = 0;
  const runner: VerificationCommandRunner = async (_executable, args) => {
    calls += 1;
    if (args[0] === "verify") {
      return {
        code: 0,
        stdout: JSON.stringify([
          {
            critical: {
              image: { "docker-manifest-digest": DIGEST },
            },
          },
        ]),
        stderr: "",
      };
    }
    const mismatched = slsaStatement();
    mismatched.subject[0].digest.sha256 = "f".repeat(64);
    return {
      code: 0,
      stdout: JSON.stringify([
        {
          payload: Buffer.from(JSON.stringify(mismatched)).toString("base64"),
        },
      ]),
      stderr: "",
    };
  };
  const verification = await verifyOciProvenance(
    [imageComponent(), imageComponent("latest")],
    {
      policy: {
        kind: "cosign",
        certificateIssuer: "https://token.actions.githubusercontent.com",
        certificateIdentityURI: "^https://github\\.com/acme/mcp/",
      },
      commandRunner: runner,
    },
  );

  assert.equal(calls, 2);
  assert.equal(verification.summary.failed, 1);
  assert.equal(
    verification.components[0].provenance?.slsaProvenance,
    "failed",
  );
  assert.equal(verification.components[1].provenance, undefined);
});

test("selects the most specific OCI policy and denies unmatched images", async () => {
  const calls: Array<{ executable: string; args: string[] }> = [];
  const runner: VerificationCommandRunner = async (executable, args) => {
    calls.push({ executable, args });
    if (args[0] === "verify") {
      return {
        code: 0,
        stdout: JSON.stringify([
          {
            critical: {
              image: { "docker-manifest-digest": DIGEST },
            },
          },
        ]),
        stderr: "",
      };
    }
    const statement = slsaStatement();
    return {
      code: 0,
      stdout:
        executable === "cosign"
          ? JSON.stringify([
              {
                payload: Buffer.from(JSON.stringify(statement)).toString(
                  "base64",
                ),
              },
            ])
          : JSON.stringify([
              {
                verificationResult: { statement },
              },
            ]),
      stderr: "",
    };
  };
  const components = [
    imageComponent(DIGEST, "ghcr.io/acme/mcp"),
    imageComponent(DIGEST, "ghcr.io/acme/special/mcp"),
    imageComponent(DIGEST, "registry.example.com/team/server"),
    imageComponent(DIGEST, "quay.io/unknown/server"),
  ];
  const verification = await verifyOciProvenance(components, {
    policies: [
      {
        id: "github-base",
        imagePrefix: "ghcr.io/acme",
        kind: "github",
        repository: "acme/mcp",
      },
      {
        id: "cosign-special",
        imagePrefix: "ghcr.io/acme/special",
        kind: "cosign",
        certificateIssuer: "https://token.actions.githubusercontent.com",
        certificateIdentityURI: "^https://github\\.com/acme/special/",
      },
      {
        id: "registry-team",
        imagePrefix: "registry.example.com/team",
        kind: "github",
        repository: "acme/registry-builds",
      },
    ],
    commandRunner: runner,
  });

  assert.equal(verification.summary.backend, "mixed");
  assert.equal(verification.summary.status, "partial");
  assert.equal(verification.summary.policies, 3);
  assert.equal(verification.summary.matched, 3);
  assert.equal(verification.summary.unmatched, 1);
  assert.equal(verification.summary.failed, 1);
  assert.deepEqual(
    verification.components.map(
      (component) => component.provenance?.policyId,
    ),
    ["github-base", "cosign-special", "registry-team", undefined],
  );
  assert.equal(
    verification.components[3].provenance?.provider,
    "oci-policy",
  );
  assert.equal(
    verification.components[3].provenance?.slsaProvenance,
    "failed",
  );
  assert.equal(calls.length, 4);
  assert.equal(
    calls.filter((call) => call.executable === "gh").length,
    2,
  );
  assert.equal(
    calls.filter((call) => call.executable === "cosign").length,
    2,
  );
});

test("parses a strict policy document and rejects duplicate prefixes", () => {
  const document = parseOciVerificationPolicyDocument({
    version: 1,
    policies: [
      {
        id: "github-acme",
        imagePrefix: "GHCR.IO/ACME/",
        kind: "github",
        repository: "acme/mcp",
      },
      {
        id: "cosign-private",
        imagePrefix: "registry.example.com/mcp",
        kind: "cosign",
        certificateIssuer: "https://token.actions.githubusercontent.com",
        certificateIdentityURI: "^https://github\\.com/acme/private/",
      },
    ],
  });
  assert.equal(document.policies.length, 2);

  assert.throws(
    () =>
      parseOciVerificationPolicyDocument({
        version: 1,
        policies: [
          {
            id: "first",
            imagePrefix: "ghcr.io/acme",
            kind: "github",
            repository: "acme/one",
          },
          {
            id: "second",
            imagePrefix: "GHCR.IO/ACME/",
            kind: "github",
            repository: "acme/two",
          },
        ],
      }),
    /Préfixe de politique OCI dupliqué/,
  );
});

test("classifies an unavailable Sigstore trust root as a verifier error", async () => {
  const verification = await verifyOciProvenance([imageComponent()], {
    policies: [
      {
        id: "github-acme",
        imagePrefix: "ghcr.io/acme",
        kind: "github",
        repository: "acme/mcp",
      },
    ],
    commandRunner: async () => ({
      code: 1,
      stdout: "",
      stderr:
        "error creating Sigstore verifier: no valid Sigstore verifiers could be initialized",
    }),
  });

  assert.equal(verification.summary.status, "error");
  assert.equal(
    verification.components[0].provenance?.slsaProvenance,
    "error",
  );
});
