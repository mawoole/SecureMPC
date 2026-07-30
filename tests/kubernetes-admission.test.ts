import assert from "node:assert/strict";
import test from "node:test";
import { parse, parseAllDocuments } from "yaml";
import {
  generateKubernetesAdmissionBundle,
  GITHUB_TRUST_CHART_VERSION,
  POLICY_CONTROLLER_CHART_VERSION,
} from "../lib/kubernetes-admission.ts";
import type { OciVerificationRule } from "../lib/oci-provenance.ts";

type ParsedAdmissionManifest = {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    labels?: Record<string, string>;
  };
  spec: {
    images: Array<{ glob: string }>;
    authorities: Array<{
      keyless: {
        identities: Array<{ issuer: string }>;
      };
      attestations?: Array<{ predicateType: string }>;
    }>;
  };
};

type ParsedGithubValues = {
  policy: {
    organization: string;
    repository: string;
    images: string[];
    trust: {
      github: boolean;
      sigstorePublic: boolean;
    };
  };
};

const GITHUB_POLICY: Extract<
  OciVerificationRule,
  { kind: "github" }
> = {
  id: "github-acme",
  imagePrefix: "ghcr.io/acme",
  kind: "github",
  repository: "acme/mcp-images",
};

const COSIGN_POLICY: Extract<
  OciVerificationRule,
  { kind: "cosign" }
> = {
  id: "cosign-private",
  imagePrefix: "registry.example.com/mcp",
  kind: "cosign",
  certificateIssuer: "https://token.actions.githubusercontent.com",
  certificateIdentityURI:
    "^https://github\\.com/acme/mcp-images/.github/workflows/release\\.yml@refs/tags/.+$",
  predicateType: "slsaprovenance1",
};

const POLICIES: OciVerificationRule[] = [GITHUB_POLICY, COSIGN_POLICY];

test("generates deterministic Cosign, GitHub and namespace admission files", () => {
  const first = generateKubernetesAdmissionBundle(POLICIES, {
    namespaces: ["production", "mcp-system", "production"],
  });
  const second = generateKubernetesAdmissionBundle(POLICIES, {
    namespaces: ["production", "mcp-system", "production"],
  });

  assert.deepEqual(first, second);
  assert.deepEqual(first.summary, {
    policies: 2,
    cosignPolicies: 1,
    githubPolicies: 1,
    clusterImagePolicies: 3,
    namespaces: 2,
  });

  const cosign = first.files.find(
    (file) => file.purpose === "cosign-policies",
  );
  assert.ok(cosign);
  const manifests = parseAllDocuments(cosign.content).map((document) =>
    document.toJSON(),
  ) as ParsedAdmissionManifest[];
  assert.equal(manifests.length, 2);
  assert.equal(
    manifests.every(
      (manifest) =>
        manifest.apiVersion === "policy.sigstore.dev/v1beta1" &&
        manifest.kind === "ClusterImagePolicy" &&
        manifest.metadata.name.length <= 63,
    ),
    true,
  );
  assert.deepEqual(manifests[0].spec.images, [
    { glob: "registry.example.com/mcp@**" },
    { glob: "registry.example.com/mcp/**" },
  ]);
  assert.equal(
    manifests[0].spec.authorities[0].keyless.identities[0].issuer,
    "https://token.actions.githubusercontent.com",
  );
  assert.equal(
    manifests.some(
      (manifest) =>
        manifest.spec.authorities[0].attestations?.[0].predicateType ===
        "https://slsa.dev/provenance/v1",
    ),
    true,
  );

  const github = first.files.find(
    (file) => file.purpose === "github-values",
  );
  assert.ok(github);
  const values = parse(github.content) as ParsedGithubValues;
  assert.equal(values.policy.organization, "acme");
  assert.equal(values.policy.repository, "mcp-images");
  assert.deepEqual(values.policy.images, [
    "ghcr.io/acme@**",
    "ghcr.io/acme/**",
  ]);
  assert.equal(values.policy.trust.github, true);
  assert.equal(values.policy.trust.sigstorePublic, true);

  const namespaces = first.files.find(
    (file) => file.purpose === "namespaces",
  );
  assert.ok(namespaces);
  const namespaceManifests = parseAllDocuments(namespaces.content).map(
    (document) => document.toJSON(),
  ) as ParsedAdmissionManifest[];
  assert.deepEqual(
    namespaceManifests.map((manifest) => manifest.metadata.name),
    ["mcp-system", "production"],
  );
  assert.equal(
    namespaceManifests.every(
      (manifest) =>
        manifest.metadata.labels?.["policy.sigstore.dev/include"] === "true",
    ),
    true,
  );

  const readme = first.files.find(
    (file) => file.purpose === "instructions",
  );
  assert.ok(readme);
  assert.match(readme.content, /--dry-run=server/);
  assert.match(readme.content, new RegExp(POLICY_CONTROLLER_CHART_VERSION));
  assert.match(readme.content, new RegExp(GITHUB_TRUST_CHART_VERSION));
  assert.match(readme.content, /no-match-policy/);
});

test("rejects overlapping prefixes because matching Kubernetes policies are ANDed", () => {
  assert.throws(
    () =>
      generateKubernetesAdmissionBundle(
        [
          POLICIES[0],
          {
            id: "github-critical",
            imagePrefix: "ghcr.io/acme/critical",
            kind: "github",
            repository: "acme/critical",
          },
        ],
        { namespaces: ["production"] },
      ),
    /se chevauchent/,
  );
});

test("requires explicit valid namespaces before generating enforcement", () => {
  assert.throws(
    () =>
      generateKubernetesAdmissionBundle(POLICIES, {
        namespaces: [],
      }),
    /Au moins un namespace/,
  );
  assert.throws(
    () =>
      generateKubernetesAdmissionBundle(POLICIES, {
        namespaces: ["Production"],
      }),
    /Namespace Kubernetes invalide/,
  );
});

test("rejects identity expressions that Kubernetes RE2 cannot evaluate", () => {
  assert.throws(
    () =>
      generateKubernetesAdmissionBundle(
        [
          {
            ...COSIGN_POLICY,
            certificateIdentityURI: "^(?=https://github\\.com/)example$",
          },
        ],
        { namespaces: ["production"] },
      ),
    /incompatible avec RE2\/Go/,
  );
});
