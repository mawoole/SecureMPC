import assert from "node:assert/strict";
import test from "node:test";

import {
  generateKubernetesAdmissionBundle,
  type AdmissionBundleFile,
} from "../lib/kubernetes-admission.ts";
import { validateKubernetesAdmissionBundle } from "../lib/kubernetes-admission-validation.ts";
import type { OciVerificationRule } from "../lib/oci-provenance.ts";

const POLICIES: OciVerificationRule[] = [
  {
    id: "github-acme",
    imagePrefix: "ghcr.io/acme",
    kind: "github",
    repository: "acme/mcp-images",
  },
  {
    id: "cosign-private",
    imagePrefix: "registry.example.com/mcp",
    kind: "cosign",
    certificateIssuer: "https://token.actions.githubusercontent.com",
    certificateIdentityURI:
      "^https://github\\.com/acme/mcp-images/.github/workflows/release\\.yml@refs/tags/.+$",
    predicateType: "slsaprovenance1",
  },
];

const OPTIONS = { namespaces: ["mcp-system", "production"] };

function files(): AdmissionBundleFile[] {
  return generateKubernetesAdmissionBundle(POLICIES, OPTIONS).files.map(
    (file) => ({ ...file }),
  );
}

test("validates a deterministic admission bundle and returns its digest", () => {
  const first = validateKubernetesAdmissionBundle(
    POLICIES,
    OPTIONS,
    files(),
  );
  const second = validateKubernetesAdmissionBundle(
    POLICIES,
    OPTIONS,
    files().reverse(),
  );

  assert.equal(first.valid, true);
  assert.equal(first.files, 4);
  assert.equal(first.yamlDocuments, 5);
  assert.equal(first.policies, 2);
  assert.equal(first.namespaces, 2);
  assert.match(first.sha256, /^[a-f0-9]{64}$/);
  assert.equal(first.sha256, second.sha256);
});

test("rejects a modified or stale generated file", () => {
  const modified = files().map((file) =>
    file.name === "README.md"
      ? { ...file, content: `${file.content}\nModification locale\n` }
      : file,
  );

  assert.throws(
    () =>
      validateKubernetesAdmissionBundle(POLICIES, OPTIONS, modified),
    /README\.md diverge/,
  );
});

test("rejects malformed YAML before comparing deterministic content", () => {
  const malformed = files().map((file) =>
    file.name === "namespaces.yaml"
      ? { ...file, content: "apiVersion: [\n" }
      : file,
  );

  assert.throws(
    () =>
      validateKubernetesAdmissionBundle(POLICIES, OPTIONS, malformed),
    /n’est pas un YAML valide/,
  );
});

test("rejects missing, unexpected, duplicate and unsafe files", () => {
  const generated = files();
  assert.throws(
    () =>
      validateKubernetesAdmissionBundle(
        POLICIES,
        OPTIONS,
        generated.filter((file) => file.name !== "README.md"),
      ),
    /README du bundle/,
  );
  assert.throws(
    () =>
      validateKubernetesAdmissionBundle(POLICIES, OPTIONS, [
        ...generated,
        { name: "unexpected.txt", content: "unexpected" },
      ]),
    /liste des fichiers diverge/,
  );
  assert.throws(
    () =>
      validateKubernetesAdmissionBundle(POLICIES, OPTIONS, [
        ...generated,
        { ...generated[0] },
      ]),
    /Fichier dupliqué/,
  );
  assert.throws(
    () =>
      validateKubernetesAdmissionBundle(POLICIES, OPTIONS, [
        ...generated,
        { name: "../escape.yaml", content: "kind: Namespace" },
      ]),
    /Nom de fichier non sûr/,
  );
});
