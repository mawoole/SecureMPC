import { createHash } from "node:crypto";
import { parseAllDocuments } from "yaml";
import {
  generateKubernetesAdmissionBundle,
  type KubernetesAdmissionOptions,
} from "./kubernetes-admission.ts";
import type { OciVerificationRule } from "./oci-provenance.ts";

export type AdmissionBundleValidationFile = {
  name: string;
  content: string;
};

export type AdmissionBundleValidationSummary = {
  valid: true;
  files: number;
  bytes: number;
  yamlDocuments: number;
  sha256: string;
  policies: number;
  namespaces: number;
};

const MAX_BUNDLE_FILES = 100;
const MAX_BUNDLE_BYTES = 2_000_000;
const SAFE_FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;

function objectValue(
  value: unknown,
  context: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${context} doit être un objet YAML.`);
  }
  return value as Record<string, unknown>;
}

function nestedObject(
  record: Record<string, unknown>,
  key: string,
  context: string,
): Record<string, unknown> {
  return objectValue(record[key], `${context}.${key}`);
}

function validateNamespaceDocument(
  value: unknown,
  fileName: string,
  index: number,
): void {
  const context = `${fileName} document ${index + 1}`;
  const manifest = objectValue(value, context);
  const metadata = nestedObject(manifest, "metadata", context);
  const labels = nestedObject(metadata, "labels", `${context}.metadata`);
  if (
    manifest.apiVersion !== "v1" ||
    manifest.kind !== "Namespace" ||
    typeof metadata.name !== "string" ||
    labels["policy.sigstore.dev/include"] !== "true"
  ) {
    throw new Error(
      `${context} doit être un Namespace v1 explicitement inclus dans Policy Controller.`,
    );
  }
}

function validateClusterImagePolicyDocument(
  value: unknown,
  fileName: string,
  index: number,
): void {
  const context = `${fileName} document ${index + 1}`;
  const manifest = objectValue(value, context);
  const metadata = nestedObject(manifest, "metadata", context);
  const annotations = nestedObject(metadata, "annotations", `${context}.metadata`);
  const spec = nestedObject(manifest, "spec", context);
  if (
    manifest.apiVersion !== "policy.sigstore.dev/v1beta1" ||
    manifest.kind !== "ClusterImagePolicy" ||
    typeof metadata.name !== "string" ||
    typeof annotations["mcp-sentinel.dev/policy-id"] !== "string" ||
    !["signature", "slsa"].includes(
      String(annotations["mcp-sentinel.dev/required-proof"]),
    ) ||
    !Array.isArray(spec.images) ||
    !spec.images.length ||
    !Array.isArray(spec.authorities) ||
    !spec.authorities.length
  ) {
    throw new Error(
      `${context} n’est pas une ClusterImagePolicy MCP Sentinel complète.`,
    );
  }
}

function validateGithubValuesDocument(
  value: unknown,
  fileName: string,
): void {
  const root = objectValue(value, fileName);
  const policy = nestedObject(root, "policy", fileName);
  const trust = nestedObject(policy, "trust", `${fileName}.policy`);
  if (
    policy.enabled !== true ||
    typeof policy.organization !== "string" ||
    typeof policy.repository !== "string" ||
    !Array.isArray(policy.images) ||
    !policy.images.length ||
    trust.github !== true ||
    trust.sigstorePublic !== true
  ) {
    throw new Error(
      `${fileName} ne contient pas une politique GitHub complète et activée.`,
    );
  }
}

function validateYamlFile(file: AdmissionBundleValidationFile): number {
  const documents = parseAllDocuments(file.content, { uniqueKeys: true });
  const parserErrors = documents.flatMap((document) => document.errors);
  if (parserErrors.length) {
    throw new Error(
      `${file.name} n’est pas un YAML valide : ${parserErrors[0].message}`,
    );
  }
  if (!documents.length || documents.some((document) => document.contents === null)) {
    throw new Error(`${file.name} ne doit pas contenir de document YAML vide.`);
  }

  const values = documents.map((document) => document.toJSON());
  if (file.name === "namespaces.yaml") {
    values.forEach((value, index) =>
      validateNamespaceDocument(value, file.name, index),
    );
  } else if (file.name === "cosign-cluster-image-policies.yaml") {
    values.forEach((value, index) =>
      validateClusterImagePolicyDocument(value, file.name, index),
    );
  } else if (file.name.startsWith("github-")) {
    if (values.length !== 1) {
      throw new Error(`${file.name} doit contenir un seul document YAML.`);
    }
    validateGithubValuesDocument(values[0], file.name);
  } else {
    throw new Error(`Fichier YAML inattendu dans le bundle : ${file.name}.`);
  }
  return documents.length;
}

function bundleDigest(files: AdmissionBundleValidationFile[]): string {
  const hash = createHash("sha256");
  [...files]
    .sort((left, right) => left.name.localeCompare(right.name))
    .forEach((file) => {
      hash.update(file.name);
      hash.update("\0");
      hash.update(file.content);
      hash.update("\0");
    });
  return hash.digest("hex");
}

export function validateKubernetesAdmissionBundle(
  policies: OciVerificationRule[],
  options: KubernetesAdmissionOptions,
  files: AdmissionBundleValidationFile[],
): AdmissionBundleValidationSummary {
  if (!files.length || files.length > MAX_BUNDLE_FILES) {
    throw new Error(
      `Le bundle doit contenir entre 1 et ${MAX_BUNDLE_FILES} fichiers.`,
    );
  }

  const seen = new Set<string>();
  let bytes = 0;
  let yamlDocuments = 0;
  files.forEach((file) => {
    if (
      !SAFE_FILE_NAME.test(file.name) ||
      file.name.includes("..") ||
      file.name.includes("/") ||
      file.name.includes("\\")
    ) {
      throw new Error(`Nom de fichier non sûr dans le bundle : ${file.name}.`);
    }
    if (seen.has(file.name)) {
      throw new Error(`Fichier dupliqué dans le bundle : ${file.name}.`);
    }
    seen.add(file.name);
    bytes += Buffer.byteLength(file.content, "utf8");
    if (bytes > MAX_BUNDLE_BYTES) {
      throw new Error(
        `Le bundle dépasse la limite de ${MAX_BUNDLE_BYTES} octets.`,
      );
    }
    if (file.name.endsWith(".yaml")) {
      yamlDocuments += validateYamlFile(file);
    }
  });

  const readme = files.find((file) => file.name === "README.md");
  if (
    !readme ||
    !readme.content.includes("--dry-run=server") ||
    !readme.content.includes("no-match-policy")
  ) {
    throw new Error(
      "Le README du bundle doit imposer la validation serveur et le refus sans correspondance.",
    );
  }

  const expected = generateKubernetesAdmissionBundle(policies, options);
  const actualByName = new Map(files.map((file) => [file.name, file.content]));
  const expectedNames = expected.files.map((file) => file.name).sort();
  const actualNames = [...actualByName.keys()].sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    throw new Error(
      `La liste des fichiers diverge. Attendus : ${expectedNames.join(", ")}. Reçus : ${actualNames.join(", ")}.`,
    );
  }
  expected.files.forEach((file) => {
    if (actualByName.get(file.name) !== file.content) {
      throw new Error(
        `${file.name} diverge du bundle déterministe attendu. Régénérez-le depuis le document de politiques.`,
      );
    }
  });

  return {
    valid: true,
    files: files.length,
    bytes,
    yamlDocuments,
    sha256: bundleDigest(files),
    policies: expected.summary.policies,
    namespaces: expected.summary.namespaces,
  };
}
