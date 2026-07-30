import { createHash } from "node:crypto";
import {
  normalizeOciImagePrefix,
  validateOciVerificationRules,
  type OciVerificationRule,
} from "./oci-provenance.ts";

const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
const SIGSTORE_FULCIO = "https://fulcio.sigstore.dev";
const SIGSTORE_REKOR = "https://rekor.sigstore.dev";
const GITHUB_TRUST_CHART =
  "oci://ghcr.io/github/artifact-attestations-helm-charts/trust-policies";

export const POLICY_CONTROLLER_CHART_VERSION = "0.10.5";
export const GITHUB_TRUST_CHART_VERSION = "v0.7.0";

export type AdmissionBundleFile = {
  name: string;
  content: string;
  purpose:
    | "cosign-policies"
    | "github-values"
    | "namespaces"
    | "instructions";
};

export type KubernetesAdmissionBundle = {
  files: AdmissionBundleFile[];
  summary: {
    policies: number;
    cosignPolicies: number;
    githubPolicies: number;
    clusterImagePolicies: number;
    namespaces: number;
  };
};

export type KubernetesAdmissionOptions = {
  namespaces: string[];
};

function yamlString(value: string): string {
  return JSON.stringify(value);
}

function resourceStem(identifier: string): string {
  const normalized =
    identifier
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 40) || "policy";
  const digest = createHash("sha256")
    .update(identifier)
    .digest("hex")
    .slice(0, 8);
  return `mcp-${normalized}-${digest}`;
}

function validateNamespaces(namespaces: string[]): string[] {
  const unique = [...new Set(namespaces.map((namespace) => namespace.trim()))];
  if (!unique.length) {
    throw new Error(
      "Au moins un namespace Kubernetes est requis pour activer l’admission.",
    );
  }
  unique.forEach((namespace) => {
    if (
      namespace.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(namespace)
    ) {
      throw new Error(
        `Namespace Kubernetes invalide : ${namespace || "(vide)"}.`,
      );
    }
  });
  return unique.sort();
}

function imageGlobs(prefix: string): string[] {
  return [`${prefix}@**`, `${prefix}/**`];
}

function rejectOverlappingPrefixes(policies: OciVerificationRule[]): void {
  const prefixes = policies
    .map((policy) => ({
      id: policy.id,
      prefix: normalizeOciImagePrefix(policy.imagePrefix),
    }))
    .sort((left, right) => left.prefix.localeCompare(right.prefix));
  for (let index = 0; index < prefixes.length; index += 1) {
    for (let candidate = index + 1; candidate < prefixes.length; candidate += 1) {
      if (
        prefixes[candidate].prefix.startsWith(`${prefixes[index].prefix}/`)
      ) {
        throw new Error(
          `Les politiques OCI ${prefixes[index].id} et ${prefixes[candidate].id} se chevauchent. Kubernetes exige toutes les ClusterImagePolicy correspondantes ; utilisez des préfixes disjoints avant de générer l’admission.`,
        );
      }
    }
  }
}

function validateAdmissionIdentityExpressions(
  policies: OciVerificationRule[],
): void {
  policies.forEach((policy) => {
    if (
      policy.kind === "cosign" &&
      (/\\[1-9]/.test(policy.certificateIdentityURI) ||
        /\(\?(?:[=!]|<)/.test(policy.certificateIdentityURI))
    ) {
      throw new Error(
        `La politique OCI ${policy.id} utilise une expression d’identité incompatible avec RE2/Go. Retirez les références arrière, anticipations ou groupes nommés avant de générer l’admission.`,
      );
    }
  });
}

function cosignAuthority(
  policy: Extract<OciVerificationRule, { kind: "cosign" }>,
  includeAttestation: boolean,
): string[] {
  return [
    `  - name: ${yamlString(includeAttestation ? "slsa-provenance" : "cosign-signature")}`,
    "    keyless:",
    `      url: ${yamlString(SIGSTORE_FULCIO)}`,
    "      identities:",
    `      - issuer: ${yamlString(policy.certificateIssuer)}`,
    `        subjectRegExp: ${yamlString(policy.certificateIdentityURI)}`,
    "    ctlog:",
    `      url: ${yamlString(SIGSTORE_REKOR)}`,
    ...(includeAttestation
      ? [
          "    attestations:",
          `    - name: ${yamlString("slsa-provenance-v1")}`,
          `      predicateType: ${yamlString(SLSA_PROVENANCE_V1)}`,
        ]
      : []),
  ];
}

function cosignClusterImagePolicy(
  policy: Extract<OciVerificationRule, { kind: "cosign" }>,
  proof: "signature" | "slsa",
): string {
  const prefix = normalizeOciImagePrefix(policy.imagePrefix);
  const name = `${resourceStem(policy.id)}-${proof}`;
  return [
    "apiVersion: policy.sigstore.dev/v1beta1",
    "kind: ClusterImagePolicy",
    "metadata:",
    `  name: ${yamlString(name)}`,
    "  annotations:",
    `    mcp-trustmap.dev/policy-id: ${yamlString(policy.id)}`,
    `    mcp-trustmap.dev/image-prefix: ${yamlString(prefix)}`,
    `    mcp-trustmap.dev/required-proof: ${yamlString(proof)}`,
    "spec:",
    "  images:",
    ...imageGlobs(prefix).map((glob) => `  - glob: ${yamlString(glob)}`),
    "  authorities:",
    ...cosignAuthority(policy, proof === "slsa"),
  ].join("\n");
}

function githubValues(
  policy: Extract<OciVerificationRule, { kind: "github" }>,
): string {
  const prefix = normalizeOciImagePrefix(policy.imagePrefix);
  const [organization, repository] = policy.repository.split("/");
  return [
    "# Généré par MCP TrustMap. Vérifiez ce fichier avant installation.",
    "policy:",
    "  enabled: true",
    `  organization: ${yamlString(organization)}`,
    `  repository: ${yamlString(repository)}`,
    `  predicateType: ${yamlString(SLSA_PROVENANCE_V1)}`,
    "  images:",
    ...imageGlobs(prefix).map((glob) => `  - ${yamlString(glob)}`),
    "  exemptImages: []",
    "  trust:",
    "    github: true",
    "    githubTrustDomain: \"\"",
    "    sigstorePublic: true",
  ].join("\n");
}

function namespacesManifest(namespaces: string[]): string {
  return namespaces
    .map((namespace) =>
      [
        "apiVersion: v1",
        "kind: Namespace",
        "metadata:",
        `  name: ${yamlString(namespace)}`,
        "  labels:",
        "    policy.sigstore.dev/include: \"true\"",
      ].join("\n"),
    )
    .join("\n---\n");
}

function instructions(
  policies: OciVerificationRule[],
  namespaces: string[],
  files: AdmissionBundleFile[],
): string {
  const cosignFile = files.find(
    (file) => file.purpose === "cosign-policies",
  );
  const githubPolicies = policies.filter(
    (policy): policy is Extract<OciVerificationRule, { kind: "github" }> =>
      policy.kind === "github",
  );
  const lines = [
    "# Admission Kubernetes générée par MCP TrustMap",
    "",
    "Ce dossier ne modifie aucun cluster. Contrôlez les manifestes dans un environnement de test avant l’activation en production.",
    "",
    "## 1. Installer Sigstore Policy Controller",
    "",
    "```bash",
    "helm upgrade policy-controller --install --atomic \\",
    "  --create-namespace --namespace artifact-attestations \\",
    "  oci://ghcr.io/sigstore/helm-charts/policy-controller \\",
    `  --version ${POLICY_CONTROLLER_CHART_VERSION}`,
    "```",
    "",
  ];
  let step = 2;
  if (cosignFile) {
    lines.push(
      `## ${step}. Contrôler puis appliquer les politiques Cosign`,
      "",
      "```bash",
      `kubectl apply --server-side --dry-run=server -f ${cosignFile.name}`,
      `kubectl apply --server-side -f ${cosignFile.name}`,
      "```",
      "",
    );
    step += 1;
  }
  if (githubPolicies.length) {
    lines.push(
      `## ${step}. Installer les racines et politiques GitHub`,
      "",
    );
    githubPolicies.forEach((policy) => {
      const fileName = `github-${resourceStem(policy.id)}-values.yaml`;
      lines.push(
        "```bash",
        `helm upgrade ${resourceStem(policy.id)} --install --atomic \\`,
        "  --namespace artifact-attestations \\",
        `  ${GITHUB_TRUST_CHART} \\`,
        `  --version ${GITHUB_TRUST_CHART_VERSION} \\`,
        `  --values ${fileName}`,
        "```",
        "",
      );
    });
    step += 1;
  }
  lines.push(
    `## ${step}. Activer l’admission dans les namespaces choisis`,
    "",
    "```bash",
    "kubectl apply --server-side --dry-run=server -f namespaces.yaml",
    "kubectl apply --server-side -f namespaces.yaml",
    "```",
    "",
    `Namespaces ciblés : ${namespaces.map((namespace) => `\`${namespace}\``).join(", ")}.`,
    "",
    `## ${step + 1}. Rendre le refus sans correspondance explicite`,
    "",
    "```bash",
    "kubectl -n artifact-attestations patch configmap config-policy-controller \\",
    "  --type merge \\",
    "  -p '{\"data\":{\"no-match-policy\":\"deny\"}}'",
    "```",
    "",
    "Chaque règle Cosign produit deux ClusterImagePolicy qui se cumulent : une signature valide et une attestation SLSA v1 sont donc toutes deux obligatoires. Les règles GitHub utilisent le chart officiel avec une identité de dépôt exacte.",
    "",
  );
  return `${lines.join("\n")}\n`;
}

export function generateKubernetesAdmissionBundle(
  policies: OciVerificationRule[],
  options: KubernetesAdmissionOptions,
): KubernetesAdmissionBundle {
  validateOciVerificationRules(policies);
  rejectOverlappingPrefixes(policies);
  validateAdmissionIdentityExpressions(policies);
  const namespaces = validateNamespaces(options.namespaces);
  const ordered = [...policies].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
  const cosignPolicies = ordered.filter(
    (policy): policy is Extract<OciVerificationRule, { kind: "cosign" }> =>
      policy.kind === "cosign",
  );
  const githubPolicies = ordered.filter(
    (policy): policy is Extract<OciVerificationRule, { kind: "github" }> =>
      policy.kind === "github",
  );
  const files: AdmissionBundleFile[] = [];
  if (cosignPolicies.length) {
    const documents = cosignPolicies.flatMap((policy) => [
      cosignClusterImagePolicy(policy, "signature"),
      cosignClusterImagePolicy(policy, "slsa"),
    ]);
    files.push({
      name: "cosign-cluster-image-policies.yaml",
      content: `${documents.join("\n---\n")}\n`,
      purpose: "cosign-policies",
    });
  }
  githubPolicies.forEach((policy) => {
    files.push({
      name: `github-${resourceStem(policy.id)}-values.yaml`,
      content: `${githubValues(policy)}\n`,
      purpose: "github-values",
    });
  });
  files.push({
    name: "namespaces.yaml",
    content: `${namespacesManifest(namespaces)}\n`,
    purpose: "namespaces",
  });
  files.push({
    name: "README.md",
    content: instructions(ordered, namespaces, files),
    purpose: "instructions",
  });
  return {
    files,
    summary: {
      policies: ordered.length,
      cosignPolicies: cosignPolicies.length,
      githubPolicies: githubPolicies.length,
      clusterImagePolicies: cosignPolicies.length * 2 + githubPolicies.length,
      namespaces: namespaces.length,
    },
  };
}
