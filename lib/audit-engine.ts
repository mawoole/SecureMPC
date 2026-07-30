import {
  extractSupplyChainComponents,
  type SupplyChainComponent,
} from "./supply-chain.ts";
import type { VulnerabilityScanSummary } from "./osv.ts";
import type { OciVerificationSummary } from "./oci-provenance.ts";
import type { ProvenanceScanSummary } from "./provenance.ts";

export type Severity = "critical" | "high" | "medium";
export type ServerStatus = "critical" | "attention" | "secure";
export type ProbeStatus =
  | "not-requested"
  | "reachable"
  | "auth-required"
  | "skipped-insecure"
  | "skipped-stdio"
  | "timeout"
  | "unreachable"
  | "protocol-error";

export type PassiveProbe = {
  status: ProbeStatus;
  checkedAt: string;
  durationMs: number;
  protocolVersion?: string;
  capabilities?: string[];
  serverName?: string;
  serverVersion?: string;
  httpStatus?: number;
  message: string;
};

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  snippet: string;
  rule: string;
};

export type McpServer = {
  id: string;
  name: string;
  owner: string;
  transport: string;
  source: string;
  score: number;
  status: ServerStatus;
  controls: number;
  findings: Finding[];
  lastScan: string;
  probe?: PassiveProbe;
  components?: SupplyChainComponent[];
  componentGraph?: {
    direct: number;
    transitive: number;
    truncated: boolean;
    lockfiles: string[];
    workspaces?: string[];
  };
  vulnerabilityScan?: VulnerabilityScanSummary;
  provenanceScan?: ProvenanceScanSummary;
  ociVerification?: OciVerificationSummary;
};

export type SecurityRule = {
  code: string;
  title: string;
  detail: string;
  category: string;
};

export type AuditMetrics = {
  score: number;
  controls: number;
  critical: number;
  high: number;
  medium: number;
  toFix: number;
  secure: number;
};

export type AuditReport = {
  schemaVersion: "1.0";
  generatedAt: string;
  generator: {
    name: "Secure MPC";
    version: string;
  };
  summary: AuditMetrics & {
    servers: number;
  };
  servers: McpServer[];
};

export const SECURITY_RULES: SecurityRule[] = [
  {
    code: "MCP-SEC-01",
    title: "Gestion des secrets",
    detail:
      "Détecte les jetons, mots de passe et clés stockés en clair dans les configurations.",
    category: "Secrets",
  },
  {
    code: "MCP-AUTHN-01",
    title: "Authentification distante",
    detail:
      "Signale les serveurs distants sans mécanisme d’authentification visible.",
    category: "Identité",
  },
  {
    code: "MCP-AUTHZ-01",
    title: "Moindre privilège",
    detail:
      "Recherche les comptes administrateurs et les autorisations supérieures au besoin.",
    category: "Accès",
  },
  {
    code: "MCP-AUTHZ-03",
    title: "Périmètre de fichiers",
    detail:
      "Identifie les racines système et répertoires utilisateurs exposés en totalité.",
    category: "Accès",
  },
  {
    code: "MCP-NET-01",
    title: "Transport chiffré",
    detail: "Refuse HTTP pour les connexions à des serveurs MCP distants.",
    category: "Réseau",
  },
  {
    code: "MCP-SUP-02",
    title: "Versions verrouillées",
    detail:
      "Signale les paquets latest ou téléchargés sans version exacte.",
    category: "Supply chain",
  },
  {
    code: "MCP-EXEC-01",
    title: "Exécution directe",
    detail:
      "Détecte les shells intermédiaires qui augmentent le risque d’injection.",
    category: "Exécution",
  },
  {
    code: "MCP-EXEC-02",
    title: "Isolation du processus",
    detail:
      "Recherche les options qui désactivent sandbox, permissions ou contrôles d’accès.",
    category: "Exécution",
  },
  {
    code: "MCP-AUDIT-01",
    title: "Traçabilité",
    detail:
      "Vérifie que la configuration permet d’identifier et corréler les appels.",
    category: "Audit",
  },
  {
    code: "MCP-DATA-01",
    title: "Minimisation des données",
    detail:
      "Encourage l’exposition du seul périmètre de données utile au serveur.",
    category: "Données",
  },
  {
    code: "MCP-PROTO-01",
    title: "Négociation MCP",
    detail:
      "Vérifie passivement la disponibilité, la version et les capacités des endpoints HTTPS.",
    category: "Protocole",
  },
  {
    code: "MCP-VULN-01",
    title: "Vulnérabilités connues",
    detail:
      "Croise les composants versionnés avec les avis agrégés par OSV.dev.",
    category: "Supply chain",
  },
  {
    code: "MCP-SUP-03",
    title: "Provenance et authenticité",
    detail:
      "Vérifie les signatures du registre, les attestations SLSA, leur journal Sigstore et le digest du sujet.",
    category: "Supply chain",
  },
];

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 28,
  high: 17,
  medium: 8,
};

function makeFinding(
  id: string,
  severity: Severity,
  title: string,
  description: string,
  remediation: string,
  snippet: string,
  rule: string,
): Finding {
  return {
    id,
    severity,
    title,
    description,
    remediation,
    snippet,
    rule,
  };
}

function isSensitiveKey(key: string): boolean {
  return /(token|secret|password|passwd|api.?key|authorization|credential)/i.test(
    key,
  );
}

function containsPlaceholder(value: string): boolean {
  return [
    /\$\{[A-Z_][A-Z0-9_]*\}/i,
    /\$[A-Z_][A-Z0-9_]*/i,
    /%[A-Z_][A-Z0-9_]*%/i,
    /\{\{[^{}]+\}\}/,
    /\b(?:env|secret):[A-Z_][A-Z0-9_]*\b/i,
    /<[^<>]+>/,
  ].some((pattern) => pattern.test(value));
}

function containsConcreteSecret(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed || containsPlaceholder(trimmed)) return false;
  return trimmed.length >= 8;
}

function inspectForSecrets(value: unknown, parentKey = ""): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => inspectForSecrets(item, parentKey));
  }

  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(
      ([key, child]) =>
        (isSensitiveKey(key) && containsConcreteSecret(child)) ||
        inspectForSecrets(child, key),
    );
  }

  return isSensitiveKey(parentKey) && containsConcreteSecret(value);
}

function urlContainsCredential(urlValue: string): boolean {
  if (!urlValue) return false;

  try {
    const url = new URL(urlValue);
    if (url.username || url.password) return true;
    return [...url.searchParams.entries()].some(
      ([key, value]) => isSensitiveKey(key) && containsConcreteSecret(value),
    );
  } catch {
    return false;
  }
}

function hasConfiguredAuthentication(
  config: Record<string, unknown>,
): boolean {
  if (config.auth) return true;
  if (!config.headers || typeof config.headers !== "object") return false;

  return Object.keys(config.headers as Record<string, unknown>).some((key) =>
    /(authorization|api.?key|token)/i.test(key),
  );
}

function hasBroadFilesystemPath(args: string[]): boolean {
  return args.some((arg) => {
    const normalized = arg.trim();
    return (
      normalized === "/" ||
      normalized === "\\" ||
      /^[a-z]:[\\/]?$/i.test(normalized) ||
      /^~[/\\]?$/.test(normalized) ||
      /^\/(?:home|users)\/[^/]+\/?$/i.test(normalized) ||
      /^[a-z]:[\\/]users[\\/][^\\/]+[\\/]?$/i.test(normalized)
    );
  });
}

function hasPrivilegedDatabaseIdentity(
  config: Record<string, unknown>,
  text: string,
): boolean {
  if (!/(postgres|mysql|mariadb|mongodb|database|sql)/i.test(text)) {
    return false;
  }

  const values = [
    ...Object.values(
      config.env && typeof config.env === "object"
        ? (config.env as Record<string, unknown>)
        : {},
    ),
    ...Object.values(
      config.connection && typeof config.connection === "object"
        ? (config.connection as Record<string, unknown>)
        : {},
    ),
  ]
    .filter((value): value is string => typeof value === "string")
    .join(" ");

  return /(?:^|[:/@\s])(root|admin|administrator|postgres)(?:[:/@\s]|$)/i.test(
    values,
  );
}

function slugify(value: string): string {
  return (
    value
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "") || "server"
  );
}

function importedText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned ? cleaned.slice(0, maxLength) : undefined;
}

function sanitizeImportedComponent(
  value: unknown,
): SupplyChainComponent | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const ecosystem = importedText(record.ecosystem, 20);
  const componentType = importedText(record.componentType, 20);
  const pinStatus = importedText(record.pinStatus, 30);
  const id = importedText(record.id, 200);
  const name = importedText(record.name, 300);
  const reference = importedText(record.reference, 500);
  const evidence = importedText(record.evidence, 100);
  if (
    !id ||
    !name ||
    !reference ||
    !evidence ||
    !["npm", "pypi", "oci", "executable"].includes(ecosystem ?? "") ||
    !["library", "container", "application"].includes(componentType ?? "") ||
    ![
      "pinned",
      "unpinned",
      "mutable",
      "unknown",
      "not-applicable",
    ].includes(pinStatus ?? "")
  ) {
    return undefined;
  }

  const vulnerabilities = Array.isArray(record.vulnerabilities)
    ? record.vulnerabilities.flatMap((value) => {
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          return [];
        }
        const vulnerability = value as Record<string, unknown>;
        const vulnerabilityId = importedText(vulnerability.id, 100);
        const summary = importedText(vulnerability.summary, 500);
        const severity = importedText(vulnerability.severity, 20);
        if (
          !vulnerabilityId ||
          !summary ||
          !["critical", "high", "medium", "low", "unknown"].includes(
            severity ?? "",
          )
        ) {
          return [];
        }
        const suppliedUrl = importedText(vulnerability.advisoryUrl, 2_048);
        const advisoryUrl =
          suppliedUrl?.startsWith("https://")
            ? suppliedUrl
            : `https://osv.dev/vulnerability/${encodeURIComponent(vulnerabilityId)}`;
        const modified = importedText(vulnerability.modified, 100);
        const fixed = importedText(vulnerability.fixedVersion, 100);
        return [
          {
            id: vulnerabilityId,
            aliases: Array.isArray(vulnerability.aliases)
              ? vulnerability.aliases
                  .map((alias) => importedText(alias, 100))
                  .filter((alias): alias is string => Boolean(alias))
                  .slice(0, 10)
              : [],
            summary,
            severity: severity as NonNullable<
              SupplyChainComponent["vulnerabilities"]
            >[number]["severity"],
            ...(modified ? { modified } : {}),
            advisoryUrl,
            ...(fixed ? { fixedVersion: fixed } : {}),
          },
        ];
      })
    : [];
  const version = importedText(record.version, 100);
  const purl = importedText(record.purl, 2_048);
  const scope =
    record.scope === "transitive" ? "transitive" : "direct";
  const dependencies = Array.isArray(record.dependencies)
    ? record.dependencies
        .map((dependency) => importedText(dependency, 2_048))
        .filter(
          (dependency): dependency is string =>
            Boolean(dependency?.startsWith("pkg:")),
        )
        .slice(0, 1_000)
    : [];
  const lockfile = importedText(record.lockfile, 500);
  const integrityStatus =
    record.integrityStatus === "recorded" ||
    record.integrityStatus === "missing"
      ? record.integrityStatus
      : undefined;
  const integrity = importedText(record.integrity, 1_024);
  const workspace = importedText(record.workspace, 500);
  const rawProvenance =
    record.provenance &&
    typeof record.provenance === "object" &&
    !Array.isArray(record.provenance)
      ? (record.provenance as Record<string, unknown>)
      : undefined;
  const verificationStates = [
    "verified",
    "missing",
    "failed",
    "unverifiable",
    "error",
    "not-applicable",
  ];
  const registrySignature = importedText(
    rawProvenance?.registrySignature,
    30,
  );
  const slsaProvenance = importedText(rawProvenance?.slsaProvenance, 30);
  const subjectDigest = importedText(rawProvenance?.subjectDigest, 30);
  const identityPolicy = importedText(rawProvenance?.identityPolicy, 30);
  const policyId = importedText(rawProvenance?.policyId, 64);
  const provenanceMessage = importedText(rawProvenance?.message, 500);
  const sourceRepository = importedText(
    rawProvenance?.sourceRepository,
    2_048,
  );
  const builderId = importedText(rawProvenance?.builderId, 2_048);
  const checkedAt = importedText(rawProvenance?.checkedAt, 100);
  const provenanceProvider = importedText(rawProvenance?.provider, 50);
  const provenance =
    [
      "npm-registry-sigstore",
      "oci-cosign",
      "oci-github-attestation",
      "oci-policy",
    ].includes(provenanceProvider ?? "") &&
    registrySignature &&
    slsaProvenance &&
    verificationStates.includes(registrySignature) &&
    verificationStates.includes(slsaProvenance) &&
    ["matched", "mismatched", "unavailable"].includes(subjectDigest ?? "") &&
    ["matched", "mismatched", "not-configured"].includes(
      identityPolicy ?? "",
    ) &&
    provenanceMessage &&
    checkedAt
      ? {
          provider: provenanceProvider as NonNullable<
            SupplyChainComponent["provenance"]
          >["provider"],
          checkedAt,
          registrySignature: registrySignature as NonNullable<
            SupplyChainComponent["provenance"]
          >["registrySignature"],
          slsaProvenance: slsaProvenance as NonNullable<
            SupplyChainComponent["provenance"]
          >["slsaProvenance"],
          subjectDigest: subjectDigest as NonNullable<
            SupplyChainComponent["provenance"]
          >["subjectDigest"],
          identityPolicy: identityPolicy as NonNullable<
            SupplyChainComponent["provenance"]
          >["identityPolicy"],
          ...(policyId ? { policyId } : {}),
          ...(sourceRepository?.startsWith("https://")
            ? { sourceRepository }
            : {}),
          ...(builderId?.startsWith("https://") ? { builderId } : {}),
          message: provenanceMessage,
        }
      : undefined;

  return {
    id,
    ecosystem: ecosystem as SupplyChainComponent["ecosystem"],
    name,
    ...(version ? { version } : {}),
    reference,
    ...(purl?.startsWith("pkg:") ? { purl } : {}),
    componentType:
      componentType as SupplyChainComponent["componentType"],
    pinStatus: pinStatus as SupplyChainComponent["pinStatus"],
    evidence,
    scope,
    dependencies,
    ...(lockfile ? { lockfile } : {}),
    ...(integrityStatus ? { integrityStatus } : {}),
    ...(integrity && /^sha(?:256|384|512)-/.test(integrity)
      ? { integrity }
      : {}),
    ...(workspace ? { workspace } : {}),
    ...(provenance ? { provenance } : {}),
    vulnerabilities,
  };
}

function sanitizeOciVerification(
  value: unknown,
): OciVerificationSummary | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const status = importedText(record.status, 20);
  const backend = importedText(record.backend, 30);
  const checkedAt = importedText(record.checkedAt, 100);
  const message = importedText(record.message, 500);
  if (
    record.provider !== "oci-provenance" ||
    !["cosign", "github-attestations", "mixed"].includes(backend ?? "") ||
    !["complete", "partial", "error"].includes(status ?? "") ||
    !checkedAt ||
    !message
  ) {
    return undefined;
  }
  const count = (candidate: unknown) =>
    typeof candidate === "number" &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0
      ? candidate
      : 0;
  return {
    provider: "oci-provenance",
    backend: backend as OciVerificationSummary["backend"],
    status: status as OciVerificationSummary["status"],
    checkedAt,
    images: count(record.images),
    policies: count(record.policies),
    matched: count(record.matched),
    unmatched: count(record.unmatched),
    signaturesVerified: count(record.signaturesVerified),
    slsaProvenanceVerified: count(record.slsaProvenanceVerified),
    missing: count(record.missing),
    failed: count(record.failed),
    message,
  };
}

function sanitizeProvenanceScan(
  value: unknown,
): ProvenanceScanSummary | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const status = importedText(record.status, 20);
  const checkedAt = importedText(record.checkedAt, 100);
  const message = importedText(record.message, 500);
  if (
    record.provider !== "npm-registry-sigstore" ||
    !["complete", "partial", "error"].includes(status ?? "") ||
    !checkedAt ||
    !message
  ) {
    return undefined;
  }
  const count = (candidate: unknown) =>
    typeof candidate === "number" &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0
      ? candidate
      : 0;
  return {
    provider: "npm-registry-sigstore",
    status: status as ProvenanceScanSummary["status"],
    checkedAt,
    packages: count(record.packages),
    registrySignaturesVerified: count(record.registrySignaturesVerified),
    slsaProvenanceVerified: count(record.slsaProvenanceVerified),
    missing: count(record.missing),
    failed: count(record.failed),
    message,
  };
}

function sanitizeVulnerabilityScan(
  value: unknown,
): VulnerabilityScanSummary | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const status = importedText(record.status, 20);
  const checkedAt = importedText(record.checkedAt, 100);
  const message = importedText(record.message, 500);
  if (
    record.provider !== "OSV.dev" ||
    !["complete", "partial", "error"].includes(status ?? "") ||
    !checkedAt ||
    !message
  ) {
    return undefined;
  }
  const count = (candidate: unknown) =>
    typeof candidate === "number" &&
    Number.isSafeInteger(candidate) &&
    candidate >= 0
      ? candidate
      : 0;
  return {
    provider: "OSV.dev",
    status: status as VulnerabilityScanSummary["status"],
    checkedAt,
    queriedComponents: count(record.queriedComponents),
    skippedComponents: count(record.skippedComponents),
    vulnerabilities: count(record.vulnerabilities),
    message,
  };
}

function serverStatus(findings: Finding[]): ServerStatus {
  if (findings.some((finding) => finding.severity === "critical")) {
    return "critical";
  }
  return findings.length ? "attention" : "secure";
}

function serverScore(findings: Finding[]): number {
  const penalty = findings.reduce(
    (sum, finding) => sum + SEVERITY_PENALTY[finding.severity],
    0,
  );
  return Math.max(12, 100 - penalty);
}

function extractServerContainer(
  parsed: Record<string, unknown>,
): Record<string, unknown> {
  const nestedMcp = parsed.mcp;
  const container =
    (parsed.mcpServers as Record<string, unknown> | undefined) ??
    (parsed.servers as Record<string, unknown> | undefined) ??
    (nestedMcp &&
    typeof nestedMcp === "object" &&
    !Array.isArray(nestedMcp)
      ? ((nestedMcp as Record<string, unknown>).servers as
          | Record<string, unknown>
          | undefined)
      : undefined) ??
    parsed;

  if (!container || typeof container !== "object" || Array.isArray(container)) {
    throw new Error("Aucun objet de serveurs MCP n’a été trouvé.");
  }

  return container;
}

export function auditConfiguration(raw: string): McpServer[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("La configuration JSON n’est pas valide.");
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Aucun objet de serveurs MCP n’a été trouvé.");
  }

  const parsedRecord = parsed as Record<string, unknown>;
  const collector =
    parsedRecord.collector &&
    typeof parsedRecord.collector === "object" &&
    !Array.isArray(parsedRecord.collector)
      ? (parsedRecord.collector as Record<string, unknown>)
      : undefined;
  const isCollectorInventory =
    parsedRecord.schemaVersion === "1.0" &&
    collector?.name === "Secure MPC Collector" &&
    Array.isArray(parsedRecord.servers);

  if (isCollectorInventory) {
    const vulnerabilityScan = sanitizeVulnerabilityScan(
      parsedRecord.vulnerabilityScan,
    );
    const provenanceScan = sanitizeProvenanceScan(
      parsedRecord.provenanceScan,
    );
    const ociVerification = sanitizeOciVerification(
      parsedRecord.ociVerification,
    );

    return (parsedRecord.servers as unknown[]).map((entry, index) => {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        throw new Error(
          `L’entrée ${index + 1} de l’inventaire collecteur est invalide.`,
        );
      }

      const collected = entry as Record<string, unknown>;
      const name =
        typeof collected.name === "string" && collected.name.trim()
          ? collected.name
          : `Serveur ${index + 1}`;
      const configuration =
        collected.configuration &&
        typeof collected.configuration === "object" &&
        !Array.isArray(collected.configuration)
          ? (collected.configuration as Record<string, unknown>)
          : undefined;
      if (!configuration) {
        throw new Error(
          `La configuration du serveur « ${name} » est invalide.`,
        );
      }

      const base = auditConfiguration(
        JSON.stringify({ mcpServers: { [name]: configuration } }),
      )[0];
      const redactions = Array.isArray(collected.redactions)
        ? collected.redactions
        : [];
      let findings = [...base.findings];
      const components = Array.isArray(collected.components)
        ? collected.components
            .map(sanitizeImportedComponent)
            .filter(
              (component): component is SupplyChainComponent =>
                component !== undefined,
            )
        : base.components;
      const componentGraph = components?.some(
        (component) =>
          component.scope === "transitive" || component.lockfile,
      )
        ? {
            direct: components.filter(
              (component) => component.scope !== "transitive",
            ).length,
            transitive: components.filter(
              (component) => component.scope === "transitive",
            ).length,
            truncated:
              Boolean(
                collected.componentGraph &&
                  typeof collected.componentGraph === "object" &&
                  !Array.isArray(collected.componentGraph) &&
                  (collected.componentGraph as Record<string, unknown>)
                    .truncated,
              ),
            lockfiles: [
              ...new Set(
                components.flatMap((component) =>
                  component.lockfile ? [component.lockfile] : [],
                ),
              ),
            ],
            workspaces: [
              ...new Set(
                components.flatMap((component) =>
                  component.workspace ? [component.workspace] : [],
                ),
              ),
            ],
          }
        : undefined;

      if (
        redactions.length > 0 &&
        !findings.some((finding) => finding.rule === "MCP-SEC-01")
      ) {
        findings.push(
          makeFinding(
            `collected-${index}-${slugify(name)}-secret`,
            "critical",
            "Secret masqué par le collecteur",
            `${redactions.length} valeur${redactions.length > 1 ? "s sensibles ont" : " sensible a"} été remplacée${redactions.length > 1 ? "s" : ""} avant la création de l’inventaire. Aucune valeur n’est conservée dans le rapport.`,
            "Déplacez la valeur dans un coffre de secrets ou une variable d’environnement. Révoquez-la si le fichier source a été partagé ou committé.",
            `"env": {\n  "SERVICE_TOKEN": "\${SERVICE_TOKEN}"\n}`,
            "MCP-SEC-01",
          ),
        );
      }

      for (const [componentIndex, component] of (
        components ?? []
      ).entries()) {
        for (const [vulnerabilityIndex, vulnerability] of (
          component.vulnerabilities ?? []
        ).entries()) {
          const vulnerabilityId =
            typeof vulnerability.id === "string"
              ? vulnerability.id.slice(0, 100)
              : "OSV";
          const summary =
            typeof vulnerability.summary === "string"
              ? vulnerability.summary
                  .replace(/[\u0000-\u001f\u007f]/g, " ")
                  .slice(0, 500)
              : `Avis de sécurité ${vulnerabilityId}`;
          const severity =
            vulnerability.severity === "critical"
              ? "critical"
              : vulnerability.severity === "high"
                ? "high"
                : "medium";
          const advisoryUrl =
            typeof vulnerability.advisoryUrl === "string" &&
            vulnerability.advisoryUrl.startsWith("https://")
              ? vulnerability.advisoryUrl
              : `https://osv.dev/vulnerability/${encodeURIComponent(vulnerabilityId)}`;
          const fixedVersion =
            typeof vulnerability.fixedVersion === "string"
              ? vulnerability.fixedVersion.slice(0, 100)
              : undefined;
          const parents = (components ?? [])
            .filter((candidate) =>
              (candidate.dependencies ?? []).includes(
                component.purl ?? component.id,
              ),
            )
            .map((candidate) => candidate.name)
            .slice(0, 3);
          const transitive = component.scope === "transitive";

          findings.push(
            makeFinding(
              `collected-${index}-${slugify(name)}-osv-${componentIndex}-${vulnerabilityIndex}`,
              severity,
              `Vulnérabilité connue ${vulnerabilityId}`,
              `${summary} ${transitive ? "Dépendance transitive" : "Composant direct"} concerné${transitive ? "e" : ""} : ${component.name}${component.version ? ` ${component.version}` : ""}${parents.length ? `, introduite par ${parents.join(", ")}` : ""}.`,
              fixedVersion
                ? transitive
                  ? `Mettez à jour ${parents.length ? parents.join(", ") : "la dépendance directe qui l’introduit"} afin de résoudre ${component.name} en version ${fixedVersion} ou ultérieure, régénérez le lockfile puis l’inventaire.`
                  : `Mettez à jour ${component.name} vers la version corrigée ${fixedVersion} ou une version ultérieure compatible, puis régénérez l’inventaire.`
                : transitive
                  ? `Mettez à jour la dépendance directe qui introduit ${component.name}, régénérez le lockfile et vérifiez que l’avis disparaît avant remise en service.`
                  : `Consultez l’avis, identifiez une version corrigée compatible et régénérez l’inventaire avant remise en service.`,
              advisoryUrl,
              "MCP-VULN-01",
            ),
          );
        }
      }

      const provenanceComponents = (components ?? []).filter(
        (component) => component.provenance,
      );
      const failedProvenance = provenanceComponents.filter(
        (component) =>
          component.provenance?.registrySignature === "failed" ||
          component.provenance?.slsaProvenance === "failed",
      );
      const missingProvenance = provenanceComponents.filter(
        (component) =>
          component.scope !== "transitive" &&
          (["missing", "unverifiable"].includes(
            component.provenance?.registrySignature ?? "",
          ) ||
            ["missing", "unverifiable"].includes(
              component.provenance?.slsaProvenance ?? "",
            )),
      );
      const provenanceErrors = provenanceComponents.filter(
        (component) =>
          component.provenance?.registrySignature === "error" ||
          component.provenance?.slsaProvenance === "error",
      );
      const policyMissing = provenanceComponents.filter(
        (component) =>
          component.provenance?.slsaProvenance === "verified" &&
          component.provenance.identityPolicy === "not-configured",
      );
      if (failedProvenance.length) {
        const includesOci = failedProvenance.some(
          (component) => component.ecosystem === "oci",
        );
        const includesUnmatchedPolicy = failedProvenance.some(
          (component) => component.provenance?.provider === "oci-policy",
        );
        findings.push(
          makeFinding(
            `collected-${index}-${slugify(name)}-provenance-failed`,
            "critical",
            "Preuve de provenance invalide",
            `${failedProvenance.length} composant${failedProvenance.length > 1 ? "s ont" : " a"} une signature invalide, un digest divergent ou une attestation Sigstore non vérifiable : ${failedProvenance.slice(0, 3).map((component) => component.name).join(", ")}.`,
            includesUnmatchedPolicy
              ? "Bloquez la mise en service et ajoutez une règle au fichier de politiques OCI pour chaque préfixe d’image attendu. Relancez ensuite la vérification sans modifier le digest."
              : includesOci
                ? "Bloquez la mise en service, vérifiez le digest, l’identité du workflow, la signature et l’attestation SLSA de l’image."
                : "Bloquez la mise en service, régénérez le lockfile depuis une source de confiance et vérifiez le paquet, la version, le digest ainsi que l’identité du workflow de publication.",
            includesUnmatchedPolicy
              ? "npm run collect -- --oci-policy-file ./oci-policies.json"
              : includesOci
                ? "npm run collect -- --oci-cosign --oci-issuer https://token.actions.githubusercontent.com --oci-identity '^https://github\\.com/ORG/REPO/.github/workflows/release\\.yml@refs/tags/.+$'"
                : "npm run collect -- --provenance --provenance-issuer https://token.actions.githubusercontent.com --provenance-identity '^https://github\\.com/ORG/REPO/.github/workflows/release\\.yml@refs/tags/.+$'",
            "MCP-SUP-03",
          ),
        );
      }
      if (missingProvenance.length) {
        const includesOci = missingProvenance.some(
          (component) => component.ecosystem === "oci",
        );
        findings.push(
          makeFinding(
            `collected-${index}-${slugify(name)}-provenance-missing`,
            "medium",
            "Provenance incomplète",
            `${missingProvenance.length} composant direct n’a pas de signature ou de provenance SLSA vérifiable : ${missingProvenance.slice(0, 3).map((component) => component.name).join(", ")}.`,
            includesOci
              ? "Publiez l’image avec une signature et une attestation SLSA liées au digest, puis relancez avec une politique Cosign ou un dépôt GitHub attendu."
              : "Préférez une version publiée avec provenance npm, conservez son intégrité SRI dans le lockfile et relancez le collecteur avec --provenance.",
            includesOci
              ? "npm run collect -- --oci-cosign --oci-issuer https://token.actions.githubusercontent.com --oci-identity '^https://github\\.com/ORG/REPO/.github/workflows/release\\.yml@refs/tags/.+$'"
              : "npm run collect -- --provenance",
            "MCP-SUP-03",
          ),
        );
      }
      if (provenanceErrors.length) {
        findings.push(
          makeFinding(
            `collected-${index}-${slugify(name)}-provenance-error`,
            "medium",
            "Vérification de provenance indisponible",
            `La vérification réseau ou le matériel de confiance Sigstore a échoué pour ${provenanceErrors.length} composant${provenanceErrors.length > 1 ? "s" : ""}.`,
            "Vérifiez l’accès HTTPS au registre concerné, à Sigstore et au vérificateur sélectionné, puis relancez exactement le même inventaire.",
            provenanceErrors.some(
              (component) => component.ecosystem === "oci",
            )
              ? "cosign version"
              : "npm run collect -- --provenance",
            "MCP-SUP-03",
          ),
        );
      }
      if (policyMissing.length) {
        findings.push(
          makeFinding(
            `collected-${index}-${slugify(name)}-provenance-policy`,
            "medium",
            "Identité source non contrainte",
            `La preuve cryptographique est valide pour ${policyMissing.length} composant${policyMissing.length > 1 ? "s" : ""}, mais aucune identité de dépôt ou de workflow attendue n’a été imposée.`,
            "Ajoutez l’émetteur OIDC et une expression régulière ancrée pour l’identité du workflow de publication attendu.",
            "npm run collect -- --provenance --provenance-issuer https://token.actions.githubusercontent.com --provenance-identity '^https://github\\.com/ORG/REPO/.github/workflows/release\\.yml@refs/tags/.+$'",
            "MCP-SUP-03",
          ),
        );
      }

      const probe =
        collected.probe &&
        typeof collected.probe === "object" &&
        !Array.isArray(collected.probe)
          ? (collected.probe as PassiveProbe)
          : undefined;

      if (probe?.status === "auth-required") {
        findings = findings.filter(
          (finding) => finding.rule !== "MCP-AUTHN-01",
        );
      }

      if (
        probe &&
        ["timeout", "unreachable", "protocol-error"].includes(probe.status)
      ) {
        const timeout = probe.status === "timeout";
        findings.push(
          makeFinding(
            `collected-${index}-${slugify(name)}-probe`,
            timeout ? "medium" : "high",
            timeout
              ? "Vérification MCP expirée"
              : probe.status === "unreachable"
                ? "Endpoint MCP injoignable"
                : "Négociation MCP invalide",
            probe.message,
            timeout
              ? "Confirmez la disponibilité réseau, puis relancez avec un délai adapté, par exemple npm run collect -- --probe --timeout 10000."
              : "Vérifiez l’URL, le certificat TLS et la compatibilité avec la version MCP annoncée, puis relancez le collecteur.",
            `npm run collect -- --probe --timeout 10000`,
            "MCP-PROTO-01",
          ),
        );
      }

      const source =
        collected.source &&
        typeof collected.source === "object" &&
        !Array.isArray(collected.source)
          ? (collected.source as Record<string, unknown>)
          : undefined;
      const sourceClient =
        typeof source?.client === "string" ? source.client : "Collecteur local";
      const sourcePath =
        typeof source?.path === "string" ? ` · ${source.path}` : "";

      return {
        ...base,
        id:
          typeof collected.id === "string"
            ? `collected-${collected.id}`
            : `collected-${index}-${slugify(name)}`,
        source: `${sourceClient}${sourcePath}`,
        findings,
        status: serverStatus(findings),
        score: serverScore(findings),
        controls: SECURITY_RULES.length,
        lastScan: "collecté à l’instant",
        probe,
        components,
        componentGraph,
        vulnerabilityScan,
        provenanceScan,
        ociVerification,
      };
    });
  }

  const container = extractServerContainer(parsedRecord);

  return Object.entries(container).map(([name, value], index) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`La configuration du serveur « ${name} » est invalide.`);
    }

    const config = value as Record<string, unknown>;
    const command = String(config.command ?? "");
    const url = String(config.url ?? "");
    const args = Array.isArray(config.args)
      ? config.args.map((item) => String(item))
      : [];
    const text = `${command} ${args.join(" ")} ${url}`.toLowerCase();
    const safeId = `${index}-${slugify(name)}`;
    const findings: Finding[] = [];
    const components = extractSupplyChainComponents(config);

    if (inspectForSecrets(config) || urlContainsCredential(url)) {
      findings.push(
        makeFinding(
          `${safeId}-secret`,
          "critical",
          "Secret stocké dans la configuration",
          "Une valeur sensible semble être présente en clair. La valeur détectée n’est ni affichée ni conservée.",
          "Révoquez la valeur si elle a été partagée, puis injectez-la depuis un coffre de secrets ou une variable d’environnement.",
          `"env": {\n  "SERVICE_TOKEN": "\${SERVICE_TOKEN}"\n}`,
          "MCP-SEC-01",
        ),
      );
    }

    if (url.startsWith("http://")) {
      findings.push(
        makeFinding(
          `${safeId}-http`,
          "critical",
          "Transport HTTP non chiffré",
          "Le point d’accès distant ne protège pas les données et jetons en transit.",
          "Publiez ce serveur derrière HTTPS avec un certificat valide et bloquez les redirections vers HTTP.",
          `"url": "${url.replace("http://", "https://").split("?")[0]}"`,
          "MCP-NET-01",
        ),
      );
    }

    if (/(bash|sh|cmd|powershell|pwsh)(\.exe)?$/i.test(command)) {
      findings.push(
        makeFinding(
          `${safeId}-shell`,
          "critical",
          "Exécution via un shell",
          "Un interpréteur de commandes augmente le risque d’injection et masque le binaire réellement exécuté.",
          "Appelez directement le binaire ou le script du serveur avec une liste d’arguments explicite.",
          `"command": "/opt/mcp/server"\n"args": ["--readonly"]`,
          "MCP-EXEC-01",
        ),
      );
    }

    if (
      /(no-sandbox|allow-all|skip-permission|disable-security|dangerously)/i.test(
        text,
      )
    ) {
      findings.push(
        makeFinding(
          `${safeId}-unsafe`,
          "critical",
          "Option de sécurité désactivée",
          "Une option dangereuse contourne une protection d’isolation ou d’autorisation.",
          "Supprimez ce paramètre et définissez explicitement les ressources et opérations autorisées.",
          `"args": ["--readonly", "--workspace", "/workspace/project"]`,
          "MCP-EXEC-02",
        ),
      );
    }

    components.forEach((component, componentIndex) => {
      if (
        !["unpinned", "mutable"].includes(component.pinStatus) ||
        component.ecosystem === "executable"
      ) {
        return;
      }

      const isContainer = component.ecosystem === "oci";
      findings.push(
        makeFinding(
          `${safeId}-version-${componentIndex}`,
          "high",
          isContainer
            ? "Image OCI non immuable"
            : "Dépendance non verrouillée",
          component.evidence,
          isContainer
            ? "Remplacez le tag par le digest SHA-256 exact de l’image revue et conservez le tag uniquement comme information lisible."
            : "Indiquez une version exacte et effectuez les mises à jour dans une procédure contrôlée.",
          isContainer
            ? `"args": ["run", "${component.name}@sha256:<digest-validé>"]`
            : component.ecosystem === "pypi"
              ? `"args": ["${component.name}==1.0.0"]`
              : `"args": ["-y", "${component.name}@1.0.0"]`,
          "MCP-SUP-02",
        ),
      );
    });

    if (hasBroadFilesystemPath(args)) {
      findings.push(
        makeFinding(
          `${safeId}-path`,
          "critical",
          "Accès fichiers trop large",
          "Le serveur peut atteindre une racine système ou un répertoire utilisateur complet.",
          "Montez uniquement un dossier de travail dédié et rendez-le accessible en lecture seule si possible.",
          `"args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/workspace/project"]`,
          "MCP-AUTHZ-03",
        ),
      );
    }

    if (hasPrivilegedDatabaseIdentity(config, text)) {
      findings.push(
        makeFinding(
          `${safeId}-database-role`,
          "high",
          "Identité de base de données sur-privilégiée",
          "La configuration semble utiliser un compte administrateur ou superutilisateur.",
          "Créez un rôle dédié, limitez-le aux schémas nécessaires et privilégiez la lecture seule.",
          `CREATE ROLE mcp_reader LOGIN;\nGRANT CONNECT ON DATABASE app TO mcp_reader;\nGRANT SELECT ON ALL TABLES IN SCHEMA reporting TO mcp_reader;`,
          "MCP-AUTHZ-01",
        ),
      );
    }

    if (
      url.startsWith("https://") &&
      !hasConfiguredAuthentication(config)
    ) {
      findings.push(
        makeFinding(
          `${safeId}-auth`,
          "medium",
          "Authentification distante à confirmer",
          "Aucun mécanisme d’authentification n’est visible dans cette configuration statique.",
          "Vérifiez que le serveur impose OAuth 2.1 ou un jeton court, lié à l’audience et injecté hors configuration.",
          `"headers": {\n  "Authorization": "Bearer \${MCP_ACCESS_TOKEN}"\n}`,
          "MCP-AUTHN-01",
        ),
      );
    }

    const status = serverStatus(findings);
    const score = serverScore(findings);

    return {
      id: `imported-${safeId}`,
      name,
      owner: "Non attribué",
      transport: url ? (url.startsWith("https") ? "HTTPS" : "HTTP") : "Stdio",
      source: "Import local",
      score,
      status,
      controls: SECURITY_RULES.length,
      findings,
      lastScan: "à l’instant",
      components,
    };
  });
}

export function calculateAuditMetrics(servers: McpServer[]): AuditMetrics {
  const findings = servers.flatMap((server) => server.findings);

  return {
    score: servers.length
      ? Math.round(
          servers.reduce((sum, server) => sum + server.score, 0) /
            servers.length,
        )
      : 0,
    controls: servers.reduce((sum, server) => sum + server.controls, 0),
    critical: findings.filter(
      (finding) => finding.severity === "critical",
    ).length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    toFix: findings.length,
    secure: servers.filter((server) => server.status === "secure").length,
  };
}

function cloneForReport(server: McpServer): McpServer {
  return {
    ...server,
    findings: server.findings.map((finding) => ({ ...finding })),
    components: server.components?.map((component) => ({
      ...component,
      dependencies: component.dependencies
        ? [...component.dependencies]
        : undefined,
      vulnerabilities: component.vulnerabilities?.map((vulnerability) => ({
        ...vulnerability,
        aliases: [...vulnerability.aliases],
      })),
    })),
    vulnerabilityScan: server.vulnerabilityScan
      ? { ...server.vulnerabilityScan }
      : undefined,
    provenanceScan: server.provenanceScan
      ? { ...server.provenanceScan }
      : undefined,
    ociVerification: server.ociVerification
      ? { ...server.ociVerification }
      : undefined,
    componentGraph: server.componentGraph
      ? {
          ...server.componentGraph,
          lockfiles: [...server.componentGraph.lockfiles],
          workspaces: server.componentGraph.workspaces
            ? [...server.componentGraph.workspaces]
            : undefined,
        }
      : undefined,
  };
}

export function createAuditReport(
  servers: McpServer[],
  generatedAt = new Date(),
): AuditReport {
  return {
    schemaVersion: "1.0",
    generatedAt: generatedAt.toISOString(),
    generator: {
      name: "Secure MPC",
      version: "1.0.0",
    },
    summary: {
      servers: servers.length,
      ...calculateAuditMetrics(servers),
    },
    servers: servers.map(cloneForReport),
  };
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical") return "error";
  if (severity === "high") return "warning";
  return "note";
}

export function createSarifReport(
  servers: McpServer[],
  generatedAt = new Date(),
) {
  const findings = servers.flatMap((server) =>
    server.findings.map((finding) => ({ server, finding })),
  );
  const usedRules = new Map(
    findings.map(({ finding }) => [
      finding.rule,
      SECURITY_RULES.find((rule) => rule.code === finding.rule) ?? {
        code: finding.rule,
        title: finding.title,
        detail: finding.description,
        category: "MCP",
      },
    ]),
  );

  return {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Secure MPC",
            version: "1.0.0",
            informationUri: "https://github.com/mawoole/SecureMPC",
            rules: [...usedRules.values()].map((rule) => ({
              id: rule.code,
              name: rule.title,
              shortDescription: { text: rule.title },
              fullDescription: { text: rule.detail },
              properties: { category: rule.category },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: generatedAt.toISOString(),
          },
        ],
        results: findings.map(({ server, finding }) => ({
          ruleId: finding.rule,
          level: sarifLevel(finding.severity),
          message: {
            text: `${server.name}: ${finding.title}. ${finding.remediation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: `mcp-config://server/${encodeURIComponent(server.name)}`,
                },
              },
            },
          ],
          properties: {
            severity: finding.severity,
            serverId: server.id,
            findingId: finding.id,
            serverScore: server.score,
          },
        })),
      },
    ],
  };
}
