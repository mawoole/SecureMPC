import type { McpServer, Severity } from "./audit-engine.ts";
import {
  openFindingEntries,
  riskExceptionStatus,
  type RiskException,
} from "./finding-exceptions.ts";

export type TrustMapCiOptions = {
  configPath: string;
  failOn: Severity;
  sarif: boolean;
  sbom: boolean;
  osv: boolean;
  provenance: boolean;
  requireServers: boolean;
};

export type TrustMapCiEnvironment =
  | "development"
  | "staging"
  | "production";

export type TrustMapCiPolicyProfile = TrustMapCiOptions & {
  id: string;
  name: string;
  environment: TrustMapCiEnvironment;
  enabled: boolean;
};

export type DistributionItem = {
  label: string;
  count: number;
  percentage: number;
};

export type DiscoverSummary = {
  servers: number;
  sources: DistributionItem[];
  transports: DistributionItem[];
  components: number;
  pinnedComponents: number;
  provenanceVerified: number;
};

export type CiGatePreview = {
  passed: boolean;
  blockingFindings: number;
  threshold: Severity;
  label: string;
};

export type EnterpriseOwnerSummary = {
  owner: string;
  servers: number;
  averageScore: number;
  openCritical: number;
};

export type EnterpriseSummary = {
  servers: number;
  owners: EnterpriseOwnerSummary[];
  ownershipCoverage: number;
  provenanceCoverage: number;
  openCritical: number;
  activeExceptions: number;
  expiringExceptions: number;
  readinessScore: number;
};

const severityRank: Record<Severity, number> = {
  critical: 3,
  high: 2,
  medium: 1,
};

export const DEFAULT_TRUSTMAP_CI_PROFILES: TrustMapCiPolicyProfile[] = [
  {
    id: "development",
    name: "Développement",
    environment: "development",
    enabled: true,
    configPath: "./.mcp/development.json",
    failOn: "critical",
    sarif: false,
    sbom: false,
    osv: false,
    provenance: false,
    requireServers: true,
  },
  {
    id: "staging",
    name: "Préproduction",
    environment: "staging",
    enabled: true,
    configPath: "./.mcp/staging.json",
    failOn: "high",
    sarif: true,
    sbom: true,
    osv: true,
    provenance: true,
    requireServers: true,
  },
  {
    id: "production",
    name: "Production",
    environment: "production",
    enabled: true,
    configPath: "./.mcp/production.json",
    failOn: "medium",
    sarif: true,
    sbom: true,
    osv: true,
    provenance: true,
    requireServers: true,
  },
];

function distribution(values: string[]): DistributionItem[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    const label = value.trim() || "Non renseigné";
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, count]) => ({
      label,
      count,
      percentage: values.length ? Math.round((count / values.length) * 100) : 0,
    }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
}

export function createDiscoverSummary(servers: McpServer[]): DiscoverSummary {
  const components = servers.flatMap((server) => server.components ?? []);
  return {
    servers: servers.length,
    sources: distribution(servers.map((server) => server.source)),
    transports: distribution(servers.map((server) => server.transport)),
    components: components.length,
    pinnedComponents: components.filter((component) => component.pinStatus === "pinned")
      .length,
    provenanceVerified: components.filter(
      (component) =>
        component.provenance?.registrySignature === "verified" ||
        component.provenance?.slsaProvenance === "verified",
    ).length,
  };
}

function shellArgument(value: string): string {
  const trimmed = value.trim();
  if (
    !trimmed ||
    trimmed.length > 500 ||
    /[\u0000-\u001f\u007f$`;&|<>]/.test(trimmed)
  ) {
    throw new Error("Le chemin de configuration contient des caractères non autorisés.");
  }
  if (/^[A-Za-z0-9_./@:-]+$/.test(trimmed)) return trimmed;
  return `'${trimmed.replaceAll("'", "'\"'\"'")}'`;
}

function artifactSuffix(value?: string): string {
  const normalized = value
    ?.trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized ? `-${normalized.slice(0, 48)}` : "";
}

function createCiCommandForProfile(
  options: TrustMapCiOptions,
  profileId?: string,
): string {
  const suffix = artifactSuffix(profileId);
  const args = [
    "npm run collect --",
    "--no-default-paths",
    `--path ${shellArgument(options.configPath || "./.mcp.json")}`,
    `--fail-on ${options.failOn}`,
  ];
  if (options.requireServers) args.push("--require-servers");
  if (options.osv) args.push("--osv");
  if (options.provenance) args.push("--provenance");
  if (options.sbom) args.push(`--sbom ./mcp-trustmap${suffix}.cdx.json`);
  if (options.sarif) args.push(`--sarif ./mcp-trustmap${suffix}.sarif`);
  return args.join(" ");
}

export function createCiCommand(options: TrustMapCiOptions): string {
  return createCiCommandForProfile(options);
}

export function createGithubActionsWorkflow(options: TrustMapCiOptions): string {
  const auditCommand = createCiCommand(options);
  const sarifSteps = options.sarif
    ? `
      - name: Publier les constats SARIF
        if: always() && hashFiles('mcp-trustmap.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: mcp-trustmap.sarif`
    : "";
  const securityPermission = options.sarif
    ? "\n  security-events: write"
    : "";

  return `name: MCP TrustMap

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read${securityPermission}

jobs:
  trustmap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: 22.13
          cache: npm
      - run: npm ci
      - name: Appliquer la politique MCP TrustMap
        run: ${auditCommand}${sarifSteps}
`;
}

function jobId(profile: TrustMapCiPolicyProfile): string {
  const normalized = profile.id
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!normalized) {
    throw new Error("Chaque politique CI doit avoir un identifiant exploitable.");
  }
  return `trustmap_${normalized.slice(0, 48)}`;
}

function yamlString(value: string): string {
  return JSON.stringify(value);
}

export function createMultiEnvironmentWorkflow(
  profiles: TrustMapCiPolicyProfile[],
): string {
  const activeProfiles = profiles.filter((profile) => profile.enabled);
  if (!activeProfiles.length) {
    throw new Error("Activez au moins une politique CI.");
  }

  const usedJobs = new Set<string>();
  const jobs = activeProfiles.map((profile) => {
    const profileName = profile.name.trim();
    if (
      !profileName ||
      profileName.length > 60 ||
      /[\u0000-\u001f\u007f]/.test(profileName)
    ) {
      throw new Error("Chaque politique CI doit avoir un nom valide.");
    }
    const id = jobId(profile);
    if (usedJobs.has(id)) {
      throw new Error("Les identifiants de politique CI doivent être uniques.");
    }
    usedJobs.add(id);
    const command = createCiCommandForProfile(profile, profile.id);
    const suffix = artifactSuffix(profile.id);
    const sarifStep = profile.sarif
      ? `
      - name: Publier les constats SARIF
        if: always() && hashFiles('mcp-trustmap${suffix}.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: mcp-trustmap${suffix}.sarif
          category: ${yamlString(`mcp-trustmap/${profile.environment}`)}`
      : "";

    return `  ${id}:
    name: ${yamlString(`TrustMap · ${profileName}`)}
    runs-on: ubuntu-latest
    environment: ${yamlString(profile.environment)}
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: 22.13
          cache: npm
      - run: npm ci --ignore-scripts --no-audit --no-fund
      - name: ${yamlString(`Appliquer la politique ${profileName}`)}
        run: ${command}${sarifStep}`;
  });

  const securityPermission = activeProfiles.some((profile) => profile.sarif)
    ? "\n  security-events: write"
    : "";

  return `name: MCP TrustMap policies

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read${securityPermission}

jobs:
${jobs.join("\n\n")}
`;
}

export function evaluateCiGate(
  servers: McpServer[],
  exceptions: RiskException[],
  threshold: Severity,
): CiGatePreview {
  const blockingFindings = openFindingEntries(servers, exceptions).filter(
    ({ finding }) => severityRank[finding.severity] >= severityRank[threshold],
  ).length;
  return {
    passed: blockingFindings === 0,
    blockingFindings,
    threshold,
    label:
      blockingFindings === 0
        ? "La politique réussirait sur l’inventaire actuel."
        : `${blockingFindings} écart${blockingFindings > 1 ? "s" : ""} bloquerai${blockingFindings > 1 ? "ent" : "t"} la livraison.`,
  };
}

export function createEnterpriseSummary(
  servers: McpServer[],
  exceptions: RiskException[],
  now = new Date(),
): EnterpriseSummary {
  const owners = new Map<string, McpServer[]>();
  for (const server of servers) {
    const owner = server.owner.trim() || "Non attribué";
    owners.set(owner, [...(owners.get(owner) ?? []), server]);
  }

  const openEntries = openFindingEntries(servers, exceptions, now);
  const ownerSummaries = [...owners.entries()]
    .map(([owner, ownerServers]) => ({
      owner,
      servers: ownerServers.length,
      averageScore: Math.round(
        ownerServers.reduce((sum, server) => sum + server.score, 0) /
          ownerServers.length,
      ),
      openCritical: openEntries.filter(
        ({ server, finding }) =>
          (server.owner.trim() || "Non attribué") === owner &&
          finding.severity === "critical",
      ).length,
    }))
    .sort(
      (left, right) =>
        right.openCritical - left.openCritical ||
        left.averageScore - right.averageScore ||
        left.owner.localeCompare(right.owner),
    );

  const assigned = servers.filter(
    (server) => server.owner.trim() && server.owner !== "Non attribué",
  ).length;
  const components = servers.flatMap((server) => server.components ?? []);
  const verified = components.filter(
    (component) =>
      component.provenance?.registrySignature === "verified" ||
      component.provenance?.slsaProvenance === "verified",
  ).length;
  const active = exceptions.filter(
    (exception) => riskExceptionStatus(exception, now) === "active",
  );
  const thirtyDays = 30 * 24 * 60 * 60 * 1_000;
  const ownershipCoverage = servers
    ? Math.round((assigned / servers.length) * 100)
    : 0;
  const provenanceCoverage = components
    ? Math.round((verified / components.length) * 100)
    : 0;
  const openCritical = openEntries.filter(
    ({ finding }) => finding.severity === "critical",
  ).length;
  const readinessScore = Math.round(
    ownershipCoverage * 0.35 +
      provenanceCoverage * 0.25 +
      (openCritical === 0 ? 25 : Math.max(0, 25 - openCritical * 5)) +
      (servers.length ? 15 : 0),
  );

  return {
    servers: servers.length,
    owners: ownerSummaries,
    ownershipCoverage,
    provenanceCoverage,
    openCritical,
    activeExceptions: active.length,
    expiringExceptions: active.filter(
      (exception) =>
        Date.parse(exception.expiresAt) - now.getTime() <= thirtyDays,
    ).length,
    readinessScore,
  };
}

export function createEnterprisePolicyPack(
  servers: McpServer[],
  exceptions: RiskException[],
  generatedAt = new Date(),
) {
  const summary = createEnterpriseSummary(servers, exceptions, generatedAt);
  return {
    schemaVersion: "1.0",
    generatedAt: generatedAt.toISOString(),
    generator: { name: "MCP TrustMap", module: "TrustMap Enterprise" },
    policy: {
      minimumOwnershipCoverage: 100,
      minimumProvenanceCoverage: 80,
      maximumOpenCritical: 0,
      maximumExceptionDays: 30,
    },
    summary,
    owners: summary.owners,
    activeExceptions: exceptions
      .filter(
        (exception) =>
          riskExceptionStatus(exception, generatedAt) === "active",
      )
      .map((exception) => ({
        id: exception.id,
        owner: exception.owner,
        serverId: exception.serverId,
        rule: exception.rule,
        expiresAt: exception.expiresAt,
        reason: exception.reason,
      })),
  };
}
