import type { Finding, McpServer, Severity } from "./audit-engine.ts";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 3,
  high: 2,
  medium: 1,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "critique",
  high: "élevé",
  medium: "moyen",
};

export type SecurityGateOptions = {
  threshold?: Severity;
  requireServers?: boolean;
};

export type BlockingFinding = {
  serverId: string;
  serverName: string;
  finding: Finding;
};

export type SecurityGateResult = {
  passed: boolean;
  threshold?: Severity;
  requireServers: boolean;
  servers: number;
  findings: Record<Severity, number>;
  blockingFindings: BlockingFinding[];
  missingRequiredServers: boolean;
};

export function severityAtOrAbove(
  severity: Severity,
  threshold: Severity,
): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

export function evaluateSecurityGate(
  servers: McpServer[],
  options: SecurityGateOptions,
): SecurityGateResult {
  const findings = servers.flatMap((server) =>
    server.findings.map((finding) => ({
      serverId: server.id,
      serverName: server.name,
      finding,
    })),
  );
  const threshold = options.threshold;
  const blockingFindings = threshold
    ? findings
        .filter(({ finding }) =>
          severityAtOrAbove(finding.severity, threshold),
        )
        .sort(
          (left, right) =>
            SEVERITY_RANK[right.finding.severity] -
              SEVERITY_RANK[left.finding.severity] ||
            left.serverName.localeCompare(right.serverName) ||
            left.finding.rule.localeCompare(right.finding.rule),
        )
    : [];
  const missingRequiredServers =
    Boolean(options.requireServers) && servers.length === 0;

  return {
    passed: !missingRequiredServers && blockingFindings.length === 0,
    threshold: options.threshold,
    requireServers: Boolean(options.requireServers),
    servers: servers.length,
    findings: {
      critical: findings.filter(
        ({ finding }) => finding.severity === "critical",
      ).length,
      high: findings.filter(({ finding }) => finding.severity === "high")
        .length,
      medium: findings.filter(
        ({ finding }) => finding.severity === "medium",
      ).length,
    },
    blockingFindings,
    missingRequiredServers,
  };
}

export function formatSecurityGateSummary(
  result: SecurityGateResult,
  maximumDetails = 20,
): string {
  const lines = [
    `[Secure MPC] Contrôle CI : ${result.passed ? "RÉUSSI" : "ÉCHEC"}.`,
    `${result.servers} serveur${result.servers === 1 ? "" : "s"} audité${result.servers === 1 ? "" : "s"} ; ${result.findings.critical} critique${result.findings.critical === 1 ? "" : "s"}, ${result.findings.high} élevé${result.findings.high === 1 ? "" : "s"}, ${result.findings.medium} moyen${result.findings.medium === 1 ? "" : "s"}.`,
  ];

  if (result.threshold) {
    lines.push(
      `Seuil bloquant : ${SEVERITY_LABEL[result.threshold]} et niveaux supérieurs.`,
    );
  }
  if (result.missingRequiredServers) {
    lines.push(
      "Aucun serveur MCP n’a été découvert alors que --require-servers est actif.",
    );
  }

  for (const entry of result.blockingFindings.slice(0, maximumDetails)) {
    lines.push(
      `- [${entry.finding.severity.toUpperCase()}] ${entry.serverName} · ${entry.finding.rule} · ${entry.finding.title}`,
    );
  }
  const omitted = result.blockingFindings.length - maximumDetails;
  if (omitted > 0) {
    lines.push(
      `- ${omitted} constat${omitted === 1 ? "" : "s"} bloquant${omitted === 1 ? "" : "s"} supplémentaire${omitted === 1 ? "" : "s"} dans le rapport SARIF.`,
    );
  }

  return lines.join("\n");
}
