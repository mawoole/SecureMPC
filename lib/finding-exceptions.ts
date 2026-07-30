import {
  createAuditReport,
  createSarifReport,
  type Finding,
  type McpServer,
} from "./audit-engine.ts";

export type RiskExceptionStatus = "active" | "expired" | "revoked";

export type RiskException = {
  schemaVersion: "1.0";
  id: string;
  serverId: string;
  serverName: string;
  findingId: string;
  rule: string;
  findingTitle: string;
  reason: string;
  owner: string;
  createdAt: string;
  expiresAt: string;
  revokedAt?: string;
};

export type RiskExceptionInput = {
  id: string;
  server: McpServer;
  finding: Finding;
  reason: string;
  owner: string;
  expiresAt: string;
};

const MAX_EXCEPTION_DURATION_MS = 366 * 24 * 60 * 60 * 1_000;
const MAX_STORED_EXCEPTIONS = 1_000;

function isIsoDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 40 &&
    Number.isFinite(Date.parse(value))
  );
}

function isStoredRiskException(value: unknown): value is RiskException {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;
  return (
    record.schemaVersion === "1.0" &&
    typeof record.id === "string" &&
    record.id.length > 0 &&
    record.id.length <= 120 &&
    typeof record.serverId === "string" &&
    record.serverId.length > 0 &&
    record.serverId.length <= 200 &&
    typeof record.serverName === "string" &&
    record.serverName.length > 0 &&
    record.serverName.length <= 200 &&
    typeof record.findingId === "string" &&
    record.findingId.length > 0 &&
    record.findingId.length <= 240 &&
    typeof record.rule === "string" &&
    record.rule.length > 0 &&
    record.rule.length <= 80 &&
    typeof record.findingTitle === "string" &&
    record.findingTitle.length > 0 &&
    record.findingTitle.length <= 240 &&
    typeof record.reason === "string" &&
    record.reason.length >= 12 &&
    record.reason.length <= 500 &&
    typeof record.owner === "string" &&
    record.owner.length >= 2 &&
    record.owner.length <= 80 &&
    isIsoDate(record.createdAt) &&
    isIsoDate(record.expiresAt) &&
    (record.revokedAt === undefined || isIsoDate(record.revokedAt))
  );
}

export function findingExceptionKey(
  server: Pick<McpServer, "id">,
  finding: Pick<Finding, "id" | "rule">,
): string {
  return `${server.id}\u001f${finding.rule}\u001f${finding.id}`;
}

function exceptionKey(exception: RiskException): string {
  return `${exception.serverId}\u001f${exception.rule}\u001f${exception.findingId}`;
}

export function riskExceptionStatus(
  exception: RiskException,
  now = new Date(),
): RiskExceptionStatus {
  if (exception.revokedAt) return "revoked";
  return Date.parse(exception.expiresAt) > now.getTime() ? "active" : "expired";
}

export function createRiskException(
  input: RiskExceptionInput,
  now = new Date(),
): RiskException {
  const id = input.id.trim();
  const reason = input.reason.trim();
  const owner = input.owner.trim();
  const expiresAt = new Date(input.expiresAt);

  if (!id || id.length > 120) {
    throw new Error("L’identifiant de l’exception est invalide.");
  }
  if (reason.length < 12 || reason.length > 500) {
    throw new Error("Le motif doit contenir entre 12 et 500 caractères.");
  }
  if (owner.length < 2 || owner.length > 80) {
    throw new Error("Le responsable doit contenir entre 2 et 80 caractères.");
  }
  if (!Number.isFinite(expiresAt.getTime())) {
    throw new Error("La date d’expiration est invalide.");
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw new Error("La date d’expiration doit être future.");
  }
  if (expiresAt.getTime() - now.getTime() > MAX_EXCEPTION_DURATION_MS) {
    throw new Error("Une exception ne peut pas dépasser 366 jours.");
  }

  return {
    schemaVersion: "1.0",
    id,
    serverId: input.server.id,
    serverName: input.server.name.slice(0, 200),
    findingId: input.finding.id,
    rule: input.finding.rule,
    findingTitle: input.finding.title.slice(0, 240),
    reason,
    owner,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}

export function revokeRiskException(
  exception: RiskException,
  revokedAt = new Date(),
): RiskException {
  if (riskExceptionStatus(exception, revokedAt) !== "active") {
    return exception;
  }
  return { ...exception, revokedAt: revokedAt.toISOString() };
}

export function parseRiskExceptions(serialized: string | null): RiskException[] {
  if (!serialized) return [];

  try {
    const parsed: unknown = JSON.parse(serialized);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(isStoredRiskException)
      .slice(0, MAX_STORED_EXCEPTIONS)
      .map((exception) => ({ ...exception }));
  } catch {
    return [];
  }
}

export function findActiveRiskException(
  server: Pick<McpServer, "id">,
  finding: Pick<Finding, "id" | "rule">,
  exceptions: RiskException[],
  now = new Date(),
): RiskException | undefined {
  const key = findingExceptionKey(server, finding);
  return exceptions.find(
    (exception) =>
      exceptionKey(exception) === key &&
      riskExceptionStatus(exception, now) === "active",
  );
}

export function findLatestRiskException(
  server: Pick<McpServer, "id">,
  finding: Pick<Finding, "id" | "rule">,
  exceptions: RiskException[],
): RiskException | undefined {
  const key = findingExceptionKey(server, finding);
  return exceptions
    .filter((exception) => exceptionKey(exception) === key)
    .sort(
      (left, right) =>
        Date.parse(right.createdAt) - Date.parse(left.createdAt),
    )[0];
}

export function openFindingEntries(
  servers: McpServer[],
  exceptions: RiskException[],
  now = new Date(),
): { server: McpServer; finding: Finding }[] {
  return servers.flatMap((server) =>
    server.findings
      .filter(
        (finding) =>
          !findActiveRiskException(server, finding, exceptions, now),
      )
      .map((finding) => ({ server, finding })),
  );
}

function exceptionSnapshot(exception: RiskException, now: Date) {
  return {
    ...exception,
    status: riskExceptionStatus(exception, now),
  };
}

export function createGovernedAuditReport(
  servers: McpServer[],
  exceptions: RiskException[],
  generatedAt = new Date(),
) {
  const report = createAuditReport(servers, generatedAt);
  const activeKeys = new Set(
    exceptions
      .filter(
        (exception) =>
          riskExceptionStatus(exception, generatedAt) === "active",
      )
      .map(exceptionKey),
  );
  const acceptedFindingKeys = new Set<string>();

  const annotatedServers = report.servers.map((server) => ({
    ...server,
    findings: server.findings.map((finding) => {
      const key = findingExceptionKey(server, finding);
      const matching = exceptions
        .filter((exception) => exceptionKey(exception) === key)
        .sort(
          (left, right) =>
            Date.parse(right.createdAt) - Date.parse(left.createdAt),
        );
      const current =
        matching.find(
          (exception) =>
            riskExceptionStatus(exception, generatedAt) === "active",
        ) ?? matching[0];

      if (activeKeys.has(key)) acceptedFindingKeys.add(key);
      return current
        ? {
            ...finding,
            riskException: exceptionSnapshot(current, generatedAt),
          }
        : finding;
    }),
  }));

  const statuses = exceptions.map((exception) =>
    riskExceptionStatus(exception, generatedAt),
  );

  return {
    ...report,
    schemaVersion: "1.1" as const,
    summary: {
      ...report.summary,
      openFindings: Math.max(
        0,
        report.summary.toFix - acceptedFindingKeys.size,
      ),
      acceptedFindings: acceptedFindingKeys.size,
      activeExceptions: statuses.filter((status) => status === "active").length,
      expiredExceptions: statuses.filter((status) => status === "expired")
        .length,
      revokedExceptions: statuses.filter((status) => status === "revoked")
        .length,
    },
    riskExceptions: exceptions
      .map((exception) => exceptionSnapshot(exception, generatedAt))
      .sort(
        (left, right) =>
          Date.parse(right.createdAt) - Date.parse(left.createdAt),
      ),
    servers: annotatedServers,
  };
}

export function createGovernedSarifReport(
  servers: McpServer[],
  exceptions: RiskException[],
  generatedAt = new Date(),
) {
  const report = createSarifReport(servers, generatedAt);

  return {
    ...report,
    runs: report.runs.map((run) => ({
      ...run,
      results: run.results.map((result) => {
        const exception = exceptions.find(
          (candidate) =>
            candidate.serverId === result.properties.serverId &&
            candidate.findingId === result.properties.findingId &&
            candidate.rule === result.ruleId &&
            riskExceptionStatus(candidate, generatedAt) === "active",
        );

        if (!exception) return result;
        return {
          ...result,
          suppressions: [
            {
              kind: "external" as const,
              status: "accepted" as const,
              justification: `${exception.reason} Responsable : ${exception.owner}. Expiration : ${exception.expiresAt}.`,
            },
          ],
          properties: {
            ...result.properties,
            riskExceptionId: exception.id,
            riskExceptionOwner: exception.owner,
            riskExceptionExpiresAt: exception.expiresAt,
          },
        };
      }),
    })),
  };
}
