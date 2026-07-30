import {
  calculateAuditMetrics,
  type McpServer,
  type Severity,
} from "./audit-engine.ts";

export const AUDIT_HISTORY_LIMIT = 60;

export type AuditHistorySource = "manual" | "import" | "discovery";

export type AuditRuleSummary = {
  rule: string;
  severity: Severity;
  count: number;
};

export type AuditHistoryPayload = {
  source: AuditHistorySource;
  score: number;
  servers: number;
  critical: number;
  high: number;
  medium: number;
  toFix: number;
  secure: number;
  rules: AuditRuleSummary[];
};

export type AuditHistoryRecord = AuditHistoryPayload & {
  id: string;
  createdAt: string;
};

export type AuditHistoryComparison = {
  scoreDelta: number;
  findingDelta: number;
  criticalDelta: number;
  introducedFindings: number;
  resolvedFindings: number;
};

export class AuditHistoryValidationError extends Error {}

const SOURCE_VALUES = new Set<AuditHistorySource>([
  "manual",
  "import",
  "discovery",
]);
const SEVERITY_VALUES = new Set<Severity>([
  "critical",
  "high",
  "medium",
]);
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 3,
  high: 2,
  medium: 1,
};

function integerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
  field: string,
): number {
  if (
    !Number.isInteger(value) ||
    Number(value) < minimum ||
    Number(value) > maximum
  ) {
    throw new AuditHistoryValidationError(`${field} est invalide.`);
  }
  return Number(value);
}

function parseRules(value: unknown): AuditRuleSummary[] {
  if (!Array.isArray(value) || value.length > 100) {
    throw new AuditHistoryValidationError(
      "Le résumé des règles est invalide.",
    );
  }

  const seen = new Set<string>();
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new AuditHistoryValidationError(
        "Une règle de l’historique est invalide.",
      );
    }
    const record = entry as Record<string, unknown>;
    const rule =
      typeof record.rule === "string" ? record.rule.trim() : "";
    const severity =
      typeof record.severity === "string"
        ? (record.severity as Severity)
        : undefined;
    if (
      !/^[A-Z0-9][A-Z0-9._-]{1,63}$/.test(rule) ||
      !severity ||
      !SEVERITY_VALUES.has(severity) ||
      seen.has(rule)
    ) {
      throw new AuditHistoryValidationError(
        "Une règle de l’historique est invalide.",
      );
    }
    seen.add(rule);
    return {
      rule,
      severity,
      count: integerInRange(record.count, 1, 10_000, "count"),
    };
  });
}

export function createAuditHistoryPayload(
  servers: McpServer[],
  source: AuditHistorySource,
): AuditHistoryPayload {
  if (!servers.length) {
    throw new AuditHistoryValidationError(
      "Aucun serveur MCP ne peut être enregistré.",
    );
  }
  const metrics = calculateAuditMetrics(servers);
  const ruleMap = new Map<string, AuditRuleSummary>();

  for (const finding of servers.flatMap((server) => server.findings)) {
    const current = ruleMap.get(finding.rule);
    ruleMap.set(finding.rule, {
      rule: finding.rule,
      severity:
        current &&
        SEVERITY_RANK[current.severity] > SEVERITY_RANK[finding.severity]
          ? current.severity
          : finding.severity,
      count: (current?.count ?? 0) + 1,
    });
  }

  return {
    source,
    score: metrics.score,
    servers: servers.length,
    critical: metrics.critical,
    high: metrics.high,
    medium: metrics.medium,
    toFix: metrics.toFix,
    secure: metrics.secure,
    rules: [...ruleMap.values()].sort((left, right) =>
      left.rule.localeCompare(right.rule),
    ),
  };
}

export function parseAuditHistoryPayload(
  value: unknown,
): AuditHistoryPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AuditHistoryValidationError(
      "Le résumé d’audit est invalide.",
    );
  }
  const record = value as Record<string, unknown>;
  const source =
    typeof record.source === "string"
      ? (record.source as AuditHistorySource)
      : undefined;
  if (!source || !SOURCE_VALUES.has(source)) {
    throw new AuditHistoryValidationError(
      "La source de l’audit est invalide.",
    );
  }

  const payload: AuditHistoryPayload = {
    source,
    score: integerInRange(record.score, 0, 100, "score"),
    servers: integerInRange(record.servers, 1, 10_000, "servers"),
    critical: integerInRange(record.critical, 0, 100_000, "critical"),
    high: integerInRange(record.high, 0, 100_000, "high"),
    medium: integerInRange(record.medium, 0, 100_000, "medium"),
    toFix: integerInRange(record.toFix, 0, 100_000, "toFix"),
    secure: integerInRange(record.secure, 0, 10_000, "secure"),
    rules: parseRules(record.rules),
  };

  if (
    payload.critical + payload.high + payload.medium !== payload.toFix ||
    payload.secure > payload.servers ||
    payload.rules.reduce((sum, rule) => sum + rule.count, 0) !== payload.toFix
  ) {
    throw new AuditHistoryValidationError(
      "Les compteurs de l’audit sont incohérents.",
    );
  }
  return payload;
}

export function parseAuditHistoryRecords(
  value: unknown,
): AuditHistoryRecord[] {
  if (!Array.isArray(value) || value.length > AUDIT_HISTORY_LIMIT) {
    throw new AuditHistoryValidationError(
      "La réponse d’historique est invalide.",
    );
  }

  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new AuditHistoryValidationError(
        "Une entrée d’historique est invalide.",
      );
    }
    const record = entry as Record<string, unknown>;
    const id = typeof record.id === "string" ? record.id : "";
    const createdAt =
      typeof record.createdAt === "string" ? record.createdAt : "";
    if (
      !/^[0-9a-f-]{36}$/i.test(id) ||
      !createdAt ||
      !Number.isFinite(Date.parse(createdAt))
    ) {
      throw new AuditHistoryValidationError(
        "Une entrée d’historique est invalide.",
      );
    }
    return {
      id,
      createdAt,
      ...parseAuditHistoryPayload(record),
    };
  });
}

export function compareAuditHistory(
  current: AuditHistoryRecord,
  previous?: AuditHistoryRecord,
): AuditHistoryComparison {
  if (!previous) {
    return {
      scoreDelta: 0,
      findingDelta: 0,
      criticalDelta: 0,
      introducedFindings: 0,
      resolvedFindings: 0,
    };
  }

  const currentRules = new Map(
    current.rules.map((rule) => [rule.rule, rule.count]),
  );
  const previousRules = new Map(
    previous.rules.map((rule) => [rule.rule, rule.count]),
  );
  const rules = new Set([...currentRules.keys(), ...previousRules.keys()]);
  let introducedFindings = 0;
  let resolvedFindings = 0;

  for (const rule of rules) {
    const delta =
      (currentRules.get(rule) ?? 0) - (previousRules.get(rule) ?? 0);
    if (delta > 0) introducedFindings += delta;
    if (delta < 0) resolvedFindings += Math.abs(delta);
  }

  return {
    scoreDelta: current.score - previous.score,
    findingDelta: current.toFix - previous.toFix,
    criticalDelta: current.critical - previous.critical,
    introducedFindings,
    resolvedFindings,
  };
}

function csvCell(value: string | number): string {
  const text = String(value);
  return /[;"\r\n]/.test(text)
    ? `"${text.replaceAll('"', '""')}"`
    : text;
}

export function createAuditHistoryCsv(
  history: AuditHistoryRecord[],
): string {
  const chronological = [...history].reverse();
  const header = [
    "audit_id",
    "created_at",
    "source",
    "score",
    "servers",
    "secure_servers",
    "critical",
    "high",
    "medium",
    "open_findings",
    "score_delta",
    "finding_delta",
    "introduced_findings",
    "resolved_findings",
    "rules",
  ];
  const rows = chronological.map((entry, index) => {
    const comparison = compareAuditHistory(
      entry,
      chronological[index - 1],
    );
    const rules = [...entry.rules]
      .sort((left, right) => left.rule.localeCompare(right.rule))
      .map((rule) => `${rule.rule}:${rule.severity}:${rule.count}`)
      .join("|");
    return [
      entry.id,
      entry.createdAt,
      entry.source,
      entry.score,
      entry.servers,
      entry.secure,
      entry.critical,
      entry.high,
      entry.medium,
      entry.toFix,
      comparison.scoreDelta,
      comparison.findingDelta,
      comparison.introducedFindings,
      comparison.resolvedFindings,
      rules,
    ]
      .map(csvCell)
      .join(";");
  });

  return `\uFEFFsep=;\r\n${header.join(";")}\r\n${rows.join("\r\n")}${rows.length ? "\r\n" : ""}`;
}
