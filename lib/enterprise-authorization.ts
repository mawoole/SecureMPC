import type { Severity } from "./audit-engine.ts";
import {
  riskExceptionStatus,
  type RiskException,
} from "./finding-exceptions.ts";

export type EnterpriseRole = "reader" | "auditor" | "admin";

export type EnterpriseCapabilities = {
  canRead: true;
  canSync: boolean;
  canApprove: boolean;
  canReject: boolean;
  canRevoke: boolean;
};

export type EnterpriseActor = {
  actorHash: string;
  displayName: string;
  role: EnterpriseRole;
};

export type ExceptionDecision = "approve" | "reject";

export class EnterpriseAuthorizationError extends Error {
  readonly status: 403 | 404 | 409;

  constructor(message: string, status: 403 | 404 | 409) {
    super(message);
    this.status = status;
  }
}

const ROLE_VALUES = new Set<EnterpriseRole>(["reader", "auditor", "admin"]);
const SEVERITY_RANK: Record<Severity, number> = {
  medium: 1,
  high: 2,
  critical: 3,
};

const RULE_SEVERITY_FLOORS: Record<string, Severity> = {
  "MCP-SEC-01": "critical",
  "MCP-AUTHN-01": "medium",
  "MCP-AUTHZ-01": "high",
  "MCP-AUTHZ-03": "critical",
  "MCP-NET-01": "critical",
  "MCP-SUP-02": "high",
  "MCP-EXEC-01": "critical",
  "MCP-EXEC-02": "critical",
  "MCP-AUDIT-01": "medium",
  "MCP-DATA-01": "medium",
  "MCP-PROTO-01": "medium",
  "MCP-VULN-01": "medium",
  "MCP-SUP-03": "medium",
};

export function roleCapabilities(
  role: EnterpriseRole,
): EnterpriseCapabilities {
  return {
    canRead: true,
    canSync: role !== "reader",
    canApprove: role !== "reader",
    canReject: role === "admin",
    canRevoke: role !== "reader",
  };
}

export function resolveEnterpriseRole(
  email: string | null,
  runtime: Record<string, unknown>,
  localPreview = false,
): EnterpriseRole {
  if (localPreview) return "admin";
  if (!email) return "reader";
  const configured = runtime.TRUSTMAP_ROLE_BINDINGS;
  if (typeof configured !== "string" || configured.length > 50_000) {
    return "reader";
  }
  try {
    const parsed: unknown = JSON.parse(configured);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return "reader";
    }
    const value = (parsed as Record<string, unknown>)[email.toLowerCase()];
    return typeof value === "string" &&
      ROLE_VALUES.has(value as EnterpriseRole)
      ? (value as EnterpriseRole)
      : "reader";
  } catch {
    return "reader";
  }
}

export function authoritativeSeverity(
  rule: string,
  claimed?: Severity,
): Severity {
  const floor = RULE_SEVERITY_FLOORS[rule] ?? "critical";
  if (!claimed) return floor;
  return SEVERITY_RANK[claimed] >= SEVERITY_RANK[floor] ? claimed : floor;
}

export function normalizeStoredRiskException(
  exception: RiskException,
  originalActorHash: string,
): RiskException {
  const severity = authoritativeSeverity(exception.rule, exception.severity);
  if (severity !== "critical") {
    return { ...exception, severity, approval: undefined };
  }
  if (exception.approval) {
    return { ...exception, severity };
  }
  return {
    ...exception,
    severity,
    approval: {
      status: "pending",
      requiredApprovals: 2,
      requestedBy: originalActorHash,
      requestedAt: exception.createdAt,
      approvals: [],
    },
  };
}

export function prepareRiskExceptionForSync(
  incoming: RiskException,
  actorHash: string,
  existing?: RiskException,
): RiskException {
  if (existing) {
    const normalized = normalizeStoredRiskException(existing, actorHash);
    if (incoming.revokedAt && !normalized.revokedAt) {
      return { ...normalized, revokedAt: incoming.revokedAt };
    }
    return normalized;
  }

  const severity = authoritativeSeverity(incoming.rule, incoming.severity);
  const prepared: RiskException = {
    ...incoming,
    severity,
    approval: undefined,
  };
  if (severity !== "critical") return prepared;
  return {
    ...prepared,
    approval: {
      status: "pending",
      requiredApprovals: 2,
      requestedBy: actorHash,
      requestedAt: new Date().toISOString(),
      approvals: [],
    },
  };
}

export function applyRiskExceptionDecision(
  exception: RiskException,
  actor: Pick<EnterpriseActor, "actorHash" | "role">,
  decision: ExceptionDecision,
  now = new Date(),
): RiskException {
  const capabilities = roleCapabilities(actor.role);
  if (!capabilities.canApprove) {
    throw new EnterpriseAuthorizationError(
      "Le rôle lecteur ne peut pas approuver une exception.",
      403,
    );
  }
  if (decision === "reject" && !capabilities.canReject) {
    throw new EnterpriseAuthorizationError(
      "Seul un administrateur peut rejeter une exception.",
      403,
    );
  }
  if (
    exception.severity !== "critical" ||
    !exception.approval ||
    riskExceptionStatus(exception, now) !== "pending"
  ) {
    throw new EnterpriseAuthorizationError(
      "Cette exception n’est pas en attente d’approbation.",
      409,
    );
  }
  if (actor.actorHash === exception.approval.requestedBy) {
    throw new EnterpriseAuthorizationError(
      "Le demandeur ne peut pas approuver ou rejeter sa propre exception.",
      409,
    );
  }
  if (
    exception.approval.approvals.some(
      (approval) => approval.actorRef === actor.actorHash,
    )
  ) {
    throw new EnterpriseAuthorizationError(
      "Cet approbateur a déjà validé cette exception.",
      409,
    );
  }

  const decidedAt = now.toISOString();
  if (decision === "reject") {
    return {
      ...exception,
      approval: {
        ...exception.approval,
        status: "rejected",
        rejectedBy: actor.actorHash,
        rejectedAt: decidedAt,
      },
    };
  }

  const approvals = [
    ...exception.approval.approvals,
    { actorRef: actor.actorHash, approvedAt: decidedAt },
  ].slice(0, exception.approval.requiredApprovals);
  return {
    ...exception,
    approval: {
      ...exception.approval,
      status:
        approvals.length === exception.approval.requiredApprovals
          ? "approved"
          : "pending",
      approvals,
    },
  };
}
