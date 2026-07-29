export type Severity = "critical" | "high" | "medium";
export type ServerStatus = "critical" | "attention" | "secure";

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
    name: "MCP Sentinel";
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

function findPackageArgument(args: string[]): string | undefined {
  return args.find(
    (arg) =>
      !arg.startsWith("-") &&
      !arg.startsWith("/") &&
      !/^[a-z]:[\\/]/i.test(arg) &&
      /[a-z0-9@/_-]+/i.test(arg),
  );
}

function isPackagePinned(packageName: string): boolean {
  if (packageName.endsWith("@latest")) return false;
  return /(?:^|\/)[^@/]+@\d+\.\d+\.\d+(?:[-+][a-z0-9.-]+)?$/i.test(
    packageName,
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

  const container = extractServerContainer(parsed as Record<string, unknown>);

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

    const packageArgument = findPackageArgument(args);
    if (
      command.toLowerCase().includes("npx") &&
      packageArgument &&
      !isPackagePinned(packageArgument)
    ) {
      findings.push(
        makeFinding(
          `${safeId}-version`,
          "high",
          "Paquet non verrouillé",
          "Le gestionnaire peut télécharger et exécuter une version différente sans revue préalable.",
          "Indiquez une version exacte et effectuez les mises à jour dans une procédure contrôlée.",
          `"args": ["-y", "${packageArgument.replace(/@latest$/, "")}@1.0.0"]`,
          "MCP-SUP-02",
        ),
      );
    }

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
      name: "MCP Sentinel",
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
            name: "MCP Sentinel",
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
            serverScore: server.score,
          },
        })),
      },
    ],
  };
}
