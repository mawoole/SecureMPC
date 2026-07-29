import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import {
  basename,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  win32,
} from "node:path";
import {
  extractSupplyChainComponents,
  type SupplyChainComponent,
} from "./supply-chain.ts";
import type { VulnerabilityScanSummary } from "./osv.ts";

export const COLLECTOR_SCHEMA_VERSION = "1.0" as const;
export const MCP_PROTOCOL_VERSION = "2025-11-25";
export const REDACTED_VALUE = "${REDACTED}";

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

export type CollectorSource = {
  client: string;
  path: string;
  status: "read" | "missing" | "invalid";
  servers: number;
  message?: string;
};

export type Redaction = {
  path: string;
  kind: "secret" | "url-credential";
};

export type CollectedServer = {
  id: string;
  name: string;
  source: {
    client: string;
    path: string;
  };
  configuration: Record<string, unknown>;
  redactions: Redaction[];
  components: SupplyChainComponent[];
  probe: PassiveProbe;
};

export type CollectorInventory = {
  schemaVersion: typeof COLLECTOR_SCHEMA_VERSION;
  generatedAt: string;
  collector: {
    name: "MCP Sentinel Collector";
    version: string;
    platform: NodeJS.Platform;
    security: {
      secretsRedacted: true;
      configuredCredentialsSent: false;
      stdioProcessesExecuted: false;
    };
  };
  sources: CollectorSource[];
  servers: CollectedServer[];
  vulnerabilityScan?: VulnerabilityScanSummary;
};

export type CandidateFile = {
  client: string;
  path: string;
};

export type DiscoveryContext = {
  platform?: NodeJS.Platform;
  home?: string;
  environment?: NodeJS.ProcessEnv;
  workspace?: string;
};

export type CollectOptions = DiscoveryContext & {
  candidates?: CandidateFile[];
  additionalPaths?: string[];
  probe?: boolean;
  timeoutMs?: number;
  now?: () => Date;
  fetchImpl?: typeof fetch;
};

const SENSITIVE_KEY =
  /(token|secret|password|passwd|api.?key|authorization|credential|private.?key|client.?secret)/i;

function isPlaceholder(value: string): boolean {
  return [
    /\$\{[A-Z_][A-Z0-9_]*\}/i,
    /\$[A-Z_][A-Z0-9_]*/i,
    /%[A-Z_][A-Z0-9_]*%/i,
    /\{\{[^{}]+\}\}/,
    /\b(?:env|secret):[A-Z_][A-Z0-9_]*\b/i,
    /<[^<>]+>/,
  ].some((pattern) => pattern.test(value));
}

function normalizeHomePath(filePath: string, home: string): string {
  const absolutePath = resolve(filePath);
  const homePath = resolve(home);
  const childPath = relative(homePath, absolutePath);
  const normalized =
    childPath && !childPath.startsWith("..") && !isAbsolute(childPath)
      ? join("~", childPath)
      : absolutePath;

  return normalized.replaceAll("\\", "/");
}

function deduplicateCandidates(candidates: CandidateFile[]): CandidateFile[] {
  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    const key = resolve(candidate.path).toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function discoverCandidateFiles(
  context: DiscoveryContext = {},
): CandidateFile[] {
  const platform = context.platform ?? process.platform;
  const home = context.home ?? homedir();
  const environment = context.environment ?? process.env;
  const pathApi = platform === "win32" ? win32 : posix;
  const workspace = pathApi.resolve(context.workspace ?? process.cwd());
  const candidates: CandidateFile[] = [
    {
      client: "Workspace VS Code",
      path: pathApi.join(workspace, ".vscode", "mcp.json"),
    },
    {
      client: "Workspace Cursor",
      path: pathApi.join(workspace, ".cursor", "mcp.json"),
    },
    {
      client: "Cursor",
      path: pathApi.join(home, ".cursor", "mcp.json"),
    },
    {
      client: "Windsurf",
      path: pathApi.join(home, ".codeium", "windsurf", "mcp_config.json"),
    },
  ];

  if (platform === "win32") {
    const appData =
      environment.APPDATA ?? pathApi.join(home, "AppData", "Roaming");
    candidates.push(
      {
        client: "Claude Desktop",
        path: pathApi.join(
          appData,
          "Claude",
          "claude_desktop_config.json",
        ),
      },
      {
        client: "VS Code",
        path: pathApi.join(appData, "Code", "User", "mcp.json"),
      },
      {
        client: "VS Code (settings)",
        path: pathApi.join(appData, "Code", "User", "settings.json"),
      },
    );
  } else if (platform === "darwin") {
    const applicationSupport = pathApi.join(
      home,
      "Library",
      "Application Support",
    );
    candidates.push(
      {
        client: "Claude Desktop",
        path: pathApi.join(
          applicationSupport,
          "Claude",
          "claude_desktop_config.json",
        ),
      },
      {
        client: "VS Code",
        path: pathApi.join(applicationSupport, "Code", "User", "mcp.json"),
      },
      {
        client: "VS Code (settings)",
        path: pathApi.join(
          applicationSupport,
          "Code",
          "User",
          "settings.json",
        ),
      },
    );
  } else {
    const configHome =
      environment.XDG_CONFIG_HOME ?? pathApi.join(home, ".config");
    candidates.push(
      {
        client: "Claude Desktop",
        path: pathApi.join(
          configHome,
          "Claude",
          "claude_desktop_config.json",
        ),
      },
      {
        client: "Claude Desktop",
        path: pathApi.join(
          configHome,
          "claude",
          "claude_desktop_config.json",
        ),
      },
      {
        client: "VS Code",
        path: pathApi.join(configHome, "Code", "User", "mcp.json"),
      },
      {
        client: "VS Code (settings)",
        path: pathApi.join(configHome, "Code", "User", "settings.json"),
      },
    );
  }

  return deduplicateCandidates(candidates);
}

function extractServers(
  parsed: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const nestedMcp =
    parsed.mcp && typeof parsed.mcp === "object" && !Array.isArray(parsed.mcp)
      ? (parsed.mcp as Record<string, unknown>)
      : undefined;
  const candidates = [
    parsed.mcpServers,
    parsed.servers,
    nestedMcp?.servers,
    parsed["mcp.servers"],
  ];

  return candidates.find(
    (candidate): candidate is Record<string, unknown> =>
      Boolean(candidate) &&
      typeof candidate === "object" &&
      !Array.isArray(candidate),
  );
}

function redact(
  redactions: Redaction[],
  path: string,
  kind: Redaction["kind"],
): string {
  redactions.push({ path, kind });
  return REDACTED_VALUE;
}

function sanitizeUrl(
  value: string,
  path: string,
  redactions: Redaction[],
): string {
  try {
    const url = new URL(value);
    let changed = false;

    if (url.username || url.password) {
      url.username = "";
      url.password = "";
      redactions.push({ path: `${path}.userinfo`, kind: "url-credential" });
      changed = true;
    }

    for (const [key, queryValue] of url.searchParams.entries()) {
      if (SENSITIVE_KEY.test(key) && queryValue && !isPlaceholder(queryValue)) {
        url.searchParams.set(key, REDACTED_VALUE);
        redactions.push({
          path: `${path}.query.${key}`,
          kind: "url-credential",
        });
        changed = true;
      }
    }

    return changed ? url.toString() : value;
  } catch {
    return value;
  }
}

function sanitizeString(
  value: string,
  key: string,
  path: string,
  redactions: Redaction[],
  inheritedSensitive: boolean,
): string {
  if ((inheritedSensitive || SENSITIVE_KEY.test(key)) && !isPlaceholder(value)) {
    return redact(redactions, path, "secret");
  }

  if (/^\s*Bearer\s+\S+/i.test(value) && !isPlaceholder(value)) {
    return redact(redactions, path, "secret");
  }

  const argumentSecret = value.match(
    /^(\s*--?(?:token|secret|password|api[-_]?key)=)(.+)$/i,
  );
  if (argumentSecret && !isPlaceholder(argumentSecret[2])) {
    redactions.push({ path, kind: "secret" });
    return `${argumentSecret[1]}${REDACTED_VALUE}`;
  }

  return sanitizeUrl(value, path, redactions);
}

function sanitizeValue(
  value: unknown,
  key: string,
  path: string,
  redactions: Redaction[],
  inheritedSensitive = false,
): unknown {
  const sensitive = inheritedSensitive || SENSITIVE_KEY.test(key);

  if (typeof value === "string") {
    return sanitizeString(value, key, path, redactions, inheritedSensitive);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) =>
      sanitizeValue(item, "", `${path}[${index}]`, redactions, sensitive),
    );
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(
        ([childKey, childValue]) => [
          childKey,
          sanitizeValue(
            childValue,
            childKey,
            path ? `${path}.${childKey}` : childKey,
            redactions,
            sensitive,
          ),
        ],
      ),
    );
  }

  if (sensitive && value !== undefined && value !== null) {
    return redact(redactions, path, "secret");
  }

  return value;
}

export function sanitizeConfiguration(
  configuration: Record<string, unknown>,
): { configuration: Record<string, unknown>; redactions: Redaction[] } {
  const redactions: Redaction[] = [];
  const sanitized = sanitizeValue(
    configuration,
    "",
    "configuration",
    redactions,
  ) as Record<string, unknown>;

  return {
    configuration: sanitized,
    redactions: redactions.filter(
      (redaction, index, all) =>
        all.findIndex(
          (candidate) =>
            candidate.path === redaction.path &&
            candidate.kind === redaction.kind,
        ) === index,
    ),
  };
}

function parseSsePayload(body: string): unknown {
  const eventPayloads = body
    .split(/\r?\n\r?\n/)
    .map((event) =>
      event
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trimStart())
        .join("\n"),
    )
    .filter(Boolean);

  for (const payload of eventPayloads) {
    try {
      const parsed = JSON.parse(payload) as { id?: unknown };
      if (parsed.id === 1) return parsed;
    } catch {
      // Ignore keep-alives and non-JSON events.
    }
  }

  throw new Error("La réponse SSE ne contient pas de résultat initialize.");
}

async function parseInitializeResponse(response: Response): Promise<{
  protocolVersion: string;
  capabilities: string[];
  serverName?: string;
  serverVersion?: string;
}> {
  const contentType = response.headers.get("content-type") ?? "";
  const payload = contentType.includes("text/event-stream")
    ? parseSsePayload(await response.text())
    : await response.json();

  if (!payload || typeof payload !== "object") {
    throw new Error("La réponse initialize n’est pas un objet JSON-RPC.");
  }

  const envelope = payload as Record<string, unknown>;
  if (envelope.error) {
    throw new Error("Le serveur a refusé la négociation MCP.");
  }

  const result =
    envelope.result &&
    typeof envelope.result === "object" &&
    !Array.isArray(envelope.result)
      ? (envelope.result as Record<string, unknown>)
      : undefined;
  if (!result || typeof result.protocolVersion !== "string") {
    throw new Error("La réponse initialize est incomplète.");
  }

  const capabilities =
    result.capabilities &&
    typeof result.capabilities === "object" &&
    !Array.isArray(result.capabilities)
      ? Object.keys(result.capabilities as Record<string, unknown>).sort()
      : [];
  const serverInfo =
    result.serverInfo &&
    typeof result.serverInfo === "object" &&
    !Array.isArray(result.serverInfo)
      ? (result.serverInfo as Record<string, unknown>)
      : undefined;

  return {
    protocolVersion: result.protocolVersion,
    capabilities,
    serverName:
      typeof serverInfo?.name === "string" ? serverInfo.name : undefined,
    serverVersion:
      typeof serverInfo?.version === "string" ? serverInfo.version : undefined,
  };
}

function probeResult(
  status: ProbeStatus,
  startedAt: number,
  now: () => Date,
  message: string,
  details: Partial<PassiveProbe> = {},
): PassiveProbe {
  return {
    status,
    checkedAt: now().toISOString(),
    durationMs: Math.max(0, Date.now() - startedAt),
    message,
    ...details,
  };
}

export async function probeConfiguration(
  configuration: Record<string, unknown>,
  options: {
    timeoutMs?: number;
    now?: () => Date;
    fetchImpl?: typeof fetch;
  } = {},
): Promise<PassiveProbe> {
  const now = options.now ?? (() => new Date());
  const startedAt = Date.now();
  const url =
    typeof configuration.url === "string" ? configuration.url.trim() : "";

  if (!url) {
    return probeResult(
      "skipped-stdio",
      startedAt,
      now,
      "Probe ignoré : aucun processus stdio n’est exécuté par le collecteur.",
    );
  }

  if (url.startsWith("http://")) {
    return probeResult(
      "skipped-insecure",
      startedAt,
      now,
      "Probe ignoré : le collecteur ne contacte jamais un endpoint HTTP non chiffré.",
    );
  }

  if (!url.startsWith("https://")) {
    return probeResult(
      "protocol-error",
      startedAt,
      now,
      "Le transport distant n’utilise pas une URL HTTPS valide.",
    );
  }

  const timeoutMs = Math.min(
    15_000,
    Math.max(500, options.timeoutMs ?? 5_000),
  );
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const initializeResponse = await fetchImpl(url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: {
            name: "mcp-sentinel-collector",
            version: "1.2.0",
          },
        },
      }),
    });

    if (
      initializeResponse.status === 401 ||
      initializeResponse.status === 403
    ) {
      return probeResult(
        "auth-required",
        startedAt,
        now,
        "Le serveur répond et exige une authentification. Aucun identifiant découvert n’a été envoyé.",
        { httpStatus: initializeResponse.status },
      );
    }

    if (!initializeResponse.ok) {
      return probeResult(
        "protocol-error",
        startedAt,
        now,
        `Le serveur a répondu HTTP ${initializeResponse.status} à initialize.`,
        { httpStatus: initializeResponse.status },
      );
    }

    const negotiated = await parseInitializeResponse(initializeResponse);
    const sessionId = initializeResponse.headers.get("mcp-session-id");
    const followUpHeaders: Record<string, string> = {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      "MCP-Protocol-Version": negotiated.protocolVersion,
    };
    if (sessionId) followUpHeaders["MCP-Session-Id"] = sessionId;

    const initializedResponse = await fetchImpl(url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: followUpHeaders,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
    });

    if (!initializedResponse.ok) {
      return probeResult(
        "protocol-error",
        startedAt,
        now,
        `La négociation a réussi, mais la notification initialized a répondu HTTP ${initializedResponse.status}.`,
        {
          httpStatus: initializedResponse.status,
          ...negotiated,
        },
      );
    }

    if (sessionId) {
      await fetchImpl(url, {
        method: "DELETE",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          Accept: "application/json, text/event-stream",
          "MCP-Protocol-Version": negotiated.protocolVersion,
          "MCP-Session-Id": sessionId,
        },
      }).catch(() => undefined);
    }

    return probeResult(
      "reachable",
      startedAt,
      now,
      "Négociation MCP réussie sans appel d’outil.",
      {
        httpStatus: initializeResponse.status,
        ...negotiated,
      },
    );
  } catch (error) {
    const aborted =
      controller.signal.aborted ||
      (error instanceof Error && error.name === "AbortError");
    return probeResult(
      aborted ? "timeout" : "unreachable",
      startedAt,
      now,
      aborted
        ? `Le serveur n’a pas répondu en ${timeoutMs} ms.`
        : "Le serveur n’est pas joignable ou la connexion TLS a échoué.",
    );
  } finally {
    clearTimeout(timeout);
  }
}

function notRequestedProbe(now: () => Date): PassiveProbe {
  return {
    status: "not-requested",
    checkedAt: now().toISOString(),
    durationMs: 0,
    message: "Probe réseau non demandé.",
  };
}

function stableServerId(sourcePath: string, name: string): string {
  return createHash("sha256")
    .update(`${resolve(sourcePath)}\0${name}`)
    .digest("hex")
    .slice(0, 16);
}

export async function collectInventory(
  options: CollectOptions = {},
): Promise<CollectorInventory> {
  const now = options.now ?? (() => new Date());
  const home = options.home ?? homedir();
  const defaults =
    options.candidates ??
    discoverCandidateFiles({
      platform: options.platform,
      home,
      environment: options.environment,
      workspace: options.workspace,
    });
  const additional = (options.additionalPaths ?? []).map((filePath) => ({
    client: `Fichier explicite (${basename(filePath)})`,
    path: resolve(filePath),
  }));
  const candidates = deduplicateCandidates([...defaults, ...additional]);
  const sources: CollectorSource[] = [];
  const servers: CollectedServer[] = [];

  for (const candidate of candidates) {
    const safePath = normalizeHomePath(candidate.path, home);
    let raw: string;
    try {
      raw = await readFile(candidate.path, "utf8");
    } catch (error) {
      const missing =
        error &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "ENOENT";
      sources.push({
        client: candidate.client,
        path: safePath,
        status: missing ? "missing" : "invalid",
        servers: 0,
        message: missing
          ? "Fichier absent."
          : "Fichier inaccessible avec les permissions actuelles.",
      });
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      sources.push({
        client: candidate.client,
        path: safePath,
        status: "invalid",
        servers: 0,
        message: "JSON invalide.",
      });
      continue;
    }

    const container =
      parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? extractServers(parsed as Record<string, unknown>)
        : undefined;
    if (!container) {
      sources.push({
        client: candidate.client,
        path: safePath,
        status: "invalid",
        servers: 0,
        message: "Aucun objet de serveurs MCP reconnu.",
      });
      continue;
    }

    let sourceServerCount = 0;
    for (const [name, value] of Object.entries(container)) {
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      const sanitized = sanitizeConfiguration(
        value as Record<string, unknown>,
      );
      const components = extractSupplyChainComponents(
        sanitized.configuration,
      );
      const probe = options.probe
        ? await probeConfiguration(sanitized.configuration, {
            timeoutMs: options.timeoutMs,
            now,
            fetchImpl: options.fetchImpl,
          })
        : notRequestedProbe(now);

      servers.push({
        id: stableServerId(candidate.path, name),
        name,
        source: {
          client: candidate.client,
          path: safePath,
        },
        configuration: sanitized.configuration,
        redactions: sanitized.redactions,
        components,
        probe,
      });
      sourceServerCount += 1;
    }

    sources.push({
      client: candidate.client,
      path: safePath,
      status: "read",
      servers: sourceServerCount,
      message:
        sourceServerCount > 0
          ? undefined
          : "Le fichier ne contient aucun serveur valide.",
    });
  }

  return {
    schemaVersion: COLLECTOR_SCHEMA_VERSION,
    generatedAt: now().toISOString(),
    collector: {
      name: "MCP Sentinel Collector",
      version: "1.2.0",
      platform: options.platform ?? process.platform,
      security: {
        secretsRedacted: true,
        configuredCredentialsSent: false,
        stdioProcessesExecuted: false,
      },
    },
    sources,
    servers,
  };
}
