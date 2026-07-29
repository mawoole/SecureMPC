import type {
  ComponentVulnerability,
  SupplyChainComponent,
  VulnerabilitySeverity,
} from "./supply-chain.ts";

const OSV_API = "https://api.osv.dev/v1";
const MAX_COMPONENTS_PER_QUERY = 1_000;
const DETAIL_CONCURRENCY = 8;

export type VulnerabilityScanSummary = {
  provider: "OSV.dev";
  status: "complete" | "partial" | "error";
  checkedAt: string;
  queriedComponents: number;
  skippedComponents: number;
  vulnerabilities: number;
  message: string;
};

export type OsvScanResult = {
  components: SupplyChainComponent[];
  summary: VulnerabilityScanSummary;
};

type OsvReference = {
  type?: unknown;
  url?: unknown;
};

type OsvAffected = {
  package?: {
    purl?: unknown;
  };
  ranges?: Array<{
    type?: unknown;
    events?: Array<{
      fixed?: unknown;
    }>;
  }>;
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
};

type OsvRecord = {
  id?: unknown;
  aliases?: unknown;
  summary?: unknown;
  modified?: unknown;
  withdrawn?: unknown;
  references?: OsvReference[];
  affected?: OsvAffected[];
  database_specific?: Record<string, unknown>;
};

type OsvBatchResult = {
  vulns?: Array<{
    id?: unknown;
    modified?: unknown;
  }>;
  next_page_token?: unknown;
};

function cleanText(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned ? cleaned.slice(0, 500) : fallback;
}

function severityFromValue(value: unknown): VulnerabilitySeverity | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.toLowerCase();
  if (normalized.includes("critical")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("moderate") || normalized.includes("medium")) {
    return "medium";
  }
  if (normalized.includes("low")) return "low";
  return undefined;
}

function purlPackageKey(purl: string): string {
  const withoutQualifiers = purl.split(/[?#]/, 1)[0];
  const versionSeparator = withoutQualifiers.lastIndexOf("@");
  return versionSeparator > "pkg:".length
    ? withoutQualifiers.slice(0, versionSeparator)
    : withoutQualifiers;
}

function affectedForPurl(
  record: OsvRecord,
  targetPurl: string,
): OsvAffected[] {
  const affected = record.affected ?? [];
  const targetKey = purlPackageKey(targetPurl);
  const matches = affected.filter(
    (entry) =>
      typeof entry.package?.purl === "string" &&
      purlPackageKey(entry.package.purl) === targetKey,
  );
  return matches.length ? matches : affected;
}

function recordSeverity(
  record: OsvRecord,
  affected: OsvAffected[],
): VulnerabilitySeverity {
  const candidates: unknown[] = [record.database_specific?.severity];
  for (const entry of affected) {
    candidates.push(
      entry.ecosystem_specific?.severity,
      entry.database_specific?.severity,
    );
  }

  for (const candidate of candidates) {
    const severity = severityFromValue(candidate);
    if (severity) return severity;
  }
  return "unknown";
}

function fixedVersion(affected: OsvAffected[]): string | undefined {
  for (const entry of affected) {
    const ranges = [...(entry.ranges ?? [])].sort((left, right) => {
      if (left.type === "ECOSYSTEM") return -1;
      if (right.type === "ECOSYSTEM") return 1;
      if (left.type === "GIT") return 1;
      if (right.type === "GIT") return -1;
      return 0;
    });
    for (const range of ranges) {
      if (range.type === "GIT") continue;
      for (const event of range.events ?? []) {
        if (typeof event.fixed === "string" && event.fixed.trim()) {
          const value = event.fixed.trim();
          if (/^[a-f0-9]{40,64}$/i.test(value)) continue;
          return value.slice(0, 100);
        }
      }
    }
  }
  return undefined;
}

function advisoryUrl(record: OsvRecord, id: string): string {
  const references = (record.references ?? []).filter(
    (reference): reference is { type?: string; url: string } =>
      typeof reference.url === "string" &&
      reference.url.startsWith("https://"),
  );
  const preferred =
    references.find((reference) => reference.type === "ADVISORY") ??
    references.find((reference) => reference.type === "REPORT") ??
    references[0];
  return preferred?.url.slice(0, 2_048) ??
    `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

function normalizeRecord(
  record: OsvRecord,
  fallbackId: string,
  fallbackModified?: string,
  targetPurl?: string,
): ComponentVulnerability | undefined {
  if (record.withdrawn) return undefined;
  const id =
    typeof record.id === "string" && record.id.trim()
      ? record.id.trim().slice(0, 100)
      : fallbackId;
  const aliases = Array.isArray(record.aliases)
    ? record.aliases
        .filter((alias): alias is string => typeof alias === "string")
        .map((alias) => alias.trim().slice(0, 100))
        .filter(Boolean)
        .slice(0, 10)
    : [];
  const affected = targetPurl
    ? affectedForPurl(record, targetPurl)
    : (record.affected ?? []);

  return {
    id,
    aliases,
    summary: cleanText(record.summary, `Avis de sécurité ${id}`),
    severity: recordSeverity(record, affected),
    modified:
      typeof record.modified === "string"
        ? record.modified
        : fallbackModified,
    advisoryUrl: advisoryUrl(record, id),
    fixedVersion: fixedVersion(affected),
  };
}

async function mapWithConcurrency<T, R>(
  values: T[],
  concurrency: number,
  mapper: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let cursor = 0;

  async function worker() {
    while (cursor < values.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await mapper(values[index]);
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(concurrency, values.length) },
      () => worker(),
    ),
  );
  return results;
}

function emptySummary(
  now: () => Date,
  skippedComponents: number,
): VulnerabilityScanSummary {
  return {
    provider: "OSV.dev",
    status: "complete",
    checkedAt: now().toISOString(),
    queriedComponents: 0,
    skippedComponents,
    vulnerabilities: 0,
    message:
      "Aucun composant avec une version exacte et un PURL n’était interrogeable.",
  };
}

export async function scanComponentsWithOsv(
  components: SupplyChainComponent[],
  options: {
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
    now?: () => Date;
  } = {},
): Promise<OsvScanResult> {
  const now = options.now ?? (() => new Date());
  const eligibleByPurl = new Map<string, SupplyChainComponent[]>();
  for (const component of components) {
    if (
      component.purl &&
      component.version &&
      component.pinStatus === "pinned"
    ) {
      const matches = eligibleByPurl.get(component.purl) ?? [];
      matches.push(component);
      eligibleByPurl.set(component.purl, matches);
    }
  }

  const purls = [...eligibleByPurl.keys()].slice(
    0,
    MAX_COMPONENTS_PER_QUERY,
  );
  const eligibleComponents = [...eligibleByPurl.values()].reduce(
    (total, matches) => total + matches.length,
    0,
  );
  const skippedComponents =
    components.length -
    eligibleComponents +
    Math.max(0, eligibleByPurl.size - MAX_COMPONENTS_PER_QUERY);
  if (!purls.length) {
    return {
      components: components.map((component) => ({ ...component })),
      summary: emptySummary(now, skippedComponents),
    };
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = Math.min(
    30_000,
    Math.max(1_000, options.timeoutMs ?? 15_000),
  );
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const batchResponse = await fetchImpl(`${OSV_API}/querybatch`, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        queries: purls.map((purl) => ({
          package: { purl },
        })),
      }),
    });
    if (!batchResponse.ok) {
      throw new Error(`OSV querybatch HTTP ${batchResponse.status}`);
    }

    const payload = (await batchResponse.json()) as {
      results?: OsvBatchResult[];
    };
    const batchResults = Array.isArray(payload.results)
      ? payload.results
      : [];
    if (batchResults.length !== purls.length) {
      throw new Error("OSV querybatch response mismatch");
    }

    const vulnerabilityMetadata = new Map<
      string,
      { modified?: string; purls: Set<string> }
    >();
    let paginated = false;
    batchResults.forEach((result, index) => {
      if (result.next_page_token) paginated = true;
      for (const vulnerability of result.vulns ?? []) {
        if (typeof vulnerability.id !== "string") continue;
        const existing = vulnerabilityMetadata.get(vulnerability.id) ?? {
          modified:
            typeof vulnerability.modified === "string"
              ? vulnerability.modified
              : undefined,
          purls: new Set<string>(),
        };
        existing.purls.add(purls[index]);
        vulnerabilityMetadata.set(vulnerability.id, existing);
      }
    });

    let missingDetails = false;
    const records = await mapWithConcurrency(
      [...vulnerabilityMetadata.entries()],
      DETAIL_CONCURRENCY,
      async ([id, metadata]) => {
        try {
          const response = await fetchImpl(
            `${OSV_API}/vulns/${encodeURIComponent(id)}`,
            {
              method: "GET",
              redirect: "error",
              signal: controller.signal,
              headers: { Accept: "application/json" },
            },
          );
          if (!response.ok) throw new Error(`OSV detail HTTP ${response.status}`);
          return {
            id,
            metadata,
            record: (await response.json()) as OsvRecord,
          };
        } catch {
          missingDetails = true;
          return {
            id,
            metadata,
            record: { id, modified: metadata.modified } as OsvRecord,
          };
        }
      },
    );

    const vulnerabilitiesByPurl = new Map<
      string,
      ComponentVulnerability[]
    >();
    const uniqueVulnerabilities = new Set<string>();
    for (const record of records) {
      for (const purl of record.metadata.purls) {
        const vulnerability = normalizeRecord(
          record.record,
          record.id,
          record.metadata.modified,
          purl,
        );
        if (!vulnerability) continue;
        const vulnerabilities = vulnerabilitiesByPurl.get(purl) ?? [];
        vulnerabilities.push(vulnerability);
        vulnerabilitiesByPurl.set(purl, vulnerabilities);
        uniqueVulnerabilities.add(record.id);
      }
    }

    const partial = paginated || missingDetails;
    return {
      components: components.map((component) => ({
        ...component,
        vulnerabilities: component.purl
          ? (vulnerabilitiesByPurl.get(component.purl) ?? [])
          : [],
      })),
      summary: {
        provider: "OSV.dev",
        status: partial ? "partial" : "complete",
        checkedAt: now().toISOString(),
        queriedComponents: purls.length,
        skippedComponents,
        vulnerabilities: uniqueVulnerabilities.size,
        message: partial
          ? "Analyse OSV terminée avec des détails ou pages indisponibles."
          : "Analyse OSV terminée.",
      },
    };
  } catch {
    return {
      components: components.map((component) => ({ ...component })),
      summary: {
        provider: "OSV.dev",
        status: "error",
        checkedAt: now().toISOString(),
        queriedComponents: purls.length,
        skippedComponents,
        vulnerabilities: 0,
        message:
          "OSV.dev n’a pas pu être interrogé. Aucun résultat de vulnérabilité ne doit être considéré comme complet.",
      },
    };
  } finally {
    clearTimeout(timeout);
  }
}
