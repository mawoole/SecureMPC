import { readFile, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import type { SupplyChainComponent } from "./supply-chain.ts";

const MAX_LOCKFILE_BYTES = 20_000_000;
const MAX_COMPONENTS_PER_LOCKFILE = 5_000;
const MAX_TRANSITIVE_COMPONENTS_PER_SERVER = 1_000;

export const SUPPORTED_LOCKFILES = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "uv.lock",
  "poetry.lock",
] as const;

export type LockfileFormat = "npm" | "uv" | "poetry";
export type LockfileStatus = "read" | "partial" | "missing" | "invalid";

export type LockfileSummary = {
  path: string;
  format: LockfileFormat;
  ecosystem: "npm" | "pypi";
  status: LockfileStatus;
  components: number;
  matchedServers: number;
  message: string;
};

export type LockfileAnalysis = {
  summary: LockfileSummary;
  components: SupplyChainComponent[];
};

type PackageRecord = Record<string, unknown>;

function cleanText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  return cleaned && cleaned.length <= maxLength ? cleaned : undefined;
}

function packageName(
  value: unknown,
  ecosystem: "npm" | "pypi",
): string | undefined {
  const name = cleanText(value, ecosystem === "npm" ? 214 : 200);
  if (!name || /[\s\\]/.test(name)) return undefined;
  return ecosystem === "pypi"
    ? name.toLowerCase().replace(/[_.]+/g, "-")
    : name;
}

function packageVersion(value: unknown): string | undefined {
  const version = cleanText(value, 100);
  return version && !/[\s/\\]/.test(version) ? version : undefined;
}

function encodePurlName(name: string): string {
  return name
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function purl(
  ecosystem: "npm" | "pypi",
  name: string,
  version: string,
): string {
  const type = ecosystem === "npm" ? "npm" : "pypi";
  return `pkg:${type}/${encodePurlName(name)}@${encodeURIComponent(version)}`;
}

function graphComponent(
  ecosystem: "npm" | "pypi",
  name: string,
  version: string,
  lockfile: string,
  integrityRecorded: boolean,
): SupplyChainComponent {
  const componentPurl = purl(ecosystem, name, version);
  return {
    id: `${ecosystem}:${encodeURIComponent(name)}@${encodeURIComponent(version)}`,
    ecosystem,
    name,
    version,
    reference:
      ecosystem === "npm" ? `${name}@${version}` : `${name}==${version}`,
    purl: componentPurl,
    componentType: "library",
    pinStatus: "pinned",
    evidence: `Version verrouillée dans ${lockfile}.`,
    scope: "transitive",
    dependencies: [],
    lockfile,
    integrityStatus: integrityRecorded ? "recorded" : "missing",
  };
}

function dependencyNames(record: PackageRecord): string[] {
  const sections = [
    record.dependencies,
    record.optionalDependencies,
    record.peerDependencies,
  ];
  const names = new Set<string>();
  for (const section of sections) {
    if (!section || typeof section !== "object" || Array.isArray(section)) {
      continue;
    }
    for (const name of Object.keys(section)) {
      const safeName = packageName(name, "npm");
      if (safeName) names.add(safeName);
    }
  }
  return [...names];
}

function npmNameFromPath(packagePath: string): string | undefined {
  const normalized = packagePath.replaceAll("\\", "/");
  const marker = "node_modules/";
  const markerIndex = normalized.lastIndexOf(marker);
  if (markerIndex < 0) return undefined;
  const tail = normalized.slice(markerIndex + marker.length);
  const parts = tail.split("/");
  return packageName(
    parts[0]?.startsWith("@") ? `${parts[0]}/${parts[1] ?? ""}` : parts[0],
    "npm",
  );
}

function resolveNpmDependency(
  packagePath: string,
  dependencyName: string,
  records: Map<string, PackageRecord>,
): string | undefined {
  let base = packagePath.replaceAll("\\", "/");
  while (true) {
    const candidate = base
      ? `${base}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`;
    if (records.has(candidate)) return candidate;
    const marker = base.lastIndexOf("/node_modules/");
    if (marker >= 0) {
      base = base.slice(0, marker);
      continue;
    }
    if (base.startsWith("node_modules/")) {
      base = "";
      continue;
    }
    return undefined;
  }
}

function parseModernNpmLock(
  parsed: PackageRecord,
  displayPath: string,
): { components: SupplyChainComponent[]; truncated: boolean } | undefined {
  if (
    !parsed.packages ||
    typeof parsed.packages !== "object" ||
    Array.isArray(parsed.packages)
  ) {
    return undefined;
  }
  const allRecords = new Map(
    Object.entries(parsed.packages as Record<string, unknown>)
      .filter(
        (entry): entry is [string, PackageRecord] =>
          Boolean(entry[1]) &&
          typeof entry[1] === "object" &&
          !Array.isArray(entry[1]),
      )
      .map(([path, record]) => [path.replaceAll("\\", "/"), record]),
  );
  const records = new Map(
    [...allRecords.entries()]
      .filter(([path]) => path.includes("node_modules/"))
      .slice(0, MAX_COMPONENTS_PER_LOCKFILE),
  );
  const byPath = new Map<string, SupplyChainComponent>();

  for (const [path, record] of records) {
    const name =
      packageName(record.name, "npm") ?? npmNameFromPath(path);
    const version = packageVersion(record.version);
    if (!name || !version) continue;
    byPath.set(
      path,
      graphComponent(
        "npm",
        name,
        version,
        displayPath,
        typeof record.integrity === "string",
      ),
    );
  }

  for (const [path, component] of byPath) {
    const record = records.get(path);
    if (!record) continue;
    component.dependencies = dependencyNames(record).flatMap((name) => {
      const dependencyPath = resolveNpmDependency(path, name, allRecords);
      const dependency = dependencyPath
        ? byPath.get(dependencyPath)
        : undefined;
      return dependency?.purl ? [dependency.purl] : [];
    });
  }

  return {
    components: [...byPath.values()],
    truncated:
      [...allRecords.keys()].filter((path) =>
        path.includes("node_modules/"),
      ).length > MAX_COMPONENTS_PER_LOCKFILE,
  };
}

function parseLegacyNpmLock(
  parsed: PackageRecord,
  displayPath: string,
): { components: SupplyChainComponent[]; truncated: boolean } | undefined {
  if (
    !parsed.dependencies ||
    typeof parsed.dependencies !== "object" ||
    Array.isArray(parsed.dependencies)
  ) {
    return undefined;
  }
  const components = new Map<string, SupplyChainComponent>();
  let seen = 0;
  let truncated = false;

  function visit(tree: Record<string, unknown>): string[] {
    const children: string[] = [];
    for (const [rawName, value] of Object.entries(tree)) {
      if (seen >= MAX_COMPONENTS_PER_LOCKFILE) {
        truncated = true;
        break;
      }
      if (!value || typeof value !== "object" || Array.isArray(value)) continue;
      const record = value as PackageRecord;
      const name = packageName(rawName, "npm");
      const version = packageVersion(record.version);
      if (!name || !version) continue;
      seen += 1;
      const component = graphComponent(
        "npm",
        name,
        version,
        displayPath,
        typeof record.integrity === "string",
      );
      const nested =
        record.dependencies &&
        typeof record.dependencies === "object" &&
        !Array.isArray(record.dependencies)
          ? visit(record.dependencies as Record<string, unknown>)
          : [];
      component.dependencies = nested;
      const existing = components.get(component.purl ?? "");
      if (existing) {
        existing.dependencies = [
          ...new Set([
            ...(existing.dependencies ?? []),
            ...component.dependencies,
          ]),
        ];
      } else if (component.purl) {
        components.set(component.purl, component);
      }
      if (component.purl) children.push(component.purl);
    }
    return children;
  }

  visit(parsed.dependencies as Record<string, unknown>);
  return { components: [...components.values()], truncated };
}

function tomlString(block: string, key: string): string | undefined {
  const match = block.match(
    new RegExp(`^${key}\\s*=\\s*["']([^"'\\r\\n]+)["']`, "m"),
  );
  return match?.[1];
}

function pythonDependencyNames(block: string): string[] {
  const names = new Set<string>();
  const arrayStart = block.search(/^dependencies\s*=\s*\[/m);
  if (arrayStart >= 0) {
    const section = block.slice(arrayStart);
    const closing = section.search(/^\]\s*$/m);
    const array = closing >= 0 ? section.slice(0, closing + 1) : section;
    for (const match of array.matchAll(
      /\{\s*name\s*=\s*["']([^"']+)["']/g,
    )) {
      const name = packageName(match[1], "pypi");
      if (name) names.add(name);
    }
  }

  const poetryHeader = /^\[package\.dependencies\]\s*$/m.exec(block);
  let poetrySection: string | undefined;
  if (poetryHeader?.index !== undefined) {
    const remainder = block.slice(
      poetryHeader.index + poetryHeader[0].length,
    );
    const nextHeader = remainder.search(/^\[/m);
    poetrySection =
      nextHeader >= 0 ? remainder.slice(0, nextHeader) : remainder;
  }
  if (poetrySection) {
    for (const match of poetrySection.matchAll(
      /^["']?([A-Za-z0-9_.-]+)["']?\s*=/gm,
    )) {
      const name = packageName(match[1], "pypi");
      if (name && name !== "python") names.add(name);
    }
  }
  return [...names];
}

function parsePythonLock(
  raw: string,
  displayPath: string,
): { components: SupplyChainComponent[]; truncated: boolean } {
  const blocks = raw.split(/^\[\[package\]\]\s*$/m).slice(1);
  const records = blocks
    .slice(0, MAX_COMPONENTS_PER_LOCKFILE)
    .flatMap((block) => {
      const name = packageName(tomlString(block, "name"), "pypi");
      const version = packageVersion(tomlString(block, "version"));
      if (!name || !version) return [];
      return [
        {
          name,
          dependencies: pythonDependencyNames(block),
          component: graphComponent(
            "pypi",
            name,
            version,
            displayPath,
            /\bhash\s*=\s*["']sha(?:256|384|512):/i.test(block),
          ),
        },
      ];
    });
  const byName = new Map<string, SupplyChainComponent[]>();
  for (const record of records) {
    const matches = byName.get(record.name) ?? [];
    matches.push(record.component);
    byName.set(record.name, matches);
  }
  for (const record of records) {
    record.component.dependencies = record.dependencies.flatMap(
      (name) => {
        const matches = byName.get(name) ?? [];
        return matches.length === 1 && matches[0].purl
          ? [matches[0].purl]
          : [];
      },
    );
  }
  return {
    components: records.map((record) => record.component),
    truncated: blocks.length > MAX_COMPONENTS_PER_LOCKFILE,
  };
}

function formatForPath(filePath: string): LockfileFormat {
  const name = basename(filePath).toLowerCase();
  if (name === "uv.lock") return "uv";
  if (name === "poetry.lock") return "poetry";
  return "npm";
}

function ecosystemForFormat(format: LockfileFormat): "npm" | "pypi" {
  return format === "npm" ? "npm" : "pypi";
}

function failedAnalysis(
  displayPath: string,
  format: LockfileFormat,
  status: "missing" | "invalid",
  message: string,
): LockfileAnalysis {
  return {
    summary: {
      path: displayPath,
      format,
      ecosystem: ecosystemForFormat(format),
      status,
      components: 0,
      matchedServers: 0,
      message,
    },
    components: [],
  };
}

export function discoverLockfilePaths(workspace: string): string[] {
  return SUPPORTED_LOCKFILES.map((name) => join(resolve(workspace), name));
}

export async function analyzeLockfile(
  filePath: string,
  displayPath = basename(filePath),
): Promise<LockfileAnalysis> {
  const format = formatForPath(filePath);
  let fileSize: number;
  try {
    fileSize = (await stat(filePath)).size;
  } catch (error) {
    const missing =
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT";
    return failedAnalysis(
      displayPath,
      format,
      missing ? "missing" : "invalid",
      missing ? "Fichier absent." : "Fichier inaccessible.",
    );
  }
  if (fileSize > MAX_LOCKFILE_BYTES) {
    return failedAnalysis(
      displayPath,
      format,
      "invalid",
      "Lockfile ignoré : taille supérieure à 20 Mo.",
    );
  }

  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch {
    return failedAnalysis(
      displayPath,
      format,
      "invalid",
      "Lockfile illisible.",
    );
  }

  try {
    const result =
      format === "npm"
        ? (() => {
            const parsed = JSON.parse(raw) as PackageRecord;
            return (
              parseModernNpmLock(parsed, displayPath) ??
              parseLegacyNpmLock(parsed, displayPath)
            );
          })()
        : parsePythonLock(raw, displayPath);
    if (!result) {
      return failedAnalysis(
        displayPath,
        format,
        "invalid",
        "Structure de lockfile non reconnue.",
      );
    }
    return {
      summary: {
        path: displayPath,
        format,
        ecosystem: ecosystemForFormat(format),
        status: result.truncated ? "partial" : "read",
        components: result.components.length,
        matchedServers: 0,
        message: result.truncated
          ? `Analyse limitée aux ${MAX_COMPONENTS_PER_LOCKFILE} premiers composants.`
          : "Lockfile analysé sans exécuter de gestionnaire de paquets.",
      },
      components: result.components,
    };
  } catch {
    return failedAnalysis(
      displayPath,
      format,
      "invalid",
      "Syntaxe ou structure de lockfile invalide.",
    );
  }
}

function componentKey(
  component: Pick<
    SupplyChainComponent,
    "ecosystem" | "name" | "version"
  >,
): string {
  const name =
    component.ecosystem === "pypi"
      ? component.name.toLowerCase().replace(/[_.]+/g, "-")
      : component.name;
  return `${component.ecosystem}:${name}:${component.version ?? ""}`;
}

export function enrichComponentsFromLockfiles(
  directComponents: SupplyChainComponent[],
  analyses: LockfileAnalysis[],
): {
  components: SupplyChainComponent[];
  matchedLockfiles: Set<string>;
  truncated: boolean;
} {
  const result = new Map<string, SupplyChainComponent>();
  const matchedLockfiles = new Set<string>();
  let truncated = false;
  for (const component of directComponents) {
    const ref = component.purl ?? component.id;
    result.set(ref, { ...component, scope: "direct" });
  }

  for (const analysis of analyses) {
    if (!["read", "partial"].includes(analysis.summary.status)) continue;
    const byRef = new Map<string, SupplyChainComponent>();
    for (const component of analysis.components) {
      if (!component.purl) continue;
      const existing = byRef.get(component.purl);
      byRef.set(
        component.purl,
        existing
          ? {
              ...existing,
              dependencies: [
                ...new Set([
                  ...(existing.dependencies ?? []),
                  ...(component.dependencies ?? []),
                ]),
              ],
            }
          : component,
      );
    }
    const byKey = new Map(
      [...byRef.values()].map((component) => [
        componentKey(component),
        component,
      ]),
    );

    for (const direct of directComponents) {
      if (!direct.version || direct.pinStatus !== "pinned") continue;
      const match = byKey.get(componentKey(direct));
      if (!match) continue;
      matchedLockfiles.add(analysis.summary.path);
      const directRef = direct.purl ?? direct.id;
      const current = result.get(directRef) ?? direct;
      result.set(directRef, {
        ...current,
        scope: "direct",
        dependencies: [
          ...new Set([
            ...(current.dependencies ?? []),
            ...(match.dependencies ?? []),
          ]),
        ],
        lockfile: match.lockfile,
        integrityStatus: match.integrityStatus,
      });

      const queue = [...(match.dependencies ?? [])];
      const visited = new Set<string>();
      while (queue.length) {
        const dependencyRef = queue.shift();
        if (!dependencyRef || visited.has(dependencyRef)) continue;
        visited.add(dependencyRef);
        const dependency = byRef.get(dependencyRef);
        if (!dependency) continue;
        if (result.size >= MAX_TRANSITIVE_COMPONENTS_PER_SERVER) {
          truncated = true;
          break;
        }
        const existing = result.get(dependencyRef);
        result.set(
          dependencyRef,
          existing
            ? {
                ...existing,
                dependencies: [
                  ...new Set([
                    ...(existing.dependencies ?? []),
                    ...(dependency.dependencies ?? []),
                  ]),
                ],
              }
            : { ...dependency, scope: "transitive" },
        );
        queue.push(...(dependency.dependencies ?? []));
      }
    }
  }

  return {
    components: [...result.values()],
    matchedLockfiles,
    truncated,
  };
}
