import { readFile, readdir, stat } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
} from "node:path";
import { parse as parseYaml } from "yaml";

const MAX_MANIFEST_BYTES = 1_000_000;
const MAX_WORKSPACE_PACKAGES = 250;
const MAX_DISCOVERY_DEPTH = 6;
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".next",
  ".turbo",
  ".yarn",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "target",
]);

export type WorkspacePackage = {
  path: string;
  absolutePath: string;
  name: string;
  version?: string;
  private: boolean;
  dependencies: string[];
};

type PackageManifest = Record<string, unknown>;

function cleanText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  return cleaned && cleaned.length <= maxLength ? cleaned : undefined;
}

function normalizeRelativePath(value: string): string {
  const normalized = value.replaceAll("\\", "/").replace(/^\.\/+/, "");
  return normalized === "" ? "." : normalized.replace(/\/+$/, "");
}

function workspacePatterns(manifest: PackageManifest): string[] {
  if (Array.isArray(manifest.workspaces)) {
    return manifest.workspaces.flatMap((value) => {
      const pattern = cleanText(value, 500);
      return pattern ? [normalizeRelativePath(pattern)] : [];
    });
  }
  if (
    manifest.workspaces &&
    typeof manifest.workspaces === "object" &&
    !Array.isArray(manifest.workspaces)
  ) {
    const packages = (manifest.workspaces as PackageManifest).packages;
    if (Array.isArray(packages)) {
      return packages.flatMap((value) => {
        const pattern = cleanText(value, 500);
        return pattern ? [normalizeRelativePath(pattern)] : [];
      });
    }
  }
  return [];
}

function pnpmWorkspacePatterns(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const packages = (value as PackageManifest).packages;
  if (!Array.isArray(packages)) return [];
  return packages.flatMap((value) => {
    const pattern = cleanText(value, 500);
    return pattern ? [normalizeRelativePath(pattern)] : [];
  });
}

function globPattern(pattern: string): RegExp {
  let result = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*" && pattern[index + 1] === "*") {
      result += ".*";
      index += 1;
    } else if (character === "*") {
      result += "[^/]*";
    } else if (character === "?") {
      result += "[^/]";
    } else {
      result += character.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
    }
  }
  return new RegExp(`${result}$`);
}

function matchesPatterns(path: string, patterns: string[]): boolean {
  const positive = patterns.filter((pattern) => !pattern.startsWith("!"));
  const negative = patterns
    .filter((pattern) => pattern.startsWith("!"))
    .map((pattern) => pattern.slice(1));
  const included =
    path === "." || positive.some((pattern) => globPattern(pattern).test(path));
  return (
    included &&
    !negative.some((pattern) => globPattern(pattern).test(path))
  );
}

async function readJsonManifest(
  filePath: string,
): Promise<PackageManifest | undefined> {
  try {
    if ((await stat(filePath)).size > MAX_MANIFEST_BYTES) return undefined;
    const parsed = JSON.parse(await readFile(filePath, "utf8")) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as PackageManifest)
      : undefined;
  } catch {
    return undefined;
  }
}

function dependencyNames(manifest: PackageManifest): string[] {
  const dependencies = new Set<string>();
  for (const key of [
    "dependencies",
    "optionalDependencies",
    "devDependencies",
  ]) {
    const section = manifest[key];
    if (!section || typeof section !== "object" || Array.isArray(section)) {
      continue;
    }
    for (const name of Object.keys(section)) {
      const cleaned = cleanText(name, 214);
      if (cleaned && !/[\s\\]/.test(cleaned)) dependencies.add(cleaned);
    }
  }
  return [...dependencies];
}

async function discoverManifestPaths(root: string): Promise<string[]> {
  const results: string[] = [];
  async function visit(directory: string, depth: number): Promise<void> {
    if (
      depth > MAX_DISCOVERY_DEPTH ||
      results.length >= MAX_WORKSPACE_PACKAGES
    ) {
      return;
    }
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    if (entries.some((entry) => entry.isFile() && entry.name === "package.json")) {
      results.push(resolve(directory, "package.json"));
    }
    await Promise.all(
      entries
        .filter(
          (entry) =>
            entry.isDirectory() &&
            !entry.isSymbolicLink() &&
            !IGNORED_DIRECTORIES.has(entry.name),
        )
        .map((entry) => visit(resolve(directory, entry.name), depth + 1)),
    );
  }
  await visit(root, 0);
  return results.slice(0, MAX_WORKSPACE_PACKAGES);
}

export async function discoverWorkspacePackages(
  workspace: string,
): Promise<WorkspacePackage[]> {
  const root = resolve(workspace);
  const rootManifest = await readJsonManifest(resolve(root, "package.json"));
  let patterns = rootManifest ? workspacePatterns(rootManifest) : [];
  try {
    const pnpmRaw = await readFile(resolve(root, "pnpm-workspace.yaml"), "utf8");
    if (pnpmRaw.length <= MAX_MANIFEST_BYTES) {
      patterns = [
        ...patterns,
        ...pnpmWorkspacePatterns(parseYaml(pnpmRaw, { maxAliasCount: 0 })),
      ];
    }
  } catch {
    // A pnpm workspace declaration is optional for npm and Yarn projects.
  }
  const uniquePatterns = [...new Set(patterns)];
  const manifestPaths = uniquePatterns.length
    ? await discoverManifestPaths(root)
    : rootManifest
      ? [resolve(root, "package.json")]
      : [];

  const packages: WorkspacePackage[] = [];
  for (const manifestPath of manifestPaths) {
    const packagePath = normalizeRelativePath(relative(root, dirname(manifestPath)));
    if (
      uniquePatterns.length &&
      !matchesPatterns(packagePath, uniquePatterns)
    ) {
      continue;
    }
    const manifest =
      packagePath === "." && rootManifest
        ? rootManifest
        : await readJsonManifest(manifestPath);
    if (!manifest) continue;
    const name =
      cleanText(manifest.name, 214) ??
      `workspace:${packagePath === "." ? basename(root) : packagePath}`;
    const version = cleanText(manifest.version, 100);
    packages.push({
      path: packagePath,
      absolutePath: dirname(manifestPath),
      name,
      ...(version ? { version } : {}),
      private: manifest.private === true,
      dependencies: dependencyNames(manifest),
    });
  }
  return packages.slice(0, MAX_WORKSPACE_PACKAGES);
}

function containedBy(parent: string, child: string): boolean {
  const childPath = relative(resolve(parent), resolve(child));
  return (
    childPath === "" ||
    (!childPath.startsWith("..") && !isAbsolute(childPath))
  );
}

function commandWorkingDirectory(
  configuration: Record<string, unknown>,
  workspace: string,
): string {
  const configured =
    typeof configuration.cwd === "string" ? configuration.cwd.trim() : "";
  if (!configured) return resolve(workspace);
  return isAbsolute(configured)
    ? resolve(configured)
    : resolve(workspace, configured);
}

function localCommandTarget(
  configuration: Record<string, unknown>,
  workspace: string,
): string | undefined {
  const command =
    typeof configuration.command === "string"
      ? configuration.command.trim()
      : "";
  const args = Array.isArray(configuration.args)
    ? configuration.args.map((value) => String(value))
    : [];
  const cwd = commandWorkingDirectory(configuration, workspace);
  const launcher = command
    .split(/[\\/]/)
    .pop()
    ?.toLowerCase()
    .replace(/\.(?:cmd|bat|exe)$/i, "");
  const pathLike = (value: string) =>
    value.startsWith(".") ||
    value.includes("/") ||
    value.includes("\\") ||
    isAbsolute(value);
  if (pathLike(command)) {
    return isAbsolute(command) ? resolve(command) : resolve(cwd, command);
  }
  if (
    ["node", "deno", "bun", "python", "python3"].includes(launcher ?? "") &&
    args[0] &&
    pathLike(args[0])
  ) {
    return isAbsolute(args[0]) ? resolve(args[0]) : resolve(cwd, args[0]);
  }
  if (
    ["npm", "pnpm", "yarn"].includes(launcher ?? "") &&
    args.some((argument) => argument.toLowerCase() === "run")
  ) {
    return cwd;
  }
  return typeof configuration.cwd === "string" ? cwd : undefined;
}

export function selectWorkspacePackage(
  packages: WorkspacePackage[],
  configuration: Record<string, unknown>,
  workspace: string,
): WorkspacePackage | undefined {
  const target = localCommandTarget(configuration, workspace);
  if (!target) return undefined;
  return packages
    .filter((candidate) => containedBy(candidate.absolutePath, target))
    .sort(
      (left, right) =>
        right.absolutePath.length - left.absolutePath.length,
    )[0];
}
