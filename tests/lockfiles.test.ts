import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  analyzeLockfile,
  enrichComponentsFromLockfiles,
} from "../lib/lockfiles.ts";
import {
  createCycloneDxReport,
  extractSupplyChainComponents,
} from "../lib/supply-chain.ts";

test("resolves an npm package-lock graph with nearest nested dependencies", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-lockfile-npm-"));
  const lockfilePath = join(directory, "package-lock.json");
  try {
    await writeFile(
      lockfilePath,
      JSON.stringify({
        name: "fixture",
        lockfileVersion: 3,
        packages: {
          "": {
            dependencies: {
              "@acme/mcp-server": "1.2.3",
            },
          },
          "node_modules/@acme/mcp-server": {
            name: "@acme/mcp-server",
            version: "1.2.3",
            integrity: "sha512-direct",
            dependencies: { alpha: "^1.0.0" },
          },
          "node_modules/alpha": {
            version: "1.0.0",
            integrity: "sha512-alpha",
            dependencies: { beta: "^2.0.0" },
          },
          "node_modules/alpha/node_modules/beta": {
            version: "2.0.0",
            integrity: "sha512-beta-two",
          },
          "node_modules/beta": {
            version: "9.0.0",
            integrity: "sha512-beta-nine",
          },
        },
      }),
      "utf8",
    );
    const analysis = await analyzeLockfile(
      lockfilePath,
      "package-lock.json",
    );
    const direct = extractSupplyChainComponents({
      command: "npx",
      args: ["-y", "@acme/mcp-server@1.2.3"],
    });
    const enriched = enrichComponentsFromLockfiles(direct, [analysis]);

    assert.equal(analysis.summary.status, "read");
    assert.equal(analysis.summary.components, 4);
    assert.equal(enriched.components.length, 3);
    assert.equal(enriched.matchedLockfiles.has("package-lock.json"), true);
    assert.equal(enriched.components[0].scope, "direct");
    assert.deepEqual(
      enriched.components
        .filter((component) => component.scope === "transitive")
        .map((component) => `${component.name}@${component.version}`)
        .sort(),
      ["alpha@1.0.0", "beta@2.0.0"],
    );
    assert.equal(
      enriched.components.some(
        (component) =>
          component.name === "beta" && component.version === "9.0.0",
      ),
      false,
    );

    const report = createCycloneDxReport(
      [
        {
          id: "server",
          name: "Server",
          transport: "Stdio",
          source: "Test",
          components: enriched.components,
        },
      ],
      new Date("2026-07-29T12:00:00.000Z"),
      "00000000-0000-4000-8000-000000000003",
    );
    const serverDependency = report.dependencies.find(
      (dependency) => dependency.ref === "urn:mcp-server:server",
    );
    const directDependency = report.dependencies.find(
      (dependency) =>
        dependency.ref === "pkg:npm/%40acme/mcp-server@1.2.3",
    );
    assert.deepEqual(serverDependency?.dependsOn, [
      "pkg:npm/%40acme/mcp-server@1.2.3",
    ]);
    assert.deepEqual(directDependency?.dependsOn, [
      "pkg:npm/alpha@1.0.0",
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reads uv and Poetry dependency sections without executing Python tools", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-lockfile-python-"));
  const uvPath = join(directory, "uv.lock");
  const poetryPath = join(directory, "poetry.lock");
  try {
    await writeFile(
      uvPath,
      `version = 1

[[package]]
name = "mcp-server-fetch"
version = "1.0.0"
dependencies = [
  { name = "anyio" },
]
sdist = { hash = "sha256:abc" }

[[package]]
name = "anyio"
version = "4.8.0"
dependencies = [
  { name = "idna" },
]

[[package]]
name = "idna"
version = "3.10"
`,
      "utf8",
    );
    await writeFile(
      poetryPath,
      `[[package]]
name = "mcp-server-fetch"
version = "1.0.0"

[package.dependencies]
anyio = ">=4"
python = ">=3.11"

[[package]]
name = "anyio"
version = "4.8.0"
`,
      "utf8",
    );

    const uv = await analyzeLockfile(uvPath, "uv.lock");
    const poetry = await analyzeLockfile(poetryPath, "poetry.lock");
    const direct = extractSupplyChainComponents({
      command: "uvx",
      args: ["mcp-server-fetch==1.0.0"],
    });
    const uvGraph = enrichComponentsFromLockfiles(direct, [uv]);
    const poetryGraph = enrichComponentsFromLockfiles(direct, [poetry]);

    assert.equal(uv.summary.components, 3);
    assert.deepEqual(
      uvGraph.components.map((component) => component.name),
      ["mcp-server-fetch", "anyio", "idna"],
    );
    assert.deepEqual(
      poetryGraph.components.map((component) => component.name),
      ["mcp-server-fetch", "anyio"],
    );
    assert.equal(uvGraph.components[0].integrityStatus, "recorded");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("rejects malformed lockfiles and never guesses from unpinned launchers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-lockfile-invalid-"));
  const lockfilePath = join(directory, "package-lock.json");
  try {
    await writeFile(lockfilePath, "{", "utf8");
    const invalid = await analyzeLockfile(lockfilePath);
    assert.equal(invalid.summary.status, "invalid");

    const direct = extractSupplyChainComponents({
      command: "npx",
      args: ["@acme/mcp-server@latest"],
    });
    const enriched = enrichComponentsFromLockfiles(direct, []);
    assert.equal(enriched.components.length, 1);
    assert.equal(enriched.components[0].version, undefined);
    assert.equal(enriched.components[0].scope, "direct");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("resolves pnpm importers and keeps each monorepo package graph isolated", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-lockfile-pnpm-"));
  const lockfilePath = join(directory, "pnpm-lock.yaml");
  try {
    await writeFile(
      lockfilePath,
      `lockfileVersion: '9.0'
importers:
  packages/mcp:
    dependencies:
      "@acme/mcp-server":
        specifier: 1.2.3
        version: 1.2.3
  packages/web:
    dependencies:
      unrelated:
        specifier: 9.0.0
        version: 9.0.0
packages:
  "@acme/mcp-server@1.2.3":
    resolution:
      integrity: sha512-ZGlyZWN0
  helper@2.0.0:
    resolution:
      integrity: sha512-aGVscGVy
  unrelated@9.0.0:
    resolution:
      integrity: sha512-dW5yZWxhdGVk
snapshots:
  "@acme/mcp-server@1.2.3":
    dependencies:
      helper: 2.0.0
  helper@2.0.0: {}
  unrelated@9.0.0: {}
`,
      "utf8",
    );
    const analysis = await analyzeLockfile(lockfilePath, "pnpm-lock.yaml");
    const enriched = enrichComponentsFromLockfiles([], [analysis], {
      path: "packages/mcp",
      absolutePath: join(directory, "packages", "mcp"),
      name: "@acme/local-mcp",
      version: "1.0.0",
      private: true,
      dependencies: ["@acme/mcp-server"],
    });

    assert.equal(analysis.summary.format, "pnpm");
    assert.equal(analysis.summary.importers, 2);
    assert.deepEqual(
      enriched.components.map((component) => component.name),
      ["@acme/local-mcp", "@acme/mcp-server", "helper"],
    );
    assert.equal(
      enriched.components.some((component) => component.name === "unrelated"),
      false,
    );
    assert.equal(enriched.components[0].workspace, "packages/mcp");
    assert.equal(enriched.matchedLockfiles.has("pnpm-lock.yaml"), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reads Yarn Classic and Berry dependency graphs without executing Yarn", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-lockfile-yarn-"));
  const classicPath = join(directory, "classic", "yarn.lock");
  const berryPath = join(directory, "berry", "yarn.lock");
  try {
    await mkdir(join(directory, "classic"), { recursive: true });
    await mkdir(join(directory, "berry"), { recursive: true });
    await writeFile(
      classicPath,
      `# yarn lockfile v1

"@acme/mcp-server@1.2.3":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@acme/mcp-server/-/mcp-server-1.2.3.tgz"
  integrity sha512-ZGlyZWN0
  dependencies:
    helper "^2.0.0"

helper@^2.0.0:
  version "2.1.0"
  integrity sha512-aGVscGVy
`,
      "utf8",
    );
    await writeFile(
      berryPath,
      `__metadata:
  version: 8

"@acme/mcp-server@npm:1.2.3":
  version: 1.2.3
  resolution: "@acme/mcp-server@npm:1.2.3"
  checksum: 10c0/example
  dependencies:
    helper: "npm:^2.0.0"

"helper@npm:^2.0.0":
  version: 2.1.0
  resolution: "helper@npm:2.1.0"
  checksum: 10c0/helper
`,
      "utf8",
    );
    const direct = extractSupplyChainComponents({
      command: "npx",
      args: ["@acme/mcp-server@1.2.3"],
    });
    const classic = await analyzeLockfile(classicPath, "yarn.lock");
    const berry = await analyzeLockfile(berryPath, "yarn.lock");
    const classicGraph = enrichComponentsFromLockfiles(direct, [classic]);
    const berryGraph = enrichComponentsFromLockfiles(direct, [berry]);

    assert.equal(classic.summary.format, "yarn");
    assert.equal(berry.summary.format, "yarn");
    assert.deepEqual(
      classicGraph.components.map((component) => component.name),
      ["@acme/mcp-server", "helper"],
    );
    assert.deepEqual(
      berryGraph.components.map((component) => component.name),
      ["@acme/mcp-server", "helper"],
    );
    assert.equal(berryGraph.components[0].integrityStatus, "recorded");
    assert.equal(berryGraph.components[0].integrity, undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
