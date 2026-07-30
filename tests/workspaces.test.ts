import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  discoverWorkspacePackages,
  selectWorkspacePackage,
} from "../lib/workspaces.ts";

test("discovers bounded npm/Yarn workspaces and selects the local MCP package", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-workspaces-"));
  try {
    await mkdir(join(directory, "packages", "mcp"), { recursive: true });
    await mkdir(join(directory, "packages", "web"), { recursive: true });
    await writeFile(
      join(directory, "package.json"),
      JSON.stringify({
        name: "fixture-root",
        private: true,
        workspaces: ["packages/*"],
      }),
      "utf8",
    );
    await writeFile(
      join(directory, "packages", "mcp", "package.json"),
      JSON.stringify({
        name: "@acme/mcp",
        version: "1.0.0",
        private: true,
        dependencies: { helper: "^2.0.0" },
      }),
      "utf8",
    );
    await writeFile(
      join(directory, "packages", "web", "package.json"),
      JSON.stringify({ name: "@acme/web", private: true }),
      "utf8",
    );

    const packages = await discoverWorkspacePackages(directory);
    const selected = selectWorkspacePackage(
      packages,
      {
        command: "node",
        args: ["./src/server.js"],
        cwd: "packages/mcp",
      },
      directory,
    );

    assert.deepEqual(
      packages.map((workspace) => workspace.path).sort(),
      [".", "packages/mcp", "packages/web"],
    );
    assert.equal(selected?.name, "@acme/mcp");
    assert.deepEqual(selected?.dependencies, ["helper"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
