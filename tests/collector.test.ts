import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  collectInventory,
  discoverCandidateFiles,
  MCP_PROTOCOL_VERSION,
  probeConfiguration,
  sanitizeConfiguration,
} from "../lib/collector.ts";
import { createCycloneDxReport } from "../lib/supply-chain.ts";

test("discovers the common MCP configuration paths on every platform", () => {
  const windows = discoverCandidateFiles({
    platform: "win32",
    home: "C:\\Users\\alice",
    environment: {
      APPDATA: "C:\\Users\\alice\\AppData\\Roaming",
      LOCALAPPDATA: "C:\\Users\\alice\\AppData\\Local",
      ProgramFiles: "C:\\Program Files",
    },
    workspace: "C:\\work\\project",
  });
  const mac = discoverCandidateFiles({
    platform: "darwin",
    home: "/Users/alice",
    environment: {},
    workspace: "/work/project",
  });
  const linux = discoverCandidateFiles({
    platform: "linux",
    home: "/home/alice",
    environment: { XDG_CONFIG_HOME: "/home/alice/.config" },
    workspace: "/work/project",
  });

  assert.ok(
    windows.some((candidate) =>
      candidate.path.endsWith("Claude\\claude_desktop_config.json"),
    ),
  );
  assert.ok(
    windows.some(
      (candidate) =>
        candidate.client === "Codex" &&
        candidate.format === "toml" &&
        candidate.path === "C:\\Users\\alice\\.codex\\config.toml",
    ),
  );
  assert.ok(
    windows.some(
      (candidate) =>
        candidate.client === "Claude Code" &&
        candidate.layout === "claude-code" &&
        candidate.path === "C:\\Users\\alice\\.claude.json",
    ),
  );
  assert.ok(
    windows.some(
      (candidate) =>
        candidate.client === "Claude Code (projet)" &&
        candidate.path === "C:\\work\\project\\.mcp.json",
    ),
  );
  assert.ok(
    windows.some(
      (candidate) =>
        candidate.client === "Claude Desktop (Microsoft Store)" &&
        candidate.path.endsWith(
          "Packages\\Claude_pzs8sxrjxfjjc\\LocalCache\\Roaming\\Claude\\claude_desktop_config.json",
        ),
    ),
  );
  assert.ok(
    windows.some(
      (candidate) =>
        candidate.client === "Claude Code (administré)" &&
        candidate.path ===
          "C:\\Program Files\\ClaudeCode\\managed-mcp.json",
    ),
  );
  assert.ok(
    mac.some(
      (candidate) =>
        candidate.client === "Codex" &&
        candidate.path === "/Users/alice/.codex/config.toml",
    ),
  );
  assert.ok(
    linux.some(
      (candidate) =>
        candidate.client === "Codex" &&
        candidate.path === "/home/alice/.codex/config.toml",
    ),
  );
  assert.ok(
    mac.some((candidate) =>
      candidate.path.endsWith(
        "Library/Application Support/Claude/claude_desktop_config.json",
      ),
    ),
  );
  assert.ok(
    linux.some((candidate) =>
      candidate.path.endsWith("Code/User/mcp.json"),
    ),
  );
  assert.ok(
    mac.some(
      (candidate) =>
        candidate.client === "Claude Code (administré)" &&
        candidate.path ===
          "/Library/Application Support/ClaudeCode/managed-mcp.json",
    ),
  );
  assert.ok(
    linux.some(
      (candidate) =>
        candidate.client === "Claude Code (administré)" &&
        candidate.path === "/etc/claude-code/managed-mcp.json",
    ),
  );
  assert.ok(
    windows.some((candidate) =>
      candidate.path.endsWith(".vscode\\mcp.json"),
    ),
  );
});

test("redacts concrete credentials but preserves environment placeholders", () => {
  const secret = "collector-secret-that-must-not-leak";
  const { configuration, redactions } = sanitizeConfiguration({
    url: `https://alice:password@mcp.example.test/v1?token=${secret}`,
    headers: {
      Authorization: `Bearer ${secret}`,
      "X-API-Key": "${MCP_API_KEY}",
    },
    args: [`--token=${secret}`],
  });
  const serialized = JSON.stringify(configuration);

  assert.doesNotMatch(serialized, new RegExp(secret));
  assert.doesNotMatch(serialized, /alice|password/);
  assert.match(serialized, /\$\{MCP_API_KEY\}/);
  assert.ok(redactions.length >= 3);
});

test("collects supported containers without retaining source secrets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "secure-mpc-"));
  const configPath = join(directory, "mcp.json");
  const secret = "source-secret-that-must-not-leak";

  try {
    await writeFile(
      configPath,
      JSON.stringify({
        mcp: {
          servers: {
            github: {
              command: "npx",
              args: ["-y", "@modelcontextprotocol/server-github@1.2.3"],
              env: { GITHUB_TOKEN: secret },
            },
          },
        },
      }),
      "utf8",
    );

    const inventory = await collectInventory({
      candidates: [{ client: "Test client", path: configPath }],
      home: directory,
      platform: "linux",
      now: () => new Date("2026-07-29T12:00:00.000Z"),
    });
    const serialized = JSON.stringify(inventory);

    assert.equal(inventory.servers.length, 1);
    assert.equal(inventory.sources[0].status, "read");
    assert.equal(inventory.servers[0].probe.status, "not-requested");
    assert.equal(inventory.servers[0].components.length, 1);
    assert.equal(inventory.servers[0].components[0].ecosystem, "npm");
    assert.equal(inventory.servers[0].components[0].pinStatus, "pinned");
    assert.match(inventory.servers[0].source.path, /^~\//);
    assert.doesNotMatch(serialized, new RegExp(secret));
    assert.match(serialized, /\$\{REDACTED\}/);

    const sbom = createCycloneDxReport(
      inventory.servers.map((server) => ({
        id: server.id,
        name: server.name,
        transport: "Stdio",
        source: server.source.client,
        components: server.components,
      })),
      new Date(inventory.generatedAt),
      "00000000-0000-4000-8000-000000000002",
    );
    assert.doesNotMatch(JSON.stringify(sbom), new RegExp(secret));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("collects Codex TOML servers and redacts nested secrets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "secure-mpc-codex-"));
  const configPath = join(directory, "config.toml");
  const secret = "codex-secret-that-must-not-leak";

  try {
    await writeFile(
      configPath,
      [
        'model = "gpt-5"',
        "",
        "[mcp_servers.node_repl]",
        'command = "node"',
        'args = ["server.mjs"]',
        "",
        "[mcp_servers.node_repl.env]",
        `MCP_ACCESS_TOKEN = "${secret}"`,
        "",
        '[mcp_servers."remote.docs"]',
        'url = "https://mcp.example.test/v1"',
        "",
        '[mcp_servers."remote.docs".http_headers]',
        `Authorization = "Bearer ${secret}"`,
      ].join("\n"),
      "utf8",
    );

    const inventory = await collectInventory({
      candidates: [],
      additionalPaths: [configPath],
      home: directory,
      platform: "linux",
      scanLockfiles: false,
      now: () => new Date("2026-07-30T12:00:00.000Z"),
    });
    const serialized = JSON.stringify(inventory);

    assert.equal(inventory.servers.length, 2);
    assert.equal(inventory.sources[0].status, "read");
    assert.equal(inventory.sources[0].servers, 2);
    assert.equal(inventory.servers[0].name, "node_repl");
    assert.equal(inventory.servers[1].name, "remote.docs");
    assert.equal(inventory.servers[0].configuration.command, "node");
    assert.equal(
      (
        inventory.servers[0].configuration.env as Record<string, unknown>
      ).MCP_ACCESS_TOKEN,
      "${REDACTED}",
    );
    assert.doesNotMatch(serialized, new RegExp(secret));
    assert.match(serialized, /\$\{REDACTED\}/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("collects Claude Code user and local project scopes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "secure-mpc-claude-"));
  const configPath = join(directory, ".claude.json");
  const secret = "claude-secret-that-must-not-leak";

  try {
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          shared: {
            command: "npx",
            args: ["-y", "@acme/shared-mcp@1.2.3"],
            env: { API_TOKEN: secret },
          },
        },
        projects: {
          "/work/private-project-one": {
            mcpServers: {
              shared: {
                url: "https://mcp.example.test/tenant-alpha",
                headers: { Authorization: `Bearer ${secret}` },
              },
            },
          },
          "/work/private-project-two": {
            mcpServers: {
              projectOnly: {
                command: "uvx",
                args: ["project-mcp==2.3.4"],
              },
            },
          },
        },
      }),
      "utf8",
    );

    const inventory = await collectInventory({
      candidates: [],
      additionalPaths: [configPath],
      home: directory,
      platform: "linux",
      scanLockfiles: false,
      now: () => new Date("2026-07-30T12:00:00.000Z"),
    });
    const serialized = JSON.stringify(inventory);

    assert.equal(inventory.sources[0].status, "read");
    assert.equal(inventory.sources[0].servers, 3);
    assert.equal(inventory.servers.length, 3);
    assert.equal(new Set(inventory.servers.map((server) => server.id)).size, 3);
    assert.equal(
      inventory.servers.filter((server) =>
        server.source.client.endsWith("(utilisateur)"),
      ).length,
      1,
    );
    assert.equal(
      inventory.servers.filter((server) =>
        server.source.client.endsWith("(projet local)"),
      ).length,
      2,
    );
    assert.doesNotMatch(
      serialized,
      /private-project-one|private-project-two/,
    );
    assert.doesNotMatch(serialized, new RegExp(secret));
    assert.match(serialized, /\$\{REDACTED\}/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("accepts a Claude Code state file without configured MCP servers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "secure-mpc-claude-empty-"));
  const configPath = join(directory, ".claude.json");

  try {
    await writeFile(
      configPath,
      JSON.stringify({ projects: { "/work/project": { trusted: true } } }),
      "utf8",
    );
    const inventory = await collectInventory({
      candidates: [
        {
          client: "Claude Code",
          path: configPath,
          layout: "claude-code",
        },
      ],
      home: directory,
      platform: "linux",
      scanLockfiles: false,
    });

    assert.equal(inventory.servers.length, 0);
    assert.equal(inventory.sources[0].status, "read");
    assert.equal(inventory.sources[0].servers, 0);
    assert.match(
      inventory.sources[0].message ?? "",
      /portées utilisateur ou locales/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("reports invalid TOML sources without exposing their contents", async () => {
  const directory = await mkdtemp(join(tmpdir(), "secure-mpc-toml-"));
  const configPath = join(directory, "config.toml");
  const secret = "invalid-toml-content-must-not-leak";

  try {
    await writeFile(
      configPath,
      `[mcp_servers.broken\ncredential = '${secret}'`,
      "utf8",
    );
    const inventory = await collectInventory({
      candidates: [{ client: "Codex", path: configPath, format: "toml" }],
      home: directory,
      platform: "linux",
      scanLockfiles: false,
    });

    assert.equal(inventory.servers.length, 0);
    assert.equal(inventory.sources[0].status, "invalid");
    assert.equal(inventory.sources[0].message, "TOML invalide.");
    assert.doesNotMatch(JSON.stringify(inventory), new RegExp(secret));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("attaches workspace lockfile dependencies to matching MCP servers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "secure-mpc-lock-"));
  const configPath = join(directory, "mcp.json");
  try {
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "@acme/mcp-server@1.2.3"],
          },
        },
      }),
      "utf8",
    );
    await writeFile(
      join(directory, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/@acme/mcp-server": {
            name: "@acme/mcp-server",
            version: "1.2.3",
            integrity: "sha512-direct",
            dependencies: { helper: "2.0.0" },
          },
          "node_modules/helper": {
            version: "2.0.0",
            integrity: "sha512-helper",
          },
        },
      }),
      "utf8",
    );

    const inventory = await collectInventory({
      candidates: [{ client: "Test client", path: configPath }],
      home: directory,
      workspace: directory,
      platform: "linux",
      scanLockfiles: true,
      now: () => new Date("2026-07-29T12:00:00.000Z"),
    });

    assert.equal(inventory.lockfiles?.length, 1);
    assert.equal(inventory.lockfiles?.[0].matchedServers, 1);
    assert.equal(inventory.servers[0].componentGraph?.direct, 1);
    assert.equal(inventory.servers[0].componentGraph?.transitive, 1);
    assert.equal(inventory.servers[0].components[1].name, "helper");
    assert.doesNotMatch(JSON.stringify(inventory), new RegExp(directory));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("passive HTTPS probe negotiates capabilities without credentials or tools", async () => {
  const requests: Array<{ input: string; init?: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    requests.push({ input: String(input), init });
    if (requests.length === 1) {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: {
              resources: { subscribe: true },
              tools: { listChanged: true },
            },
            serverInfo: { name: "Test MCP", version: "2.1.0" },
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "mcp-session-id": "test-session",
          },
        },
      );
    }
    if (requests.length === 2) {
      return new Response(null, { status: 202 });
    }
    return new Response(null, { status: 200 });
  };

  const result = await probeConfiguration(
    {
      url: "https://mcp.example.test/v1",
      headers: { Authorization: "Bearer ${MCP_TOKEN}" },
    },
    {
      fetchImpl,
      now: () => new Date("2026-07-29T12:00:00.000Z"),
    },
  );

  assert.equal(result.status, "reachable");
  assert.deepEqual(result.capabilities, ["resources", "tools"]);
  assert.equal(result.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.equal(requests.length, 3);
  assert.equal(requests[0].init?.method, "POST");
  assert.match(String(requests[0].init?.body), /"method":"initialize"/);
  assert.doesNotMatch(
    requests.map((request) => String(request.init?.body)).join(" "),
    /tools\/list|tools\/call/,
  );
  for (const request of requests) {
    assert.equal(new Headers(request.init?.headers).has("authorization"), false);
  }
  assert.equal(requests[2].init?.method, "DELETE");
});

test("passive probe reports authentication and refuses clear-text HTTP", async () => {
  let calls = 0;
  const authRequired = await probeConfiguration(
    { url: "https://mcp.example.test/v1" },
    {
      fetchImpl: async () => {
        calls += 1;
        return new Response(null, { status: 401 });
      },
    },
  );
  const insecure = await probeConfiguration({
    url: "http://mcp.example.test/v1",
  });

  assert.equal(authRequired.status, "auth-required");
  assert.equal(authRequired.httpStatus, 401);
  assert.equal(insecure.status, "skipped-insecure");
  assert.equal(calls, 1);
});

test("passive probe parses an SSE initialize response", async () => {
  let calls = 0;
  const result = await probeConfiguration(
    { url: "https://mcp.example.test/sse" },
    {
      fetchImpl: async () => {
        calls += 1;
        if (calls === 1) {
          return new Response(
            [
              "event: message",
              `data: ${JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                result: {
                  protocolVersion: MCP_PROTOCOL_VERSION,
                  capabilities: { prompts: {} },
                  serverInfo: { name: "SSE MCP", version: "1.0.0" },
                },
              })}`,
              "",
              "",
            ].join("\n"),
            {
              status: 200,
              headers: { "content-type": "text/event-stream" },
            },
          );
        }
        return new Response(null, { status: 202 });
      },
    },
  );

  assert.equal(result.status, "reachable");
  assert.deepEqual(result.capabilities, ["prompts"]);
});
