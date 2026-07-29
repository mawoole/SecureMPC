import assert from "node:assert/strict";
import test from "node:test";
import { scanComponentsWithOsv } from "../lib/osv.ts";
import {
  extractSupplyChainComponents,
  type SupplyChainComponent,
} from "../lib/supply-chain.ts";

const checkedAt = new Date("2026-07-29T12:00:00.000Z");

function pinnedComponent(): SupplyChainComponent {
  return extractSupplyChainComponents({
    command: "npx",
    args: ["-y", "@acme/mcp-server@1.2.3"],
  })[0];
}

test("queries OSV with versioned PURLs only and normalizes advisories", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = String(input);
    requests.push({ url, init });

    if (url.endsWith("/querybatch")) {
      const body = JSON.parse(String(init?.body)) as {
        queries: Array<Record<string, unknown>>;
      };
      assert.deepEqual(body, {
        queries: [
          {
            package: {
              purl: "pkg:npm/%40acme/mcp-server@1.2.3",
            },
          },
        ],
      });
      assert.equal(new Headers(init?.headers).has("Authorization"), false);
      return Response.json({
        results: [
          {
            vulns: [
              {
                id: "GHSA-test-1234",
                modified: "2026-07-28T10:00:00Z",
              },
            ],
          },
        ],
      });
    }

    assert.equal(
      url,
      "https://api.osv.dev/v1/vulns/GHSA-test-1234",
    );
    assert.equal(new Headers(init?.headers).has("Authorization"), false);
    return Response.json({
      id: "GHSA-test-1234",
      aliases: ["CVE-2026-1234"],
      summary: "Injection\u0000 de commande",
      modified: "2026-07-28T10:00:00Z",
      database_specific: { severity: "HIGH" },
      references: [
        {
          type: "ADVISORY",
          url: "https://example.test/advisories/GHSA-test-1234",
        },
      ],
      affected: [
        {
          package: { purl: "pkg:npm/%40acme/another-package" },
          ranges: [
            {
              type: "ECOSYSTEM",
              events: [{ introduced: "0" }, { fixed: "9.9.9" }],
            },
          ],
        },
        {
          package: { purl: "pkg:npm/%40acme/mcp-server" },
          ranges: [
            {
              type: "GIT",
              events: [
                {
                  fixed: "0123456789abcdef0123456789abcdef01234567",
                },
              ],
            },
          ],
        },
        {
          package: { purl: "pkg:npm/%40acme/mcp-server" },
          ranges: [
            {
              type: "ECOSYSTEM",
              events: [{ introduced: "0" }, { fixed: "1.2.4" }],
            },
          ],
        },
      ],
    });
  }) as typeof fetch;

  const result = await scanComponentsWithOsv([pinnedComponent()], {
    fetchImpl,
    now: () => checkedAt,
  });

  assert.equal(requests.length, 2);
  assert.equal(result.summary.status, "complete");
  assert.equal(result.summary.checkedAt, checkedAt.toISOString());
  assert.equal(result.summary.queriedComponents, 1);
  assert.equal(result.summary.skippedComponents, 0);
  assert.equal(result.summary.vulnerabilities, 1);
  assert.equal(result.components[0].vulnerabilities?.length, 1);
  assert.deepEqual(result.components[0].vulnerabilities?.[0], {
    id: "GHSA-test-1234",
    aliases: ["CVE-2026-1234"],
    summary: "Injection de commande",
    severity: "high",
    modified: "2026-07-28T10:00:00Z",
    advisoryUrl:
      "https://example.test/advisories/GHSA-test-1234",
    fixedVersion: "1.2.4",
  });
});

test("deduplicates identical PURLs without counting components as skipped", async () => {
  let batchQueries = 0;
  const fetchImpl = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = String(input);
    if (url.endsWith("/querybatch")) {
      const body = JSON.parse(String(init?.body)) as {
        queries: unknown[];
      };
      batchQueries = body.queries.length;
      return Response.json({
        results: [{ vulns: [{ id: "OSV-2026-1" }] }],
      });
    }
    return Response.json({
      id: "OSV-2026-1",
      summary: "Avis de test",
    });
  }) as typeof fetch;
  const component = pinnedComponent();

  const result = await scanComponentsWithOsv(
    [component, { ...component, id: `${component.id}-copy` }],
    { fetchImpl, now: () => checkedAt },
  );

  assert.equal(batchQueries, 1);
  assert.equal(result.summary.queriedComponents, 1);
  assert.equal(result.summary.skippedComponents, 0);
  assert.equal(result.components[0].vulnerabilities?.length, 1);
  assert.equal(result.components[1].vulnerabilities?.length, 1);
});

test("does not contact OSV for unpinned or unversioned components", async () => {
  let requests = 0;
  const fetchImpl = (async () => {
    requests += 1;
    throw new Error("unexpected request");
  }) as typeof fetch;
  const components = [
    ...extractSupplyChainComponents({
      command: "npx",
      args: ["@acme/mcp-server@latest"],
    }),
    ...extractSupplyChainComponents({
      command: "C:\\Tools\\mcp-server.exe",
      args: [],
    }),
  ];

  const result = await scanComponentsWithOsv(components, {
    fetchImpl,
    now: () => checkedAt,
  });

  assert.equal(requests, 0);
  assert.equal(result.summary.status, "complete");
  assert.equal(result.summary.queriedComponents, 0);
  assert.equal(result.summary.skippedComponents, 2);
});

test("reports an OSV outage without inventing vulnerability results", async () => {
  const fetchImpl = (async () => {
    throw new Error("network unavailable");
  }) as typeof fetch;

  const result = await scanComponentsWithOsv([pinnedComponent()], {
    fetchImpl,
    now: () => checkedAt,
  });

  assert.equal(result.summary.status, "error");
  assert.equal(result.summary.vulnerabilities, 0);
  assert.equal(result.components[0].vulnerabilities, undefined);
  assert.match(result.summary.message, /ne doit être considéré comme complet/);
});
