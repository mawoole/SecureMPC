#!/usr/bin/env node

import { chmod, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { collectInventory } from "../lib/collector.ts";
import { scanComponentsWithOsv } from "../lib/osv.ts";
import { createCycloneDxReport } from "../lib/supply-chain.ts";

type CliOptions = {
  additionalPaths: string[];
  lockfilePaths: string[];
  output: string;
  osv: boolean;
  probe: boolean;
  scanLockfiles: boolean;
  sbomOutput?: string;
  stdout: boolean;
  timeoutMs: number;
  workspace?: string;
};

function help(): string {
  return `MCP Sentinel Collector

Usage:
  npm run collect
  npm run collect:security
  npm run collect -- --probe
  npm run collect -- --sbom
  npm run collect -- --osv --sbom
  npm run collect -- --path ./mcp.json --output ./mcp-inventory.json

Options:
  --path <fichier>       Ajoute un fichier de configuration explicite (répétable)
  --workspace <dossier>  Dossier où rechercher .vscode/mcp.json et .cursor/mcp.json
  --lockfile <fichier>    Ajoute un package-lock.json, uv.lock ou poetry.lock
  --no-lockfiles          Désactive la découverte des lockfiles du workspace
  --probe                Vérifie passivement les endpoints HTTPS distants
  --osv                  Interroge OSV.dev avec les PURL versionnés uniquement
  --sbom [fichier]       Produit aussi un SBOM CycloneDX 1.7
  --timeout <ms>         Délai du probe, entre 500 et 15000 ms (défaut : 5000)
  --output <fichier>     Fichier produit (défaut : mcp-inventory.json)
  --stdout               Écrit l’inventaire sur la sortie standard
  --help                 Affiche cette aide

Garanties du collecteur :
  - les secrets concrets sont remplacés avant l’écriture ;
  - les lockfiles sont lus sans exécuter npm, uv, Poetry ou un serveur MCP ;
  - aucun en-tête d’authentification découvert n’est envoyé ;
  - avec --osv, seuls les PURL versionnés sont envoyés à OSV.dev ;
  - aucun serveur stdio ni outil MCP n’est exécuté.`;
}

function readValue(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`Une valeur est requise après ${option}.`);
  }
  return value;
}

function parseArguments(args: string[]): CliOptions {
  const options: CliOptions = {
    additionalPaths: [],
    lockfilePaths: [],
    output: resolve("mcp-inventory.json"),
    osv: false,
    probe: false,
    scanLockfiles: true,
    stdout: false,
    timeoutMs: 5_000,
  };

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help") {
      process.stdout.write(`${help()}\n`);
      process.exit(0);
    }
    if (argument === "--probe") {
      options.probe = true;
      continue;
    }
    if (argument === "--no-lockfiles") {
      options.scanLockfiles = false;
      continue;
    }
    if (argument === "--osv") {
      options.osv = true;
      continue;
    }
    if (argument === "--stdout") {
      options.stdout = true;
      continue;
    }
    if (argument === "--sbom") {
      const candidate = args[index + 1];
      if (candidate && !candidate.startsWith("--")) {
        options.sbomOutput = resolve(candidate);
        index += 1;
      } else {
        options.sbomOutput = resolve("mcp-sbom.cdx.json");
      }
      continue;
    }
    if (argument === "--path") {
      options.additionalPaths.push(
        resolve(readValue(args, index, argument)),
      );
      index += 1;
      continue;
    }
    if (argument === "--lockfile") {
      options.lockfilePaths.push(
        resolve(readValue(args, index, argument)),
      );
      index += 1;
      continue;
    }
    if (argument === "--workspace") {
      options.workspace = resolve(readValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--output") {
      options.output = resolve(readValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--timeout") {
      options.timeoutMs = Number(readValue(args, index, argument));
      if (
        !Number.isInteger(options.timeoutMs) ||
        options.timeoutMs < 500 ||
        options.timeoutMs > 15_000
      ) {
        throw new Error("--timeout doit être un entier entre 500 et 15000.");
      }
      index += 1;
      continue;
    }
    throw new Error(`Option inconnue : ${argument}`);
  }

  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const inventory = await collectInventory(options);

  if (options.osv) {
    const componentCounts = inventory.servers.map(
      (server) => server.components.length,
    );
    const scan = await scanComponentsWithOsv(
      inventory.servers.flatMap((server) => server.components),
    );
    let cursor = 0;
    inventory.servers.forEach((server, index) => {
      const count = componentCounts[index];
      server.components = scan.components.slice(cursor, cursor + count);
      cursor += count;
    });
    inventory.vulnerabilityScan = scan.summary;
  }

  const serialized = `${JSON.stringify(inventory, null, 2)}\n`;

  if (options.stdout) {
    process.stdout.write(serialized);
  } else {
    await writeFile(options.output, serialized, {
      encoding: "utf8",
      mode: 0o600,
    });
    if (process.platform !== "win32") {
      await chmod(options.output, 0o600);
    }
  }

  if (options.sbomOutput) {
    const sbom = createCycloneDxReport(
      inventory.servers.map((server) => {
        const url =
          typeof server.configuration.url === "string"
            ? server.configuration.url
            : "";
        return {
          id: server.id,
          name: server.name,
          transport: url
            ? url.startsWith("https://")
              ? "HTTPS"
              : "HTTP"
            : "Stdio",
          source: `${server.source.client} · ${server.source.path}`,
          components: server.components,
        };
      }),
      new Date(inventory.generatedAt),
    );
    await writeFile(
      options.sbomOutput,
      `${JSON.stringify(sbom, null, 2)}\n`,
      {
        encoding: "utf8",
        mode: 0o600,
      },
    );
    if (process.platform !== "win32") {
      await chmod(options.sbomOutput, 0o600);
    }
  }

  const discovered = inventory.servers.length;
  const redactions = inventory.servers.reduce(
    (total, server) => total + server.redactions.length,
    0,
  );
  const reachable = inventory.servers.filter(
    (server) => server.probe.status === "reachable",
  ).length;
  const vulnerabilities = inventory.vulnerabilityScan?.vulnerabilities ?? 0;
  const lockfiles = inventory.lockfiles?.filter((lockfile) =>
    ["read", "partial"].includes(lockfile.status),
  ).length ?? 0;
  const transitive = inventory.servers.reduce(
    (total, server) => total + (server.componentGraph?.transitive ?? 0),
    0,
  );
  process.stderr.write(
    [
      `${discovered} serveur${discovered > 1 ? "s" : ""} découvert${discovered > 1 ? "s" : ""}.`,
      `${redactions} valeur${redactions > 1 ? "s" : ""} sensible${redactions > 1 ? "s" : ""} masquée${redactions > 1 ? "s" : ""}.`,
      options.probe
        ? `${reachable} endpoint${reachable > 1 ? "s" : ""} MCP négocié${reachable > 1 ? "s" : ""}.`
        : "Probe réseau non demandé.",
      options.osv
        ? `${vulnerabilities} avis OSV trouvé${vulnerabilities > 1 ? "s" : ""}.`
        : "Analyse OSV non demandée.",
      options.scanLockfiles || options.lockfilePaths.length
        ? `${lockfiles} lockfile${lockfiles > 1 ? "s" : ""} analysé${lockfiles > 1 ? "s" : ""}, ${transitive} dépendance${transitive > 1 ? "s" : ""} transitive${transitive > 1 ? "s" : ""} rattachée${transitive > 1 ? "s" : ""}.`
        : "Analyse des lockfiles désactivée.",
      options.stdout ? "" : `Inventaire : ${options.output}`,
      options.sbomOutput ? `SBOM : ${options.sbomOutput}` : "",
    ]
      .filter(Boolean)
      .join(" "),
  );
  process.stderr.write("\n");
  if (inventory.vulnerabilityScan?.status === "error") {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : "Échec du collecteur."}\n`,
  );
  process.exitCode = 1;
});
