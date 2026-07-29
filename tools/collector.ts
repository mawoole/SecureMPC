#!/usr/bin/env node

import { chmod, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { collectInventory } from "../lib/collector.ts";

type CliOptions = {
  additionalPaths: string[];
  output: string;
  probe: boolean;
  stdout: boolean;
  timeoutMs: number;
  workspace?: string;
};

function help(): string {
  return `MCP Sentinel Collector

Usage:
  npm run collect
  npm run collect -- --probe
  npm run collect -- --path ./mcp.json --output ./mcp-inventory.json

Options:
  --path <fichier>       Ajoute un fichier de configuration explicite (répétable)
  --workspace <dossier>  Dossier où rechercher .vscode/mcp.json et .cursor/mcp.json
  --probe                Vérifie passivement les endpoints HTTPS distants
  --timeout <ms>         Délai du probe, entre 500 et 15000 ms (défaut : 5000)
  --output <fichier>     Fichier produit (défaut : mcp-inventory.json)
  --stdout               Écrit l’inventaire sur la sortie standard
  --help                 Affiche cette aide

Garanties du collecteur :
  - les secrets concrets sont remplacés avant l’écriture ;
  - aucun en-tête d’authentification découvert n’est envoyé ;
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
    output: resolve("mcp-inventory.json"),
    probe: false,
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
    if (argument === "--stdout") {
      options.stdout = true;
      continue;
    }
    if (argument === "--path") {
      options.additionalPaths.push(
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

  const discovered = inventory.servers.length;
  const redactions = inventory.servers.reduce(
    (total, server) => total + server.redactions.length,
    0,
  );
  const reachable = inventory.servers.filter(
    (server) => server.probe.status === "reachable",
  ).length;
  process.stderr.write(
    [
      `${discovered} serveur${discovered > 1 ? "s" : ""} découvert${discovered > 1 ? "s" : ""}.`,
      `${redactions} valeur${redactions > 1 ? "s" : ""} sensible${redactions > 1 ? "s" : ""} masquée${redactions > 1 ? "s" : ""}.`,
      options.probe
        ? `${reachable} endpoint${reachable > 1 ? "s" : ""} MCP négocié${reachable > 1 ? "s" : ""}.`
        : "Probe réseau non demandé.",
      options.stdout ? "" : `Inventaire : ${options.output}`,
    ]
      .filter(Boolean)
      .join(" "),
  );
  process.stderr.write("\n");
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : "Échec du collecteur."}\n`,
  );
  process.exitCode = 1;
});
