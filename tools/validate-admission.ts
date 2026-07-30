#!/usr/bin/env node

import { readFile, readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { validateKubernetesAdmissionBundle } from "../lib/kubernetes-admission-validation.ts";
import { parseOciVerificationPolicyDocument } from "../lib/oci-provenance.ts";

type CliOptions = {
  namespaces: string[];
  bundle?: string;
  policyFile?: string;
};

function help(): string {
  return `MCP TrustMap — Validation de bundle d’admission Kubernetes

Usage:
  npm run validate:admission -- \\
    --policy-file ./examples/oci-policies.json \\
    --namespace production \\
    --bundle ./kubernetes-admission

Options:
  --policy-file <fichier>  Document JSON de politiques OCI (obligatoire)
  --namespace <nom>        Namespace attendu (répétable, obligatoire)
  --bundle <dossier>       Bundle existant à valider (obligatoire)
  --help                   Affiche cette aide

Contrôles :
  - aucun accès à un cluster, registre ou serveur MCP ;
  - refus des liens symboliques, sous-dossiers et fichiers inattendus ;
  - validation de la syntaxe et des types Kubernetes/YAML ;
  - comparaison octet par octet avec une génération déterministe ;
  - calcul d’une empreinte SHA-256 du bundle complet.`;
}

function readValue(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`Une valeur est requise après ${option}.`);
  }
  return value;
}

function parseArguments(args: string[]): CliOptions {
  const options: CliOptions = { namespaces: [] };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help") {
      process.stdout.write(`${help()}\n`);
      process.exit(0);
    }
    if (argument === "--policy-file") {
      options.policyFile = resolve(readValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--namespace") {
      options.namespaces.push(readValue(args, index, argument));
      index += 1;
      continue;
    }
    if (argument === "--bundle") {
      options.bundle = resolve(readValue(args, index, argument));
      index += 1;
      continue;
    }
    throw new Error(`Option inconnue : ${argument}`);
  }
  if (!options.policyFile) {
    throw new Error("--policy-file est obligatoire.");
  }
  if (!options.namespaces.length) {
    throw new Error("Au moins un --namespace est obligatoire.");
  }
  if (!options.bundle) {
    throw new Error("--bundle est obligatoire.");
  }
  return options;
}

async function loadPolicies(filePath: string) {
  const information = await stat(filePath);
  if (!information.isFile() || information.size > 256_000) {
    throw new Error(
      "Le fichier de politiques OCI doit être un fichier JSON de 256 Ko maximum.",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(filePath, "utf8")) as unknown;
  } catch {
    throw new Error("Le fichier de politiques OCI n’est pas un JSON valide.");
  }
  return parseOciVerificationPolicyDocument(parsed).policies;
}

async function loadBundle(directory: string) {
  const information = await stat(directory);
  if (!information.isDirectory()) {
    throw new Error(`Le bundle n’est pas un dossier : ${directory}.`);
  }
  const entries = await readdir(directory, { withFileTypes: true });
  return Promise.all(
    entries
      .sort((left, right) => left.name.localeCompare(right.name))
      .map(async (entry) => {
        if (!entry.isFile() || entry.isSymbolicLink()) {
          throw new Error(
            `Le bundle ne peut contenir que des fichiers ordinaires : ${entry.name}.`,
          );
        }
        const filePath = join(directory, entry.name);
        const fileInformation = await stat(filePath);
        if (fileInformation.size > 2_000_000) {
          throw new Error(
            `Le fichier ${entry.name} dépasse la limite de 2 Mo.`,
          );
        }
        return {
          name: entry.name,
          content: await readFile(filePath, "utf8"),
        };
      }),
  );
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const policies = await loadPolicies(options.policyFile ?? "");
  const files = await loadBundle(options.bundle ?? "");
  const summary = validateKubernetesAdmissionBundle(
    policies,
    { namespaces: options.namespaces },
    files,
  );
  process.stdout.write(
    `Bundle Kubernetes valide : ${summary.files} fichiers, ${summary.yamlDocuments} documents YAML, SHA-256 ${summary.sha256}.\n`,
  );
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : "Échec de la validation Kubernetes."}\n`,
  );
  process.exitCode = 1;
});
