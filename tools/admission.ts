#!/usr/bin/env node

import {
  chmod,
  mkdir,
  readFile,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { generateKubernetesAdmissionBundle } from "../lib/kubernetes-admission.ts";
import { parseOciVerificationPolicyDocument } from "../lib/oci-provenance.ts";

type CliOptions = {
  namespaces: string[];
  output: string;
  policyFile?: string;
};

function help(): string {
  return `Secure MPC — Générateur d’admission Kubernetes

Usage:
  npm run generate:admission -- \\
    --policy-file ./examples/oci-policies.json \\
    --namespace production

Options:
  --policy-file <fichier>  Document JSON de politiques OCI (obligatoire)
  --namespace <nom>        Namespace à protéger (répétable, obligatoire)
  --output <dossier>       Nouveau dossier produit (défaut : kubernetes-admission)
  --help                   Affiche cette aide

Garanties :
  - aucun accès à un cluster, registre ou serveur MCP ;
  - aucun appel à kubectl, Helm, Cosign ou GitHub ;
  - aucun écrasement d’un dossier de sortie existant ;
  - rejet des préfixes qui se chevauchent, car Kubernetes cumule les politiques correspondantes.`;
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
    namespaces: [],
    output: resolve("kubernetes-admission"),
  };
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
    if (argument === "--output") {
      options.output = resolve(readValue(args, index, argument));
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

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const policies = await loadPolicies(options.policyFile ?? "");
  const bundle = generateKubernetesAdmissionBundle(policies, {
    namespaces: options.namespaces,
  });
  try {
    await mkdir(options.output, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(
        `Le dossier de sortie existe déjà : ${options.output}. Choisissez un nouveau --output.`,
      );
    }
    throw error;
  }
  for (const file of bundle.files) {
    const destination = join(options.output, file.name);
    await writeFile(destination, file.content, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    if (process.platform !== "win32") {
      await chmod(destination, 0o600);
    }
  }
  process.stdout.write(
    [
      `${bundle.summary.policies} politique${bundle.summary.policies > 1 ? "s" : ""} OCI convertie${bundle.summary.policies > 1 ? "s" : ""}.`,
      `${bundle.summary.clusterImagePolicies} politique${bundle.summary.clusterImagePolicies > 1 ? "s" : ""} d’admission générée${bundle.summary.clusterImagePolicies > 1 ? "s" : ""}.`,
      `${bundle.summary.namespaces} namespace${bundle.summary.namespaces > 1 ? "s" : ""} ciblé${bundle.summary.namespaces > 1 ? "s" : ""}.`,
      `Dossier : ${options.output}`,
    ].join(" "),
  );
  process.stdout.write("\n");
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : "Échec de la génération Kubernetes."}\n`,
  );
  process.exitCode = 1;
});
