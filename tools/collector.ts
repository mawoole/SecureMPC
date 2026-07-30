#!/usr/bin/env node

import { chmod, readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  auditConfiguration,
  createSarifReport,
  type Severity,
} from "../lib/audit-engine.ts";
import {
  evaluateSecurityGate,
  formatSecurityGateSummary,
} from "../lib/ci-gate.ts";
import { collectInventory } from "../lib/collector.ts";
import {
  parseOciVerificationPolicyDocument,
  type OciVerificationPolicy,
  type OciVerificationRule,
} from "../lib/oci-provenance.ts";
import { scanComponentsWithOsv } from "../lib/osv.ts";
import type { ProvenancePolicy } from "../lib/provenance.ts";
import { createCycloneDxReport } from "../lib/supply-chain.ts";

type CliOptions = {
  additionalPaths: string[];
  failOn?: Severity;
  includeDefaultPaths: boolean;
  lockfilePaths: string[];
  output: string;
  ociBackend?: "cosign" | "github";
  ociIdentity?: string;
  ociIssuer?: string;
  ociPolicyFile?: string;
  ociRepository?: string;
  ociVerificationPolicy?: OciVerificationPolicy;
  ociVerificationPolicies?: OciVerificationRule[];
  ociVerifierExecutable?: string;
  osv: boolean;
  probe: boolean;
  provenanceIdentity?: string;
  provenanceIssuer?: string;
  provenancePolicy?: ProvenancePolicy;
  requireServers: boolean;
  scanLockfiles: boolean;
  sarifOutput?: string;
  sbomOutput?: string;
  stdout: boolean;
  timeoutMs: number;
  verifyProvenance: boolean;
  verifyOciProvenance: boolean;
  workspace?: string;
};

function help(): string {
  return `Secure MPC Collector

Usage:
  npm run collect
  npm run collect:security
  npm run collect -- --probe
  npm run collect -- --sbom
  npm run collect -- --osv --sbom
  npm run collect -- --path ./mcp.json --output ./mcp-inventory.json
  npm run audit:ci -- --path ./.mcp.json --sarif

Options:
  --path <fichier>       Ajoute une configuration JSON ou TOML explicite (répétable)
  --no-default-paths     Ignore les configurations utilisateur et du workspace
  --workspace <dossier>  Dossier où rechercher .mcp.json, .vscode/mcp.json et .cursor/mcp.json
  --lockfile <fichier>    Ajoute un lockfile npm, pnpm, Yarn, uv ou Poetry
  --no-lockfiles          Désactive la découverte des lockfiles du workspace
  --probe                Vérifie passivement les endpoints HTTPS distants
  --osv                  Interroge OSV.dev avec les PURL versionnés uniquement
  --provenance           Vérifie signatures npm et attestations SLSA/Sigstore
  --provenance-issuer <url>
                         Exige cet émetteur de certificat Sigstore
  --provenance-identity <regexp>
                         Exige cette identité URI dans le certificat Sigstore
  --oci-cosign           Vérifie signatures et provenance OCI avec Cosign
  --oci-issuer <url>     Émetteur OIDC attendu pour la signature OCI
  --oci-identity <regexp>
                         Identité attendue du certificat Cosign
  --cosign-path <fichier>
                         Chemin facultatif vers cosign ou cosign.exe
  --oci-github-repo <owner/repo>
                         Vérifie l’attestation OCI liée à ce dépôt GitHub
  --oci-policy-file <fichier>
                         Applique plusieurs politiques OCI par préfixe d’image
  --sbom [fichier]       Produit aussi un SBOM CycloneDX 1.7
  --sarif [fichier]      Produit un rapport SARIF (défaut : secure-mpc.sarif)
  --fail-on <niveau>     Échoue sur critical, high ou medium et niveaux supérieurs
  --require-servers      Échoue si aucun serveur MCP n’est découvert
  --timeout <ms>         Délai du probe, entre 500 et 15000 ms (défaut : 5000)
  --output <fichier>     Fichier produit (défaut : mcp-inventory.json)
  --stdout               Écrit l’inventaire sur la sortie standard
  --help                 Affiche cette aide

Garanties du collecteur :
  - les secrets concrets sont remplacés avant l’écriture ;
  - les lockfiles sont lus sans exécuter npm, pnpm, Yarn, uv, Poetry ou un serveur MCP ;
  - aucun en-tête d’authentification découvert n’est envoyé ;
  - avec --osv, seuls les PURL versionnés sont envoyés à OSV.dev ;
  - avec --provenance, seuls nom, version et digest sont rapprochés du registre npm ;
  - la vérification OCI transmet uniquement la référence verrouillée au vérificateur choisi ;
  - aucune image n’est téléchargée ou exécutée par Docker, Podman ou nerdctl ;
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
    includeDefaultPaths: true,
    lockfilePaths: [],
    output: resolve("mcp-inventory.json"),
    osv: false,
    probe: false,
    requireServers: false,
    scanLockfiles: true,
    stdout: false,
    timeoutMs: 5_000,
    verifyOciProvenance: false,
    verifyProvenance: false,
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
    if (argument === "--no-default-paths") {
      options.includeDefaultPaths = false;
      continue;
    }
    if (argument === "--osv") {
      options.osv = true;
      continue;
    }
    if (argument === "--provenance") {
      options.verifyProvenance = true;
      continue;
    }
    if (argument === "--provenance-issuer") {
      options.provenanceIssuer = readValue(args, index, argument);
      options.verifyProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--provenance-identity") {
      options.provenanceIdentity = readValue(args, index, argument);
      options.verifyProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--oci-cosign") {
      options.ociBackend = "cosign";
      options.verifyOciProvenance = true;
      continue;
    }
    if (argument === "--oci-issuer") {
      options.ociIssuer = readValue(args, index, argument);
      options.ociBackend = "cosign";
      options.verifyOciProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--oci-identity") {
      options.ociIdentity = readValue(args, index, argument);
      options.ociBackend = "cosign";
      options.verifyOciProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--cosign-path") {
      options.ociVerifierExecutable = resolve(
        readValue(args, index, argument),
      );
      options.verifyOciProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--oci-github-repo") {
      options.ociRepository = readValue(args, index, argument);
      options.ociBackend = "github";
      options.verifyOciProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--oci-policy-file") {
      options.ociPolicyFile = resolve(readValue(args, index, argument));
      options.verifyOciProvenance = true;
      index += 1;
      continue;
    }
    if (argument === "--stdout") {
      options.stdout = true;
      continue;
    }
    if (argument === "--fail-on") {
      const threshold = readValue(args, index, argument);
      if (!["critical", "high", "medium"].includes(threshold)) {
        throw new Error(
          "--fail-on doit valoir critical, high ou medium.",
        );
      }
      options.failOn = threshold as Severity;
      index += 1;
      continue;
    }
    if (argument === "--require-servers") {
      options.requireServers = true;
      continue;
    }
    if (argument === "--sarif") {
      const candidate = args[index + 1];
      if (candidate && !candidate.startsWith("--")) {
        options.sarifOutput = resolve(candidate);
        index += 1;
      } else {
        options.sarifOutput = resolve("secure-mpc.sarif");
      }
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

  if (Boolean(options.provenanceIssuer) !== Boolean(options.provenanceIdentity)) {
    throw new Error(
      "--provenance-issuer et --provenance-identity doivent être fournis ensemble.",
    );
  }
  if (options.provenanceIssuer && options.provenanceIdentity) {
    const issuer = new URL(options.provenanceIssuer);
    if (issuer.protocol !== "https:") {
      throw new Error("--provenance-issuer doit être une URL HTTPS.");
    }
    try {
      new RegExp(options.provenanceIdentity);
    } catch {
      throw new Error(
        "--provenance-identity doit être une expression régulière valide.",
      );
    }
    options.provenancePolicy = {
      certificateIssuer: options.provenanceIssuer,
      certificateIdentityURI: options.provenanceIdentity,
    };
  }
  if (
    options.ociRepository &&
    (options.ociIssuer || options.ociIdentity || options.ociVerifierExecutable)
  ) {
    throw new Error(
      "--oci-github-repo ne peut pas être combiné avec les options Cosign.",
    );
  }
  if (
    options.ociPolicyFile &&
    (options.ociBackend ||
      options.ociIssuer ||
      options.ociIdentity ||
      options.ociRepository)
  ) {
    throw new Error(
      "--oci-policy-file ne peut pas être combiné avec une politique OCI globale.",
    );
  }
  if (options.ociBackend === "cosign") {
    if (!options.ociIssuer || !options.ociIdentity) {
      throw new Error(
        "--oci-cosign exige --oci-issuer et --oci-identity.",
      );
    }
    const issuer = new URL(options.ociIssuer);
    if (issuer.protocol !== "https:") {
      throw new Error("--oci-issuer doit être une URL HTTPS.");
    }
    try {
      new RegExp(options.ociIdentity);
    } catch {
      throw new Error(
        "--oci-identity doit être une expression régulière valide.",
      );
    }
    options.ociVerificationPolicy = {
      kind: "cosign",
      certificateIssuer: options.ociIssuer,
      certificateIdentityURI: options.ociIdentity,
      predicateType: "slsaprovenance1",
    };
  } else if (options.ociBackend === "github") {
    if (
      !options.ociRepository ||
      !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(options.ociRepository)
    ) {
      throw new Error(
        "--oci-github-repo doit utiliser le format owner/repository.",
      );
    }
    options.ociVerificationPolicy = {
      kind: "github",
      repository: options.ociRepository,
    };
  }

  const outputs = [
    ...(options.stdout ? [] : [options.output]),
    ...(options.sbomOutput ? [options.sbomOutput] : []),
    ...(options.sarifOutput ? [options.sarifOutput] : []),
  ].map((filePath) => resolve(filePath).toLowerCase());
  if (new Set(outputs).size !== outputs.length) {
    throw new Error(
      "Les sorties inventaire, SBOM et SARIF doivent utiliser des fichiers distincts.",
    );
  }
  return options;
}

async function loadOciPolicyFile(
  filePath: string,
): Promise<OciVerificationRule[]> {
  const information = await stat(filePath);
  if (!information.isFile() || information.size > 256_000) {
    throw new Error(
      "Le fichier de politiques OCI doit être un fichier JSON de 256 Ko maximum.",
    );
  }
  const raw = await readFile(filePath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Le fichier de politiques OCI n’est pas un JSON valide.");
  }
  return parseOciVerificationPolicyDocument(parsed).policies;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.ociPolicyFile) {
    options.ociVerificationPolicies = await loadOciPolicyFile(
      options.ociPolicyFile,
    );
  }
  const inventory = await collectInventory({
    ...options,
    ...(options.includeDefaultPaths ? {} : { candidates: [] }),
  });

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
  const auditServers =
    options.sarifOutput || options.failOn || options.requireServers
      ? auditConfiguration(serialized)
      : undefined;

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

  if (options.sarifOutput && auditServers) {
    await writeFile(
      options.sarifOutput,
      `${JSON.stringify(
        createSarifReport(auditServers, new Date(inventory.generatedAt)),
        null,
        2,
      )}\n`,
      {
        encoding: "utf8",
        mode: 0o600,
      },
    );
    if (process.platform !== "win32") {
      await chmod(options.sarifOutput, 0o600);
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
  const provenance = inventory.provenanceScan;
  const oci = inventory.ociVerification;
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
      options.verifyProvenance
        ? `${provenance?.registrySignaturesVerified ?? 0} signature${provenance?.registrySignaturesVerified === 1 ? "" : "s"} npm et ${provenance?.slsaProvenanceVerified ?? 0} provenance${provenance?.slsaProvenanceVerified === 1 ? "" : "s"} SLSA vérifiée${provenance?.slsaProvenanceVerified === 1 ? "" : "s"}.`
        : "Vérification de provenance non demandée.",
      options.verifyOciProvenance
        ? `${oci?.matched ?? 0}/${oci?.images ?? 0} image${oci?.images === 1 ? "" : "s"} rattachée${oci?.images === 1 ? "" : "s"} à ${oci?.policies ?? 0} politique${oci?.policies === 1 ? "" : "s"} OCI ; ${oci?.unmatched ?? 0} sans correspondance.`
        : "Vérification OCI non demandée.",
      options.stdout ? "" : `Inventaire : ${options.output}`,
      options.sbomOutput ? `SBOM : ${options.sbomOutput}` : "",
      options.sarifOutput ? `SARIF : ${options.sarifOutput}` : "",
    ]
      .filter(Boolean)
      .join(" "),
  );
  process.stderr.write("\n");
  const incomplete =
    inventory.vulnerabilityScan?.status === "error" ||
    inventory.provenanceScan?.status === "error" ||
    inventory.ociVerification?.status === "error";
  const gate =
    auditServers && (options.failOn || options.requireServers)
      ? evaluateSecurityGate(auditServers, {
          threshold: options.failOn,
          requireServers: options.requireServers,
        })
      : undefined;
  if (gate) {
    process.stderr.write(`${formatSecurityGateSummary(gate)}\n`);
  }
  if (gate && !gate.passed) {
    process.exitCode = 3;
  } else if (incomplete) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : "Échec du collecteur."}\n`,
  );
  process.exitCode = 1;
});
