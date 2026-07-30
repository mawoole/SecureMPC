export type ComponentEcosystem = "npm" | "pypi" | "oci" | "executable";
export type ComponentPinStatus =
  | "pinned"
  | "unpinned"
  | "mutable"
  | "unknown"
  | "not-applicable";

export type VulnerabilitySeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "unknown";

export type ComponentVulnerability = {
  id: string;
  aliases: string[];
  summary: string;
  severity: VulnerabilitySeverity;
  modified?: string;
  advisoryUrl: string;
  fixedVersion?: string;
};

export type VerificationState =
  | "verified"
  | "missing"
  | "failed"
  | "unverifiable"
  | "error"
  | "not-applicable";

export type ComponentProvenance = {
  provider:
    | "npm-registry-sigstore"
    | "oci-cosign"
    | "oci-github-attestation"
    | "oci-policy";
  checkedAt: string;
  registrySignature: VerificationState;
  slsaProvenance: VerificationState;
  subjectDigest: "matched" | "mismatched" | "unavailable";
  identityPolicy: "matched" | "mismatched" | "not-configured";
  policyId?: string;
  sourceRepository?: string;
  builderId?: string;
  message: string;
};

export type SupplyChainComponent = {
  id: string;
  ecosystem: ComponentEcosystem;
  name: string;
  version?: string;
  reference: string;
  purl?: string;
  componentType: "library" | "container" | "application";
  pinStatus: ComponentPinStatus;
  evidence: string;
  scope?: "direct" | "transitive";
  dependencies?: string[];
  lockfile?: string;
  integrityStatus?: "recorded" | "missing";
  integrity?: string;
  workspace?: string;
  provenance?: ComponentProvenance;
  vulnerabilities?: ComponentVulnerability[];
};

export type SbomServer = {
  id: string;
  name: string;
  transport: string;
  source: string;
  score?: number;
  findings?: unknown[];
  components?: SupplyChainComponent[];
};

const EXACT_SEMVER =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/i;

function commandName(command: string): string {
  return (
    command
      .trim()
      .split(/[\\/]/)
      .pop()
      ?.toLowerCase()
      .replace(/\.(?:bat|cmd|exe)$/i, "") ?? ""
  );
}

function componentId(
  ecosystem: ComponentEcosystem,
  name: string,
  version?: string,
): string {
  return `${ecosystem}:${encodeURIComponent(name)}@${encodeURIComponent(version ?? "unknown")}`;
}

function encodePurlPath(value: string): string {
  return value
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

function npmPurl(name: string, version?: string): string {
  const path = name.startsWith("@")
    ? `${encodeURIComponent(name.split("/")[0])}/${encodeURIComponent(name.split("/").slice(1).join("/"))}`
    : encodeURIComponent(name);
  return `pkg:npm/${path}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function pypiPurl(name: string, version?: string): string {
  const normalized = name.toLowerCase().replace(/[_.]+/g, "-");
  return `pkg:pypi/${encodeURIComponent(normalized)}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function ociPurl(name: string, version?: string): string {
  return `pkg:docker/${encodePurlPath(name)}${version ? `@${encodeURIComponent(version)}` : ""}`;
}

function parseNpmSpec(reference: string): SupplyChainComponent | undefined {
  const trimmed = reference.trim();
  if (
    !trimmed ||
    /^(?:https?|git|file):/i.test(trimmed) ||
    trimmed.startsWith(".") ||
    /^[a-z]:[\\/]/i.test(trimmed)
  ) {
    return undefined;
  }

  const separator = trimmed.startsWith("@")
    ? trimmed.lastIndexOf("@")
    : trimmed.indexOf("@");
  const hasVersion =
    separator > 0 &&
    (!trimmed.startsWith("@") || separator > trimmed.indexOf("/"));
  const name = hasVersion ? trimmed.slice(0, separator) : trimmed;
  const requestedVersion = hasVersion ? trimmed.slice(separator + 1) : "";
  if (!/^@?[a-z0-9][a-z0-9._/-]*$/i.test(name)) return undefined;

  const pinned = EXACT_SEMVER.test(requestedVersion);
  const version = pinned ? requestedVersion : undefined;
  return {
    id: componentId("npm", name, version),
    ecosystem: "npm",
    name,
    version,
    reference: trimmed,
    purl: npmPurl(name, version),
    componentType: "library",
    pinStatus: pinned ? "pinned" : "unpinned",
    evidence: pinned
      ? "Version npm exacte déclarée dans la commande."
      : "La commande peut résoudre une version npm différente à l’avenir.",
  };
}

function parsePypiSpec(reference: string): SupplyChainComponent | undefined {
  const trimmed = reference.trim();
  const match = trimmed.match(
    /^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?)(?:==([^;\s]+))?$/,
  );
  if (!match) return undefined;

  const name = match[1].replace(/\[.*\]$/, "");
  const requestedVersion = match[2] ?? "";
  const pinned = Boolean(requestedVersion) && !requestedVersion.includes("*");
  const version = pinned ? requestedVersion : undefined;
  return {
    id: componentId("pypi", name, version),
    ecosystem: "pypi",
    name,
    version,
    reference: trimmed,
    purl: pypiPurl(name, version),
    componentType: "library",
    pinStatus: pinned ? "pinned" : "unpinned",
    evidence: pinned
      ? "Version PyPI exacte déclarée avec ==."
      : "Aucune version PyPI exacte n’est déclarée.",
  };
}

function parseOciSpec(reference: string): SupplyChainComponent | undefined {
  const trimmed = reference.trim().replace(/^docker:\/\//i, "");
  if (!trimmed || /\s/.test(trimmed)) return undefined;

  const digestSeparator = trimmed.lastIndexOf("@");
  if (digestSeparator > 0) {
    const name = trimmed.slice(0, digestSeparator);
    const digest = trimmed.slice(digestSeparator + 1);
    const pinned = SHA256_DIGEST.test(digest);
    return {
      id: componentId("oci", name, pinned ? digest : undefined),
      ecosystem: "oci",
      name,
      version: pinned ? digest : undefined,
      reference: trimmed,
      purl: ociPurl(name, pinned ? digest : undefined),
      componentType: "container",
      pinStatus: pinned ? "pinned" : "unpinned",
      evidence: pinned
        ? "Image OCI verrouillée par digest SHA-256."
        : "Le digest OCI déclaré n’est pas un SHA-256 complet.",
    };
  }

  const lastSlash = trimmed.lastIndexOf("/");
  const tagSeparator = trimmed.lastIndexOf(":");
  const hasTag = tagSeparator > lastSlash;
  const name = hasTag ? trimmed.slice(0, tagSeparator) : trimmed;
  const tag = hasTag ? trimmed.slice(tagSeparator + 1) : undefined;
  return {
    id: componentId("oci", name, tag),
    ecosystem: "oci",
    name,
    version: tag,
    reference: trimmed,
    purl: ociPurl(name, tag),
    componentType: "container",
    pinStatus: tag ? "mutable" : "unpinned",
    evidence: tag
      ? "Le tag OCI est versionné mais reste mutable."
      : "L’image OCI n’a ni tag ni digest.",
  };
}

function optionValue(
  args: string[],
  longName: string,
): string | undefined {
  const directIndex = args.indexOf(longName);
  if (directIndex >= 0) return args[directIndex + 1];
  const prefix = `${longName}=`;
  return args.find((argument) => argument.startsWith(prefix))?.slice(
    prefix.length,
  );
}

function firstNonOption(
  args: string[],
  startIndex = 0,
): string | undefined {
  return args.slice(startIndex).find((argument) => !argument.startsWith("-"));
}

function npmReference(command: string, args: string[]): string | undefined {
  if (command === "npx" || command === "bunx") {
    return optionValue(args, "--package") ?? firstNonOption(args);
  }
  if (
    (command === "pnpm" || command === "yarn") &&
    args[0]?.toLowerCase() === "dlx"
  ) {
    return firstNonOption(args, 1);
  }
  if (
    command === "npm" &&
    ["exec", "x"].includes(args[0]?.toLowerCase())
  ) {
    const separator = args.indexOf("--");
    return (
      optionValue(args, "--package") ??
      firstNonOption(args, separator >= 0 ? separator + 1 : 1)
    );
  }
  return undefined;
}

function pypiReference(command: string, args: string[]): string | undefined {
  if (command === "uvx") {
    return optionValue(args, "--from") ?? firstNonOption(args);
  }
  if (command === "pipx" && args[0]?.toLowerCase() === "run") {
    return firstNonOption(args, 1);
  }
  return undefined;
}

function ociReference(command: string, args: string[]): string | undefined {
  if (!["docker", "podman", "nerdctl"].includes(command)) return undefined;
  const runIndex = args.findIndex(
    (argument) => argument.toLowerCase() === "run",
  );
  if (runIndex < 0) return undefined;

  const optionsWithValues = new Set([
    "--add-host",
    "--cap-add",
    "--cap-drop",
    "--cpus",
    "--device",
    "--dns",
    "--entrypoint",
    "--env",
    "--env-file",
    "--gpus",
    "--hostname",
    "--ipc",
    "--label",
    "--memory",
    "--mount",
    "--name",
    "--network",
    "--pid",
    "--platform",
    "--pull",
    "--publish",
    "--restart",
    "--runtime",
    "--security-opt",
    "--user",
    "--volume",
    "--workdir",
    "-e",
    "-h",
    "-l",
    "-m",
    "-p",
    "-u",
    "-v",
    "-w",
  ]);
  for (let index = runIndex + 1; index < args.length; index += 1) {
    const argument = args[index];
    const optionName = argument.split("=")[0];
    if (optionsWithValues.has(optionName)) {
      if (!argument.includes("=")) index += 1;
      continue;
    }
    if (argument.startsWith("-")) continue;
    return argument;
  }
  return undefined;
}

function executableComponent(command: string): SupplyChainComponent | undefined {
  const name = command.trim().split(/[\\/]/).pop();
  if (!name) return undefined;
  return {
    id: componentId("executable", name),
    ecosystem: "executable",
    name,
    reference: name,
    componentType: "application",
    pinStatus: "unknown",
    evidence:
      "Exécutable local détecté ; sa version n’est pas déclarée dans la configuration MCP.",
  };
}

export function extractSupplyChainComponents(
  configuration: Record<string, unknown>,
): SupplyChainComponent[] {
  const command =
    typeof configuration.command === "string" ? configuration.command : "";
  const args = Array.isArray(configuration.args)
    ? configuration.args.map((argument) => String(argument))
    : [];
  const launcher = commandName(command);
  const npm = npmReference(launcher, args);
  const pypi = pypiReference(launcher, args);
  const oci = ociReference(launcher, args);
  const components = [
    npm ? parseNpmSpec(npm) : undefined,
    pypi ? parsePypiSpec(pypi) : undefined,
    oci ? parseOciSpec(oci) : undefined,
  ].filter((component): component is SupplyChainComponent =>
    Boolean(component),
  );

  if (!components.length && command) {
    const executable = executableComponent(command);
    if (executable) components.push(executable);
  }

  return [
    ...new Map(
      components.map((component) => [
        `${component.ecosystem}:${component.name}:${component.version ?? component.reference}`,
        { ...component, scope: "direct" as const },
      ]),
    ).values(),
  ];
}

function componentBomRef(component: SupplyChainComponent): string {
  return component.purl ?? `urn:mcp-component:${component.id}`;
}

function serialNumber(value?: string): string {
  if (value) return value.startsWith("urn:uuid:") ? value : `urn:uuid:${value}`;
  return `urn:uuid:${globalThis.crypto.randomUUID()}`;
}

export function createCycloneDxReport(
  servers: SbomServer[],
  generatedAt = new Date(),
  serial?: string,
) {
  const packageComponents = new Map<string, SupplyChainComponent>();
  for (const server of servers) {
    for (const component of server.components ?? []) {
      const ref = componentBomRef(component);
      const existing = packageComponents.get(ref);
      packageComponents.set(
        ref,
        existing
          ? {
              ...existing,
              dependencies: [
                ...new Set([
                  ...(existing.dependencies ?? []),
                  ...(component.dependencies ?? []),
                ]),
              ],
              vulnerabilities: [
                ...new Map(
                  [
                    ...(existing.vulnerabilities ?? []),
                    ...(component.vulnerabilities ?? []),
                  ].map((vulnerability) => [
                    vulnerability.id,
                    vulnerability,
                  ]),
                ).values(),
              ],
            }
          : component,
      );
    }
  }

  const vulnerabilityEntries = new Map<
    string,
    {
      vulnerability: ComponentVulnerability;
      affects: Set<string>;
    }
  >();
  for (const server of servers) {
    for (const component of server.components ?? []) {
      const ref = componentBomRef(component);
      for (const vulnerability of component.vulnerabilities ?? []) {
        const existing = vulnerabilityEntries.get(vulnerability.id) ?? {
          vulnerability,
          affects: new Set<string>(),
        };
        existing.affects.add(ref);
        vulnerabilityEntries.set(vulnerability.id, existing);
      }
    }
  }

  const serverRefs = servers.map(
    (server) => `urn:mcp-server:${encodeURIComponent(server.id)}`,
  );
  const rootRef = "urn:mcp-inventory:mcp-sentinel";

  return {
    $schema: "https://cyclonedx.org/schema/bom-1.7.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: serialNumber(serial),
    version: 1,
    metadata: {
      timestamp: generatedAt.toISOString(),
      tools: {
        components: [
          {
            type: "application",
            name: "MCP Sentinel",
            version: "1.5.0",
          },
        ],
      },
      component: {
        type: "application",
        "bom-ref": rootRef,
        name: "MCP server inventory",
        version: "1",
      },
    },
    components: [
      ...servers.map((server, index) => ({
        type: "application",
        "bom-ref": serverRefs[index],
        name: server.name,
        properties: [
          { name: "mcp-sentinel:transport", value: server.transport },
          { name: "mcp-sentinel:source", value: server.source },
          ...(server.score === undefined
            ? []
            : [
                {
                  name: "mcp-sentinel:security-score",
                  value: String(server.score),
                },
              ]),
          ...(server.findings
            ? [
                {
                  name: "mcp-sentinel:findings",
                  value: String(server.findings.length),
                },
              ]
            : []),
        ],
      })),
      ...[...packageComponents.entries()].map(([bomRef, component]) => ({
        type: component.componentType,
        "bom-ref": bomRef,
        name: component.name,
        ...(component.version ? { version: component.version } : {}),
        ...(component.purl ? { purl: component.purl } : {}),
        properties: [
          {
            name: "mcp-sentinel:ecosystem",
            value: component.ecosystem,
          },
          {
            name: "mcp-sentinel:pin-status",
            value: component.pinStatus,
          },
          {
            name: "mcp-sentinel:evidence",
            value: component.evidence,
          },
          {
            name: "mcp-sentinel:scope",
            value: component.scope ?? "direct",
          },
          ...(component.lockfile
            ? [
                {
                  name: "mcp-sentinel:lockfile",
                  value: component.lockfile,
                },
              ]
            : []),
          ...(component.integrityStatus
            ? [
                {
                  name: "mcp-sentinel:integrity",
                  value: component.integrityStatus,
                },
              ]
            : []),
          ...(component.workspace
            ? [
                {
                  name: "mcp-sentinel:workspace",
                  value: component.workspace,
                },
              ]
            : []),
          ...(component.provenance
            ? [
                {
                  name: "mcp-sentinel:provenance-provider",
                  value: component.provenance.provider,
                },
                {
                  name: "mcp-sentinel:registry-signature",
                  value: component.provenance.registrySignature,
                },
                {
                  name: "mcp-sentinel:slsa-provenance",
                  value: component.provenance.slsaProvenance,
                },
                {
                  name: "mcp-sentinel:provenance-subject-digest",
                  value: component.provenance.subjectDigest,
                },
                {
                  name: "mcp-sentinel:provenance-identity-policy",
                  value: component.provenance.identityPolicy,
                },
                ...(component.provenance.policyId
                  ? [
                      {
                        name: "mcp-sentinel:provenance-policy",
                        value: component.provenance.policyId,
                      },
                    ]
                  : []),
                ...(component.provenance.sourceRepository
                  ? [
                      {
                        name: "mcp-sentinel:source-repository",
                        value: component.provenance.sourceRepository,
                      },
                    ]
                  : []),
                ...(component.provenance.builderId
                  ? [
                      {
                        name: "mcp-sentinel:builder-id",
                        value: component.provenance.builderId,
                      },
                    ]
                  : []),
              ]
            : []),
        ],
      })),
    ],
    dependencies: [
      { ref: rootRef, dependsOn: serverRefs },
      ...servers.map((server, index) => ({
        ref: serverRefs[index],
        dependsOn: [
          ...new Set(
            (server.components ?? [])
              .filter((component) => component.scope !== "transitive")
              .map(componentBomRef),
          ),
        ],
      })),
      ...[...packageComponents.entries()].map(([ref, component]) => ({
        ref,
        dependsOn: (component.dependencies ?? []).filter((dependency) =>
          packageComponents.has(dependency),
        ),
      })),
    ],
    ...(vulnerabilityEntries.size
      ? {
          vulnerabilities: [...vulnerabilityEntries.values()].map(
            ({ vulnerability, affects }) => ({
              id: vulnerability.id,
              source: {
                name: "OSV",
                url: `https://osv.dev/vulnerability/${encodeURIComponent(vulnerability.id)}`,
              },
              ratings: [
                {
                  source: { name: "OSV" },
                  severity: vulnerability.severity,
                },
              ],
              description: vulnerability.summary,
              ...(vulnerability.modified
                ? { updated: vulnerability.modified }
                : {}),
              ...(vulnerability.fixedVersion
                ? {
                    recommendation: `Mettre à jour vers ${vulnerability.fixedVersion} ou une version corrigée ultérieure.`,
                  }
                : {}),
              affects: [...affects].map((ref) => ({ ref })),
            }),
          ),
        }
      : {}),
  };
}
