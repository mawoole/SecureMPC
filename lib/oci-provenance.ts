import { spawn } from "node:child_process";
import { basename, isAbsolute } from "node:path";
import type {
  ComponentProvenance,
  SupplyChainComponent,
  VerificationState,
} from "./supply-chain.ts";

const MAX_OCI_IMAGES = 50;
const MAX_OCI_POLICIES = 50;
const MAX_COMMAND_OUTPUT_BYTES = 8_000_000;
const DEFAULT_TIMEOUT_MS = 60_000;
const SHA256_DIGEST = /^sha256:([a-f0-9]{64})$/i;
const SLSA_PROVENANCE = /^https:\/\/slsa\.dev\/provenance\/v1$/;
const POLICY_ID = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$/;

type JsonRecord = Record<string, unknown>;

export type OciVerificationPolicy =
  | {
      kind: "cosign";
      certificateIssuer: string;
      certificateIdentityURI: string;
      predicateType?: "slsaprovenance1";
    }
  | {
      kind: "github";
      repository: string;
    };

export type OciVerificationRule = (
  | Extract<OciVerificationPolicy, { kind: "cosign" }>
  | Extract<OciVerificationPolicy, { kind: "github" }>
) & {
  id: string;
  imagePrefix: string;
};

export type OciVerificationPolicyDocument = {
  version: 1;
  policies: OciVerificationRule[];
};

export type VerificationCommandResult = {
  code: number | null;
  stdout: string;
  stderr: string;
  errorCode?: string;
  timedOut?: boolean;
  outputTruncated?: boolean;
};

export type VerificationCommandRunner = (
  executable: string,
  args: string[],
  timeoutMs: number,
) => Promise<VerificationCommandResult>;

export type OciVerificationOptions = {
  policy?: OciVerificationPolicy;
  policies?: OciVerificationRule[];
  commandRunner?: VerificationCommandRunner;
  executable?: string;
  executables?: {
    cosign?: string;
    github?: string;
  };
  now?: () => Date;
  timeoutMs?: number;
};

export type OciVerificationSummary = {
  provider: "oci-provenance";
  backend: "cosign" | "github-attestations" | "mixed";
  status: "complete" | "partial" | "error";
  checkedAt: string;
  images: number;
  policies: number;
  matched: number;
  unmatched: number;
  signaturesVerified: number;
  slsaProvenanceVerified: number;
  missing: number;
  failed: number;
  message: string;
};

function record(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function cleanText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned ? cleaned.slice(0, maxLength) : undefined;
}

function safeExecutable(value: string, expected: "cosign" | "gh"): string {
  const executable = value.trim();
  const name = basename(executable).toLowerCase().replace(/\.exe$/, "");
  if (
    name !== expected ||
    (!isAbsolute(executable) && !/^[A-Za-z0-9._-]+$/.test(executable))
  ) {
    throw new Error(
      `Le chemin de l’exécutable doit cibler ${expected}${process.platform === "win32" ? ".exe" : ""}.`,
    );
  }
  return executable;
}

export function validateOciVerificationPolicy(
  policy: OciVerificationPolicy,
): void {
  if (policy.kind === "github") {
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(policy.repository)) {
      throw new Error("Le dépôt OCI attendu doit utiliser le format owner/repository.");
    }
    return;
  }
  const issuer = new URL(policy.certificateIssuer);
  if (issuer.protocol !== "https:" || issuer.username || issuer.password) {
    throw new Error("L’émetteur OCI doit être une URL HTTPS sans identifiants.");
  }
  if (
    !policy.certificateIdentityURI ||
    policy.certificateIdentityURI.length > 1_000
  ) {
    throw new Error("L’identité OCI attendue est obligatoire.");
  }
  try {
    new RegExp(policy.certificateIdentityURI);
  } catch {
    throw new Error("L’identité OCI doit être une expression régulière valide.");
  }
}

function normalizedImagePrefix(value: string): string {
  const prefix = value
    .trim()
    .replace(/^docker:\/\//i, "")
    .replace(/\/+$/, "")
    .toLowerCase();
  if (
    !prefix ||
    prefix.length > 512 ||
    prefix.includes("@") ||
    prefix.includes("://") ||
    /\s/.test(prefix)
  ) {
    throw new Error(
      "Le préfixe OCI doit être un chemin de registre sans schéma, tag ni digest.",
    );
  }
  const slash = prefix.indexOf("/");
  const registry = prefix.slice(0, slash);
  const repository = prefix.slice(slash + 1);
  const registryPort = registry.match(/:(\d{1,5})$/)?.[1];
  if (
    slash < 1 ||
    !repository ||
    (registryPort !== undefined && Number(registryPort) > 65_535) ||
    !/^(?:localhost|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::\d{1,5})?$/.test(
      registry,
    ) ||
    repository.split("/").some(
      (segment) =>
        !segment ||
        !/^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*$/.test(segment),
    )
  ) {
    throw new Error(
      "Le préfixe OCI doit utiliser le format registre/organisation[/image].",
    );
  }
  return prefix;
}

export function validateOciVerificationRules(
  policies: OciVerificationRule[],
): void {
  if (!policies.length || policies.length > MAX_OCI_POLICIES) {
    throw new Error(
      `Le document OCI doit contenir entre 1 et ${MAX_OCI_POLICIES} politiques.`,
    );
  }
  const identifiers = new Set<string>();
  const prefixes = new Set<string>();
  policies.forEach((policy) => {
    if (!POLICY_ID.test(policy.id)) {
      throw new Error(
        "Chaque politique OCI doit avoir un identifiant sûr de 1 à 64 caractères.",
      );
    }
    const identifier = policy.id.toLowerCase();
    if (identifiers.has(identifier)) {
      throw new Error(`Identifiant de politique OCI dupliqué : ${policy.id}.`);
    }
    identifiers.add(identifier);
    const prefix = normalizedImagePrefix(policy.imagePrefix);
    if (prefixes.has(prefix)) {
      throw new Error(`Préfixe de politique OCI dupliqué : ${prefix}.`);
    }
    prefixes.add(prefix);
    validateOciVerificationPolicy(policy);
  });
}

function policyText(
  value: unknown,
  field: string,
  index: number,
  maxLength: number,
): string {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength
  ) {
    throw new Error(
      `La politique OCI ${index + 1} doit définir ${field}.`,
    );
  }
  return value.trim();
}

export function parseOciVerificationPolicyDocument(
  value: unknown,
): OciVerificationPolicyDocument {
  const document = record(value);
  if (
    !document ||
    document.version !== 1 ||
    !Array.isArray(document.policies)
  ) {
    throw new Error(
      "Le fichier de politiques OCI doit déclarer version: 1 et un tableau policies.",
    );
  }
  if (
    Object.keys(document).some(
      (key) => !["version", "policies"].includes(key),
    )
  ) {
    throw new Error(
      "Le fichier de politiques OCI contient une propriété inconnue.",
    );
  }
  const policies = document.policies.map((candidate, index) => {
    const policy = record(candidate);
    if (!policy || !["cosign", "github"].includes(String(policy.kind))) {
      throw new Error(
        `La politique OCI ${index + 1} doit utiliser kind: cosign ou github.`,
      );
    }
    const id = policyText(policy.id, "id", index, 64);
    const imagePrefix = policyText(
      policy.imagePrefix,
      "imagePrefix",
      index,
      512,
    );
    if (policy.kind === "github") {
      const allowed = new Set(["id", "imagePrefix", "kind", "repository"]);
      if (Object.keys(policy).some((key) => !allowed.has(key))) {
        throw new Error(
          `La politique OCI ${id} contient une propriété inconnue.`,
        );
      }
      return {
        id,
        imagePrefix,
        kind: "github" as const,
        repository: policyText(policy.repository, "repository", index, 200),
      };
    }
    const allowed = new Set([
      "id",
      "imagePrefix",
      "kind",
      "certificateIssuer",
      "certificateIdentityURI",
      "predicateType",
    ]);
    if (Object.keys(policy).some((key) => !allowed.has(key))) {
      throw new Error(
        `La politique OCI ${id} contient une propriété inconnue.`,
      );
    }
    if (
      policy.predicateType !== undefined &&
      policy.predicateType !== "slsaprovenance1"
    ) {
      throw new Error(
        `La politique OCI ${id} doit utiliser predicateType: slsaprovenance1.`,
      );
    }
    return {
      id,
      imagePrefix,
      kind: "cosign" as const,
      certificateIssuer: policyText(
        policy.certificateIssuer,
        "certificateIssuer",
        index,
        2_048,
      ),
      certificateIdentityURI: policyText(
        policy.certificateIdentityURI,
        "certificateIdentityURI",
        index,
        1_000,
      ),
      predicateType: "slsaprovenance1" as const,
    };
  });
  validateOciVerificationRules(policies);
  return { version: 1, policies };
}

export const runVerificationCommand: VerificationCommandRunner = (
  executable,
  args,
  timeoutMs,
) =>
  new Promise((resolve) => {
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let outputTruncated = false;
    let settled = false;
    const append = (current: string, chunk: Buffer) => {
      if (outputTruncated) return current;
      const next = current + chunk.toString("utf8");
      if (Buffer.byteLength(next, "utf8") > MAX_COMMAND_OUTPUT_BYTES) {
        outputTruncated = true;
        child.kill();
        return next.slice(0, MAX_COMMAND_OUTPUT_BYTES);
      }
      return next;
    };
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = append(stdout, chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = append(stderr, chunk);
    });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      resolve({
        code: null,
        stdout,
        stderr,
        timedOut: true,
        outputTruncated,
      });
    }, timeoutMs);
    child.on("error", (error: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: null,
        stdout,
        stderr,
        errorCode: error.code ?? "SPAWN_ERROR",
        outputTruncated,
      });
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr, outputTruncated });
    });
  });

function parseJsonOutput(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    const starts = [trimmed.indexOf("["), trimmed.indexOf("{")].filter(
      (index) => index >= 0,
    );
    const start = Math.min(...starts);
    if (!Number.isFinite(start)) return undefined;
    try {
      return JSON.parse(trimmed.slice(start)) as unknown;
    } catch {
      return undefined;
    }
  }
}

function values(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function statementSubjectMatches(
  statement: unknown,
  expectedDigest: string,
): boolean {
  const parsed = record(statement);
  if (!parsed || !Array.isArray(parsed.subject)) return false;
  const expected = expectedDigest.replace(/^sha256:/, "").toLowerCase();
  return parsed.subject.some((value) => {
    const subject = record(value);
    const digests = record(subject?.digest);
    return cleanText(digests?.sha256, 128)?.toLowerCase() === expected;
  });
}

function statementDetails(statement: unknown): {
  repository?: string;
  builderId?: string;
} {
  const parsed = record(statement);
  const predicate = record(parsed?.predicate);
  const buildDefinition = record(predicate?.buildDefinition);
  const externalParameters = record(buildDefinition?.externalParameters);
  const workflow = record(externalParameters?.workflow);
  const runDetails = record(predicate?.runDetails);
  const builder = record(runDetails?.builder);
  const repository = cleanText(workflow?.repository, 2_048);
  const builderId = cleanText(builder?.id, 2_048);
  return {
    ...(repository?.startsWith("https://") ? { repository } : {}),
    ...(builderId?.startsWith("https://") ? { builderId } : {}),
  };
}

function cosignSignatureDigestMatches(
  output: unknown,
  expectedDigest: string,
): boolean {
  return values(output).some((value) => {
    const entry = record(value);
    const critical = record(entry?.critical) ?? record(entry?.Critical);
    const image = record(critical?.image) ?? record(critical?.Image);
    const digest =
      cleanText(image?.["docker-manifest-digest"], 100) ??
      cleanText(image?.["Docker-manifest-digest"], 100);
    return digest?.toLowerCase() === expectedDigest.toLowerCase();
  });
}

function cosignStatements(output: unknown): JsonRecord[] {
  return values(output).flatMap((value) => {
    const entry = record(value);
    const payload = cleanText(entry?.payload, MAX_COMMAND_OUTPUT_BYTES);
    if (!payload) return [];
    try {
      const statement = JSON.parse(
        Buffer.from(payload, "base64").toString("utf8"),
      ) as unknown;
      const parsed = record(statement);
      return parsed ? [parsed] : [];
    } catch {
      return [];
    }
  });
}

function githubStatements(output: unknown): JsonRecord[] {
  return values(output).flatMap((value) => {
    const entry = record(value);
    const verificationResult = record(entry?.verificationResult);
    const statement = record(verificationResult?.statement);
    return statement ? [statement] : [];
  });
}

function commandFailureState(
  result: VerificationCommandResult,
): { state: VerificationState; message: string } {
  if (result.errorCode === "ENOENT") {
    return {
      state: "error",
      message: "L’outil de vérification OCI n’est pas installé ou accessible.",
    };
  }
  if (result.timedOut) {
    return {
      state: "error",
      message: "La vérification OCI a dépassé le délai autorisé.",
    };
  }
  if (result.outputTruncated) {
    return {
      state: "error",
      message: "La sortie du vérificateur OCI dépasse la limite de sécurité.",
    };
  }
  const output = `${result.stderr}\n${result.stdout}`.toLowerCase();
  if (
    /no matching|no signatures|no attestations|manifest unknown|not found/.test(
      output,
    )
  ) {
    return {
      state: "missing",
      message: "Aucune preuve OCI correspondante n’a été trouvée.",
    };
  }
  if (
    /timeout|timed out|connection refused|tls handshake|network|dial tcp|unauthorized|denied|no valid sigstore verifiers|trusted root|trust root/.test(
      output,
    )
  ) {
    return {
      state: "error",
      message: "Le registre ou le service de confiance OCI est indisponible.",
    };
  }
  return {
    state: "failed",
    message: cleanText(result.stderr || result.stdout, 500) ??
      "La preuve OCI a été rejetée.",
  };
}

function initialProvenance(
  provider: ComponentProvenance["provider"],
  checkedAt: string,
  message: string,
  policyId?: string,
): ComponentProvenance {
  return {
    provider,
    checkedAt,
    registrySignature: "unverifiable",
    slsaProvenance: "unverifiable",
    subjectDigest: "unavailable",
    identityPolicy: "not-configured",
    ...(policyId ? { policyId } : {}),
    message,
  };
}

async function verifyWithCosign(
  component: SupplyChainComponent,
  policy: Extract<OciVerificationPolicy, { kind: "cosign" }>,
  executable: string,
  runner: VerificationCommandRunner,
  timeoutMs: number,
  checkedAt: string,
  policyId?: string,
): Promise<ComponentProvenance> {
  const expectedDigest = component.version ?? "";
  const common = [
    "--certificate-oidc-issuer",
    policy.certificateIssuer,
    "--certificate-identity-regexp",
    policy.certificateIdentityURI,
    "--output",
    "json",
    "--timeout",
    "45s",
  ];
  const signatureResult = await runner(
    executable,
    ["verify", ...common, component.reference],
    timeoutMs,
  );
  let registrySignature: VerificationState;
  let signatureMessage = "";
  if (signatureResult.code === 0) {
    registrySignature = cosignSignatureDigestMatches(
      parseJsonOutput(signatureResult.stdout),
      expectedDigest,
    )
      ? "verified"
      : "failed";
    if (registrySignature === "failed") {
      signatureMessage = "La signature Cosign ne cible pas le digest attendu.";
    }
  } else {
    const failure = commandFailureState(signatureResult);
    registrySignature = failure.state;
    signatureMessage = failure.message;
  }

  const attestationResult = await runner(
    executable,
    [
      "verify-attestation",
      ...common,
      "--type",
      policy.predicateType ?? "slsaprovenance1",
      component.reference,
    ],
    timeoutMs,
  );
  if (attestationResult.code !== 0) {
    const failure = commandFailureState(attestationResult);
    return {
      ...initialProvenance(
        "oci-cosign",
        checkedAt,
        failure.message,
        policyId,
      ),
      registrySignature,
      slsaProvenance: failure.state,
      identityPolicy:
        failure.state === "failed" ? "mismatched" : "not-configured",
      message: [signatureMessage, failure.message].filter(Boolean).join(" "),
    };
  }
  const statements = cosignStatements(parseJsonOutput(attestationResult.stdout));
  const statement = statements.find(
    (candidate) =>
      SLSA_PROVENANCE.test(String(candidate.predicateType ?? "")) &&
      statementSubjectMatches(candidate, expectedDigest),
  );
  if (!statement) {
    return {
      ...initialProvenance(
        "oci-cosign",
        checkedAt,
        "L’attestation vérifiée ne contient pas un sujet SLSA v1 correspondant au digest OCI.",
        policyId,
      ),
      registrySignature,
      slsaProvenance: "failed",
      subjectDigest: "mismatched",
      identityPolicy: "mismatched",
    };
  }
  const details = statementDetails(statement);
  return {
    provider: "oci-cosign",
    checkedAt,
    registrySignature,
    slsaProvenance: "verified",
    subjectDigest: "matched",
    identityPolicy: "matched",
    ...(policyId ? { policyId } : {}),
    ...(details.repository ? { sourceRepository: details.repository } : {}),
    ...(details.builderId ? { builderId: details.builderId } : {}),
    message:
      registrySignature === "verified"
        ? "Signature Cosign, identité, journal de transparence, provenance SLSA et digest OCI vérifiés."
        : `Provenance SLSA et digest OCI vérifiés. ${signatureMessage || "La signature d’image distincte n’est pas vérifiée."}`,
  };
}

async function verifyWithGitHub(
  component: SupplyChainComponent,
  policy: Extract<OciVerificationPolicy, { kind: "github" }>,
  executable: string,
  runner: VerificationCommandRunner,
  timeoutMs: number,
  checkedAt: string,
  policyId?: string,
): Promise<ComponentProvenance> {
  const result = await runner(
    executable,
    [
      "attestation",
      "verify",
      `oci://${component.reference}`,
      "--repo",
      policy.repository,
      "--format",
      "json",
    ],
    timeoutMs,
  );
  if (result.code !== 0) {
    const failure = commandFailureState(result);
    return {
      ...initialProvenance(
        "oci-github-attestation",
        checkedAt,
        failure.message,
        policyId,
      ),
      registrySignature: "not-applicable",
      slsaProvenance: failure.state,
      identityPolicy:
        failure.state === "failed" ? "mismatched" : "not-configured",
    };
  }
  const statements = githubStatements(parseJsonOutput(result.stdout));
  const statement = statements.find(
    (candidate) =>
      SLSA_PROVENANCE.test(String(candidate.predicateType ?? "")) &&
      statementSubjectMatches(candidate, component.version ?? ""),
  );
  if (!statement) {
    return {
      ...initialProvenance(
        "oci-github-attestation",
        checkedAt,
        "L’attestation GitHub vérifiée ne cible pas le digest OCI attendu avec un prédicat SLSA v1.",
        policyId,
      ),
      registrySignature: "not-applicable",
      slsaProvenance: "failed",
      subjectDigest: "mismatched",
      identityPolicy: "mismatched",
    };
  }
  const details = statementDetails(statement);
  return {
    provider: "oci-github-attestation",
    checkedAt,
    registrySignature: "not-applicable",
    slsaProvenance: "verified",
    subjectDigest: "matched",
    identityPolicy: "matched",
    ...(policyId ? { policyId } : {}),
    sourceRepository:
      details.repository ?? `https://github.com/${policy.repository}`,
    ...(details.builderId ? { builderId: details.builderId } : {}),
    message:
      "Attestation GitHub, identité du dépôt, racine de confiance et digest OCI vérifiés. Aucune signature Cosign distincte n’a été demandée.",
  };
}

export async function verifyOciProvenance(
  components: SupplyChainComponent[],
  options: OciVerificationOptions,
): Promise<{
  components: SupplyChainComponent[];
  summary: OciVerificationSummary;
}> {
  if (Boolean(options.policy) === Boolean(options.policies)) {
    throw new Error(
      "Configurez soit une politique OCI globale, soit un ensemble de politiques par préfixe.",
    );
  }
  if (options.policy) {
    validateOciVerificationPolicy(options.policy);
  }
  if (options.policies) {
    validateOciVerificationRules(options.policies);
  }
  const resolvedPolicies = (options.policies ?? [])
    .map((policy) => ({
      policy,
      prefix: normalizedImagePrefix(policy.imagePrefix),
    }))
    .sort((left, right) => right.prefix.length - left.prefix.length);
  const selectPolicy = (component: SupplyChainComponent) =>
    resolvedPolicies.find(
      ({ prefix }) =>
        component.name.toLowerCase() === prefix ||
        component.name.toLowerCase().startsWith(`${prefix}/`),
    )?.policy;
  const checkedAt = (options.now ?? (() => new Date()))().toISOString();
  const timeoutMs = Math.min(
    180_000,
    Math.max(5_000, options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  );
  const executableFor = (kind: OciVerificationPolicy["kind"]) =>
    safeExecutable(
      options.executables?.[kind] ??
        options.executable ??
        (kind === "cosign" ? "cosign" : "gh"),
      kind === "cosign" ? "cosign" : "gh",
    );
  const runner = options.commandRunner ?? runVerificationCommand;
  const allEligible = [
    ...new Map(
      components
        .filter(
          (component) =>
            component.ecosystem === "oci" &&
            Boolean(component.version?.match(SHA256_DIGEST)),
        )
        .map((component) => [component.purl ?? component.id, component]),
    ).values(),
  ];
  const eligible = allEligible.slice(0, MAX_OCI_IMAGES);
  const results = new Map<string, ComponentProvenance>();
  let unmatched = 0;
  let cursor = 0;
  const worker = async () => {
    while (cursor < eligible.length) {
      const component = eligible[cursor];
      cursor += 1;
      const selectedPolicy = options.policy ?? selectPolicy(component);
      if (!selectedPolicy) {
        unmatched += 1;
        results.set(component.purl ?? component.id, {
          ...initialProvenance(
            "oci-policy",
            checkedAt,
            `Aucune politique d’identité OCI ne correspond à ${component.name}.`,
          ),
          registrySignature: "not-applicable",
          slsaProvenance: "failed",
        });
        continue;
      }
      const policyId =
        "id" in selectedPolicy && typeof selectedPolicy.id === "string"
          ? selectedPolicy.id
          : "default";
      const provenance =
        selectedPolicy.kind === "cosign"
          ? await verifyWithCosign(
              component,
              selectedPolicy,
              executableFor("cosign"),
              runner,
              timeoutMs,
              checkedAt,
              policyId,
            )
          : await verifyWithGitHub(
              component,
              selectedPolicy,
              executableFor("github"),
              runner,
              timeoutMs,
              checkedAt,
              policyId,
            );
      results.set(component.purl ?? component.id, provenance);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(2, eligible.length) }, () => worker()),
  );

  const verified = [...results.values()];
  const signaturesVerified = verified.filter(
    (result) => result.registrySignature === "verified",
  ).length;
  const slsaProvenanceVerified = verified.filter(
    (result) => result.slsaProvenance === "verified",
  ).length;
  const failed = verified.filter(
    (result) =>
      result.registrySignature === "failed" ||
      result.slsaProvenance === "failed",
  ).length;
  const missing = verified.filter(
    (result) =>
      ["missing", "unverifiable"].includes(result.registrySignature) ||
      ["missing", "unverifiable"].includes(result.slsaProvenance),
  ).length;
  const errors = verified.filter(
    (result) =>
      result.registrySignature === "error" ||
      result.slsaProvenance === "error",
  ).length;
  const status: OciVerificationSummary["status"] =
    eligible.length > 0 && errors === eligible.length
      ? "error"
      : failed ||
          missing ||
          errors ||
          allEligible.length > MAX_OCI_IMAGES
        ? "partial"
        : "complete";
  const policyKinds = new Set(
    options.policy
      ? [options.policy.kind]
      : options.policies?.map((policy) => policy.kind),
  );
  const backend: OciVerificationSummary["backend"] =
    policyKinds.size > 1
      ? "mixed"
      : policyKinds.has("cosign")
        ? "cosign"
        : "github-attestations";
  const policyCount = options.policy ? 1 : (options.policies?.length ?? 0);
  const matched = eligible.length - unmatched;
  return {
    components: components.map((component) => {
      const provenance = results.get(component.purl ?? component.id);
      return provenance ? { ...component, provenance } : component;
    }),
    summary: {
      provider: "oci-provenance",
      backend,
      status,
      checkedAt,
      images: eligible.length,
      policies: policyCount,
      matched,
      unmatched,
      signaturesVerified,
      slsaProvenanceVerified,
      missing,
      failed,
      message:
        status === "complete"
          ? eligible.length
            ? `${matched} image${matched > 1 ? "s" : ""} OCI conforme${matched > 1 ? "s" : ""} à ${policyCount} politique${policyCount > 1 ? "s" : ""} d’identité.`
            : `${policyCount} politique${policyCount > 1 ? "s" : ""} OCI chargée${policyCount > 1 ? "s" : ""} ; aucune image verrouillée n’était éligible.`
          : status === "error"
            ? "L’outil OCI, le registre ou le service de confiance est indisponible."
            : unmatched
              ? `${unmatched} image${unmatched > 1 ? "s n’ont" : " n’a"} aucune politique OCI correspondante.`
            : "Vérification OCI terminée avec des preuves absentes, incomplètes ou invalides.",
    },
  };
}
