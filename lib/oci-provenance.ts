import { spawn } from "node:child_process";
import { basename, isAbsolute } from "node:path";
import type {
  ComponentProvenance,
  SupplyChainComponent,
  VerificationState,
} from "./supply-chain.ts";

const MAX_OCI_IMAGES = 50;
const MAX_COMMAND_OUTPUT_BYTES = 8_000_000;
const DEFAULT_TIMEOUT_MS = 60_000;
const SHA256_DIGEST = /^sha256:([a-f0-9]{64})$/i;
const SLSA_PROVENANCE = /^https:\/\/slsa\.dev\/provenance\/v1$/;

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
  policy: OciVerificationPolicy;
  commandRunner?: VerificationCommandRunner;
  executable?: string;
  now?: () => Date;
  timeoutMs?: number;
};

export type OciVerificationSummary = {
  provider: "oci-provenance";
  backend: "cosign" | "github-attestations";
  status: "complete" | "partial" | "error";
  checkedAt: string;
  images: number;
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
    /timeout|timed out|connection refused|tls handshake|network|dial tcp|unauthorized|denied/.test(
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
): ComponentProvenance {
  return {
    provider,
    checkedAt,
    registrySignature: "unverifiable",
    slsaProvenance: "unverifiable",
    subjectDigest: "unavailable",
    identityPolicy: "not-configured",
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
      ...initialProvenance("oci-cosign", checkedAt, failure.message),
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
  validateOciVerificationPolicy(options.policy);
  const checkedAt = (options.now ?? (() => new Date()))().toISOString();
  const timeoutMs = Math.min(
    180_000,
    Math.max(5_000, options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  );
  const executable = safeExecutable(
    options.executable ??
      (options.policy.kind === "cosign" ? "cosign" : "gh"),
    options.policy.kind === "cosign" ? "cosign" : "gh",
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
  let cursor = 0;
  const worker = async () => {
    while (cursor < eligible.length) {
      const component = eligible[cursor];
      cursor += 1;
      const provenance =
        options.policy.kind === "cosign"
          ? await verifyWithCosign(
              component,
              options.policy,
              executable,
              runner,
              timeoutMs,
              checkedAt,
            )
          : await verifyWithGitHub(
              component,
              options.policy,
              executable,
              runner,
              timeoutMs,
              checkedAt,
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
  const backend =
    options.policy.kind === "cosign" ? "cosign" : "github-attestations";
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
      signaturesVerified,
      slsaProvenanceVerified,
      missing,
      failed,
      message:
        status === "complete"
          ? backend === "cosign"
            ? "Toutes les signatures Cosign et provenances SLSA OCI ont été vérifiées."
            : "Toutes les attestations GitHub et leurs digests OCI ont été vérifiés."
          : status === "error"
            ? "L’outil OCI, le registre ou le service de confiance est indisponible."
            : "Vérification OCI terminée avec des preuves absentes, incomplètes ou invalides.",
    },
  };
}
