import {
  createPublicKey,
  verify as verifyCryptographicSignature,
} from "node:crypto";
import { verify as verifySigstore } from "sigstore";
import type { Bundle as SigstoreBundle } from "sigstore";
import type {
  ComponentProvenance,
  SupplyChainComponent,
  VerificationState,
} from "./supply-chain.ts";

const DEFAULT_REGISTRY = "https://registry.npmjs.org";
const MAX_PACKAGES = 250;
const MAX_METADATA_BYTES = 2_000_000;
const MAX_ATTESTATION_BYTES = 12_000_000;
const DEFAULT_TIMEOUT_MS = 10_000;
const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";

type JsonRecord = Record<string, unknown>;
type RegistryKey = {
  keyid: string;
  key: string;
};

export type ProvenancePolicy = {
  certificateIssuer: string;
  certificateIdentityURI: string;
};

export type ProvenanceScanSummary = {
  provider: "npm-registry-sigstore";
  status: "complete" | "partial" | "error";
  checkedAt: string;
  packages: number;
  registrySignaturesVerified: number;
  slsaProvenanceVerified: number;
  missing: number;
  failed: number;
  message: string;
};

export type ProvenanceVerificationOptions = {
  fetchImpl?: typeof fetch;
  now?: () => Date;
  registry?: string;
  timeoutMs?: number;
  policy?: ProvenancePolicy;
  verifyBundleImpl?: (
    bundle: JsonRecord,
    policy?: ProvenancePolicy,
  ) => Promise<unknown>;
};

type RegistryMetadata = {
  dist?: {
    integrity?: string;
    signatures?: Array<{ keyid?: string; sig?: string }>;
    attestations?: {
      url?: string;
      provenance?: { predicateType?: string };
    };
  };
};

type AttestationDocument = {
  attestations?: Array<{
    predicateType?: string;
    bundle?: JsonRecord;
  }>;
};

function record(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function cleanText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  return cleaned && cleaned.length <= maxLength ? cleaned : undefined;
}

function safeRegistry(value?: string): URL {
  const registry = new URL(value ?? DEFAULT_REGISTRY);
  if (registry.protocol !== "https:" || registry.username || registry.password) {
    throw new Error("Le registre de provenance doit être une URL HTTPS sans identifiants.");
  }
  registry.pathname = registry.pathname.replace(/\/+$/, "");
  return registry;
}

async function fetchJson(
  url: URL,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  maxBytes: number,
): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method: "GET",
      headers: { accept: "application/json" },
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`Réponse HTTP ${response.status}.`);
    }
    const declaredSize = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredSize) && declaredSize > maxBytes) {
      throw new Error("Réponse trop volumineuse.");
    }
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > maxBytes) {
      throw new Error("Réponse trop volumineuse.");
    }
    return JSON.parse(body) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

function registryKeyList(value: unknown): RegistryKey[] {
  const root = record(value);
  if (!root || !Array.isArray(root.keys)) return [];
  return root.keys.flatMap((value) => {
    const key = record(value);
    const keyid = cleanText(key?.keyid, 200);
    const publicKey =
      typeof key?.key === "string" && key.key.length <= 10_000
        ? key.key.trim()
        : undefined;
    return keyid && publicKey ? [{ keyid, key: publicKey }] : [];
  });
}

export function verifyNpmRegistrySignature(
  packageName: string,
  version: string,
  integrity: string,
  signatures: Array<{ keyid?: string; sig?: string }>,
  keys: RegistryKey[],
): boolean {
  const signed = Buffer.from(`${packageName}@${version}:${integrity}`, "utf8");
  return signatures.some((signature) => {
    const keyid = cleanText(signature.keyid, 200);
    const encodedSignature = cleanText(signature.sig, 2_000);
    const key = keys.find((candidate) => candidate.keyid === keyid);
    if (!key || !encodedSignature) return false;
    try {
      const publicKey = key.key.includes("BEGIN PUBLIC KEY")
        ? createPublicKey(key.key)
        : createPublicKey({
            key: Buffer.from(key.key, "base64"),
            format: "der",
            type: "spki",
          });
      return verifyCryptographicSignature(
        "sha256",
        signed,
        publicKey,
        Buffer.from(encodedSignature, "base64"),
      );
    } catch {
      return false;
    }
  });
}

function sriDigest(integrity?: string): { algorithm: string; hex: string } | undefined {
  const entry = integrity
    ?.split(/\s+/)
    .find((candidate) => /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(candidate));
  if (!entry) return undefined;
  const separator = entry.indexOf("-");
  const algorithm = entry.slice(0, separator);
  try {
    return {
      algorithm,
      hex: Buffer.from(entry.slice(separator + 1), "base64").toString("hex"),
    };
  } catch {
    return undefined;
  }
}

function statementFromBundle(bundle: JsonRecord): JsonRecord | undefined {
  const envelope = record(bundle.dsseEnvelope);
  const payload = cleanText(envelope?.payload, 10_000_000);
  if (!payload) return undefined;
  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
    return record(decoded);
  } catch {
    return undefined;
  }
}

function subjectMatches(
  statement: JsonRecord,
  component: SupplyChainComponent,
): boolean {
  if (!component.version || !Array.isArray(statement.subject)) return false;
  const digest = sriDigest(component.integrity);
  if (!digest) return false;
  const expectedName = `pkg:npm/${component.name}@${component.version}`;
  return statement.subject.some((value) => {
    const subject = record(value);
    const name = cleanText(subject?.name, 2_048);
    const digests = record(subject?.digest);
    const actual = cleanText(digests?.[digest.algorithm], 1_024);
    return name === expectedName && actual?.toLowerCase() === digest.hex.toLowerCase();
  });
}

function statementDetails(statement?: JsonRecord): {
  repository?: string;
  builderId?: string;
} {
  const predicate = record(statement?.predicate);
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

async function defaultVerifyBundle(
  bundle: JsonRecord,
  policy?: ProvenancePolicy,
): Promise<unknown> {
  return verifySigstore(bundle as SigstoreBundle, {
    tlogThreshold: 1,
    ctLogThreshold: 1,
    ...(policy
      ? {
          certificateIssuer: policy.certificateIssuer,
          certificateIdentityURI: policy.certificateIdentityURI,
        }
      : {}),
  });
}

function initialResult(
  checkedAt: string,
  message: string,
): ComponentProvenance {
  return {
    provider: "npm-registry-sigstore",
    checkedAt,
    registrySignature: "unverifiable",
    slsaProvenance: "unverifiable",
    subjectDigest: "unavailable",
    identityPolicy: "not-configured",
    message,
  };
}

async function verifyOne(
  component: SupplyChainComponent,
  keys: RegistryKey[] | undefined,
  options: Required<
    Pick<ProvenanceVerificationOptions, "fetchImpl" | "timeoutMs">
  > & {
    registry: URL;
    checkedAt: string;
    policy?: ProvenancePolicy;
    verifyBundleImpl: NonNullable<
      ProvenanceVerificationOptions["verifyBundleImpl"]
    >;
  },
): Promise<ComponentProvenance> {
  if (
    component.ecosystem !== "npm" ||
    !component.version ||
    component.workspace
  ) {
    return {
      ...initialResult(options.checkedAt, "Composant non applicable."),
      registrySignature: "not-applicable",
      slsaProvenance: "not-applicable",
    };
  }
  const metadataUrl = new URL(
    `${options.registry.pathname}/${encodeURIComponent(component.name)}/${encodeURIComponent(component.version)}`.replace(
      /\/{2,}/g,
      "/",
    ),
    options.registry,
  );
  let metadata: RegistryMetadata;
  try {
    metadata = (await fetchJson(
      metadataUrl,
      options.fetchImpl,
      options.timeoutMs,
      MAX_METADATA_BYTES,
    )) as RegistryMetadata;
  } catch (error) {
    return {
      ...initialResult(
        options.checkedAt,
        error instanceof Error ? error.message : "Métadonnées npm indisponibles.",
      ),
      registrySignature: "error",
      slsaProvenance: "error",
    };
  }

  const registryIntegrity = cleanText(metadata.dist?.integrity, 1_024);
  const integrityMatches =
    Boolean(component.integrity) && component.integrity === registryIntegrity;
  const signatures = Array.isArray(metadata.dist?.signatures)
    ? metadata.dist.signatures
    : [];
  let registrySignature: VerificationState;
  if (!component.integrity || !registryIntegrity) {
    registrySignature = "unverifiable";
  } else if (!integrityMatches) {
    registrySignature = "failed";
  } else if (!signatures.length) {
    registrySignature = "missing";
  } else if (!keys?.length) {
    registrySignature = "error";
  } else {
    registrySignature = verifyNpmRegistrySignature(
      component.name,
      component.version,
      registryIntegrity,
      signatures,
      keys,
    )
      ? "verified"
      : "failed";
  }

  const attestationUrlValue = cleanText(metadata.dist?.attestations?.url, 2_048);
  if (!attestationUrlValue) {
    return {
      ...initialResult(options.checkedAt, "Aucune provenance SLSA publiée."),
      registrySignature,
      slsaProvenance: "missing",
    };
  }
  let attestationUrl: URL;
  try {
    attestationUrl = new URL(attestationUrlValue);
    if (
      attestationUrl.protocol !== "https:" ||
      attestationUrl.hostname !== options.registry.hostname
    ) {
      throw new Error("Hôte d’attestation non autorisé.");
    }
  } catch {
    return {
      ...initialResult(options.checkedAt, "URL d’attestation npm invalide."),
      registrySignature,
      slsaProvenance: "failed",
    };
  }

  let document: AttestationDocument;
  try {
    document = (await fetchJson(
      attestationUrl,
      options.fetchImpl,
      options.timeoutMs,
      MAX_ATTESTATION_BYTES,
    )) as AttestationDocument;
  } catch (error) {
    return {
      ...initialResult(
        options.checkedAt,
        error instanceof Error ? error.message : "Attestation indisponible.",
      ),
      registrySignature,
      slsaProvenance: "error",
    };
  }
  const provenance = document.attestations?.find(
    (entry) =>
      entry.predicateType === SLSA_PROVENANCE_V1 && record(entry.bundle),
  );
  const bundle = record(provenance?.bundle);
  if (!bundle) {
    return {
      ...initialResult(options.checkedAt, "Aucune attestation SLSA v1 exploitable."),
      registrySignature,
      slsaProvenance: "missing",
    };
  }
  const statement = statementFromBundle(bundle);
  const details = statementDetails(statement);
  if (!integrityMatches || !statement || !subjectMatches(statement, component)) {
    return {
      ...initialResult(
        options.checkedAt,
        "Le sujet ou le digest de l’attestation ne correspond pas au lockfile.",
      ),
      registrySignature,
      slsaProvenance: "failed",
      subjectDigest: "mismatched",
      identityPolicy: options.policy ? "mismatched" : "not-configured",
      ...(details.repository ? { sourceRepository: details.repository } : {}),
      ...(details.builderId ? { builderId: details.builderId } : {}),
    };
  }

  try {
    await options.verifyBundleImpl(bundle, options.policy);
    return {
      provider: "npm-registry-sigstore",
      checkedAt: options.checkedAt,
      registrySignature,
      slsaProvenance: "verified",
      subjectDigest: "matched",
      identityPolicy: options.policy ? "matched" : "not-configured",
      ...(details.repository ? { sourceRepository: details.repository } : {}),
      ...(details.builderId ? { builderId: details.builderId } : {}),
      message: options.policy
        ? "Signature, journal Sigstore, digest et identité attendue vérifiés."
        : "Signature, journal Sigstore et digest vérifiés ; aucune identité source attendue n’est configurée.",
    };
  } catch (error) {
    return {
      ...initialResult(
        options.checkedAt,
        error instanceof Error
          ? `Échec Sigstore : ${error.message}`
          : "Échec de la vérification Sigstore.",
      ),
      registrySignature,
      slsaProvenance: "failed",
      subjectDigest: "matched",
      identityPolicy: options.policy ? "mismatched" : "not-configured",
      ...(details.repository ? { sourceRepository: details.repository } : {}),
      ...(details.builderId ? { builderId: details.builderId } : {}),
    };
  }
}

export async function verifyComponentProvenance(
  components: SupplyChainComponent[],
  options: ProvenanceVerificationOptions = {},
): Promise<{
  components: SupplyChainComponent[];
  summary: ProvenanceScanSummary;
}> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const checkedAt = (options.now ?? (() => new Date()))().toISOString();
  const registry = safeRegistry(options.registry);
  const timeoutMs = Math.min(
    30_000,
    Math.max(1_000, options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  );
  const eligible = [
    ...new Map(
      components
        .filter(
          (component) =>
            component.ecosystem === "npm" &&
            Boolean(component.version) &&
            !component.workspace,
        )
        .map((component) => [component.purl ?? component.id, component]),
    ).values(),
  ].slice(0, MAX_PACKAGES);

  let keys: RegistryKey[] | undefined;
  try {
    const keyUrl = new URL(
      `${registry.pathname}/-/npm/v1/keys`.replace(/\/{2,}/g, "/"),
      registry,
    );
    keys = registryKeyList(
      await fetchJson(keyUrl, fetchImpl, timeoutMs, MAX_METADATA_BYTES),
    );
    if (!keys.length) keys = undefined;
  } catch {
    // The SLSA check can still succeed, but registry signatures stay unavailable.
  }

  const results = new Map<string, ComponentProvenance>();
  let cursor = 0;
  const worker = async () => {
    while (cursor < eligible.length) {
      const component = eligible[cursor];
      cursor += 1;
      const result = await verifyOne(component, keys, {
        fetchImpl,
        timeoutMs,
        registry,
        checkedAt,
        policy: options.policy,
        verifyBundleImpl: options.verifyBundleImpl ?? defaultVerifyBundle,
      });
      results.set(component.purl ?? component.id, result);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(6, eligible.length) }, () => worker()),
  );

  const verified = [...results.values()];
  const registrySignaturesVerified = verified.filter(
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
  const status: ProvenanceScanSummary["status"] =
    eligible.length > 0 && errors === eligible.length
      ? "error"
      : failed || missing || errors || eligible.length < components.filter(
          (component) =>
            component.ecosystem === "npm" &&
            Boolean(component.version) &&
            !component.workspace,
        ).length
        ? "partial"
        : "complete";

  return {
    components: components.map((component) => {
      const provenance = results.get(component.purl ?? component.id);
      return provenance ? { ...component, provenance } : component;
    }),
    summary: {
      provider: "npm-registry-sigstore",
      status,
      checkedAt,
      packages: eligible.length,
      registrySignaturesVerified,
      slsaProvenanceVerified,
      missing,
      failed,
      message:
        status === "complete"
          ? "Toutes les signatures registre et provenances SLSA disponibles ont été vérifiées."
          : status === "error"
            ? "Le registre npm ou le service de confiance Sigstore est indisponible."
            : "Vérification terminée avec des preuves absentes, incomplètes ou invalides.",
    },
  };
}
