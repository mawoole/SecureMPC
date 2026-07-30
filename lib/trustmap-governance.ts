import type { RiskException } from "./finding-exceptions.ts";
import { parseRiskExceptions } from "./finding-exceptions.ts";
import {
  normalizeTrustMapCiPolicyProfiles,
  type TrustMapCiPolicyProfile,
} from "./trustmap-modules.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const PBKDF2_ITERATIONS = 210_000;
const MAX_PASSPHRASE_LENGTH = 256;
const MAX_POLICY_FILE_CHARS = 256 * 1_024;
const MAX_EXCEPTION_FILE_CHARS = 2 * 1_024 * 1_024;
const EXCEPTION_AAD = "mcp-trustmap:risk-exceptions:1.0";

type EncryptedPayload = {
  algorithm: "AES-256-GCM";
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    salt: string;
  };
  iv: string;
  ciphertext: string;
};

export type PolicySigningIdentityBundle = {
  schemaVersion: "1.0";
  kind: "mcp-trustmap-signing-identity";
  createdAt: string;
  label: string;
  keyId: string;
  publicKey: JsonWebKey;
  encryptedPrivateKey: EncryptedPayload;
};

export type SignedCiPolicyBundle = {
  schemaVersion: "1.0";
  kind: "mcp-trustmap-ci-policy";
  issuedAt: string;
  profiles: TrustMapCiPolicyProfile[];
  signer: {
    label: string;
    keyId: string;
    algorithm: "ECDSA-P256-SHA256";
    publicKey: JsonWebKey;
  };
  signature: string;
};

export type EncryptedRiskExceptionBundle = {
  schemaVersion: "1.0";
  kind: "mcp-trustmap-risk-exceptions";
  createdAt: string;
  exceptionCount: number;
  encryption: EncryptedPayload;
};

function webCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto n’est pas disponible dans cet environnement.");
  }
  return globalThis.crypto;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 16_384) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 16_384));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function base64UrlToBytes(value: unknown, maximumBytes: number): Uint8Array {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    value.length > Math.ceil((maximumBytes * 4) / 3) + 8
  ) {
    throw new Error("Le document cryptographique contient une valeur invalide.");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  if (binary.length > maximumBytes) {
    throw new Error("Le document cryptographique dépasse la limite autorisée.");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function validatePassphrase(passphrase: string): void {
  if (passphrase.length < 12 || passphrase.length > MAX_PASSPHRASE_LENGTH) {
    throw new Error("La phrase secrète doit contenir entre 12 et 256 caractères.");
  }
}

async function deriveEncryptionKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  validatePassphrase(passphrase);
  if (iterations !== PBKDF2_ITERATIONS) {
    throw new Error("Les paramètres de dérivation ne sont pas acceptés.");
  }
  const subtle = webCrypto().subtle;
  const material = await subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptValue(
  value: unknown,
  passphrase: string,
  additionalData: string,
): Promise<EncryptedPayload> {
  const crypto = webCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveEncryptionKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(additionalData) },
    key,
    encoder.encode(canonicalJson(value)),
  );
  return {
    algorithm: "AES-256-GCM",
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PBKDF2_ITERATIONS,
      salt: bytesToBase64Url(salt),
    },
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
  };
}

function validateEncryptedPayload(value: unknown): EncryptedPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Le bloc chiffré est absent ou invalide.");
  }
  const record = value as Record<string, unknown>;
  const kdf = record.kdf as Record<string, unknown> | undefined;
  if (
    record.algorithm !== "AES-256-GCM" ||
    !kdf ||
    kdf.name !== "PBKDF2" ||
    kdf.hash !== "SHA-256" ||
    kdf.iterations !== PBKDF2_ITERATIONS ||
    typeof kdf.salt !== "string" ||
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new Error("Les paramètres cryptographiques ne sont pas acceptés.");
  }
  return record as EncryptedPayload;
}

async function decryptValue(
  value: unknown,
  passphrase: string,
  additionalData: string,
  maximumPlaintextBytes: number,
): Promise<unknown> {
  const payload = validateEncryptedPayload(value);
  const salt = base64UrlToBytes(payload.kdf.salt, 32);
  const iv = base64UrlToBytes(payload.iv, 16);
  if (salt.length !== 16 || iv.length !== 12) {
    throw new Error("Les paramètres cryptographiques sont invalides.");
  }
  const ciphertext = base64UrlToBytes(
    payload.ciphertext,
    maximumPlaintextBytes + 32,
  );
  const key = await deriveEncryptionKey(
    passphrase,
    salt,
    payload.kdf.iterations,
  );
  try {
    const plaintext = await webCrypto().subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: encoder.encode(additionalData),
      },
      key,
      ciphertext,
    );
    if (plaintext.byteLength > maximumPlaintextBytes) {
      throw new Error("Le contenu déchiffré dépasse la limite autorisée.");
    }
    return JSON.parse(decoder.decode(plaintext)) as unknown;
  } catch (error) {
    if (error instanceof Error && /limite autorisée/u.test(error.message)) {
      throw error;
    }
    throw new Error(
      "Le document ne peut pas être déchiffré : phrase secrète incorrecte ou fichier altéré.",
    );
  }
}

function parseJsonDocument(serialized: string, maximumCharacters: number): unknown {
  if (!serialized || serialized.length > maximumCharacters) {
    throw new Error("Le fichier est vide ou dépasse la limite autorisée.");
  }
  try {
    return JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("Le fichier JSON n’est pas valide.");
  }
}

function validatePublicKey(value: unknown): JsonWebKey {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("La clé publique est absente.");
  }
  const key = value as JsonWebKey;
  if (
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    typeof key.x !== "string" ||
    typeof key.y !== "string" ||
    key.x.length > 100 ||
    key.y.length > 100
  ) {
    throw new Error("La clé publique de signature est invalide.");
  }
  return { kty: "EC", crv: "P-256", x: key.x, y: key.y };
}

function validatePrivateKey(value: unknown): JsonWebKey {
  const publicKey = validatePublicKey(value);
  const candidate = value as JsonWebKey;
  if (typeof candidate.d !== "string" || candidate.d.length > 100) {
    throw new Error("La clé privée de signature est invalide.");
  }
  return { ...publicKey, d: candidate.d };
}

async function keyIdentifier(publicKey: JsonWebKey): Promise<string> {
  const digest = await webCrypto().subtle.digest(
    "SHA-256",
    encoder.encode(canonicalJson(validatePublicKey(publicKey))),
  );
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

function validateLabel(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.trim().length < 2 ||
    value.trim().length > 80 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("Le nom de l’identité de signature est invalide.");
  }
  return value.trim();
}

function validateDate(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length > 40 ||
    !Number.isFinite(Date.parse(value))
  ) {
    throw new Error(`${label} est invalide.`);
  }
  return value;
}

export async function createPolicySigningIdentity(
  label: string,
  passphrase: string,
  createdAt = new Date(),
): Promise<PolicySigningIdentityBundle> {
  const normalizedLabel = validateLabel(label);
  validatePassphrase(passphrase);
  const pair = (await webCrypto().subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicKey = validatePublicKey(
    await webCrypto().subtle.exportKey("jwk", pair.publicKey),
  );
  const privateKey = validatePrivateKey(
    await webCrypto().subtle.exportKey("jwk", pair.privateKey),
  );
  const keyId = await keyIdentifier(publicKey);
  return {
    schemaVersion: "1.0",
    kind: "mcp-trustmap-signing-identity",
    createdAt: createdAt.toISOString(),
    label: normalizedLabel,
    keyId,
    publicKey,
    encryptedPrivateKey: await encryptValue(
      { privateKey },
      passphrase,
      `mcp-trustmap:signing-identity:${keyId}`,
    ),
  };
}

function parseSigningIdentity(
  value: unknown,
): Omit<PolicySigningIdentityBundle, "encryptedPrivateKey"> & {
  encryptedPrivateKey: EncryptedPayload;
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Le fichier d’identité de signature est invalide.");
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== "1.0" ||
    record.kind !== "mcp-trustmap-signing-identity" ||
    typeof record.keyId !== "string" ||
    !/^sha256:[a-f0-9]{64}$/u.test(record.keyId)
  ) {
    throw new Error("Le fichier d’identité de signature est incompatible.");
  }
  return {
    schemaVersion: "1.0",
    kind: "mcp-trustmap-signing-identity",
    createdAt: validateDate(record.createdAt, "La date de création"),
    label: validateLabel(record.label),
    keyId: record.keyId,
    publicKey: validatePublicKey(record.publicKey),
    encryptedPrivateKey: validateEncryptedPayload(record.encryptedPrivateKey),
  };
}

function policyPayload(bundle: Pick<
  SignedCiPolicyBundle,
  "schemaVersion" | "kind" | "issuedAt" | "profiles"
>) {
  return {
    schemaVersion: bundle.schemaVersion,
    kind: bundle.kind,
    issuedAt: bundle.issuedAt,
    profiles: bundle.profiles,
  };
}

export async function signCiPolicyProfiles(
  profiles: TrustMapCiPolicyProfile[],
  serializedIdentity: string,
  passphrase: string,
  issuedAt = new Date(),
): Promise<SignedCiPolicyBundle> {
  const identity = parseSigningIdentity(
    parseJsonDocument(serializedIdentity, MAX_POLICY_FILE_CHARS),
  );
  const actualKeyId = await keyIdentifier(identity.publicKey);
  if (actualKeyId !== identity.keyId) {
    throw new Error("L’empreinte de l’identité de signature est incohérente.");
  }
  const privatePayload = await decryptValue(
    identity.encryptedPrivateKey,
    passphrase,
    `mcp-trustmap:signing-identity:${identity.keyId}`,
    4_096,
  );
  if (
    !privatePayload ||
    typeof privatePayload !== "object" ||
    Array.isArray(privatePayload)
  ) {
    throw new Error("La clé privée déchiffrée est invalide.");
  }
  const privateKey = validatePrivateKey(
    (privatePayload as Record<string, unknown>).privateKey,
  );
  if (
    privateKey.x !== identity.publicKey.x ||
    privateKey.y !== identity.publicKey.y
  ) {
    throw new Error("La clé privée ne correspond pas à l’identité publique.");
  }
  const normalizedProfiles = normalizeTrustMapCiPolicyProfiles(profiles);
  const unsigned = {
    schemaVersion: "1.0" as const,
    kind: "mcp-trustmap-ci-policy" as const,
    issuedAt: issuedAt.toISOString(),
    profiles: normalizedProfiles,
  };
  const importedPrivateKey = await webCrypto().subtle.importKey(
    "jwk",
    privateKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const signature = await webCrypto().subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    importedPrivateKey,
    encoder.encode(canonicalJson(unsigned)),
  );
  return {
    ...unsigned,
    signer: {
      label: identity.label,
      keyId: identity.keyId,
      algorithm: "ECDSA-P256-SHA256",
      publicKey: identity.publicKey,
    },
    signature: bytesToBase64Url(new Uint8Array(signature)),
  };
}

export async function verifySignedCiPolicy(
  serializedPolicy: string,
  expectedKeyId = "",
): Promise<{
  profiles: TrustMapCiPolicyProfile[];
  signerLabel: string;
  keyId: string;
  trusted: boolean;
}> {
  const value = parseJsonDocument(serializedPolicy, MAX_POLICY_FILE_CHARS);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Le fichier de politique signée est invalide.");
  }
  const record = value as Record<string, unknown>;
  const signer = record.signer as Record<string, unknown> | undefined;
  if (
    record.schemaVersion !== "1.0" ||
    record.kind !== "mcp-trustmap-ci-policy" ||
    !signer ||
    signer.algorithm !== "ECDSA-P256-SHA256" ||
    typeof signer.keyId !== "string" ||
    !/^sha256:[a-f0-9]{64}$/u.test(signer.keyId) ||
    typeof record.signature !== "string"
  ) {
    throw new Error("Le fichier de politique signée est incompatible.");
  }
  const publicKey = validatePublicKey(signer.publicKey);
  const actualKeyId = await keyIdentifier(publicKey);
  if (actualKeyId !== signer.keyId) {
    throw new Error("L’empreinte du signataire ne correspond pas à sa clé.");
  }
  const profiles = normalizeTrustMapCiPolicyProfiles(record.profiles);
  const unsigned = {
    schemaVersion: "1.0" as const,
    kind: "mcp-trustmap-ci-policy" as const,
    issuedAt: validateDate(record.issuedAt, "La date de signature"),
    profiles,
  };
  const importedPublicKey = await webCrypto().subtle.importKey(
    "jwk",
    publicKey,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signature = base64UrlToBytes(record.signature, 256);
  const valid = await webCrypto().subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    importedPublicKey,
    signature,
    encoder.encode(canonicalJson(policyPayload(unsigned))),
  );
  if (!valid) {
    throw new Error("La signature de la politique n’est pas valide.");
  }
  const normalizedExpected = expectedKeyId.trim().toLowerCase();
  return {
    profiles,
    signerLabel: validateLabel(signer.label),
    keyId: actualKeyId,
    trusted: Boolean(normalizedExpected) && normalizedExpected === actualKeyId,
  };
}

export async function createEncryptedRiskExceptionBundle(
  exceptions: RiskException[],
  passphrase: string,
  createdAt = new Date(),
): Promise<EncryptedRiskExceptionBundle> {
  const normalized = parseRiskExceptions(JSON.stringify(exceptions));
  if (normalized.length !== exceptions.length) {
    throw new Error("Le registre contient une exception invalide.");
  }
  const payload = {
    schemaVersion: "1.0",
    kind: "mcp-trustmap-risk-exceptions",
    createdAt: createdAt.toISOString(),
    exceptions: normalized,
  };
  return {
    schemaVersion: "1.0",
    kind: "mcp-trustmap-risk-exceptions",
    createdAt: payload.createdAt,
    exceptionCount: normalized.length,
    encryption: await encryptValue(payload, passphrase, EXCEPTION_AAD),
  };
}

export async function decryptRiskExceptionBundle(
  serializedBundle: string,
  passphrase: string,
): Promise<RiskException[]> {
  const value = parseJsonDocument(serializedBundle, MAX_EXCEPTION_FILE_CHARS);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Le bundle d’exceptions est invalide.");
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== "1.0" ||
    record.kind !== "mcp-trustmap-risk-exceptions" ||
    typeof record.exceptionCount !== "number" ||
    !Number.isInteger(record.exceptionCount) ||
    record.exceptionCount < 0 ||
    record.exceptionCount > 1_000
  ) {
    throw new Error("Le bundle d’exceptions est incompatible.");
  }
  validateDate(record.createdAt, "La date du bundle");
  const decrypted = await decryptValue(
    record.encryption,
    passphrase,
    EXCEPTION_AAD,
    1_500_000,
  );
  if (!decrypted || typeof decrypted !== "object" || Array.isArray(decrypted)) {
    throw new Error("Le contenu du bundle d’exceptions est invalide.");
  }
  const payload = decrypted as Record<string, unknown>;
  if (
    payload.schemaVersion !== "1.0" ||
    payload.kind !== "mcp-trustmap-risk-exceptions" ||
    payload.createdAt !== record.createdAt
  ) {
    throw new Error("Les métadonnées du bundle d’exceptions sont incohérentes.");
  }
  const exceptions = parseRiskExceptions(JSON.stringify(payload.exceptions));
  if (exceptions.length !== record.exceptionCount) {
    throw new Error("Le nombre d’exceptions du bundle est incohérent.");
  }
  return exceptions;
}

function chooseException(
  current: RiskException,
  incoming: RiskException,
): RiskException {
  if (current.revokedAt && incoming.revokedAt) {
    return Date.parse(incoming.revokedAt) > Date.parse(current.revokedAt)
      ? incoming
      : current;
  }
  if (incoming.revokedAt) return incoming;
  if (current.revokedAt) return current;
  return Date.parse(incoming.createdAt) > Date.parse(current.createdAt)
    ? incoming
    : current;
}

export function mergeRiskExceptions(
  current: RiskException[],
  incoming: RiskException[],
): RiskException[] {
  const normalizedCurrent = parseRiskExceptions(JSON.stringify(current));
  const normalizedIncoming = parseRiskExceptions(JSON.stringify(incoming));
  if (
    normalizedCurrent.length !== current.length ||
    normalizedIncoming.length !== incoming.length
  ) {
    throw new Error("Impossible de fusionner un registre d’exceptions invalide.");
  }
  const merged = new Map<string, RiskException>();
  for (const exception of normalizedCurrent) merged.set(exception.id, exception);
  for (const exception of normalizedIncoming) {
    const existing = merged.get(exception.id);
    merged.set(
      exception.id,
      existing ? chooseException(existing, exception) : exception,
    );
  }
  return [...merged.values()]
    .sort(
      (left, right) =>
        Date.parse(right.createdAt) - Date.parse(left.createdAt) ||
        left.id.localeCompare(right.id),
    )
    .slice(0, 1_000);
}
