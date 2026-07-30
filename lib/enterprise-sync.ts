import type { RiskException } from "./finding-exceptions.ts";
import { parseRiskExceptions } from "./finding-exceptions.ts";
import type {
  KeyManagementProvider,
  KeyManagementProviderName,
  WrappedDataKey,
} from "./key-management.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export type SyncedExceptionEnvelope = {
  schemaVersion: "1.0";
  algorithm: "AES-256-GCM";
  provider: KeyManagementProviderName;
  keyId: string;
  wrappedKey: string;
  iv: string;
  ciphertext: string;
};

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

function base64UrlToBytes(
  value: unknown,
  maximumBytes: number,
): Uint8Array {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    value.length > Math.ceil((maximumBytes * 4) / 3) + 8
  ) {
    throw new Error("L’enveloppe chiffrée est invalide.");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  if (binary.length > maximumBytes) {
    throw new Error("L’enveloppe chiffrée dépasse la limite autorisée.");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function validatedException(value: unknown): RiskException {
  const parsed = parseRiskExceptions(JSON.stringify([value]));
  if (parsed.length !== 1) {
    throw new Error("L’exception à synchroniser est invalide.");
  }
  return parsed[0];
}

function encryptionContext(spaceId: string, recordKey: string): string {
  if (
    !/^space:[a-f0-9]{64}$/u.test(spaceId) ||
    !/^record:[a-f0-9]{64}$/u.test(recordKey)
  ) {
    throw new Error("Le contexte de synchronisation est invalide.");
  }
  return `${spaceId}:${recordKey}`;
}

function additionalData(spaceId: string, recordKey: string): Uint8Array {
  return encoder.encode(
    `mcp-trustmap:exception-sync:1.0:${encryptionContext(spaceId, recordKey)}`,
  );
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function createExceptionSpaceId(namespace: string): Promise<string> {
  const normalized = namespace.trim();
  if (
    !normalized ||
    normalized.length > 200 ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new Error("L’espace de synchronisation est invalide.");
  }
  return `space:${await sha256(`mcp-trustmap:space:${normalized}`)}`;
}

export async function createExceptionRecordKey(
  spaceId: string,
  exceptionId: string,
): Promise<string> {
  if (!/^space:[a-f0-9]{64}$/u.test(spaceId)) {
    throw new Error("L’espace de synchronisation est invalide.");
  }
  const normalized = exceptionId.trim();
  if (
    !normalized ||
    normalized.length > 120 ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new Error("L’identifiant d’exception est invalide.");
  }
  return `record:${await sha256(`${spaceId}:${normalized}`)}`;
}

export async function encryptSyncedRiskException(
  exceptionValue: RiskException,
  provider: KeyManagementProvider,
  spaceId: string,
  recordKey: string,
): Promise<SyncedExceptionEnvelope> {
  const exception = validatedException(exceptionValue);
  const context = encryptionContext(spaceId, recordKey);
  const dataKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  try {
    const dataKey = await crypto.subtle.importKey(
      "raw",
      dataKeyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: additionalData(spaceId, recordKey),
      },
      dataKey,
      encoder.encode(JSON.stringify(exception)),
    );
    const wrapped = await provider.wrapKey(dataKeyBytes, context);
    return {
      schemaVersion: "1.0",
      algorithm: "AES-256-GCM",
      provider: wrapped.provider,
      keyId: wrapped.keyId,
      wrappedKey: wrapped.value,
      iv: bytesToBase64Url(iv),
      ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
    };
  } finally {
    dataKeyBytes.fill(0);
  }
}

export async function decryptSyncedRiskException(
  envelopeValue: SyncedExceptionEnvelope,
  provider: KeyManagementProvider,
  spaceId: string,
  recordKey: string,
): Promise<RiskException> {
  if (
    !envelopeValue ||
    envelopeValue.schemaVersion !== "1.0" ||
    envelopeValue.algorithm !== "AES-256-GCM" ||
    envelopeValue.provider !== provider.provider ||
    envelopeValue.keyId !== provider.keyId
  ) {
    throw new Error("L’enveloppe d’exception est incompatible.");
  }
  const wrapped: WrappedDataKey = {
    provider: envelopeValue.provider,
    keyId: envelopeValue.keyId,
    value: envelopeValue.wrappedKey,
  };
  const dataKeyBytes = await provider.unwrapKey(
    wrapped,
    encryptionContext(spaceId, recordKey),
  );
  try {
    const dataKey = await crypto.subtle.importKey(
      "raw",
      dataKeyBytes,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    const iv = base64UrlToBytes(envelopeValue.iv, 16);
    const ciphertext = base64UrlToBytes(envelopeValue.ciphertext, 4_096);
    if (iv.length !== 12) {
      throw new Error("Le vecteur d’initialisation est invalide.");
    }
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: additionalData(spaceId, recordKey),
      },
      dataKey,
      ciphertext,
    );
    return validatedException(JSON.parse(decoder.decode(plaintext)) as unknown);
  } catch (error) {
    if (
      error instanceof Error &&
      /exception à synchroniser|vecteur/u.test(error.message)
    ) {
      throw error;
    }
    throw new Error("L’exception synchronisée ne peut pas être déchiffrée.");
  } finally {
    dataKeyBytes.fill(0);
  }
}

export function serializeExceptionEnvelope(
  envelope: SyncedExceptionEnvelope,
): string {
  return JSON.stringify(envelope);
}

export function parseExceptionEnvelope(
  serialized: string,
): SyncedExceptionEnvelope {
  if (!serialized || serialized.length > 12_000) {
    throw new Error("L’enveloppe d’exception est vide ou trop volumineuse.");
  }
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("L’enveloppe d’exception n’est pas un JSON valide.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("L’enveloppe d’exception est invalide.");
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== "1.0" ||
    record.algorithm !== "AES-256-GCM" ||
    (record.provider !== "platform-secret" &&
      record.provider !== "remote-kms") ||
    typeof record.keyId !== "string" ||
    typeof record.wrappedKey !== "string" ||
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new Error("L’enveloppe d’exception est incompatible.");
  }
  return record as SyncedExceptionEnvelope;
}

