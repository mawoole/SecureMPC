const encoder = new TextEncoder();
const MAX_REMOTE_RESPONSE_BYTES = 8_192;

export type KeyManagementProviderName = "platform-secret" | "remote-kms";

export type WrappedDataKey = {
  provider: KeyManagementProviderName;
  keyId: string;
  value: string;
};

export type KeyManagementStatus = {
  provider: KeyManagementProviderName;
  keyId: string;
  label: string;
};

export interface KeyManagementProvider {
  readonly provider: KeyManagementProviderName;
  readonly keyId: string;
  status(): KeyManagementStatus;
  wrapKey(dataKey: Uint8Array, context: string): Promise<WrappedDataKey>;
  unwrapKey(wrapped: WrappedDataKey, context: string): Promise<Uint8Array>;
}

export class KeyManagementConfigurationError extends Error {}

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
    throw new Error("La clé enveloppée est invalide.");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  if (binary.length > maximumBytes) {
    throw new Error("La clé enveloppée dépasse la limite autorisée.");
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function validateContext(value: string): string {
  if (
    !value ||
    value.length > 300 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("Le contexte cryptographique est invalide.");
  }
  return value;
}

function validateKeyId(value: string): string {
  const trimmed = value.trim();
  if (
    !trimmed ||
    trimmed.length > 200 ||
    /[\u0000-\u001f\u007f]/u.test(trimmed)
  ) {
    throw new KeyManagementConfigurationError(
      "L’identifiant de clé KMS est invalide.",
    );
  }
  return trimmed;
}

function runtimeString(
  runtime: Record<string, unknown>,
  key: string,
): string {
  const value = runtime[key];
  return typeof value === "string" ? value.trim() : "";
}

export function createPlatformSecretKeyProvider(
  encodedMasterKey: string,
  keyId = "sites-secret:v1",
): KeyManagementProvider {
  const masterKeyBytes = base64UrlToBytes(encodedMasterKey, 64);
  if (masterKeyBytes.length !== 32) {
    throw new KeyManagementConfigurationError(
      "La clé d’enveloppe de plateforme doit contenir exactement 32 octets.",
    );
  }
  const normalizedKeyId = validateKeyId(keyId);
  let importedMasterKey: Promise<CryptoKey> | undefined;
  const getMasterKey = () => {
    importedMasterKey ??= crypto.subtle.importKey(
      "raw",
      masterKeyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    return importedMasterKey;
  };

  return {
    provider: "platform-secret",
    keyId: normalizedKeyId,
    status: () => ({
      provider: "platform-secret",
      keyId: normalizedKeyId,
      label: "Clé d’enveloppe gérée par l’hébergeur",
    }),
    async wrapKey(dataKey, context) {
      if (dataKey.length !== 32) {
        throw new Error("La clé de données doit contenir 32 octets.");
      }
      const safeContext = validateContext(context);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: encoder.encode(
            `mcp-trustmap:kms-wrap:${normalizedKeyId}:${safeContext}`,
          ),
        },
        await getMasterKey(),
        dataKey,
      );
      const combined = new Uint8Array(12 + ciphertext.byteLength);
      combined.set(iv, 0);
      combined.set(new Uint8Array(ciphertext), 12);
      return {
        provider: "platform-secret",
        keyId: normalizedKeyId,
        value: bytesToBase64Url(combined),
      };
    },
    async unwrapKey(wrapped, context) {
      if (
        wrapped.provider !== "platform-secret" ||
        wrapped.keyId !== normalizedKeyId
      ) {
        throw new Error("La clé enveloppée ne correspond pas au fournisseur.");
      }
      const combined = base64UrlToBytes(wrapped.value, 128);
      if (combined.length < 29) {
        throw new Error("La clé enveloppée est tronquée.");
      }
      try {
        const plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: combined.subarray(0, 12),
            additionalData: encoder.encode(
              `mcp-trustmap:kms-wrap:${normalizedKeyId}:${validateContext(context)}`,
            ),
          },
          await getMasterKey(),
          combined.subarray(12),
        );
        const dataKey = new Uint8Array(plaintext);
        if (dataKey.length !== 32) {
          throw new Error("La clé de données déchiffrée est invalide.");
        }
        return dataKey;
      } catch (error) {
        if (
          error instanceof Error &&
          /clé de données déchiffrée/u.test(error.message)
        ) {
          throw error;
        }
        throw new Error(
          "Le fournisseur de clés n’a pas pu ouvrir la clé de données.",
        );
      }
    },
  };
}

type RemoteKmsResponse = {
  wrappedKey?: string;
  plaintextKey?: string;
};

function createRemoteKmsProvider(
  endpointValue: string,
  keyId: string,
  bearerToken: string,
  fetchImplementation: typeof fetch = fetch,
): KeyManagementProvider {
  let endpoint: URL;
  try {
    endpoint = new URL(endpointValue);
  } catch {
    throw new KeyManagementConfigurationError(
      "L’URL de la passerelle KMS est invalide.",
    );
  }
  if (
    endpoint.protocol !== "https:" &&
    !["localhost", "127.0.0.1", "::1"].includes(endpoint.hostname)
  ) {
    throw new KeyManagementConfigurationError(
      "La passerelle KMS doit utiliser HTTPS.",
    );
  }
  if (
    bearerToken.length < 16 ||
    bearerToken.length > 4_096 ||
    /[\u0000-\u001f\u007f]/u.test(bearerToken)
  ) {
    throw new KeyManagementConfigurationError(
      "Le jeton de la passerelle KMS est invalide.",
    );
  }
  const normalizedKeyId = validateKeyId(keyId);

  const call = async (
    operation: "wrap" | "unwrap",
    context: string,
    value: string,
  ): Promise<RemoteKmsResponse> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    try {
      const response = await fetchImplementation(endpoint, {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${bearerToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          schemaVersion: "1.0",
          operation,
          keyId: normalizedKeyId,
          context: validateContext(context),
          value,
        }),
        signal: controller.signal,
      });
      const contentLength = Number(
        response.headers.get("Content-Length") ?? "0",
      );
      if (
        !response.ok ||
        !Number.isFinite(contentLength) ||
        contentLength > MAX_REMOTE_RESPONSE_BYTES
      ) {
        throw new Error("La passerelle KMS a refusé l’opération.");
      }
      const raw = await response.text();
      if (encoder.encode(raw).byteLength > MAX_REMOTE_RESPONSE_BYTES) {
        throw new Error("La réponse KMS dépasse la limite autorisée.");
      }
      return JSON.parse(raw) as RemoteKmsResponse;
    } catch (error) {
      if (
        error instanceof Error &&
        /passerelle KMS|réponse KMS/u.test(error.message)
      ) {
        throw error;
      }
      throw new Error("La passerelle KMS est temporairement indisponible.");
    } finally {
      clearTimeout(timeout);
    }
  };

  return {
    provider: "remote-kms",
    keyId: normalizedKeyId,
    status: () => ({
      provider: "remote-kms",
      keyId: normalizedKeyId,
      label: "KMS externe",
    }),
    async wrapKey(dataKey, context) {
      if (dataKey.length !== 32) {
        throw new Error("La clé de données doit contenir 32 octets.");
      }
      const response = await call(
        "wrap",
        context,
        bytesToBase64Url(dataKey),
      );
      if (
        typeof response.wrappedKey !== "string" ||
        response.wrappedKey.length < 16 ||
        response.wrappedKey.length > 4_096
      ) {
        throw new Error("La passerelle KMS a renvoyé une clé invalide.");
      }
      return {
        provider: "remote-kms",
        keyId: normalizedKeyId,
        value: response.wrappedKey,
      };
    },
    async unwrapKey(wrapped, context) {
      if (
        wrapped.provider !== "remote-kms" ||
        wrapped.keyId !== normalizedKeyId ||
        wrapped.value.length > 4_096
      ) {
        throw new Error("La clé enveloppée ne correspond pas au fournisseur.");
      }
      const response = await call("unwrap", context, wrapped.value);
      const dataKey = base64UrlToBytes(response.plaintextKey, 64);
      if (dataKey.length !== 32) {
        throw new Error("La passerelle KMS a renvoyé une clé invalide.");
      }
      return dataKey;
    },
  };
}

export function createKeyManagementProvider(
  runtime: Record<string, unknown>,
  requestedProvider?: KeyManagementProviderName,
  requestedKeyId?: string,
  fetchImplementation: typeof fetch = fetch,
): KeyManagementProvider {
  const endpoint = runtimeString(runtime, "TRUSTMAP_KMS_ENDPOINT");
  const configuredKeyId = runtimeString(runtime, "TRUSTMAP_KMS_KEY_ID");
  const token = runtimeString(runtime, "TRUSTMAP_KMS_BEARER_TOKEN");
  let masterKey = runtimeString(runtime, "TRUSTMAP_KMS_MASTER_KEY");
  const selected =
    requestedProvider ?? (endpoint ? "remote-kms" : "platform-secret");
  const keyId = requestedKeyId || configuredKeyId;

  if (selected === "remote-kms") {
    if (!endpoint || !keyId || !token) {
      throw new KeyManagementConfigurationError(
        "La passerelle KMS externe n’est pas complètement configurée.",
      );
    }
    return createRemoteKmsProvider(
      endpoint,
      keyId,
      token,
      fetchImplementation,
    );
  }
  if (
    requestedKeyId &&
    configuredKeyId &&
    requestedKeyId !== configuredKeyId
  ) {
    const previousKeys = runtimeString(
      runtime,
      "TRUSTMAP_KMS_PREVIOUS_KEYS",
    );
    try {
      const parsed = JSON.parse(previousKeys) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("invalid");
      }
      const entries = Object.entries(parsed as Record<string, unknown>);
      if (entries.length > 10) throw new Error("invalid");
      const previous = (parsed as Record<string, unknown>)[requestedKeyId];
      if (typeof previous !== "string") throw new Error("missing");
      masterKey = previous;
    } catch {
      throw new KeyManagementConfigurationError(
        "La version de clé d’enveloppe demandée n’est plus disponible.",
      );
    }
  }
  if (!masterKey) {
    throw new KeyManagementConfigurationError(
      "La clé d’enveloppe de plateforme n’est pas configurée.",
    );
  }
  return createPlatformSecretKeyProvider(
    masterKey,
    keyId || "sites-secret:v1",
  );
}
