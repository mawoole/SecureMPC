import { env } from "cloudflare:workers";
import { ensureExceptionSyncSchema, getD1 } from "../../../db";
import {
  createExceptionRecordKey,
  createExceptionSpaceId,
  decryptSyncedRiskException,
  encryptSyncedRiskException,
  parseExceptionEnvelope,
  serializeExceptionEnvelope,
} from "../../../lib/enterprise-sync";
import {
  parseRiskExceptions,
  type RiskException,
} from "../../../lib/finding-exceptions";
import {
  createKeyManagementProvider,
  KeyManagementConfigurationError,
} from "../../../lib/key-management";
import { mergeRiskExceptions } from "../../../lib/trustmap-governance";

export const dynamic = "force-dynamic";

const AUTHENTICATED_EMAIL_HEADER = "oai-authenticated-user-email";
const AUTHENTICATED_NAME_HEADER = "oai-authenticated-user-full-name";
const AUTHENTICATED_NAME_ENCODING_HEADER =
  "oai-authenticated-user-full-name-encoding";
const MAX_REQUEST_BYTES = 1_500_000;
const MAX_SYNCED_EXCEPTIONS = 1_000;
const runtime = env as unknown as Record<string, unknown>;

type StoredExceptionRow = {
  record_key: string;
  envelope: string;
  actor_hash: string;
  updated_at: number;
  version: number;
};

class SyncValidationError extends Error {}

function responseJson(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

function isLocalRequest(request: Request): boolean {
  return ["localhost", "127.0.0.1", "::1"].includes(
    new URL(request.url).hostname,
  );
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("Origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function decodeDisplayName(request: Request): string | null {
  const encoded = request.headers.get(AUTHENTICATED_NAME_HEADER);
  if (
    !encoded ||
    request.headers.get(AUTHENTICATED_NAME_ENCODING_HEADER) !==
      "percent-encoded-utf-8"
  ) {
    return null;
  }
  try {
    return decodeURIComponent(encoded).slice(0, 120);
  } catch {
    return null;
  }
}

async function authenticatedActor(request: Request): Promise<{
  actorHash: string;
  displayName: string;
} | null> {
  const email = request.headers
    .get(AUTHENTICATED_EMAIL_HEADER)
    ?.trim()
    .toLowerCase();
  const identity = email || (isLocalRequest(request) ? "local-preview" : "");
  if (!identity) return null;
  return {
    actorHash: await sha256(`mcp-trustmap:exception-sync:actor:${identity}`),
    displayName:
      decodeDisplayName(request) ??
      (email ? email.slice(0, 160) : "Aperçu local"),
  };
}

async function workspaceId(): Promise<string> {
  const configured = runtime.TRUSTMAP_WORKSPACE_ID;
  return createExceptionSpaceId(
    typeof configured === "string" && configured.trim()
      ? configured
      : "primary-private-site",
  );
}

async function readExceptions(request: Request): Promise<RiskException[]> {
  const contentType = request.headers.get("Content-Type") ?? "";
  const contentLength = Number(request.headers.get("Content-Length") ?? "0");
  if (
    !contentType.toLowerCase().startsWith("application/json") ||
    !Number.isFinite(contentLength) ||
    contentLength > MAX_REQUEST_BYTES
  ) {
    throw new SyncValidationError("invalid-request");
  }
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_REQUEST_BYTES) {
    throw new SyncValidationError("invalid-request");
  }
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw new SyncValidationError("invalid-json");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SyncValidationError("invalid-payload");
  }
  const candidates = (value as Record<string, unknown>).exceptions;
  if (
    !Array.isArray(candidates) ||
    candidates.length > MAX_SYNCED_EXCEPTIONS
  ) {
    throw new SyncValidationError("invalid-exceptions");
  }
  const parsed = parseRiskExceptions(JSON.stringify(candidates));
  if (parsed.length !== candidates.length) {
    throw new SyncValidationError("invalid-exceptions");
  }
  return parsed;
}

async function readStoredRows(spaceId: string): Promise<StoredExceptionRow[]> {
  const result = await getD1()
    .prepare(
      `SELECT record_key, envelope, actor_hash, updated_at, version
       FROM exception_sync_records
       WHERE space_id = ?
       ORDER BY updated_at DESC
       LIMIT ?`,
    )
    .bind(spaceId, MAX_SYNCED_EXCEPTIONS + 1)
    .all<StoredExceptionRow>();
  if (result.results.length > MAX_SYNCED_EXCEPTIONS) {
    throw new Error("Le registre partagé dépasse la limite autorisée.");
  }
  return result.results;
}

async function decryptRow(
  row: StoredExceptionRow,
  spaceId: string,
): Promise<RiskException> {
  const envelope = parseExceptionEnvelope(row.envelope);
  const provider = createKeyManagementProvider(
    runtime,
    envelope.provider,
    envelope.keyId,
  );
  return decryptSyncedRiskException(
    envelope,
    provider,
    spaceId,
    row.record_key,
  );
}

async function listSharedExceptions(
  spaceId: string,
): Promise<{
  exceptions: RiskException[];
  lastSyncedAt: string | null;
}> {
  const rows = await readStoredRows(spaceId);
  const exceptions = await Promise.all(
    rows.map((row) => decryptRow(row, spaceId)),
  );
  return {
    exceptions,
    lastSyncedAt: rows.length
      ? new Date(Math.max(...rows.map((row) => row.updated_at))).toISOString()
      : null,
  };
}

function sameException(
  left: RiskException,
  right: RiskException,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function appendAuditEvent(
  spaceId: string,
  recordKey: string,
  actorHash: string,
  action: "upserted" | "revoked" | "rekeyed",
  version: number,
  createdAt: number,
) {
  await getD1()
    .prepare(
      `INSERT INTO exception_sync_events
       (id, space_id, record_key, actor_hash, action, created_at, version)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      crypto.randomUUID(),
      spaceId,
      recordKey,
      actorHash,
      action,
      createdAt,
      version,
    )
    .run();
}

async function upsertException(
  spaceId: string,
  actorHash: string,
  incoming: RiskException,
): Promise<boolean> {
  const recordKey = await createExceptionRecordKey(spaceId, incoming.id);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const existingRow = await getD1()
      .prepare(
        `SELECT record_key, envelope, actor_hash, updated_at, version
         FROM exception_sync_records
         WHERE record_key = ? AND space_id = ?`,
      )
      .bind(recordKey, spaceId)
      .first<StoredExceptionRow>();
    const existing = existingRow
      ? await decryptRow(existingRow, spaceId)
      : undefined;
    const merged = existing
      ? mergeRiskExceptions([existing], [incoming])[0]
      : incoming;
    const provider = createKeyManagementProvider(runtime);
    const existingEnvelope = existingRow
      ? parseExceptionEnvelope(existingRow.envelope)
      : undefined;
    const requiresRekey =
      Boolean(existingEnvelope) &&
      (existingEnvelope?.provider !== provider.provider ||
        existingEnvelope.keyId !== provider.keyId);
    if (existing && sameException(existing, merged) && !requiresRekey) {
      return false;
    }

    const envelope = await encryptSyncedRiskException(
      merged,
      provider,
      spaceId,
      recordKey,
    );
    const updatedAt = Date.now();
    const version = (existingRow?.version ?? 0) + 1;
    const result = existingRow
      ? await getD1()
          .prepare(
            `UPDATE exception_sync_records
             SET envelope = ?, actor_hash = ?, updated_at = ?, version = ?
             WHERE record_key = ? AND space_id = ? AND version = ?`,
          )
          .bind(
            serializeExceptionEnvelope(envelope),
            actorHash,
            updatedAt,
            version,
            recordKey,
            spaceId,
            existingRow.version,
          )
          .run()
      : await getD1()
          .prepare(
            `INSERT OR IGNORE INTO exception_sync_records
             (record_key, space_id, envelope, actor_hash, updated_at, version)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            recordKey,
            spaceId,
            serializeExceptionEnvelope(envelope),
            actorHash,
            updatedAt,
            version,
          )
          .run();
    if ((result.meta.changes ?? 0) === 1) {
      await appendAuditEvent(
        spaceId,
        recordKey,
        actorHash,
        requiresRekey
          ? "rekeyed"
          : merged.revokedAt
            ? "revoked"
            : "upserted",
        version,
        updatedAt,
      );
      return true;
    }
  }
  throw new Error("Conflit de synchronisation persistant.");
}

async function trimAuditEvents(spaceId: string) {
  await getD1()
    .prepare(
      `DELETE FROM exception_sync_events
       WHERE space_id = ?
         AND id NOT IN (
           SELECT id FROM exception_sync_events
           WHERE space_id = ?
           ORDER BY created_at DESC
           LIMIT 500
         )`,
    )
    .bind(spaceId, spaceId)
    .run();
}

async function syncMetadata(
  request: Request,
  actor: { actorHash: string; displayName: string },
  spaceId: string,
) {
  const provider = createKeyManagementProvider(runtime);
  const event = await getD1()
    .prepare(
      `SELECT created_at
       FROM exception_sync_events
       WHERE space_id = ?
       ORDER BY created_at DESC
       LIMIT 1`,
    )
    .bind(spaceId)
    .first<{ created_at: number }>();
  return {
    authenticated: true,
    identity: actor.displayName,
    actorRef: actor.actorHash.slice(0, 12),
    workspaceRef: spaceId.slice(-12),
    kms: provider.status(),
    lastActivityAt: event?.created_at
      ? new Date(event.created_at).toISOString()
      : null,
    localPreview: isLocalRequest(request),
  };
}

export async function GET(request: Request) {
  try {
    const actor = await authenticatedActor(request);
    if (!actor) {
      return responseJson({ error: "Authentification SSO requise." }, 401);
    }
    await ensureExceptionSyncSchema();
    const spaceId = await workspaceId();
    const shared = await listSharedExceptions(spaceId);
    return responseJson({
      ...shared,
      sync: await syncMetadata(request, actor, spaceId),
    });
  } catch (error) {
    const configuration = error instanceof KeyManagementConfigurationError;
    return responseJson(
      {
        error: configuration
          ? "Le fournisseur de clés n’est pas configuré."
          : "Le registre partagé n’a pas pu être chargé.",
      },
      configuration ? 503 : 500,
    );
  }
}

export async function PUT(request: Request) {
  try {
    if (!sameOrigin(request)) {
      return responseJson({ error: "Origine de requête refusée." }, 403);
    }
    const actor = await authenticatedActor(request);
    if (!actor) {
      return responseJson({ error: "Authentification SSO requise." }, 401);
    }
    const incoming = await readExceptions(request);
    await ensureExceptionSyncSchema();
    const spaceId = await workspaceId();
    let changed = 0;
    for (const exception of incoming) {
      if (await upsertException(spaceId, actor.actorHash, exception)) changed += 1;
    }
    await trimAuditEvents(spaceId);
    const shared = await listSharedExceptions(spaceId);
    return responseJson({
      ...shared,
      changed,
      sync: await syncMetadata(request, actor, spaceId),
    });
  } catch (error) {
    const invalid =
      error instanceof SyncValidationError || error instanceof SyntaxError;
    const configuration = error instanceof KeyManagementConfigurationError;
    return responseJson(
      {
        error: invalid
          ? "Le registre d’exceptions envoyé est invalide."
          : configuration
            ? "Le fournisseur de clés n’est pas configuré."
            : "La synchronisation chiffrée a échoué.",
      },
      invalid ? 400 : configuration ? 503 : 500,
    );
  }
}
