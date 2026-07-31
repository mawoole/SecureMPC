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
  applyRiskExceptionDecision,
  EnterpriseAuthorizationError,
  normalizeStoredRiskException,
  prepareRiskExceptionForSync,
  resolveEnterpriseRole,
  roleCapabilities,
  type EnterpriseActor,
  type ExceptionDecision,
} from "../../../lib/enterprise-authorization";
import {
  parseRiskExceptions,
  type RiskException,
} from "../../../lib/finding-exceptions";
import {
  createKeyManagementProvider,
  KeyManagementConfigurationError,
} from "../../../lib/key-management";

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

async function authenticatedActor(
  request: Request,
): Promise<EnterpriseActor | null> {
  const email = request.headers
    .get(AUTHENTICATED_EMAIL_HEADER)
    ?.trim()
    .toLowerCase();
  const localPreview = isLocalRequest(request);
  const identity = email || (localPreview ? "local-preview" : "");
  if (!identity) return null;
  return {
    actorHash: await sha256(`mcp-trustmap:exception-sync:actor:${identity}`),
    displayName:
      decodeDisplayName(request) ??
      (email ? email.slice(0, 160) : "Aperçu local"),
    role: resolveEnterpriseRole(email ?? null, runtime, localPreview),
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

async function readDecision(request: Request): Promise<{
  exceptionId: string;
  action: ExceptionDecision;
}> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new SyncValidationError("invalid-request");
  }
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > 2_000) {
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
  const record = value as Record<string, unknown>;
  if (
    typeof record.exceptionId !== "string" ||
    !record.exceptionId.trim() ||
    record.exceptionId.length > 120 ||
    !["approve", "reject"].includes(String(record.action))
  ) {
    throw new SyncValidationError("invalid-decision");
  }
  return {
    exceptionId: record.exceptionId,
    action: record.action as ExceptionDecision,
  };
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
  const decrypted = await decryptSyncedRiskException(
    envelope,
    provider,
    spaceId,
    row.record_key,
  );
  return normalizeStoredRiskException(decrypted, row.actor_hash);
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
  action:
    | "upserted"
    | "revoked"
    | "rekeyed"
    | "approval-requested"
    | "approved"
    | "rejected",
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
  actor: EnterpriseActor,
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
    const merged = prepareRiskExceptionForSync(
      incoming,
      actor.actorHash,
      existing,
    );
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
            actor.actorHash,
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
            actor.actorHash,
            updatedAt,
            version,
          )
          .run();
    if ((result.meta.changes ?? 0) === 1) {
      await appendAuditEvent(
        spaceId,
        recordKey,
        actor.actorHash,
        requiresRekey
          ? "rekeyed"
          : merged.revokedAt
            ? "revoked"
            : merged.approval?.status === "pending"
              ? "approval-requested"
              : "upserted",
        version,
        updatedAt,
      );
      return true;
    }
  }
  throw new Error("Conflit de synchronisation persistant.");
}

async function applyStoredDecision(
  spaceId: string,
  actor: EnterpriseActor,
  exceptionId: string,
  action: ExceptionDecision,
): Promise<void> {
  const recordKey = await createExceptionRecordKey(spaceId, exceptionId);
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const existingRow = await getD1()
      .prepare(
        `SELECT record_key, envelope, actor_hash, updated_at, version
         FROM exception_sync_records
         WHERE record_key = ? AND space_id = ?`,
      )
      .bind(recordKey, spaceId)
      .first<StoredExceptionRow>();
    if (!existingRow) {
      throw new EnterpriseAuthorizationError(
        "L’exception demandée est introuvable.",
        404,
      );
    }
    const existing = await decryptRow(existingRow, spaceId);
    const decided = applyRiskExceptionDecision(existing, actor, action);
    const provider = createKeyManagementProvider(runtime);
    const envelope = await encryptSyncedRiskException(
      decided,
      provider,
      spaceId,
      recordKey,
    );
    const updatedAt = Date.now();
    const version = existingRow.version + 1;
    const result = await getD1()
      .prepare(
        `UPDATE exception_sync_records
         SET envelope = ?, actor_hash = ?, updated_at = ?, version = ?
         WHERE record_key = ? AND space_id = ? AND version = ?`,
      )
      .bind(
        serializeExceptionEnvelope(envelope),
        actor.actorHash,
        updatedAt,
        version,
        recordKey,
        spaceId,
        existingRow.version,
      )
      .run();
    if ((result.meta.changes ?? 0) === 1) {
      await appendAuditEvent(
        spaceId,
        recordKey,
        actor.actorHash,
        action === "approve" ? "approved" : "rejected",
        version,
        updatedAt,
      );
      return;
    }
  }
  throw new Error("Conflit d’approbation persistant.");
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
  actor: EnterpriseActor,
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
    role: actor.role,
    capabilities: roleCapabilities(actor.role),
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
    if (!roleCapabilities(actor.role).canSync) {
      return responseJson(
        { error: "Le rôle lecteur ne peut pas modifier le registre." },
        403,
      );
    }
    const incoming = await readExceptions(request);
    await ensureExceptionSyncSchema();
    const spaceId = await workspaceId();
    let changed = 0;
    for (const exception of incoming) {
      if (await upsertException(spaceId, actor, exception)) changed += 1;
    }
    await trimAuditEvents(spaceId);
    const shared = await listSharedExceptions(spaceId);
    return responseJson({
      ...shared,
      changed,
      sync: await syncMetadata(request, actor, spaceId),
    });
  } catch (error) {
    if (error instanceof EnterpriseAuthorizationError) {
      return responseJson({ error: error.message }, error.status);
    }
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

export async function PATCH(request: Request) {
  try {
    if (!sameOrigin(request)) {
      return responseJson({ error: "Origine de requête refusée." }, 403);
    }
    const actor = await authenticatedActor(request);
    if (!actor) {
      return responseJson({ error: "Authentification SSO requise." }, 401);
    }
    const decision = await readDecision(request);
    await ensureExceptionSyncSchema();
    const spaceId = await workspaceId();
    await applyStoredDecision(
      spaceId,
      actor,
      decision.exceptionId,
      decision.action,
    );
    await trimAuditEvents(spaceId);
    const shared = await listSharedExceptions(spaceId);
    return responseJson({
      ...shared,
      changed: 1,
      sync: await syncMetadata(request, actor, spaceId),
    });
  } catch (error) {
    if (error instanceof EnterpriseAuthorizationError) {
      return responseJson({ error: error.message }, error.status);
    }
    const invalid =
      error instanceof SyncValidationError || error instanceof SyntaxError;
    const configuration = error instanceof KeyManagementConfigurationError;
    return responseJson(
      {
        error: invalid
          ? "La décision d’approbation envoyée est invalide."
          : configuration
            ? "Le fournisseur de clés n’est pas configuré."
            : "La décision d’approbation n’a pas pu être enregistrée.",
      },
      invalid ? 400 : configuration ? 503 : 500,
    );
  }
}
