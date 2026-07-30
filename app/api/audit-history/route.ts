import { and, desc, eq, inArray } from "drizzle-orm";
import { ensureAuditHistorySchema, getDb } from "../../../db";
import { auditHistory } from "../../../db/schema";
import {
  AuditHistoryValidationError,
  AUDIT_HISTORY_LIMIT,
  parseAuditHistoryPayload,
  type AuditHistoryPayload,
  type AuditHistoryRecord,
} from "../../../lib/audit-history";

export const dynamic = "force-dynamic";

const AUTHENTICATED_EMAIL_HEADER = "oai-authenticated-user-email";
const MAX_REQUEST_BYTES = 16_384;

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

async function actorHash(request: Request): Promise<string | null> {
  const email = request.headers
    .get(AUTHENTICATED_EMAIL_HEADER)
    ?.trim()
    .toLowerCase();
  const identity = email || (isLocalRequest(request) ? "local-preview" : "");
  if (!identity) return null;

  const digest = await crypto.subtle.digest(
    "SHA-256",
    // Keep the original namespace so existing per-user history remains readable.
    new TextEncoder().encode(`mcp-sentinel:audit-history:${identity}`),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
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

function rowToRecord(
  row: typeof auditHistory.$inferSelect,
): AuditHistoryRecord {
  const rules = JSON.parse(row.ruleSummary) as unknown;
  const payload = parseAuditHistoryPayload({
    source: row.source,
    score: row.score,
    servers: row.servers,
    critical: row.critical,
    high: row.high,
    medium: row.medium,
    toFix: row.toFix,
    secure: row.secure,
    rules,
  });
  return {
    id: row.id,
    createdAt: new Date(row.createdAt).toISOString(),
    ...payload,
  };
}

async function readPayload(request: Request): Promise<AuditHistoryPayload> {
  const contentType = request.headers.get("Content-Type") ?? "";
  const contentLength = Number(request.headers.get("Content-Length") ?? "0");
  if (
    !contentType.toLowerCase().startsWith("application/json") ||
    !Number.isFinite(contentLength) ||
    contentLength > MAX_REQUEST_BYTES
  ) {
    throw new AuditHistoryValidationError("invalid-request");
  }
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_REQUEST_BYTES) {
    throw new AuditHistoryValidationError("invalid-request");
  }
  return parseAuditHistoryPayload(JSON.parse(raw) as unknown);
}

export async function GET(request: Request) {
  try {
    const owner = await actorHash(request);
    if (!owner) return responseJson({ error: "Authentification requise." }, 401);

    await ensureAuditHistorySchema();
    const rows = await getDb()
      .select()
      .from(auditHistory)
      .where(eq(auditHistory.actorHash, owner))
      .orderBy(desc(auditHistory.createdAt))
      .limit(AUDIT_HISTORY_LIMIT);

    return responseJson({ history: rows.map(rowToRecord) });
  } catch {
    return responseJson(
      { error: "L’historique n’a pas pu être chargé." },
      500,
    );
  }
}

export async function POST(request: Request) {
  try {
    if (!sameOrigin(request)) {
      return responseJson({ error: "Origine de requête refusée." }, 403);
    }
    const owner = await actorHash(request);
    if (!owner) return responseJson({ error: "Authentification requise." }, 401);

    const payload = await readPayload(request);
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    await ensureAuditHistorySchema();
    const db = getDb();
    await db.insert(auditHistory).values({
      id,
      actorHash: owner,
      createdAt,
      source: payload.source,
      score: payload.score,
      servers: payload.servers,
      critical: payload.critical,
      high: payload.high,
      medium: payload.medium,
      toFix: payload.toFix,
      secure: payload.secure,
      ruleSummary: JSON.stringify(payload.rules),
    });

    const stale = await db
      .select({ id: auditHistory.id })
      .from(auditHistory)
      .where(eq(auditHistory.actorHash, owner))
      .orderBy(desc(auditHistory.createdAt))
      .limit(500)
      .offset(AUDIT_HISTORY_LIMIT);
    if (stale.length) {
      await db
        .delete(auditHistory)
        .where(
          and(
            eq(auditHistory.actorHash, owner),
            inArray(
              auditHistory.id,
              stale.map((entry) => entry.id),
            ),
          ),
        );
    }

    return responseJson(
      {
        record: {
          id,
          createdAt: new Date(createdAt).toISOString(),
          ...payload,
        } satisfies AuditHistoryRecord,
      },
      201,
    );
  } catch (error) {
    const invalid =
      error instanceof SyntaxError ||
      error instanceof AuditHistoryValidationError;
    return responseJson(
      {
        error: invalid
          ? "Le résumé d’audit est invalide."
          : "L’audit n’a pas pu être enregistré.",
      },
      invalid ? 400 : 500,
    );
  }
}

export async function DELETE(request: Request) {
  try {
    if (!sameOrigin(request)) {
      return responseJson({ error: "Origine de requête refusée." }, 403);
    }
    const owner = await actorHash(request);
    if (!owner) return responseJson({ error: "Authentification requise." }, 401);

    await ensureAuditHistorySchema();
    await getDb()
      .delete(auditHistory)
      .where(eq(auditHistory.actorHash, owner));
    return responseJson({ deleted: true });
  } catch {
    return responseJson(
      { error: "L’historique n’a pas pu être supprimé." },
      500,
    );
  }
}
