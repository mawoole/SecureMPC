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
import { getAuthContext } from "../../../lib/auth/server";

export const dynamic = "force-dynamic";

const MAX_REQUEST_BYTES = 16_384;

function responseJson(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
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
    const actor = await getAuthContext(request.headers);
    if (!actor) return responseJson({ error: "Authentification requise." }, 401);

    await ensureAuditHistorySchema();
    const rows = await getDb()
      .select()
      .from(auditHistory)
      .where(eq(auditHistory.organizationId, actor.organizationId))
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
    const actor = await getAuthContext(request.headers);
    if (!actor) return responseJson({ error: "Authentification requise." }, 401);
    if (actor.role === "reader") {
      return responseJson(
        { error: "Le rôle Reader ne peut pas enregistrer un audit." },
        403,
      );
    }

    const payload = await readPayload(request);
    const id = crypto.randomUUID();
    const createdAt = Date.now();
    await ensureAuditHistorySchema();
    const db = getDb();
    await db.insert(auditHistory).values({
      id,
      organizationId: actor.organizationId,
      actorHash: actor.actorHash,
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
      .where(eq(auditHistory.organizationId, actor.organizationId))
      .orderBy(desc(auditHistory.createdAt))
      .limit(500)
      .offset(AUDIT_HISTORY_LIMIT);
    if (stale.length) {
      await db
        .delete(auditHistory)
        .where(
          and(
            eq(auditHistory.organizationId, actor.organizationId),
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
    const actor = await getAuthContext(request.headers);
    if (!actor) return responseJson({ error: "Authentification requise." }, 401);
    if (actor.role !== "admin") {
      return responseJson(
        { error: "Seul un administrateur peut effacer l’historique." },
        403,
      );
    }

    await ensureAuditHistorySchema();
    await getDb()
      .delete(auditHistory)
      .where(eq(auditHistory.organizationId, actor.organizationId));
    return responseJson({ deleted: true });
  } catch {
    return responseJson(
      { error: "L’historique n’a pas pu être supprimé." },
      500,
    );
  }
}
