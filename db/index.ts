import { env } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

export function getD1() {
  if (!env.DB) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Set the `d1` field in .openai/hosting.json to `DB` or let your control plane inject the real binding values before using the database."
    );
  }
  return env.DB;
}

export function getDb() {
  return drizzle(getD1(), { schema });
}

let auditHistorySchemaReady: Promise<void> | undefined;

export function ensureAuditHistorySchema(): Promise<void> {
  auditHistorySchemaReady ??= getD1()
    .batch([
      getD1().prepare(`
        CREATE TABLE IF NOT EXISTS audit_history (
          id TEXT PRIMARY KEY NOT NULL,
          actor_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          source TEXT NOT NULL,
          score INTEGER NOT NULL,
          servers INTEGER NOT NULL,
          critical INTEGER NOT NULL,
          high INTEGER NOT NULL,
          medium INTEGER NOT NULL,
          to_fix INTEGER NOT NULL,
          secure INTEGER NOT NULL,
          rule_summary TEXT NOT NULL
        )
      `),
      getD1().prepare(`
        CREATE INDEX IF NOT EXISTS audit_history_actor_created_idx
        ON audit_history (actor_hash, created_at)
      `),
    ])
    .then(() => undefined)
    .catch((error) => {
      auditHistorySchemaReady = undefined;
      throw error;
    });
  return auditHistorySchemaReady;
}
