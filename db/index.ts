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
let exceptionSyncSchemaReady: Promise<void> | undefined;

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

export function ensureExceptionSyncSchema(): Promise<void> {
  exceptionSyncSchemaReady ??= getD1()
    .batch([
      getD1().prepare(`
        CREATE TABLE IF NOT EXISTS exception_sync_records (
          record_key TEXT PRIMARY KEY NOT NULL,
          space_id TEXT NOT NULL,
          envelope TEXT NOT NULL,
          actor_hash TEXT NOT NULL,
          updated_at INTEGER NOT NULL,
          version INTEGER NOT NULL
        )
      `),
      getD1().prepare(`
        CREATE INDEX IF NOT EXISTS exception_sync_space_updated_idx
        ON exception_sync_records (space_id, updated_at)
      `),
      getD1().prepare(`
        CREATE TABLE IF NOT EXISTS exception_sync_events (
          id TEXT PRIMARY KEY NOT NULL,
          space_id TEXT NOT NULL,
          record_key TEXT NOT NULL,
          actor_hash TEXT NOT NULL,
          action TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          version INTEGER NOT NULL
        )
      `),
      getD1().prepare(`
        CREATE INDEX IF NOT EXISTS exception_sync_events_space_created_idx
        ON exception_sync_events (space_id, created_at)
      `),
    ])
    .then(() => undefined)
    .catch((error) => {
      exceptionSyncSchemaReady = undefined;
      throw error;
    });
  return exceptionSyncSchemaReady;
}
