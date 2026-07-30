import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const auditHistory = sqliteTable(
  "audit_history",
  {
    id: text("id").primaryKey(),
    actorHash: text("actor_hash").notNull(),
    createdAt: integer("created_at").notNull(),
    source: text("source").notNull(),
    score: integer("score").notNull(),
    servers: integer("servers").notNull(),
    critical: integer("critical").notNull(),
    high: integer("high").notNull(),
    medium: integer("medium").notNull(),
    toFix: integer("to_fix").notNull(),
    secure: integer("secure").notNull(),
    ruleSummary: text("rule_summary").notNull(),
  },
  (table) => [
    index("audit_history_actor_created_idx").on(
      table.actorHash,
      table.createdAt,
    ),
  ],
);

export const exceptionSyncRecords = sqliteTable(
  "exception_sync_records",
  {
    recordKey: text("record_key").primaryKey(),
    spaceId: text("space_id").notNull(),
    envelope: text("envelope").notNull(),
    actorHash: text("actor_hash").notNull(),
    updatedAt: integer("updated_at").notNull(),
    version: integer("version").notNull(),
  },
  (table) => [
    index("exception_sync_space_updated_idx").on(
      table.spaceId,
      table.updatedAt,
    ),
  ],
);

export const exceptionSyncEvents = sqliteTable(
  "exception_sync_events",
  {
    id: text("id").primaryKey(),
    spaceId: text("space_id").notNull(),
    recordKey: text("record_key").notNull(),
    actorHash: text("actor_hash").notNull(),
    action: text("action").notNull(),
    createdAt: integer("created_at").notNull(),
    version: integer("version").notNull(),
  },
  (table) => [
    index("exception_sync_events_space_created_idx").on(
      table.spaceId,
      table.createdAt,
    ),
  ],
);
