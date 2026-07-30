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
