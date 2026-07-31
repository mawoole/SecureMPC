import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

export const user = sqliteTable(
  "user",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    email: text("email").notNull(),
    emailVerified: integer("email_verified", { mode: "boolean" })
      .default(false)
      .notNull(),
    image: text("image"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
    twoFactorEnabled: integer("two_factor_enabled", { mode: "boolean" })
      .default(false)
      .notNull(),
  },
  (table) => [uniqueIndex("user_email_uidx").on(table.email)],
);

export const session = sqliteTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
    token: text("token").notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    activeOrganizationId: text("active_organization_id"),
  },
  (table) => [
    uniqueIndex("session_token_uidx").on(table.token),
    index("session_user_idx").on(table.userId),
  ],
);

export const account = sqliteTable(
  "account",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: integer("access_token_expires_at", {
      mode: "timestamp_ms",
    }),
    refreshTokenExpiresAt: integer("refresh_token_expires_at", {
      mode: "timestamp_ms",
    }),
    scope: text("scope"),
    password: text("password"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  },
  (table) => [
    index("account_user_idx").on(table.userId),
    uniqueIndex("account_provider_uidx").on(
      table.providerId,
      table.accountId,
    ),
  ],
);

export const verification = sqliteTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  },
  (table) => [index("verification_identifier_idx").on(table.identifier)],
);

export const organization = sqliteTable(
  "organization",
  {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    slug: text("slug").notNull(),
    logo: text("logo"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    metadata: text("metadata"),
  },
  (table) => [uniqueIndex("organization_slug_uidx").on(table.slug)],
);

export const member = sqliteTable(
  "member",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role").notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  },
  (table) => [
    uniqueIndex("member_organization_user_uidx").on(
      table.organizationId,
      table.userId,
    ),
    index("member_user_idx").on(table.userId),
  ],
);

export const invitation = sqliteTable(
  "invitation",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    role: text("role").notNull(),
    status: text("status").notNull(),
    expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
    inviterId: text("inviter_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  },
  (table) => [
    index("invitation_organization_idx").on(table.organizationId),
    index("invitation_email_idx").on(table.email),
  ],
);

export const twoFactor = sqliteTable(
  "two_factor",
  {
    id: text("id").primaryKey(),
    secret: text("secret").notNull(),
    backupCodes: text("backup_codes").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    verified: integer("verified", { mode: "boolean" })
      .default(true)
      .notNull(),
    failedVerificationCount: integer("failed_verification_count")
      .default(0)
      .notNull(),
    lockedUntil: integer("locked_until", { mode: "timestamp_ms" }),
  },
  (table) => [
    uniqueIndex("two_factor_user_uidx").on(table.userId),
    index("two_factor_secret_idx").on(table.secret),
  ],
);

export const auditHistory = sqliteTable(
  "audit_history",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id").default("").notNull(),
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
    index("audit_history_organization_created_idx").on(
      table.organizationId,
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
