import { env } from "cloudflare:workers";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { organization, twoFactor } from "better-auth/plugins";
import { getDb, getD1 } from "../../db";
import * as schema from "../../db/schema";
import { sendTransactionalEmail } from "./email";
import {
  normalizeTrustMapRole,
  trustMapAccessControl,
  trustMapRoles,
  type TrustMapRole,
} from "./permissions";

const runtime = env as unknown as Record<string, unknown>;

function runtimeString(key: string): string {
  const value = runtime[key];
  return typeof value === "string" ? value.trim() : "";
}

function authBaseUrl(): string {
  return runtimeString("BETTER_AUTH_URL") || "http://localhost:3000";
}

function authSecret(): string {
  const configured = runtimeString("BETTER_AUTH_SECRET");
  if (configured) return configured;
  if (
    runtimeString("TRUSTMAP_ENVIRONMENT") === "development" &&
    authBaseUrl().startsWith("http://localhost")
  ) {
    return "local-development-secret-change-before-production-32chars";
  }
  throw new Error(
    "BETTER_AUTH_SECRET est obligatoire hors développement local explicite.",
  );
}

function invitationUrl(invitationId: string): string {
  const url = new URL("/accept-invitation", authBaseUrl());
  url.searchParams.set("invitationId", invitationId);
  return url.toString();
}

export const auth = betterAuth({
  appName: "MCP TrustMap",
  baseURL: authBaseUrl(),
  secret: authSecret(),
  database: drizzleAdapter(getDb(), {
    provider: "sqlite",
    schema,
  }),
  advanced: {
    database: {
      generateId: "uuid",
    },
    ipAddress: {
      ipAddressHeaders: ["cf-connecting-ip"],
    },
    useSecureCookies: authBaseUrl().startsWith("https://"),
  },
  trustedOrigins: [new URL(authBaseUrl()).origin],
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,
    minPasswordLength: 12,
    maxPasswordLength: 128,
    revokeSessionsOnPasswordReset: true,
    resetPasswordTokenExpiresIn: 3600,
    async sendResetPassword({ user, url }) {
      await sendTransactionalEmail(runtime, {
        to: user.email,
        subject: "Réinitialiser votre mot de passe MCP TrustMap",
        text: [
          `Bonjour ${user.name},`,
          "",
          "Utilisez ce lien pendant l’heure qui suit pour choisir un nouveau mot de passe :",
          url,
          "",
          "Si vous n’êtes pas à l’origine de cette demande, ignorez ce message.",
        ].join("\n"),
      });
    },
  },
  emailVerification: {
    sendOnSignUp: true,
    sendOnSignIn: true,
    autoSignInAfterVerification: true,
    expiresIn: 3600,
    async sendVerificationEmail({ user, url }) {
      await sendTransactionalEmail(runtime, {
        to: user.email,
        subject: "Confirmer votre adresse MCP TrustMap",
        text: [
          `Bonjour ${user.name},`,
          "",
          "Confirmez votre adresse e-mail pour activer votre compte MCP TrustMap :",
          url,
          "",
          "Ce lien expire dans une heure.",
        ].join("\n"),
      });
    },
  },
  rateLimit: {
    enabled: true,
    window: 60,
    max: 60,
  },
  session: {
    expiresIn: 60 * 60 * 24 * 7,
    updateAge: 60 * 60 * 24,
    cookieCache: {
      enabled: true,
      maxAge: 5 * 60,
    },
  },
  plugins: [
    organization({
      ac: trustMapAccessControl,
      roles: trustMapRoles,
      creatorRole: "admin",
      invitationExpiresIn: 60 * 60 * 24 * 7,
      requireEmailVerificationOnInvitation: true,
      cancelPendingInvitationsOnReInvite: true,
      async sendInvitationEmail(data) {
        await sendTransactionalEmail(runtime, {
          to: data.email,
          subject: `Invitation à rejoindre ${data.organization.name}`,
          text: [
            `${data.inviter.user.name} (${data.inviter.user.email}) vous invite à rejoindre`,
            `${data.organization.name} dans MCP TrustMap avec le rôle ${data.role}.`,
            "",
            invitationUrl(data.id),
            "",
            "Cette invitation expire dans sept jours.",
          ].join("\n"),
        });
      },
    }),
    twoFactor({
      issuer: "MCP TrustMap",
      totpOptions: {
        digits: 6,
        period: 30,
      },
      backupCodeOptions: {
        amount: 10,
        length: 10,
      },
      accountLockout: {
        enabled: true,
        maxFailedAttempts: 5,
        durationSeconds: 15 * 60,
      },
    }),
  ],
});

type AuthSession = Awaited<ReturnType<typeof auth.api.getSession>>;

export type TrustMapAuthContext = {
  actorHash: string;
  displayName: string;
  email: string;
  organizationId: string;
  role: TrustMapRole;
  session: NonNullable<AuthSession>;
  userId: string;
};

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function getAuthContext(
  requestHeaders: Headers,
): Promise<TrustMapAuthContext | null> {
  const currentSession = await auth.api.getSession({
    headers: requestHeaders,
  });
  if (!currentSession) return null;

  const activeOrganizationId =
    currentSession.session.activeOrganizationId?.trim();
  if (!activeOrganizationId) return null;

  const membership = await getD1()
    .prepare(
      `SELECT role
       FROM member
       WHERE organization_id = ? AND user_id = ?
       LIMIT 1`,
    )
    .bind(activeOrganizationId, currentSession.user.id)
    .first<{ role: string }>();
  if (!membership) return null;

  return {
    actorHash: await sha256(
      `mcp-trustmap:${activeOrganizationId}:actor:${currentSession.user.id}`,
    ),
    displayName: currentSession.user.name || currentSession.user.email,
    email: currentSession.user.email,
    organizationId: activeOrganizationId,
    role: normalizeTrustMapRole(membership.role),
    session: currentSession,
    userId: currentSession.user.id,
  };
}
