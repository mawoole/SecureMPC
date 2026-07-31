"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import QRCode from "react-qr-code";
import { authClient } from "../../lib/auth/client";
import type { TrustMapRole } from "../../lib/auth/permissions";
import { authErrorMessage, FormMessage } from "../auth-ui";

type MemberRecord = {
  id: string;
  role: string;
  user: {
    email: string;
    id: string;
    name: string;
  };
};

type InvitationRecord = {
  email: string;
  id: string;
  role: string;
  status: string;
};

type OrganizationRecord = {
  id: string;
  name: string;
  slug: string;
};

type MfaSetup = {
  backupCodes: string[];
  totpURI: string;
};

const roleLabel: Record<TrustMapRole, string> = {
  admin: "Admin",
  auditor: "Auditor",
  reader: "Reader",
};

function normalizeRole(value: string): TrustMapRole {
  if (value.split(",").includes("admin")) return "admin";
  if (value.split(",").includes("auditor")) return "auditor";
  return "reader";
}

export function SettingsClient() {
  const session = authClient.useSession();
  const activeOrganization = authClient.useActiveOrganization();
  const [activeRole, setActiveRole] = useState<TrustMapRole>("reader");
  const [members, setMembers] = useState<MemberRecord[]>([]);
  const [invitations, setInvitations] = useState<InvitationRecord[]>([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TrustMapRole>("reader");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaSetup, setMfaSetup] = useState<MfaSetup | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  const organization = activeOrganization.data as
    | OrganizationRecord
    | null
    | undefined;

  async function refreshOrganization() {
    const [roleResult, memberResult, invitationResult] = await Promise.all([
      authClient.organization.getActiveMemberRole(),
      authClient.organization.listMembers({
        query: { limit: 100, offset: 0 },
      }),
      authClient.organization.listInvitations(),
    ]);
    if (roleResult.data) setActiveRole(normalizeRole(roleResult.data.role));
    if (memberResult.data) {
      const data = memberResult.data as unknown as { members: MemberRecord[] };
      setMembers(data.members ?? []);
    }
    if (invitationResult.data) {
      setInvitations(
        invitationResult.data as unknown as InvitationRecord[],
      );
    }
  }

  useEffect(() => {
    if (!organization?.id) return;
    const timer = window.setTimeout(() => void refreshOrganization(), 0);
    return () => window.clearTimeout(timer);
  }, [organization?.id]);

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    setMessage("");
    const result = await authClient.organization.inviteMember({
      email: inviteEmail,
      role: inviteRole,
      organizationId: organization?.id,
      resend: true,
    });
    if (result.error) setError(authErrorMessage(result.error));
    else {
      setInviteEmail("");
      setMessage("Invitation envoyée.");
      await refreshOrganization();
    }
    setPending(false);
  }

  async function updateRole(memberId: string, role: TrustMapRole) {
    setPending(true);
    setError("");
    const result = await authClient.organization.updateMemberRole({
      memberId,
      role,
      organizationId: organization?.id,
    });
    if (result.error) setError(authErrorMessage(result.error));
    else {
      setMessage("Rôle mis à jour.");
      await refreshOrganization();
    }
    setPending(false);
  }

  async function enableMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    const result = await authClient.twoFactor.enable({
      password,
      issuer: "MCP TrustMap",
    });
    if (result.error) setError(authErrorMessage(result.error));
    else if (result.data) {
      setMfaSetup(result.data as MfaSetup);
      setMessage(
        "Scannez le QR code, puis confirmez avec le premier code généré.",
      );
    }
    setPassword("");
    setPending(false);
  }

  async function verifyMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    const result = await authClient.twoFactor.verifyTotp({
      code: mfaCode,
      trustDevice: true,
    });
    if (result.error) setError(authErrorMessage(result.error));
    else {
      setMessage("MFA activée. Conservez les codes de secours hors ligne.");
      setMfaCode("");
      await session.refetch();
    }
    setPending(false);
  }

  async function disableMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    const result = await authClient.twoFactor.disable({ password });
    if (result.error) setError(authErrorMessage(result.error));
    else {
      setMessage("MFA désactivée.");
      setPassword("");
      setMfaSetup(null);
      await session.refetch();
    }
    setPending(false);
  }

  async function signOut() {
    await authClient.signOut();
    window.location.href = "/login";
  }

  const currentUser = session.data?.user as
    | { email: string; id: string; name: string; twoFactorEnabled?: boolean }
    | undefined;

  return (
    <main className="settings-page">
      <header className="settings-header">
        <Link className="auth-brand" href="/">
          <span className="brand-mark" aria-hidden="true">
            T
          </span>
          <span>
            <strong>MCP TrustMap</strong>
            <small>Administration autonome</small>
          </span>
        </Link>
        <div>
          <Link className="button secondary" href="/">
            Retour au tableau de bord
          </Link>
          <button className="button secondary" onClick={() => void signOut()}>
            Déconnexion
          </button>
        </div>
      </header>

      <div className="settings-content">
        <section className="settings-intro">
          <p className="eyebrow">PARAMÈTRES DE L’ESPACE</p>
          <h1>{organization?.name ?? "Organisation"}</h1>
          <p>
            {currentUser?.name} · {currentUser?.email} ·{" "}
            {roleLabel[activeRole]}
          </p>
        </section>

        {error ? <FormMessage>{error}</FormMessage> : null}
        {message ? <FormMessage tone="success">{message}</FormMessage> : null}

        <div className="settings-grid">
          <section className="settings-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">ÉQUIPE</span>
                <h2>Membres et rôles</h2>
              </div>
              <span className="count-badge">{members.length}</span>
            </div>
            <div className="member-list">
              {members.map((member) => (
                <article key={member.id}>
                  <span className="avatar">
                    {member.user.name.slice(0, 2).toUpperCase()}
                  </span>
                  <span>
                    <strong>{member.user.name}</strong>
                    <small>{member.user.email}</small>
                  </span>
                  {activeRole === "admin" &&
                  member.user.id !== currentUser?.id ? (
                    <select
                      aria-label={`Rôle de ${member.user.name}`}
                      disabled={pending}
                      onChange={(event) =>
                        void updateRole(
                          member.id,
                          event.target.value as TrustMapRole,
                        )
                      }
                      value={normalizeRole(member.role)}
                    >
                      <option value="admin">Admin</option>
                      <option value="auditor">Auditor</option>
                      <option value="reader">Reader</option>
                    </select>
                  ) : (
                    <span className="role-pill">
                      {roleLabel[normalizeRole(member.role)]}
                    </span>
                  )}
                </article>
              ))}
            </div>
          </section>

          <section className="settings-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">INVITATIONS</span>
                <h2>Ajouter un membre</h2>
              </div>
            </div>
            {activeRole === "admin" ? (
              <form className="auth-form compact-form" onSubmit={invite}>
                <label>
                  Adresse e-mail
                  <input
                    onChange={(event) => setInviteEmail(event.target.value)}
                    required
                    type="email"
                    value={inviteEmail}
                  />
                </label>
                <label>
                  Rôle
                  <select
                    onChange={(event) =>
                      setInviteRole(event.target.value as TrustMapRole)
                    }
                    value={inviteRole}
                  >
                    <option value="admin">Admin</option>
                    <option value="auditor">Auditor</option>
                    <option value="reader">Reader</option>
                  </select>
                </label>
                <button className="button primary" disabled={pending}>
                  Envoyer l’invitation
                </button>
              </form>
            ) : (
              <FormMessage tone="info">
                Seuls les administrateurs peuvent inviter des membres.
              </FormMessage>
            )}
            {invitations.length ? (
              <div className="pending-invitations">
                <h3>En attente</h3>
                {invitations.map((invitation) => (
                  <p key={invitation.id}>
                    <span>{invitation.email}</span>
                    <small>{roleLabel[normalizeRole(invitation.role)]}</small>
                  </p>
                ))}
              </div>
            ) : null}
          </section>

          <section className="settings-card mfa-card">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">COMPTE</span>
                <h2>Authentification multifacteur</h2>
              </div>
              <span
                className={`status-pill ${currentUser?.twoFactorEnabled ? "secure" : "attention"}`}
              >
                {currentUser?.twoFactorEnabled ? "Activée" : "À activer"}
              </span>
            </div>
            {mfaSetup ? (
              <div className="mfa-setup">
                <div className="mfa-qr">
                  <QRCode size={180} value={mfaSetup.totpURI} />
                </div>
                <form className="auth-form compact-form" onSubmit={verifyMfa}>
                  <label>
                    Code à six chiffres
                    <input
                      autoComplete="one-time-code"
                      inputMode="numeric"
                      maxLength={6}
                      onChange={(event) => setMfaCode(event.target.value)}
                      required
                      value={mfaCode}
                    />
                  </label>
                  <button className="button primary" disabled={pending}>
                    Confirmer l’activation
                  </button>
                </form>
                <div className="backup-codes">
                  <strong>Codes de secours — affichés une seule fois</strong>
                  <code>{mfaSetup.backupCodes.join("\n")}</code>
                </div>
              </div>
            ) : currentUser?.twoFactorEnabled ? (
              <form className="auth-form compact-form" onSubmit={disableMfa}>
                <p>
                  La connexion exige un code TOTP ou un code de secours après
                  le mot de passe.
                </p>
                <label>
                  Mot de passe actuel
                  <input
                    autoComplete="current-password"
                    minLength={12}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    type="password"
                    value={password}
                  />
                </label>
                <button className="button secondary" disabled={pending}>
                  Désactiver la MFA
                </button>
              </form>
            ) : (
              <form className="auth-form compact-form" onSubmit={enableMfa}>
                <p>
                  Compatible avec les applications TOTP courantes. Dix codes
                  de secours seront générés.
                </p>
                <label>
                  Mot de passe actuel
                  <input
                    autoComplete="current-password"
                    minLength={12}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    type="password"
                    value={password}
                  />
                </label>
                <button className="button primary" disabled={pending}>
                  Configurer la MFA
                </button>
              </form>
            )}
          </section>
        </div>
      </div>
    </main>
  );
}
