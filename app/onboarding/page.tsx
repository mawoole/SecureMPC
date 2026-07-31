"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
} from "../auth-ui";

type OrganizationSummary = {
  id: string;
  name: string;
  slug: string;
};

type InvitationSummary = {
  id: string;
  email: string;
  organizationId: string;
  role: string;
  organizationName?: string;
};

function slugify(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
}

export default function OnboardingPage() {
  const router = useRouter();
  const session = authClient.useSession();
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [invitations, setInvitations] = useState<InvitationSummary[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const [loading, setLoading] = useState(true);

  async function refresh() {
    setLoading(true);
    const [organizationResult, invitationResult] = await Promise.all([
      authClient.organization.list(),
      authClient.organization.listUserInvitations(),
    ]);
    if (organizationResult.data) {
      setOrganizations(
        organizationResult.data as unknown as OrganizationSummary[],
      );
    }
    if (invitationResult.data) {
      setInvitations(
        invitationResult.data as unknown as InvitationSummary[],
      );
    }
    setLoading(false);
  }

  useEffect(() => {
    if (session.isPending) return;
    if (!session.data) {
      const returnTo = encodeURIComponent(
        `${window.location.pathname}${window.location.search}`,
      );
      router.replace(`/login?returnTo=${returnTo}`);
      return;
    }
    const timer = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timer);
  }, [router, session.data, session.isPending]);

  async function activate(organizationId: string) {
    setPending(true);
    setError("");
    const result = await authClient.organization.setActive({ organizationId });
    if (result.error) {
      setError(authErrorMessage(result.error));
      setPending(false);
      return;
    }
    router.replace("/");
  }

  async function accept(invitation: InvitationSummary) {
    setPending(true);
    setError("");
    const result = await authClient.organization.acceptInvitation({
      invitationId: invitation.id,
    });
    if (result.error) {
      setError(authErrorMessage(result.error));
      setPending(false);
      return;
    }
    await activate(invitation.organizationId);
  }

  async function createOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    const cleanSlug = slugify(slug || name);
    if (cleanSlug.length < 3) {
      setError("Choisissez un identifiant d’organisation d’au moins 3 caractères.");
      setPending(false);
      return;
    }
    try {
      const result = await authClient.organization.create({
        name: name.trim(),
        slug: cleanSlug,
      });
      if (result.error || !result.data) {
        setError(authErrorMessage(result.error));
        return;
      }
      await activate(result.data.id);
    } catch (caught) {
      setError(authErrorMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthLayout eyebrow="ORGANISATION ACTIVE" title="Choisir votre espace">
      {loading ? <FormMessage tone="info">Chargement des espaces…</FormMessage> : null}
      {invitations.length ? (
        <section className="onboarding-block">
          <h3>Invitations reçues</h3>
          <div className="organization-list">
            {invitations.map((invitation) => (
              <article key={invitation.id}>
                <span>
                  <strong>
                    {invitation.organizationName ?? "Organisation invitante"}
                  </strong>
                  <small>Rôle proposé : {invitation.role}</small>
                </span>
                <button
                  className="button secondary compact"
                  disabled={pending}
                  onClick={() => void accept(invitation)}
                >
                  Accepter
                </button>
              </article>
            ))}
          </div>
        </section>
      ) : null}
      {organizations.length ? (
        <section className="onboarding-block">
          <h3>Vos organisations</h3>
          <div className="organization-list">
            {organizations.map((organization) => (
              <article key={organization.id}>
                <span>
                  <strong>{organization.name}</strong>
                  <small>{organization.slug}</small>
                </span>
                <button
                  className="button secondary compact"
                  disabled={pending}
                  onClick={() => void activate(organization.id)}
                >
                  Ouvrir
                </button>
              </article>
            ))}
          </div>
        </section>
      ) : null}
      <section className="onboarding-block">
        <h3>Créer une organisation cliente</h3>
        <form className="auth-form" onSubmit={createOrganization}>
          <label>
            Nom de l’organisation
            <input
              maxLength={100}
              onChange={(event) => {
                setName(event.target.value);
                if (!slug) setSlug(slugify(event.target.value));
              }}
              placeholder="Ex. YouSteed"
              required
              value={name}
            />
          </label>
          <label>
            Identifiant
            <input
              maxLength={48}
              onChange={(event) => setSlug(slugify(event.target.value))}
              pattern="[a-z0-9-]{3,48}"
              placeholder="yousteed"
              required
              value={slug}
            />
          </label>
          {error ? <FormMessage>{error}</FormMessage> : null}
          <button className="button primary auth-submit" disabled={pending}>
            {pending ? "Configuration…" : "Créer et ouvrir"}
          </button>
        </form>
      </section>
    </AuthLayout>
  );
}
