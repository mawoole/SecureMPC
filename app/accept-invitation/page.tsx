"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
} from "../auth-ui";

export default function AcceptInvitationPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const session = authClient.useSession();
  const [message, setMessage] = useState("Validation de l’invitation…");
  const [error, setError] = useState("");
  const invitationId = searchParams.get("invitationId");

  useEffect(() => {
    if (session.isPending || !invitationId) return;
    if (!session.data) {
      const returnTo = encodeURIComponent(
        `/accept-invitation?invitationId=${encodeURIComponent(invitationId)}`,
      );
      router.replace(`/login?returnTo=${returnTo}`);
      return;
    }

    void (async () => {
      const invitation = await authClient.organization.getInvitation({
        query: { id: invitationId },
      });
      if (invitation.error || !invitation.data) {
        setError(authErrorMessage(invitation.error));
        return;
      }
      const result = await authClient.organization.acceptInvitation({
        invitationId,
      });
      if (result.error) {
        setError(authErrorMessage(result.error));
        return;
      }
      await authClient.organization.setActive({
        organizationId: invitation.data.organizationId,
      });
      setMessage("Invitation acceptée. Ouverture de votre espace…");
      router.replace("/");
    })();
  }, [invitationId, router, session.data, session.isPending]);

  const displayedError = invitationId
    ? error
    : "Cette invitation est absente ou invalide.";

  return (
    <AuthLayout eyebrow="INVITATION" title="Rejoindre l’organisation">
      {displayedError ? (
        <>
          <FormMessage>{displayedError}</FormMessage>
          <Link className="button secondary auth-submit" href="/onboarding">
            Voir mes espaces
          </Link>
        </>
      ) : (
        <FormMessage tone="info">{message}</FormMessage>
      )}
    </AuthLayout>
  );
}
