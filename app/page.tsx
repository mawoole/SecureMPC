import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getD1 } from "../db";
import { auth, getAuthContext } from "../lib/auth/server";
import Dashboard from "./dashboard";

export const dynamic = "force-dynamic";

export default async function Home() {
  const requestHeaders = await headers();
  const session = await auth.api.getSession({ headers: requestHeaders });
  if (!session) redirect("/login");
  if (!session.session.activeOrganizationId) redirect("/onboarding");
  const actor = await getAuthContext(requestHeaders);
  if (!actor) redirect("/onboarding");

  const organization = await getD1()
    .prepare("SELECT name FROM organization WHERE id = ? LIMIT 1")
    .bind(actor.organizationId)
    .first<{ name: string }>();
  if (!organization) redirect("/onboarding");

  return (
    <Dashboard
      identity={{
        displayName: actor.displayName,
        email: actor.email,
        organizationName: organization.name,
        role: actor.role,
      }}
    />
  );
}
