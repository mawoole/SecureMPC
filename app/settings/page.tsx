import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth } from "../../lib/auth/server";
import { SettingsClient } from "./settings-client";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/login?returnTo=%2Fsettings");
  if (!session.session.activeOrganizationId) redirect("/onboarding");
  return <SettingsClient />;
}
