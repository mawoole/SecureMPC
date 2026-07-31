"use client";

import { createAuthClient } from "better-auth/react";
import {
  organizationClient,
  twoFactorClient,
} from "better-auth/client/plugins";
import {
  trustMapAccessControl,
  trustMapRoles,
} from "./permissions";

export const authClient = createAuthClient({
  plugins: [
    organizationClient({
      ac: trustMapAccessControl,
      roles: trustMapRoles,
    }),
    twoFactorClient({
      onTwoFactorRedirect() {
        window.location.href = "/two-factor";
      },
    }),
  ],
});
