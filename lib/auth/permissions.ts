import { createAccessControl } from "better-auth/plugins/access";
import {
  adminAc,
  defaultStatements,
  memberAc,
} from "better-auth/plugins/organization/access";

const statements = {
  ...defaultStatements,
  trustmap: ["read", "audit", "approve", "admin"],
} as const;

export const trustMapAccessControl = createAccessControl(statements);

export const adminRole = trustMapAccessControl.newRole({
  ...adminAc.statements,
  trustmap: ["read", "audit", "approve", "admin"],
});

export const auditorRole = trustMapAccessControl.newRole({
  ...memberAc.statements,
  trustmap: ["read", "audit", "approve"],
});

export const readerRole = trustMapAccessControl.newRole({
  ...memberAc.statements,
  trustmap: ["read"],
});

export const trustMapRoles = {
  admin: adminRole,
  auditor: auditorRole,
  reader: readerRole,
};

export type TrustMapRole = keyof typeof trustMapRoles;

export function normalizeTrustMapRole(
  value: string | null | undefined,
): TrustMapRole {
  const roles = (value ?? "")
    .split(",")
    .map((role) => role.trim().toLowerCase())
    .filter(Boolean);
  if (roles.includes("admin")) return "admin";
  if (roles.includes("auditor")) return "auditor";
  return "reader";
}
