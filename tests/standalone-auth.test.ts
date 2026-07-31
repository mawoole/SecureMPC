import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeTrustMapRole,
  trustMapRoles,
} from "../lib/auth/permissions.ts";

test("normalizes organization memberships to the three supported roles", () => {
  assert.equal(normalizeTrustMapRole("admin"), "admin");
  assert.equal(normalizeTrustMapRole("auditor"), "auditor");
  assert.equal(normalizeTrustMapRole("reader"), "reader");
  assert.equal(normalizeTrustMapRole("reader,auditor"), "auditor");
  assert.equal(normalizeTrustMapRole("auditor,admin"), "admin");
  assert.equal(normalizeTrustMapRole("unknown"), "reader");
  assert.equal(normalizeTrustMapRole(null), "reader");
});

test("exposes only the product roles to the organization plugin", () => {
  assert.deepEqual(Object.keys(trustMapRoles).sort(), [
    "admin",
    "auditor",
    "reader",
  ]);
});
