import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({
  useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {} }),
}));
vi.mock("../src/api", () => ({
  fmtTime: (v: string) => v,
  api: async (path: string, options: any = {}) => {
    calls.push({ path, options });
    return responses[path] ?? {};
  },
}));
afterEach(() => { cleanup(); calls.length = 0; responses = {}; });

import { IsmsRolesTab } from "../src/pages/grc/IsmsRoles";

test("people without the right to manage roles only see their own role", async () => {
  responses = { "isms/me": { role: "control_owner", canManageRoles: false } };
  render(<IsmsRolesTab />);
  await waitFor(() => expect(screen.getByText("Control and risk owner")).toBeTruthy());
  expect(screen.queryByRole("button", { name: "Give someone a role" })).toBeNull();
  expect(calls.some((c) => c.path === "isms/memberships")).toBe(false);
});

test("managers list roles and a portal account can only be made staff", async () => {
  responses = {
    "isms/me": { role: null, canManageRoles: true },
    "isms/memberships": { memberships: [{ id: "m1", userId: "u1", email: "kim@acme.test", name: "Kim", role: "auditor", portal: false, expiresAt: "2027-01-31T23:59:59Z", grantedBy: "admin" }] },
    "isms/candidates": { people: [{ id: "u2", email: "jo@acme.test", name: "Jo", portal: true }] },
  };
  render(<IsmsRolesTab />);
  await waitFor(() => expect(screen.getByText("Auditor (read-only, time-limited)")).toBeTruthy());
  fireEvent.click(screen.getByRole("button", { name: "Give someone a role" }));
  await waitFor(() => expect(screen.getByRole("option", { name: "Jo (jo@acme.test), portal" })).toBeTruthy());
  fireEvent.change(screen.getByLabelText("Person"), { target: { value: "u2" } });
  const roles = screen.getByLabelText("ISMS role") as HTMLSelectElement;
  expect([...roles.options].map((o) => o.value)).toEqual(["staff"]);
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls.find((c) => c.options.method === "PUT")?.options.body).toEqual(
    { tenantId: "ten_a", userId: "u2", role: "staff", expiresAt: null }));
});
