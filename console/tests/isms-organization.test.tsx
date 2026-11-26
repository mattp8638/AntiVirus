import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({
  useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {}, me: { tenants: [] } }),
}));
vi.mock("../src/api", () => ({
  fmtTime: (v: string) => v,
  api: async (path: string, options: any = {}) => {
    calls.push({ path, options });
    return responses[path] ?? { items: [] };
  },
}));
afterEach(() => { cleanup(); calls.length = 0; responses = {}; });

import { IsmsAssetsTab, IsmsOrganizationTab } from "../src/pages/grc/IsmsOrganization";

const manager = { role: "isms_manager", permissions: ["programme.manage"], canManageRoles: false };

test("people whose ISMS role cannot run the programme are told why", async () => {
  responses = { "isms/me": { role: "staff", permissions: ["documents.view"], canManageRoles: false } };
  render(<IsmsOrganizationTab />);
  await waitFor(() => expect(screen.getByText(/Your ISMS role in this customer \(staff\) cannot run the programme/)).toBeTruthy());
  expect(calls.some((c) => c.path === "isms/scope")).toBe(false);
});

test("the scope is saved with the customer", async () => {
  responses = { "isms/me": manager, "isms/scope": { statement: "", boundaries: "", interfaces: "", exclusions: "", version: 0 } };
  render(<IsmsOrganizationTab />);
  const statement = await screen.findByLabelText("Scope statement (required)");
  fireEvent.change(statement, { target: { value: "Managed IT services" } });
  fireEvent.click(screen.getByRole("button", { name: "Save scope" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/scope" && c.options.method === "PUT")?.options.body).toMatchObject(
    { tenantId: "ten_a", statement: "Managed IT services" }));
});

test("a context issue is added with yes and no turned into true and false", async () => {
  responses = { "isms/me": manager, "isms/scope": { statement: "x", boundaries: "", interfaces: "", exclusions: "", version: 1 } };
  render(<IsmsOrganizationTab />);
  fireEvent.click(await screen.findByRole("button", { name: "Add issue" }));
  fireEvent.change(screen.getByLabelText(/Internal or external/), { target: { value: "external" } });
  fireEvent.change(screen.getByLabelText(/^Issue/), { target: { value: "Flooding" } });
  fireEvent.change(screen.getByLabelText(/Climate related/), { target: { value: "yes" } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/registers/context-issues" && c.options.body)?.options.body).toEqual(
    { tenantId: "ten_a", kind: "external", description: "Flooding", climateRelated: true, impact: "" }));
});

test("a failed CSV import lists every problem and says nothing was imported", async () => {
  responses = { "isms/me": manager, "isms/assets": { items: [], types: ["system"], classifications: ["internal"], csvColumns: ["name", "type"] },
                "isms/members": { members: [] }, "isms/assets/import": { created: 0, updated: 0, errors: [{ line: 3, message: "Name is required." }] } };
  render(<IsmsAssetsTab />);
  fireEvent.click(await screen.findByRole("button", { name: "Import CSV" }));
  fireEvent.change(screen.getByLabelText("Or paste the CSV"), { target: { value: "name,type\n,system\n" } });
  fireEvent.click(screen.getByRole("button", { name: "Import" }));
  await waitFor(() => expect(screen.getByText("Line 3: Name is required.")).toBeTruthy());
  expect(screen.getByText("Nothing was imported.")).toBeTruthy();
});
