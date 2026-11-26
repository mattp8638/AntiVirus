import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({ useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {}, me: { tenants: [] } }) }));
vi.mock("../src/api", () => ({
  fmtTime: (v: string) => v,
  api: async (path: string, options: any = {}) => { calls.push({ path, options }); return responses[path] ?? {}; },
}));
afterEach(() => { cleanup(); calls.length = 0; responses = {}; });

import { IsmsCustomControlsTab, IsmsPortfolioTab } from "../src/pages/grc/IsmsCustom";

test("a custom control is linked to requirements found by ref", async () => {
  responses = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["controls.view", "programme.manage"] },
    "isms/custom-controls": { controls: [], frequencies: ["monthly"], canManage: true,
      requirements: [{ key: "iso27001:A.7.7", framework: "iso27001", frameworkName: "ISO/IEC 27001:2022", ref: "A.7.7", title: "Clear desk and clear screen" },
                     { key: "iso27001:A.5.1", framework: "iso27001", frameworkName: "ISO/IEC 27001:2022", ref: "A.5.1", title: "Policies for information security" }] } };
  render(<IsmsCustomControlsTab />);
  fireEvent.click(await screen.findByText("Add control"));
  fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Clean desk walk-round" } });
  fireEvent.change(screen.getByLabelText("What it requires"), { target: { value: "Monthly check" } });
  fireEvent.change(screen.getByLabelText("Find"), { target: { value: "A.7" } });
  expect(screen.queryByText(/A.5.1/)).toBeNull();
  fireEvent.click(screen.getByLabelText(/A.7.7 Clear desk/));
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/custom-controls" && c.options.body)!.options.body.requirementKeys).toEqual(["iso27001:A.7.7"]));
});

test("the portfolio shows each customer's headline figures", async () => {
  responses = { "isms/portfolio": { customers: [{ tenantId: "t1", name: "Acme Dental", role: "isms_manager", canManage: true, framework: "ISO/IEC 27001:2022", readiness: 42,
    overdueTasks: 3, openNonconformities: 1, risksAboveAppetite: 2, documentsDueForReview: 0, openEvidenceRequests: 0, nextAudit: { ref: "AUD-001", plannedStart: "2027-03-01" } }] } };
  render(<IsmsPortfolioTab />);
  expect(await screen.findByText("42% (ISO/IEC 27001:2022)")).toBeTruthy();
  expect(screen.getByText("AUD-001 01/03/2027")).toBeTruthy();
});
