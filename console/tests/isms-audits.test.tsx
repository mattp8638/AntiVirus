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

import { IsmsAuditsTab } from "../src/pages/grc/IsmsAudits";

const programme = { id: "p1", title: "Audit programme 2027", periodStart: "2027-01-01", periodEnd: "2027-12-31", objectives: "",
  coverage: { required: 120, covered: 30, percent: 25, missing: [] },
  audits: [{ id: "a1", ref: "AUD-001", title: "People controls", status: "in_progress", plannedStart: "2027-03-01", plannedEnd: "2027-03-03", leadAuditorName: "Ada", checks: 2, findings: 0 }] };
const audit = { id: "a1", ref: "AUD-001", title: "People controls", status: "in_progress", frameworks: ["iso27001"], plannedStart: "2027-03-01", plannedEnd: "2027-03-03",
  leadAuditorName: "Ada", otherAuditors: "", independenceNote: "External", scope: "", summary: "",
  checks: [{ id: "k1", framework: "iso27001", ref: "A.6.3", title: "Awareness and training", groupTitle: "People controls", mandatory: false, controls: "CC-HR-02", result: null, notes: "", evidenceSeen: "", findings: [] }],
  counts: { conforms: 0, observation: 0, minor: 0, major: 0, notAssessed: 0, open: 1 }, blockers: ["Record a result for every checklist item (1 left)."] };

test("programmes show coverage and DD/MM/YYYY dates, and auditors record results with what was found", async () => {
  responses = { "isms/me": { userId: "u9", role: "auditor", permissions: ["controls.view", "findings.log"] },
    "isms/audit-programmes": { programmes: [programme], groups: [], frameworks: ["iso27001"], canPlan: false, canAudit: true },
    "isms/audits/a1": audit };
  render(<IsmsAuditsTab />);
  expect(await screen.findByText("Coverage 30 of 120 (25%)")).toBeTruthy();
  expect(screen.getByText("01/03/2027 to 03/03/2027")).toBeTruthy();
  expect(screen.queryByText("Add programme")).toBeNull();
  fireEvent.click(screen.getByText("People controls"));
  fireEvent.click(await screen.findByText("Awareness and training"));
  fireEvent.change(screen.getByLabelText("Result"), { target: { value: "minor" } });
  const save = screen.getByRole("button", { name: "Save result" }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);  // a finding needs a description
  fireEvent.change(screen.getByLabelText("What was found"), { target: { value: "No training record for two starters" } });
  fireEvent.click(save);
  await waitFor(() => expect(calls.find((c) => c.path === "isms/audit-checks/k1")!.options).toEqual({ method: "PUT", body: { result: "minor", notes: "No training record for two starters", evidenceSeen: "" } }));
});

test("the sampler sends the population line by line with the seed", async () => {
  responses = { "isms/me": { userId: "u9", role: "auditor", permissions: ["controls.view", "findings.log"] },
    "isms/audit-programmes": { programmes: [], groups: [], frameworks: [], canPlan: false, canAudit: true },
    "isms/audit-sample": { population: 2, size: 2, suggested: 2, seed: "s", items: ["b", "a"] } };
  render(<IsmsAuditsTab />);
  fireEvent.click(await screen.findByText("Draw a sample"));
  fireEvent.change(screen.getByLabelText("Population, one item per line"), { target: { value: "a\nb" } });
  fireEvent.change(screen.getByLabelText("Seed"), { target: { value: "s" } });
  fireEvent.click(screen.getByRole("button", { name: "Draw" }));
  await screen.findByText(/2 of 2/);
  expect(calls.find((c) => c.path === "isms/audit-sample")!.options.body).toEqual({ tenantId: "ten_a", population: ["a", "b"], seed: "s", size: null });
});
