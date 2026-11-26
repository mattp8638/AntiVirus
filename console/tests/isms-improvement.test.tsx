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

import { IsmsImprovementTab } from "../src/pages/grc/IsmsImprovement";

const nc = { id: "n1", ref: "NC-001", kind: "nonconformity", title: "Log reviews missed", source: "internal_audit", severity: "minor", requirementRef: "8.15",
  raisedOn: "2026-11-02", ownerId: "u1", ownerName: "Kim", dueOn: "2026-12-01", status: "open", stage: "actions_in_progress", stageText: "Actions in progress",
  overdue: false, rootCause: "No owner", blockers: ["Finish every corrective action."],
  actions: [{ id: "a1", description: "Give Kim the weekly review", ownerId: "u2", ownerName: "Sam", dueOn: "2026-11-30", done: false, overdue: false }] };

test("an action owner can mark their action done, and the effectiveness check waits for it", async () => {
  responses = { "isms/me": { userId: "u2", role: "control_owner", permissions: ["controls.view", "tasks.complete"] }, "isms/nonconformities": { nonconformities: [nc], sources: [] } };
  render(<IsmsImprovementTab />);
  fireEvent.click(await screen.findByText("Log reviews missed"));
  expect(screen.queryByText("Effective, close it")).toBeNull();  // not a manager
  fireEvent.change(screen.getByLabelText("What was done"), { target: { value: "Added to rota" } });
  fireEvent.click(screen.getByRole("button", { name: "Mark done" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/corrective-actions/a1/done")!.options.body).toEqual({ note: "Added to rota" }));
});

test("managers see why the effectiveness check is blocked", async () => {
  responses = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["controls.view", "programme.manage", "tasks.complete"] }, "isms/nonconformities": { nonconformities: [nc], sources: [] } };
  render(<IsmsImprovementTab />);
  fireEvent.click(await screen.findByText("Log reviews missed"));
  expect(screen.getByText(/Finish every corrective action/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText("How you checked it worked"), { target: { value: "Sampled" } });
  expect((screen.getByRole("button", { name: "Effective, close it" }) as HTMLButtonElement).disabled).toBe(true);
});

test("objectives show health, trend and DD/MM/YYYY dates", async () => {
  responses = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["controls.view", "programme.manage"] },
    "isms/objectives": { objectives: [{ id: "o1", ref: "OBJ-001", title: "Patch quickly", measure: "Median days", unit: "days", direction: "at_most", target: 14,
      ownerId: "u1", ownerName: "Kim", frequency: "monthly", status: "active", values: [{ id: "v1", measuredOn: "2026-11-01", value: 9 }],
      summary: { latest: { measuredOn: "2026-11-01", value: 9 }, health: "met", trend: "improving", stale: false } }] } };
  render(<IsmsImprovementTab />);
  fireEvent.change(await screen.findByLabelText("Show"), { target: { value: "objectives" } });
  expect(await screen.findByText("9 days (01/11/2026)")).toBeTruthy();
  expect(screen.getByText("on target")).toBeTruthy();
  expect(screen.getByText(/improving/)).toBeTruthy();
});
