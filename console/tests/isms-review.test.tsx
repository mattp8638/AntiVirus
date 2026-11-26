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

import { IsmsReviewTab } from "../src/pages/grc/IsmsReview";

const inputs = [{ key: "nonconformities", clause: "9.3.2 d", title: "Nonconformities and corrective actions" }, { key: "opportunities", clause: "9.3.2 g", title: "Opportunities for continual improvement" }];
const pack = { builtAt: "2026-11-26T10:00:00.000Z", periodStart: "2025-11-26", periodEnd: "2026-11-26", inputs: {
  previous_actions: { open: 0, done: 0, items: [] }, issue_changes: { current: 0, changes: [] }, party_changes: { current: 0, changes: [] },
  nonconformities: { raised: 2, closed: 1, open: 1, majorOpen: 1, overdue: 0, items: [] }, monitoring: { readiness: [], objectives: [] },
  audits: { completed: [], planned: 0, coverage: [] }, objectives: { met: 0, notMet: 0, noData: 0, achieved: 0, dropped: 0 },
  party_feedback: { notes: "", complaints: [] }, risk: { total: 0, aboveAppetite: 0, awaitingAcceptance: 0, accepted: 0, reviewOverdue: 0, lastSnapshot: null, top: [] },
  opportunities: { open: [{ ref: "OFI-001", title: "Automate reviews" }] } } };
const review = { id: "r1", ref: "MR-001", title: "Annual review", plannedOn: "2026-12-01", periodStart: "2025-12-01", status: "draft", pack, packBuiltAt: pack.builtAt,
  missing: [], interestedPartyFeedback: "", actions: [] };

test("the pack shows each input with its clause, and recording needs minutes and decisions", async () => {
  responses = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["controls.view", "programme.manage"] },
    "isms/reviews": { reviews: [review], inputs, canManage: true }, "isms/members": { members: [] } };
  render(<IsmsReviewTab />);
  expect(await screen.findByText("Planned 01/12/2026")).toBeTruthy();
  fireEvent.click(screen.getByText("Annual review"));
  expect(screen.getByText("(9.3.2 g)")).toBeTruthy();
  expect(screen.getByText(/2 raised and 1 closed in the period; 1 open \(1 major\)/)).toBeTruthy();
  expect(screen.getByText("OFI-001 Automate reviews")).toBeTruthy();
  const record = screen.getByRole("button", { name: "Record and freeze" }) as HTMLButtonElement;
  fireEvent.change(screen.getByLabelText("Held on"), { target: { value: "2026-11-25" } });
  fireEvent.change(screen.getByLabelText("Attendees"), { target: { value: "Kim, Sam" } });
  fireEvent.change(screen.getByLabelText("Minutes"), { target: { value: "We met." } });
  expect(record.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("Decisions on improvement"), { target: { value: "Fund MFA." } });
  fireEvent.click(record);
  await waitFor(() => expect(calls.find((c) => c.path === "isms/reviews/r1/held")!.options.body).toEqual({ heldOn: "2026-11-25", chairId: null, attendees: "Kim, Sam", minutes: "We met.", decisions: "Fund MFA.", changesNeeded: "" }));
});
