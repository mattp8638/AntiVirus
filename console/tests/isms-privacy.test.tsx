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

import { IsmsPrivacyTab } from "../src/pages/grc/IsmsPrivacy";

const base = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["controls.view", "programme.manage", "documents.approve"] } };
const options = { lawfulBases: [{ key: "contract", label: "Contract (article 6(1)(b))" }], safeguards: [], roles: ["controller"], requestTypes: [{ key: "access", label: "Access (subject access request)" }],
  screening: [{ key: "vulnerable", strong: false, text: "People who may be vulnerable are affected" }] };

test("records show what to fix, and requests show the deadline in DD/MM/YYYY", async () => {
  responses = { ...base, "isms/privacy": { canManage: true, canApprove: true, options, summary: { activities: 1, withGaps: 1, dpiasNeeded: 1, openRequests: 1, overdueRequests: 0, dueThisWeek: 0 }, dpias: [],
    processing: [{ id: "p1", ref: "ROPA-001", name: "Payroll", role: "controller", lawfulBasis: "contract", status: "active", gaps: ["Record how long the data is kept."], dpias: [], dpiaRequired: true, nextReviewOn: "2027-11-26", reviewOverdue: false }],
    requests: [{ id: "r1", ref: "DSR-001", type: "access", typeLabel: "Access (subject access request)", requester: "J Smith", dueOn: "2026-12-26", daysLeft: 30, overdue: false, status: "open", receivedOn: "2026-11-26" }] } };
  render(<IsmsPrivacyTab />);
  expect(await screen.findByText("Record how long the data is kept.")).toBeTruthy();
  expect(screen.getByText("needed")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Start DPIA" }));
  await waitFor(() => expect(calls.some((c) => c.path === "isms/privacy/processing/p1/dpia")).toBe(true));
  fireEvent.change(screen.getByLabelText("Show"), { target: { value: "requests" } });
  expect(await screen.findByText("26/12/2026")).toBeTruthy();
  fireEvent.click(screen.getByText("J Smith"));
  fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "refused" } });
  expect(screen.getByLabelText("Reason, and that they were told of their right to complain")).toBeTruthy();
});
