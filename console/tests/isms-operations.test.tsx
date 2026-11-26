import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({ useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {}, me: { tenants: [] } }) }));
vi.mock("../src/api", () => ({
  fmtTime: (v: string) => v,
  api: async (path: string, options: any = {}) => { calls.push({ path, options }); return responses[path] ?? {}; },
}));
afterEach(() => { cleanup(); calls.length = 0; responses = {}; });

import { IsmsOperationsTab } from "../src/pages/grc/IsmsOperations";

const incident = { id: "i1", title: "Phishing led to mailbox access", severity: "high", socStatus: "investigating", detectedAt: "2026-11-20T09:00:00.000Z", assignee: "",
  reviewId: "r1", category: "phishing", personalData: true, reportedToAuthorityAt: null, breachDeadline: "2026-11-23T09:00:00.000Z", vendorId: null, vendorName: null,
  rootCause: "", lessonsLearned: "", controls: [], status: "open", completedAt: null, blockers: ["Record the root cause."] };

test("the review explains the 72 hour deadline and why it cannot be completed yet", async () => {
  responses = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["controls.view", "programme.manage"] },
    "isms/incidents": { incidents: [incident], categories: ["phishing", "other"], canManage: true }, "isms/controls": { controls: [] }, "isms/suppliers": { suppliers: [] } };
  render(<IsmsOperationsTab />);
  fireEvent.click(await screen.findByText("Phishing led to mailbox access"));
  expect(screen.getByText(/regulator must be told by 2026-11-23T09:00:00.000Z/)).toBeTruthy();
  expect(screen.getByText(/Record the root cause\. The SOC must resolve the incident\./)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Complete review" }) as HTMLButtonElement).disabled).toBe(true);
});
