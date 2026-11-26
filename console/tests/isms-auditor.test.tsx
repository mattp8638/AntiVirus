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

import { IsmsAuditorTab } from "../src/pages/grc/IsmsAuditor";

const request = { id: "q1", controlId: "c1", controlRef: "CC-BKP-01", controlOwnerId: "u2", request: "Last restore test", dueOn: "2027-01-10", status: "open", response: "", evidenceId: null, requestedByName: "Ada" };

test("auditors are told their views are logged, and draw samples with a size", async () => {
  responses = { "isms/me": { userId: "u9", role: "auditor", permissions: ["controls.view", "findings.log"] },
    "isms/auditor": { samples: [], requests: [request], populations: [{ key: "controls", label: "Applicable controls" }], canAudit: true, canManage: false, role: "auditor" } };
  render(<IsmsAuditorTab />);
  expect(await screen.findByText(/Every page you open here is recorded in the audit log/)).toBeTruthy();
  expect(screen.getByText("10/01/2027")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Answer" })).toBeNull();  // auditors do not answer
  fireEvent.click(screen.getByText("Draw a sample"));
  fireEvent.change(screen.getByLabelText("Seed (blank uses the current time)"), { target: { value: "AUD-001" } });
  fireEvent.click(screen.getByRole("button", { name: "Draw" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/auditor/samples")!.options.body).toEqual({ tenantId: "ten_a", population: "controls", size: 10, seed: "AUD-001", note: "" }));
});

test("the control owner answers a request", async () => {
  responses = { "isms/me": { userId: "u2", role: "control_owner", permissions: ["controls.view", "evidence.upload"] },
    "isms/auditor": { samples: [], requests: [request], populations: [], canAudit: false, canManage: false, role: "control_owner" }, "isms/evidence": { evidence: [] } };
  render(<IsmsAuditorTab />);
  fireEvent.click(await screen.findByRole("button", { name: "Answer" }));
  fireEvent.change(screen.getByLabelText("Answer"), { target: { value: "Restored a file on 02/11" } });
  fireEvent.click(screen.getByRole("button", { name: "Send answer" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/auditor/requests/q1/answer")!.options.body).toEqual({ response: "Restored a file on 02/11", evidenceId: null }));
});
