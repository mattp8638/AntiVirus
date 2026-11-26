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

import { IsmsPeopleTab } from "../src/pages/grc/IsmsPeople";

const pending = { id: "c1", tenantId: "ten_a", documentNumber: "ACM-POL-001", documentTitle: "Information security policy", version: 2, dueOn: "2026-12-10", overdue: false };

test("a person reads a document and must tick before acknowledging; the hash of what was shown is sent", async () => {
  responses = { "isms/me": { userId: "u1", role: "staff", permissions: ["documents.view", "documents.acknowledge", "tasks.complete"] },
    "isms/acknowledgements/mine": { pending: [pending] }, "isms/acknowledgements/campaigns": { campaigns: [], canManage: false },
    "isms/acknowledgements/c1/read": { id: "c1", documentNumber: "ACM-POL-001", documentTitle: "Information security policy", version: 2, dueOn: "2026-12-10",
      sha256: "abc", acknowledgedAt: null, blocks: [{ ref: "isp.purpose", markdown: "We protect information." }] } };
  render(<IsmsPeopleTab />);
  expect(screen.queryByRole("option", { name: "Roles and RACI" })).toBeNull();  // staff cannot see the RACI
  fireEvent.click(await screen.findByText("ACM-POL-001 Information security policy (version 2)"));
  expect(await screen.findByText("We protect information.")).toBeTruthy();
  const ack = screen.getByRole("button", { name: "Acknowledge" }) as HTMLButtonElement;
  expect(ack.disabled).toBe(true);
  fireEvent.click(screen.getByLabelText("I have read and understood this document"));
  fireEvent.click(ack);
  await waitFor(() => expect(calls.find((c) => c.path === "isms/acknowledgements/c1/acknowledge")!.options.body).toEqual({ sha256: "abc", confirm: true }));
});

test("the RACI matrix shows issues and saves a whole row", async () => {
  responses = { "isms/me": { userId: "u1", role: "isms_manager", permissions: ["documents.acknowledge", "controls.view", "programme.manage"] },
    "isms/acknowledgements/mine": { pending: [] }, "isms/acknowledgements/campaigns": { campaigns: [], canManage: true, candidates: [], byUser: [], roles: [] },
    "isms/people": { canManage: true, roles: [{ id: "r1", name: "Security lead", holders: [], responsibilities: "" }, { id: "r2", name: "Board", holders: [], responsibilities: "" }], competence: [],
      raci: { activities: [{ id: "a1", title: "Risk assessment" }], roles: [{ id: "r1", name: "Security lead" }, { id: "r2", name: "Board" }],
        cells: [{ activityId: "a1", roleId: "r1", letter: "R" }], issues: [{ activityId: "a1", problem: "no_accountable", text: "No role is accountable." }] } } };
  render(<IsmsPeopleTab />);
  fireEvent.change(await screen.findByLabelText("Show"), { target: { value: "roles" } });
  expect(await screen.findByText("No role is accountable.")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Risk assessment, Board"), { target: { value: "A" } });
  await waitFor(() => expect(calls.find((c) => c.path === "isms/raci/activities/a1")!.options).toEqual({ method: "PUT", body: { letters: { r1: "R", r2: "A" } } }));
});
