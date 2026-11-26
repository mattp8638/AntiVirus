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

import { IsmsTasksTab } from "../src/pages/grc/IsmsTasks";

const check = { id: "t1", kind: "operate", title: "Check CC-BKP-01: Backups", controlId: "c1", controlRef: "CC-BKP-01", assigneeId: "u1", assigneeName: "Kim",
                dueOn: "2026-11-20", recurrence: "monthly", status: "open", urgency: "overdue" };
const plan = { ...check, id: "t2", kind: "implement", title: "Put CC-MAL-01 in place", controlRef: "CC-MAL-01", dueOn: "2026-12-03", urgency: "later" };

test("dates are DD/MM/YYYY, overdue is written out, and a check is completed with what was checked", async () => {
  responses = { "isms/me": { userId: "u1", role: "control_owner", permissions: ["tasks.complete", "controls.view"] },
                "isms/tasks": { tasks: [check, plan], ownOnly: true }, "isms/evidence": { evidence: [] } };
  render(<IsmsTasksTab />);
  await screen.findByText("20/11/2026");
  expect(screen.getByText("overdue")).toBeTruthy();
  fireEvent.click(screen.getByText("Check CC-BKP-01: Backups"));
  const done = screen.getByRole("button", { name: "Mark as done" }) as HTMLButtonElement;
  expect(done.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("What was checked"), { target: { value: "Restored a sample file" } });
  fireEvent.click(done);
  await waitFor(() => expect(calls.find((c) => c.path === "isms/tasks/t1/complete")!.options.body).toEqual({ note: "Restored a sample file", evidenceId: null }));
});

test("the calendar shows tasks on their due day, Monday first", async () => {
  responses = { "isms/me": { userId: "u1", role: "control_owner", permissions: ["tasks.complete"] }, "isms/tasks": { tasks: [check, plan], ownOnly: true } };
  render(<IsmsTasksTab />);
  await screen.findByText("20/11/2026");
  fireEvent.change(screen.getByLabelText("View"), { target: { value: "calendar" } });
  const table = screen.getByRole("table", { name: "Tasks due in November 2026" });
  expect(table.querySelector("th")!.textContent).toBe("Mon");
  expect(screen.getByRole("button", { name: "CC-BKP-01 (overdue)" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Next month" }));
  expect(screen.getByRole("button", { name: "CC-MAL-01" })).toBeTruthy();
});
