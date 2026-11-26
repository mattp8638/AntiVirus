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

import { IsmsDashboardTab } from "../src/pages/grc/IsmsDashboard";

test("tiles show their status in words, open their tab, and the layout and digest save", async () => {
  responses = { "isms/dashboard": { layout: ["tasks"], digest: null,
    tiles: [{ id: "tasks", title: "Tasks", value: "2 overdue tasks", detail: "1 due this week, 5 open", status: "problem", tab: "ISMS tasks" }],
    available: [{ id: "tasks", title: "Tasks", description: "Overdue tasks" }, { id: "risks", title: "Risks", description: "Above appetite" }] } };
  const open = vi.fn();
  render(<IsmsDashboardTab onOpenTab={open} />);
  expect(await screen.findByText("Action needed")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Open ISMS tasks" }));
  expect(open).toHaveBeenCalledWith("ISMS tasks");
  fireEvent.click(screen.getByText("Choose tiles and email"));
  fireEvent.click(screen.getByLabelText(/Risks: Above appetite/));
  fireEvent.click(screen.getByRole("button", { name: "Move Risks up" }));
  fireEvent.change(screen.getByLabelText("Email me these figures"), { target: { value: "weekly" } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/dashboard/digest")!.options.body).toEqual({ tenantId: "ten_a", frequency: "weekly", enabled: true }));
  expect(calls.find((c) => c.path === "isms/dashboard/layout")!.options.body.tiles).toEqual(["risks", "tasks"]);
});
