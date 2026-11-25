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

import { IsmsRiskTab } from "../src/pages/grc/IsmsRisk";

const method = { likelihoodScale: [1, 2, 3, 4, 5].map((v) => ({ value: v, label: `L${v}`, description: "" })),
                 impactScale: [1, 2, 3, 4, 5].map((v) => ({ value: v, label: `I${v}`, description: "" })),
                 levels: [], appetite: 8, maxScore: 25, reviewMonths: 12, acceptanceCriteria: "x", version: 0 };
const risk = { id: "r1", ref: "R-001", title: "Phishing", assetIds: [], assetNames: [], ownerId: "u1", ownerName: "Kim", inherentScore: 20, inherentLevel: "Critical",
               residualScore: null, residualLevel: null, withinAppetite: false, status: "treatment_planned", reviewOverdue: false, treatment: "retain" };

test("levels are written out, not shown by colour alone, and only the owner is offered acceptance", async () => {
  responses = { "isms/me": { userId: "u1", role: "control_owner", permissions: ["risks.view"] }, "isms/risk/method": method,
                "isms/risks": { risks: [risk], treatments: ["modify", "retain"], heatMap: { grid: [[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,1],[0,0,0,0,0]], unrated: 0, likelihood: ["L1","L2","L3","L4","L5"], impact: ["I1","I2","I3","I4","I5"] } } };
  render(<IsmsRiskTab />);
  await screen.findByText("20 Critical");
  expect(screen.getByText("Above")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Add risk" })).toBeNull();
  expect(screen.getByRole("table", { name: /heat map/ })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Accept" }));
  const accept = screen.getByRole("button", { name: "Accept the residual risk" }) as HTMLButtonElement;
  fireEvent.change(screen.getByLabelText("Rationale"), { target: { value: "Too short" } });
  expect(accept.disabled).toBe(true);  // above appetite: at least 40 characters
  fireEvent.change(screen.getByLabelText("Rationale"), { target: { value: "Training and filtering in place; accepted at the March board review." } });
  fireEvent.click(accept);
  await waitFor(() => expect(calls.find((c) => c.path === "isms/risks/r1/accept")).toBeTruthy());
});
