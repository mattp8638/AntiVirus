import { afterEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { SystemTab } from "../src/pages/DeviceSystem";

const state = vi.hoisted(() => ({ profile: {} as Record<string, unknown> }));
vi.mock("../src/app-context", () => ({ useApp: () => ({ can: () => true }) }));
vi.mock("../src/components/ui", async (original) => ({
  ...await original<typeof import("../src/components/ui")>(),
  useData: () => ({ data: { collectedAt: "2026-01-01T00:00:00Z", profile: state.profile, findings: [], recoveryKeys: [] } }),
  useAction: () => ({ run: vi.fn(), busy: false }),
}));
afterEach(cleanup);

test("a collected profile with an empty object in a text field does not blank System", () => {
  state.profile = { hardware: { chassis: {}, serial: {} }, os: { name: "Windows Server 2025", architecture: {} },
    battery: { present: true, status: {} }, events: { errorsLast24h: {} } };
  render(<SystemTab deviceId="server-1" />);
  expect(screen.getByText("Windows Server 2025")).toBeTruthy();
  expect(screen.getByText("Hardware")).toBeTruthy();
});
