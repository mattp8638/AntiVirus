import { afterEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ReviewPanel, ReviewPill } from "../src/components/ScriptReview";

let email = "reviewer@msp.example";
vi.mock("../src/app-context", () => ({
  useApp: () => ({ me: { user: { email } }, can: () => true, toast: () => {} }),
}));
afterEach(() => { cleanup(); email = "reviewer@msp.example"; });

const pending = { required: true, status: "pending" as const, hash: "h", editors: ["author@msp.example"],
                  diff: "--- body (reviewed)\n+++ body (now)\n-Write-Output 'old'\n+Remove-Item C:\\temp" };

test("a second person sees what changed and can approve it", () => {
  render(<ReviewPanel review={pending} path="rmm/scripts/s1" onReviewed={() => {}} />);
  expect(screen.getByText(/Waiting for review/)).toBeTruthy();
  expect(screen.getByText("+Remove-Item C:\\temp")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Approve this version" })).toBeTruthy();
});

test("whoever changed the version is told someone else must review it", () => {
  email = "author@msp.example";
  render(<ReviewPanel review={pending} path="rmm/scripts/s1" onReviewed={() => {}} />);
  expect(screen.queryByRole("button", { name: "Approve this version" })).toBeNull();
  expect(screen.getByText(/someone else has to review it/)).toBeTruthy();
});

test("nothing is shown while review is not required", () => {
  const { container } = render(<><ReviewPill review={{ ...pending, required: false }} />
    <ReviewPanel review={{ ...pending, required: false }} path="x" onReviewed={() => {}} /></>);
  expect(container.textContent).toBe("");
});
