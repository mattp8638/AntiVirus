import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { displayValue } from "../src/components/DisplayValue";
import { PageBoundary } from "../src/components/PageBoundary";
import { ErrorNote, Modal, Pill, Sev, Stat, Table } from "../src/components/ui";

vi.mock("../src/app-context", () => ({ useApp: () => ({ can: () => true }) }));
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

test("display fields preserve text, zero and React content without exposing structured data", () => {
  render(<div>{displayValue(["Server ", 0, <b key="ok">ready</b>, null, false, { password: "must-not-render" }])}</div>);
  expect(screen.getByText("ready").tagName).toBe("B");
  expect(document.body.textContent).toContain("Server 0readyUnavailable");
  expect(document.body.textContent).not.toContain("must-not-render");
  expect(document.body.textContent).not.toContain("[object Object]");
});

test("shared cards, modal titles, errors, badges and table renderers tolerate object values", () => {
  const invalid: any = {};
  render(<>
    <Stat label="Count" value={invalid} hint={invalid} />
    <ErrorNote error={invalid} /><Sev level={invalid} /><Pill value={invalid} tone="good" />
    <Modal title={invalid} onClose={() => {}}>Details</Modal>
    <Table rows={[{ id: "1", value: invalid }]} columns={[{ key: "value", label: "Value", render: (row) => row.value }]} />
  </>);
  expect(screen.getAllByText("Unavailable").length).toBeGreaterThanOrEqual(5);
  expect(screen.getByText("unknown")).toBeTruthy();
  expect(document.querySelector(".tone-good")).toBeNull();
});

test("malformed collection entries produce a visible error instead of a table crash", () => {
  render(<Table rows={[null] as any} columns={[{ key: "name", label: "Name" }]} />);
  expect(screen.getByRole("alert").textContent).toContain("some records could not be read");
});

test("a failed page keeps surrounding navigation and can recover on retry or navigation", () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  let broken = true;
  function View() { if (broken) throw new Error("fixture render failure"); return <p>Healthy view</p>; }
  const { rerender } = render(<><nav>Navigation remains</nav><PageBoundary resetKey="/devices?tab=system"><View /></PageBoundary></>);
  expect(screen.getByText("Navigation remains")).toBeTruthy();
  expect(screen.getByRole("alert").textContent).toContain("This view could not be displayed");
  broken = false;
  fireEvent.click(screen.getByText("Try again"));
  expect(screen.getByText("Healthy view")).toBeTruthy();
  broken = true;
  rerender(<PageBoundary resetKey="/same"><View /></PageBoundary>);
  expect(screen.getByRole("alert")).toBeTruthy();
  broken = false;
  rerender(<PageBoundary resetKey="/different"><View /></PageBoundary>);
  expect(screen.getByText("Healthy view")).toBeTruthy();
});
