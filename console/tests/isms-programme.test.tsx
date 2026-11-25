import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({
  useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {}, me: { tenants: [] } }),
}));
const downloads: string[] = [];
vi.mock("../src/api", () => ({
  downloadFile: async (path: string) => { downloads.push(path); },
  api: async (path: string, options: any = {}) => {
    calls.push({ path, options });
    const r = responses[path];
    return typeof r === "function" ? r(options) : r ?? {};
  },
}));
afterEach(() => { cleanup(); calls.length = 0; responses = {}; });

import { IsmsControlsTab, IsmsProgrammeTab, IsmsSoaTab } from "../src/pages/grc/IsmsProgramme";

const iso = { framework: "iso27001", name: "ISO/IEC 27001", version: "2022", packVersion: "1.1.0", pinnedVersion: "1.1.0", certifiable: true,
              requirementCount: 123, selected: true, status: "target_certification", targetDate: null, licence: "id-and-title" };
const ce = { ...iso, framework: "cyber-essentials", name: "Cyber Essentials", certifiable: false, selected: false, pinnedVersion: null, requirementCount: 30 };

test("only changed answers are sent for review, and applying sends the same", async () => {
  responses = {
    "isms/me": { role: "isms_manager", permissions: ["programme.manage"] },
    "isms/programme/frameworks": { frameworks: [iso, ce] },
    "isms/programme/questions": { questions: [
      { ref: "develops_software", text: "Do you develop software in house?", help: null, type: "bool", options: [], value: true },
      { ref: "has_premises", text: "Do you have premises?", help: null, type: "bool", options: [], value: true }] },
    "isms/programme/preview": { changes: [{ key: "requirement:iso27001:A.8.25", type: "requirement", item: "iso27001:A.8.25", from: true, to: false, reason: "No development." }],
                                rejectedOverrides: [], counts: { requirement: { applicable: 120, excluded: 3 }, control: { applicable: 50, excluded: 7 } } },
    "isms/programme/apply": { changes: [], rejectedOverrides: [], counts: {} },
  };
  render(<IsmsProgrammeTab />);
  const no = await screen.findAllByRole("radio", { name: "No" });
  fireEvent.click(no[0]);
  fireEvent.click(screen.getByRole("button", { name: "Review the changes" }));
  await screen.findByText("No development.");
  expect(calls.find((c) => c.path === "isms/programme/preview")!.options.body).toEqual({ tenantId: "ten_a", answers: { develops_software: false } });
  expect(screen.getByText(/120 requirements apply and 3 are excluded/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(calls.find((c) => c.path === "isms/programme/apply")!.options.body).toEqual({ tenantId: "ten_a", answers: { develops_software: false } }));
});

test("adding a framework keeps the ones already chosen", async () => {
  responses = { "isms/me": { role: "isms_manager", permissions: ["programme.manage"] },
                "isms/programme/frameworks": { frameworks: [iso, ce] }, "isms/programme/questions": { questions: [] } };
  render(<IsmsProgrammeTab />);
  fireEvent.click(await screen.findByLabelText("Include Cyber Essentials"));
  await waitFor(() => expect(calls.find((c) => c.options.method === "PUT")!.options.body).toEqual({ tenantId: "ten_a", frameworks: {
    iso27001: { status: "target_certification", targetDate: null }, "cyber-essentials": { status: "target_certification", targetDate: null } } }));
});

test("a control owner can change the state and notes of their control but not its owner", async () => {
  const control = { id: "c1", ref: "CC-BKP-01", title: "Backups", statement: "Back up data.", state: "not_started", ownerId: "u1", ownerName: "Kim",
                    notes: "", applicable: true, reason: "Needed for iso27001 A.8.13.", requirements: ["iso27001:A.8.13"], testProcedure: "Restore a file." };
  responses = { "isms/me": { userId: "u1", role: "control_owner", permissions: ["controls.view"] },
                "isms/controls": { controls: [control], manualStates: ["not_started", "in_progress", "implemented"] } };
  render(<IsmsControlsTab />);
  fireEvent.click(await screen.findByText("Backups"));
  expect(screen.queryByLabelText("Owner")).toBeNull();
  fireEvent.change(screen.getByLabelText("State"), { target: { value: "in_progress" } });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(calls.find((c) => c.options.method === "PATCH")!.options.body).toEqual({ notes: "", state: "in_progress" }));
});

test("the Statement of Applicability shows readiness, filters exclusions and downloads the workbook", async () => {
  responses = {
    "isms/me": { role: "auditor", permissions: ["controls.view"] },
    "isms/readiness": { frameworks: [{ framework: "iso27001", met: 4, partial: 6, notMet: 76, applicable: 86, notApplicable: 7, withoutControls: 0, score: 4.7,
                                       formula: "Readiness = met / applicable.", coverage: { evidenced: 4, applicable: 53, score: 7.5 } }] },
    "isms/soa": { rows: [
      { ref: "A.8.13", title: "Information backup", group: "Technological", applicable: true, reason: "In scope.", justification: null, controls: [{ ref: "CC-BKP-01" }], status: "Implemented and evidenced", owners: ["Kim"] },
      { ref: "A.8.25", title: "Secure development life cycle", group: "Technological", applicable: false, reason: "No development.", justification: null, controls: [], status: "Not applicable", owners: [] }] },
  };
  render(<IsmsSoaTab />);
  await screen.findByText(/Readiness 4.7%/);
  expect(screen.getByText(/4 of 86 applicable requirements met/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Show"), { target: { value: "excluded" } });
  expect(screen.queryByText("Information backup")).toBeNull();
  expect(screen.getByText("No development.")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Download (Excel)" }));
  await waitFor(() => expect(downloads).toEqual(["isms/soa/export?tenant_id=ten_a&framework=iso27001"]));
});

test("only managers are offered the does-not-apply answer", async () => {
  const control = { id: "c1", ref: "CC-PHY-01", title: "Physical security", statement: "Secure premises.", state: "not_started", ownerId: "u1", ownerName: "Kim",
                    notes: "", applicable: true, reason: "Needed.", requirements: [], satisfies: ["iso27001:A.7.1"], assessment: null, implementation: null };
  responses = { "isms/me": { userId: "u1", role: "control_owner", permissions: ["controls.view"] },
                "isms/controls": { controls: [control], manualStates: ["not_started", "in_progress", "implemented"] } };
  render(<IsmsControlsTab />);
  fireEvent.click(await screen.findByText("Physical security"));
  expect(screen.getByRole("radio", { name: "Yes, it is in place" })).toBeTruthy();
  expect(screen.queryByRole("radio", { name: "It does not apply to us" })).toBeNull();
  fireEvent.click(screen.getByRole("radio", { name: "Yes, it is in place" }));
  const save = screen.getByRole("button", { name: "Save answer" }) as HTMLButtonElement;
  expect(save.disabled).toBe(true);  // a description is required
  fireEvent.change(screen.getByLabelText(/How it is done today/), { target: { value: "Badge access" } });
  fireEvent.click(save);
  await waitFor(() => expect(calls.find((c) => c.path === "isms/controls/c1/assessment")!.options.body).toEqual({ answer: "yes", implementation: "Badge access" }));
});
