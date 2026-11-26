import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
const uploads: any[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({ useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {}, me: { tenants: [] } }) }));
vi.mock("../src/api", () => ({
  fmtTime: (v: string) => v,
  downloadFile: async () => {},
  uploadFile: async (path: string, file: Blob, query: any) => { uploads.push({ path, query }); return { scanStatus: "clean" }; },
  api: async (path: string, options: any = {}) => { calls.push({ path, options }); return responses[path] ?? {}; },
}));
afterEach(() => { cleanup(); calls.length = 0; uploads.length = 0; responses = {}; });

import { IsmsEvidenceTab } from "../src/pages/grc/IsmsEvidence";

test("a file is uploaded with its controls, and evidence that does not count is labelled", async () => {
  responses = {
    "isms/me": { role: "control_owner", permissions: ["evidence.view", "evidence.upload", "controls.view"] },
    "isms/controls": { controls: [{ id: "c1", ref: "CC-BKP-01", title: "Backups", applicable: true }] },
    "isms/evidence": { evidence: [{ id: "e1", title: "Old report", kind: "file", collectedAt: "2026-01-01", controls: [{ id: "c1", ref: "CC-BKP-01" }],
                                    validUntil: "2026-02-01", current: false, scanStatus: "clean", uploadedBy: "Kim" }] },
  };
  render(<IsmsEvidenceTab />);
  await screen.findByText("not current");
  fireEvent.click(screen.getByRole("button", { name: "Add evidence" }));
  const add = screen.getByRole("button", { name: "Add" }) as HTMLButtonElement;
  fireEvent.change(screen.getByLabelText("File"), { target: { files: [new File(["x"], "restore.pdf", { type: "application/pdf" })] } });
  expect(add.disabled).toBe(true);  // no control chosen yet
  fireEvent.click(screen.getByRole("checkbox", { name: "CC-BKP-01 Backups" }));
  fireEvent.click(add);
  await waitFor(() => expect(uploads[0]).toEqual({ path: "isms/evidence/upload", query: { tenant_id: "ten_a", filename: "restore.pdf", title: "", controls: "c1", valid_until: "" } }));
});
