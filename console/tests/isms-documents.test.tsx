import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const calls: { path: string; options: any }[] = [];
let responses: Record<string, any> = {};
vi.mock("../src/app-context", () => ({ useApp: () => ({ tenantId: "ten_a", can: () => true, toast: () => {}, me: { tenants: [] } }) }));
vi.mock("../src/api", () => ({
  fmtTime: (v: string) => v,
  downloadFile: async () => {},
  api: async (path: string, options: any = {}) => { calls.push({ path, options }); return responses[path] ?? {}; },
}));
afterEach(() => { cleanup(); calls.length = 0; responses = {}; });

import { IsmsDocumentsTab } from "../src/pages/grc/IsmsDocuments";

const draft = { id: "v1", version: 1, state: "in_review", stateLabel: "In review", hasPdf: true };

test("documents render as safe Markdown and an approver can approve a version in review", async () => {
  responses = {
    "isms/me": { role: "approver", permissions: ["documents.view", "documents.approve"] },
    "isms/documents": { documents: [{ docType: "information-security-policy", title: "Information security policy", source: "template", documentId: "d1",
                                      number: "ACM-POL-001", latest: draft, published: null, outOfDate: false }] },
    "isms/documents/d1": { documentId: "d1", docType: "information-security-policy", number: "ACM-POL-001", title: "Information security policy", source: "template",
                           versions: [draft], viewing: draft, blocks: [{ ref: "isp.purpose", markdown: "## Purpose\n\n<script>alert(1)</script> **Acme** protects data." }],
                           changes: [], overrides: {}, templateBlocks: [] },
  };
  const { container } = render(<IsmsDocumentsTab />);
  fireEvent.click(await screen.findByText("Information security policy"));
  await screen.findByText("Purpose");
  expect(container.ownerDocument.querySelector("script")).toBeNull();
  expect(screen.getByText("Acme").tagName).toBe("B");
  expect(screen.queryByRole("button", { name: "Use our own wording" })).toBeNull();  // approvers do not edit wording
  fireEvent.click(screen.getByRole("button", { name: "Approve" }));
  await waitFor(() => expect(calls.some((c) => c.path === "isms/documents/versions/v1/approve")).toBe(true));
});
