import { afterAll, afterEach, beforeAll, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { Root } from "../src/App";

// Canvas rendering and Windows shell execution are outside a DOM render test.
// Keep the remote viewer and all its panes real; substitute its terminal widget
// and desktop transport with deterministic protocol peers.
vi.mock("@xterm/xterm", () => ({ Terminal: class {
  cols = 80; rows = 24;
  open() {} loadAddon() {} onData() { return { dispose() {} }; }
  onResize() { return { dispose() {} }; } write() {} writeln() {} dispose() {} focus() {}
} }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));

class DesktopPeer extends EventTarget {
  static OPEN = 1;
  readyState = 1;
  binaryType = "arraybuffer";
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: ((event: { reason: string }) => void) | null = null;
  constructor(_url: string) {
    super();
    setTimeout(() => {
      this.dispatchEvent(new Event("open"));
      this.deliver({ ch: "sys", t: "hello", agentConnected: true, viewOnly: false, allowTerminal: true, allowFileTransfer: true });
      this.deliver({ ch: "sys", t: "info", hostname: "RENDER-SERVER", os: "windows", home: "C:\\", monitors: [{ index: 0 }],
        capabilities: ["desktop", "cad", "terminal", "files", "processes", "services", "chat"], shells: ["powershell"] });
    }, 0);
  }
  deliver(message: unknown) { this.onmessage?.({ data: JSON.stringify(message) }); }
  send(data: string | Uint8Array) {
    if (typeof data !== "string") return;
    const message = JSON.parse(data);
    setTimeout(() => {
      if (message.t === "ls") this.deliver({ ...message, path: "C:\\", parent: "", sep: "\\", entries: [{ name: "Logs", dir: true }] });
      else if (message.t === "list") this.deliver({ ...message, items: [] });
      else if (message.ch === "input" && message.t === "cad") this.deliver({ ch: "sys", t: "action.result", action: "cad", req: message.req,
        ok: true, message: "Ctrl+Alt+Del requested for this Windows session." });
    }, 0);
  }
  close() { this.readyState = 3; }
}

const context = vi.hoisted(() => ({ me: null as any, tenantId: "" }));
vi.mock("../src/app-context", () => ({
  useApp: () => ({ me: context.me, loading: false, tenantId: context.tenantId, can: () => true,
    tenantName: (id: string) => context.me?.tenants.find((t: any) => t.id === id)?.name ?? "Customer",
    setTenantId: vi.fn(), toast: vi.fn(), login: vi.fn(), logout: vi.fn(), refreshMe: vi.fn() }),
}));

let child: ChildProcessWithoutNullStreams;
let ids: Record<string, string>;
let sequence = 0;
let diagnostic = "";
const pending = new Map<number, (response: any) => void>();
const failures: { path: string; status: number }[] = [];
const renderErrors: unknown[][] = [];
const coverage = new Set<string>();

beforeAll(async () => {
  vi.stubGlobal("WebSocket", DesktopPeer);
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.spyOn(console, "error").mockImplementation((...args) => { renderErrors.push(args); });
  child = spawn(process.env.FENRIR_UI_PYTHON || "python", ["tests/api-bridge.py"], {
    cwd: process.cwd(), env: { ...process.env, FENRIR_FEED_SYNC: "false", FENRIR_VULN_INTEL: "false" },
  });
  child.stderr.on("data", (chunk) => { diagnostic += String(chunk); });
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`Test API exited (${code}): ${diagnostic}`)));
    createInterface({ input: child.stdout }).on("line", (line) => {
      const reply = JSON.parse(line);
      if (reply.ready) { context.me = reply.me; ids = reply.ids; resolve(); }
      else { const receive = pending.get(reply.id); pending.delete(reply.id); receive?.(reply); }
    });
  });
  vi.stubGlobal("fetch", async (input: string | URL | Request, options: RequestInit = {}) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost");
    const id = ++sequence;
    const response = await new Promise<any>((resolve) => {
      pending.set(id, resolve);
      child.stdin.write(JSON.stringify({ id, path: url.pathname + url.search, method: options.method || "GET",
        body: typeof options.body === "string" ? JSON.parse(options.body) : undefined }) + "\n");
    });
    if (response.status >= 400) failures.push({ path: url.pathname, status: response.status });
    return { ok: response.status >= 200 && response.status < 300, status: response.status,
      headers: new Headers(response.headers), arrayBuffer: async () => Uint8Array.from(Buffer.from(response.bytes, "base64")).buffer,
      text: async () => response.text, json: async () => JSON.parse(response.text), blob: async () => new Blob([response.text]) } as Response;
  });
}, 30000);

afterEach(() => { context.tenantId = ""; cleanup(); failures.length = 0; renderErrors.length = 0; });
afterAll(() => {
  child?.stdin.end();
  child?.kill();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  console.log(`Console render coverage: ${coverage.size} route/tab views checked with the real test API.`);
});

async function settled() {
  // Rendering an API result may mount a tab that starts another request.
  for (let i = 0; i < 60; i++) {
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    if (!pending.size) {
      await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
      if (!pending.size && !document.body.textContent?.includes("Opening session…") && !document.body.textContent?.includes("Loading map…")) break;
    }
  }
  expect(pending.size, "API requests did not settle").toBe(0);
}

function assertView(label: string) {
  expect(screen.queryByText("This view could not be displayed"), `${label}: page boundary caught a render error`).toBeNull();
  expect(renderErrors, `${label}: React reported an error`).toEqual([]);
  expect(failures, `${label}: API request failed`).toEqual([]);
  expect(document.body.textContent?.trim().length, `${label}: blank page`).toBeGreaterThan(30);
  coverage.add(label);
}

const tabButtons = () => [...document.querySelectorAll<HTMLButtonElement>(".tabs > button, .subtabs > button, .rv-tabs > button")];

async function checkTabs(route: string) {
  const labels = [...new Set(tabButtons().map((button) => button.textContent || ""))];
  for (const label of labels) {
    const button = tabButtons().find((button) => button.textContent === label);
    if (!button) continue;
    fireEvent.click(button);
    await settled();
    assertView(`${route} › ${label}`);
    for (const sub of [...document.querySelectorAll<HTMLButtonElement>(".subtabs > button")]) {
      fireEvent.click(sub);
      await settled();
      assertView(`${route} › ${label} › ${sub.textContent}`);
    }
  }
}

// Derive the inventory from the application's actual routes, so adding a page
// automatically adds a smoke case. Device tabs and subpages are clicked too.
const source = readFileSync("src/App.tsx", "utf8");
const paths = [...new Set([...source.matchAll(/<Route path="([^"]+)"/g)].map((match) => match[1]))].filter((path) => path !== "*");
paths.push("/portal", "/enroll-phone");

function concrete(path: string) {
  const kind = path.startsWith("/devices/") ? "device" : path.startsWith("/policies/") ? "policy"
    : path.startsWith("/incidents/") ? "incident" : path.startsWith("/tickets/") ? "ticket"
    : path.startsWith("/projects/") ? "project" : path.startsWith("/governance/policies/") ? "grcPolicy"
    : path.startsWith("/crm/accounts/") || path.startsWith("/companies/") ? "tenant" : path.startsWith("/remote/") ? "remote"
    : path.startsWith("/recordings/") ? "recording" : "device";
  return path.replace(":id", ids[kind]).replace(":tenantId", ids.tenant).replace(":framework", ids.framework);
}

for (const path of paths) test(`renders ${path} and its tabs`, async () => {
  const route = concrete(path);
  render(<MemoryRouter initialEntries={[route]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  assertView(route);
  if (path.startsWith("/remote/")) {
    fireEvent.click(screen.getByRole("button", { name: "Ctrl+Alt+Del" }));
    await settled();
    expect(screen.getByText("Ctrl+Alt+Del requested for this Windows session.")).toBeTruthy();
  }
  if (path.startsWith("/recordings/")) expect(screen.getByRole("button", { name: "Play" })).toBeTruthy();
  await checkTabs(route);
  // Drill into read-only record views and editors, without submitting actions.
  const row = document.querySelector<HTMLTableRowElement>(".content tr.clickable");
  if (row) {
    fireEvent.click(row);
    await settled();
    assertView(`${route} › record detail`);
    await checkTabs(`${route} › record detail`);
  }
}, 20000);

test("renders Android device pages including Location", async () => {
  const route = `/devices/${ids.phone}`;
  render(<MemoryRouter initialEntries={[route]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  assertView(route);
  await checkTabs(route);
}, 20000);

test("UK governance catalogue shows scope and adopts a working DORA programme", async () => {
  context.tenantId = ids.tenant;
  render(<MemoryRouter initialEntries={["/governance"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  fireEvent.click(screen.getByRole("button", { name: "Add framework", exact: true }));
  await settled();
  const cards = [...document.querySelectorAll<HTMLButtonElement>("button.domain-card")].filter(b => b.textContent?.includes("matching policies"));
  expect(cards).toHaveLength(15);
  expect(cards.some(b => /ACSC|Essential Eight/.test(b.textContent || ""))).toBe(false);
  expect(cards.every(b => b.textContent?.includes("Owner:") && b.textContent?.includes("Assessment:") && b.textContent?.includes("UK scope:"))).toBe(true);
  fireEvent.click(cards.find(b => b.textContent?.startsWith("DORA"))!);
  const source = screen.getByRole("link", { name: "Official framework guidance" });
  expect(source.getAttribute("href")).toBe("https://eur-lex.europa.eu/eli/reg/2022/2554/oj");
  const add = screen.getAllByRole<HTMLButtonElement>("button", { name: "Add framework", exact: true }).find(b => b.closest(".modal"));
  expect(add).toBeTruthy();
  expect(add!.disabled).toBe(false);
  fireEvent.click(add!);
  await settled();
  assertView("UK governance › DORA adoption");
  expect(screen.getByRole("heading", { name: "DORA", exact: true })).toBeTruthy();
  expect(screen.getByText("Entity and supplier applicability", { exact: true })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Export answers (CSV)" })).toBeTruthy();
}, 30000);

test("a dispatched job can be stopped and removed while awaiting its endpoint", async () => {
  render(<MemoryRouter initialEntries={[`/automation?job=${ids.cancellationJob}`]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  fireEvent.click(screen.getByRole("button", { name: "Stop job", exact: true }));
  await settled();
  expect(screen.getAllByText("Stopping").length).toBeGreaterThan(0);
  expect(document.body.textContent).toContain("awaiting stop acknowledgement");
  fireEvent.click(screen.getByRole("button", { name: "Remove job", exact: true }));
  await settled();
  // The in-page confirmation (not the browser's), with a red button for a destructive action.
  const dialog = screen.getByRole("dialog", { name: "Please confirm" });
  expect(dialog.textContent).toContain("Remove this job and stop its outstanding work?");
  fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
  await settled();
  assertView("Automation › remove dispatched job");
  expect(screen.queryByRole("dialog", { name: "Cancellable UI job" })).toBeNull();
  expect(document.body.textContent).not.toContain("Cancellable UI job");
}, 20000);

test("decommissioning succeeds while a command is awaiting its stop acknowledgement", async () => {
  render(<MemoryRouter initialEntries={[`/devices/${ids.cancellationDevice}`]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  fireEvent.click(screen.getByRole("button", { name: "More ▾", exact: true }));
  fireEvent.click(screen.getByRole("menuitem", { name: "Decommission device…", exact: true }));
  fireEvent.change(screen.getByLabelText("Type CANCEL-SERVER to confirm"), { target: { value: "CANCEL-SERVER" } });
  fireEvent.click(screen.getByRole("button", { name: "Decommission and retain history", exact: true }));
  await settled();
  assertView("Device › decommission with in-flight work");
  expect(document.body.textContent).toContain("Decommissioned: agent access is revoked");
  expect(document.body.textContent).toContain("awaiting a stop acknowledgement");
}, 20000);

test("the service board can be worked from the keyboard", async () => {
  render(<MemoryRouter initialEntries={["/service-board"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  expect(document.querySelector("tr.active-row")).toBeNull();
  fireEvent.keyDown(document, { key: "j" });
  await settled();
  expect(document.querySelector("tr.active-row")).toBeTruthy();
  fireEvent.keyDown(document, { key: "?" });
  await settled();
  expect(screen.getByRole("dialog", { name: "Keyboard shortcuts" }).textContent).toContain("Next / previous ticket");
}, 20000);

test("custom fields are defined in settings and shown on devices", async () => {
  render(<MemoryRouter initialEntries={["/settings?tab=Custom%20fields"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  fireEvent.change(screen.getByPlaceholderText("Label, e.g. Asset tag"), { target: { value: "Asset tag" } });
  fireEvent.click(screen.getByRole("button", { name: "Add field" }));
  await settled();
  expect(document.body.textContent).toContain("asset_tag");
  cleanup();
  render(<MemoryRouter initialEntries={[`/devices/${ids.device}`]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><Root /></MemoryRouter>);
  await settled();
  expect(screen.getByRole("heading", { name: "Custom fields" })).toBeTruthy();
  assertView("Device › custom fields");
}, 20000);
