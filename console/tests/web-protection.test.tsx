import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AppleEnrol, appleKind, WebProtectionCard, type WebProtectionView } from "../src/components/WebProtection";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
const DESKTOP_SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";

test("iPhones, iPads (even when they claim to be a Mac) and Macs are told apart", () => {
  expect(appleKind(IPHONE, 5)).toBe("iphone");
  expect(appleKind("Mozilla/5.0 (iPad; CPU OS 12_5 like Mac OS X)", 5)).toBe("ipad");
  expect(appleKind(DESKTOP_SAFARI, 5)).toBe("ipad");
  expect(appleKind(DESKTOP_SAFARI, 0)).toBe("mac");
  expect(appleKind("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 0)).toBeNull();
});

test("installing sends the code and opens the profile Safari installs", async () => {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ profileUrl: "/dns/abc/apple.mobileconfig" }), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  const opened: string[] = [];
  render(<AppleEnrol token="fet_code" kind="iphone" onProfile={(url) => opened.push(url)} />);
  fireEvent.change(screen.getByPlaceholderText("Jo's iPhone"), { target: { value: "Sam's iPhone" } });
  fireEvent.click(screen.getByRole("button", { name: "Install web protection" }));
  await waitFor(() => expect(opened).toEqual(["/dns/abc/apple.mobileconfig"]));
  const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
  expect(url).toBe("/api/v1/enroll/apple");
  expect(JSON.parse(String(init.body))).toEqual({ enrollmentToken: "fet_code", name: "Sam's iPhone", kind: "iphone" });
  expect(screen.getByRole("status").textContent).toContain("Profile downloaded");
  expect(screen.getByText(/Tap Install, enter your passcode/)).toBeTruthy();
});

test("a used code says why", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "Enrollment token has no uses left" }), { status: 403 })));
  const opened: string[] = [];
  render(<AppleEnrol token="fet_code" kind="mac" onProfile={(url) => opened.push(url)} />);
  fireEvent.click(screen.getByRole("button", { name: "Install web protection" }));
  await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Enrollment token has no uses left"));
  expect(opened).toEqual([]);
  expect(screen.getByText(/Privacy & Security › Profiles/)).toBeTruthy();
});

const view: WebProtectionView = { status: "active", kind: "iphone", firstLookupAt: "2026-10-01T09:00:00Z", lastLookupAt: new Date().toISOString(),
  blocked7d: 3, recent: [], filtering: true, filteringNote: null, signed: false, silentAfterHours: 72, profileUrl: "https://fenrir.test/dns/abc/apple.mobileconfig" };

test("a working profile shows when it was last used and how to reinstall it", () => {
  render(<WebProtectionCard view={view} />);
  expect(screen.getByText("Working")).toBeTruthy();
  expect(screen.getByText(/looked up a website through Fenrir just now/)).toBeTruthy();
  expect(screen.getByText("https://fenrir.test/dns/abc/apple.mobileconfig")).toBeTruthy();
});

test("a profile that was never installed, and a policy that blocks nothing, are both called out", () => {
  render(<WebProtectionCard view={{ ...view, status: "never", lastLookupAt: null, firstLookupAt: null, filtering: false,
    filteringNote: "DNS protection is off in this device's policy, so nothing is blocked.", profileUrl: undefined }} />);
  expect(screen.getByText("Not installed")).toBeTruthy();
  expect(screen.getByText("not blocking")).toBeTruthy();
  expect(screen.getByRole("note").textContent).toContain("nothing is blocked");
  expect(screen.queryByText("Install the profile again")).toBeNull();
});
