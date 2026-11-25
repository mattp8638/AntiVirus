// Thin client for the Fenrir Cloud console API.

const TOKEN_KEY = "fenrir.token";

export class ApiError extends Error {
  constructor(public status: number, message: string, public detail?: unknown) {
    super(message);
  }
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null) {
  unlocks.clear();
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: session lasts until reload */
  }
}

// Sensitive actions (revealing a secret, identity changes, restores) need a recent password check.
// The server answers 403 "reauth_required"; we ask the user once, keep the 5-minute token in memory
// only (never in storage), and retry the request.
let reauthToken: { value: string; expires: number } | null = null;
let reauthPrompt: (() => Promise<string | null>) | null = null;
export function setReauthPrompt(prompt: (() => Promise<string | null>) | null) {
  reauthPrompt = prompt;
}
export function rememberReauth(token: string, seconds: number) {
  reauthToken = { value: token, expires: Date.now() + (seconds - 10) * 1000 };
}

// Device backup: repositories unlocked in this browser session (passphrase checked on a machine, plus a fresh
// password/MFA check). Kept in memory only, so a reload or sign-out locks them again.
const unlocks = new Map<string, { token: string; expires: number }>();
const unlockListeners = new Set<() => void>();
export function rememberUnlock(repoId: string, token: string, seconds: number) {
  unlocks.set(repoId, { token, expires: Date.now() + (seconds - 10) * 1000 });
  unlockListeners.forEach((f) => f());
}
export function unlockedUntil(repoId: string): number | null {
  const u = unlocks.get(repoId);
  return u && u.expires > Date.now() ? u.expires : null;
}
export function lockRepositories(ids?: string[]) {
  for (const id of ids ?? [...unlocks.keys()]) unlocks.delete(id);
  unlockListeners.forEach((f) => f());
}
export function onUnlockChange(f: () => void): () => void {
  unlockListeners.add(f);
  return () => unlockListeners.delete(f);
}
function unlockHeader(): string {
  return [...unlocks.values()].filter((u) => u.expires > Date.now()).map((u) => u.token).join(",");
}

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export async function api<T = any>(path: string, options: { method?: string; body?: unknown; query?: Record<string, unknown> } = {}): Promise<T> {
  try {
    return await rawApi<T>(path, options);
  } catch (err) {
    if (err instanceof ApiError && err.status === 403 && err.message === "reauth_required" && reauthPrompt) {
      reauthToken = null;
      if (await reauthPrompt()) return rawApi<T>(path, options);
    }
    throw err;
  }
}

async function rawApi<T>(path: string, options: { method?: string; body?: unknown; query?: Record<string, unknown> }): Promise<T> {
  const url = new URL(path.startsWith("/") ? path : `/api/console/${path}`, window.location.origin);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  }
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (reauthToken && reauthToken.expires > Date.now()) headers["X-Fenrir-Reauth"] = reauthToken.value;
  const unlocked = unlockHeader();
  if (unlocked) headers["X-Fenrir-Unlock"] = unlocked;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(url.toString(), {
    method: options.method ?? (options.body !== undefined ? "POST" : "GET"),
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  if (response.status === 401) {
    onUnauthorized();
  }
  const text = await response.text();
  const data = text ? safeJson(text) : null;
  if (response.status === 202 && data && typeof data === "object" && (data as any).approvalRequired) {
    // CORE-15: held for a second person's approval - not a success. Settings > Approvals has "Run now" once approved.
    throw new ApiError(202, "Sent for approval: a second person must approve this before it runs (Settings > Approvals).");
  }
  if (!response.ok) {
    const detail = data && typeof data === "object" && "detail" in data ? (data as any).detail : text;
    if (detail === "repository_locked") {
      throw new ApiError(response.status, "These backups are locked (the unlock lasts 30 minutes). Open the machine again from Backups › Images & restore to unlock them.");
    }
    if (detail && typeof detail === "object" && (detail as any).code === "image_infected") {
      const d = detail as { message: string; infected: string[]; count: number };
      throw new ApiError(response.status, `${d.message} ${d.infected.slice(0, 3).join(", ")}${d.count > 3 ? ` and ${d.count - 3} more` : ""}. Tick "restore it anyway" to go ahead.`, detail);
    }
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

/** GET a binary body from the console API (with the session's token). */
export async function apiBytes(path: string): Promise<ArrayBuffer> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const unlocked = unlockHeader();
  if (unlocked) headers["X-Fenrir-Unlock"] = unlocked;
  const response = await fetch(new URL(path.startsWith("/") ? path : `/api/console/${path}`, window.location.origin).toString(), { headers });
  if (response.status === 401) onUnauthorized();
  if (!response.ok) {
    const data = safeJson(await response.text());
    const detail = data && typeof data === "object" && "detail" in data ? (data as any).detail : `HTTP ${response.status}`;
    throw new ApiError(response.status, String(detail));
  }
  return response.arrayBuffer();
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function fmtTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function ago(value?: string | null): string {
  if (!value) return "never";
  const seconds = (Date.now() - new Date(value).getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// The MSP's default currency (Settings → Region & holidays), loaded after sign-in.
let defaultCurrency = "GBP";
export function setDefaultCurrency(code: string) { if (/^[A-Z]{3}$/.test(code)) defaultCurrency = code; }
export function getDefaultCurrency() { return defaultCurrency; }

export function money(value: number, currency?: string | null): string {
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency: currency || defaultCurrency }).format(value || 0);
  } catch {
    return `${currency || defaultCurrency} ${(value || 0).toFixed(2)}`;  // a code the browser does not know
  }
}

/** Upload a file as the raw request body (the server reads metadata from the query string). */
export async function uploadFile<T = any>(path: string, file: Blob, query: Record<string, unknown> = {}): Promise<T> {
  const url = new URL(`/api/console/${path}`, window.location.origin);
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") url.searchParams.set(key, String(value));
  }
  const headers: Record<string, string> = { "Content-Type": file.type || "application/octet-stream" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url.toString(), { method: "POST", headers, body: file });
  const text = await response.text();
  const data = text ? safeJson(text) : null;
  if (response.status === 202 && data && typeof data === "object" && (data as any).approvalRequired) {
    // CORE-15: held for a second person's approval - not a success. Settings > Approvals has "Run now" once approved.
    throw new ApiError(202, "Sent for approval: a second person must approve this before it runs (Settings > Approvals).");
  }
  if (!response.ok) {
    const detail = data && typeof data === "object" && "detail" in data ? (data as any).detail : text;
    if (detail && typeof detail === "object" && (detail as any).code === "image_infected") {
      const d = detail as { message: string; infected: string[]; count: number };
      throw new ApiError(response.status, `${d.message} ${d.infected.slice(0, 3).join(", ")}${d.count > 3 ? ` and ${d.count - 3} more` : ""}. Tick "restore it anyway" to go ahead.`, detail);
    }
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

/** Download an authenticated file and save it with the server's (or the given) file name. */
export async function downloadFile(path: string, fallbackName = "download") {
  const fetchIt = () => {
    const headers: Record<string, string> = {};
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    if (reauthToken && reauthToken.expires > Date.now()) headers["X-Fenrir-Reauth"] = reauthToken.value;
    return fetch(new URL(`/api/console/${path}`, window.location.origin).toString(), { headers });
  };
  const detail = async (r: Response) => {
    const text = await r.text();
    try { const d = JSON.parse(text).detail; return typeof d === "string" ? d : text; } catch { return text; }
  };
  let response = await fetchIt();
  if (response.status === 403 && reauthPrompt) {
    const why = await detail(response);
    if (why !== "reauth_required") throw new ApiError(403, why);
    reauthToken = null;  // sensitive download (a customer export): confirm the password, then try again
    if (!(await reauthPrompt())) throw new ApiError(403, why);
    response = await fetchIt();
  }
  if (!response.ok) throw new ApiError(response.status, (await detail(response)) || "Download failed");
  const disposition = response.headers.get("Content-Disposition") || "";
  const name = /filename="?([^";]+)"?/.exec(disposition)?.[1] || fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
