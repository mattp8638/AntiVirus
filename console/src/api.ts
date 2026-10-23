// Thin client for the Fenrir Cloud console API.

const TOKEN_KEY = "fenrir.token";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
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
  if (!response.ok) {
    const detail = data && typeof data === "object" && "detail" in data ? (data as any).detail : text;
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
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

export function money(value: number, currency = "GBP"): string {
  return new Intl.NumberFormat(undefined, { style: "currency", currency }).format(value || 0);
}
