import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "./api";
import { passkeyResponse } from "./passkeys";

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  kind: string;
  plan: string;
  parentId: string | null;
  defaultPolicyId: string | null;
}

export interface Me {
  user: { id: string; email: string; name: string; role: string; tenantId: string; mfaEnabled?: boolean };
  permissions: string[];
  tenants: Tenant[];
  mfaSetupRequired?: boolean;  // the MSP requires MFA and this account has not enrolled yet
  emergencyStop?: { active: boolean; by: string; reason: string; at: string } | null;
  passkeys?: number;  // how many passkeys this account has registered
  sessionIdleMinutes?: number;  // signed out after this long without keyboard or mouse use (0: never)
}

interface Ctx {
  me: Me | null;
  loading: boolean;
  tenantId: string;
  setTenantId: (id: string) => void;
  tenantName: (id?: string | null) => string;
  can: (permission: string) => boolean;
  login: (email: string, password: string, code?: string) => Promise<void>;
  completeSso: (handoff: string) => Promise<void>;
  loginWithPasskey: () => Promise<void>;
  logout: () => void;
  refreshMe: () => Promise<void>;
  toast: (message: string, error?: boolean) => void;
}

const AppContext = createContext<Ctx | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [tenantId, setTenantIdState] = useState<string>(() => {
    try {
      return localStorage.getItem("fenrir.tenant") ?? "";
    } catch {
      return "";
    }
  });
  const [toastState, setToastState] = useState<{ message: string; error: boolean } | null>(null);

  const clearSession = useCallback(() => {
    setToken(null);
    setMe(null);
  }, []);
  // Signing out ends the session on the server too, so the token is dead even if it was copied.
  const logout = useCallback(() => {
    const token = getToken();
    if (token) {
      fetch("/api/console/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } }).catch(() => {});
    }
    clearSession();
  }, [clearSession]);

  const refreshMe = useCallback(async () => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    try {
      setMe(await api<Me>("auth/me"));
    } catch {
      setToken(null);
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(clearSession);
    refreshMe();
  }, [clearSession, refreshMe]);

  // Sign out after the configured time without keyboard, mouse or touch use in any open console tab. The server
  // ends idle sessions too, but the console's own background refreshes would otherwise keep them alive.
  const idleMinutes = me?.sessionIdleMinutes ?? 0;
  useEffect(() => {
    if (!me || idleMinutes <= 0) return;
    const key = "fenrir.activity";
    let last = Date.now();
    const mark = () => {
      const now = Date.now();
      if (now - last < 5000) return;
      last = now;
      try { localStorage.setItem(key, String(now)); } catch { /* private window */ }
    };
    const events = ["keydown", "pointerdown", "pointermove", "wheel", "touchstart"] as const;
    events.forEach((name) => window.addEventListener(name, mark, { passive: true }));
    mark();
    const timer = window.setInterval(() => {
      let shared = last;
      try { shared = Math.max(last, Number(localStorage.getItem(key)) || 0); } catch { /* ignore */ }
      if (Date.now() - shared > idleMinutes * 60_000) {
        logout();
        setToastState({ message: `Signed out after ${idleMinutes} minutes without use.`, error: false });
      }
    }, 30_000);
    return () => {
      events.forEach((name) => window.removeEventListener(name, mark));
      window.clearInterval(timer);
    };
  }, [me, idleMinutes, logout]);

  // Microsoft sign-in returns with a one-minute, single-use code; swap it for the session token.
  const completeSso = async (handoff: string) => {
    const result = await api<{ token: string }>("auth/sso/complete", { body: { handoff } });
    setToken(result.token);
    await refreshMe();
  };

  // A passkey is the password and the second factor in one, so no code is asked for afterwards.
  const loginWithPasskey = async () => {
    const result = await api<{ token: string }>("auth/passkey/login", { body: await passkeyResponse() });
    setToken(result.token);
    await refreshMe();
  };

  const login = async (email: string, password: string, code?: string) => {
    const result = await api<{ token: string }>("auth/login", { body: { email, password, ...(code ? { code } : {}) } });
    setToken(result.token);
    await refreshMe();
  };

  const setTenantId = (id: string) => {
    setTenantIdState(id);
    try {
      localStorage.setItem("fenrir.tenant", id);
    } catch {
      /* ignore */
    }
  };

  const toast = (message: string, error = false) => {
    setToastState({ message, error });
    window.setTimeout(() => setToastState(null), 4500);
  };

  const value: Ctx = {
    me,
    loading,
    tenantId,
    setTenantId,
    tenantName: (id) => me?.tenants.find((t) => t.id === id)?.name ?? (id ? "Unknown tenant" : "Global"),
    can: (permission) => !!me?.permissions.includes(permission),
    login,
    completeSso,
    loginWithPasskey,
    logout,
    refreshMe,
    toast,
  };

  return (
    <AppContext.Provider value={value}>
      {children}
      {toastState && <div className={`toast ${toastState.error ? "error" : ""}`}>{toastState.message}</div>}
    </AppContext.Provider>
  );
}

export function useApp(): Ctx {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp outside provider");
  return ctx;
}
