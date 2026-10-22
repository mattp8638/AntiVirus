import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { api, getToken, setToken, setUnauthorizedHandler } from "./api";

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
  user: { id: string; email: string; name: string; role: string; tenantId: string };
  permissions: string[];
  tenants: Tenant[];
}

interface Ctx {
  me: Me | null;
  loading: boolean;
  tenantId: string;
  setTenantId: (id: string) => void;
  tenantName: (id?: string | null) => string;
  can: (permission: string) => boolean;
  login: (email: string, password: string) => Promise<void>;
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

  const logout = useCallback(() => {
    setToken(null);
    setMe(null);
  }, []);

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
    setUnauthorizedHandler(logout);
    refreshMe();
  }, [logout, refreshMe]);

  const login = async (email: string, password: string) => {
    const result = await api<{ token: string }>("auth/login", { body: { email, password } });
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
