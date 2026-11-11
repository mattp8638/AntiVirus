// The MSP's brand (Settings › Branding): name, logo and colours on the sign-in page, the menu, page titles and buttons.
// Loaded from the public /api/console/auth/branding before sign-in, and remembered so the next visit starts branded.
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

export interface Brand {
  companyName: string;
  tagline: string;
  primaryColour: string;
  accentColour: string;
  onPrimary: string;
  logoUrl: string | null;
  demo?: { login?: string; resets?: string } | null;  // set on a read-only public demo
}

export const DEFAULT_BRAND: Brand = {
  companyName: "Fenrir", tagline: "Unified security platform", primaryColour: "#3b82f6", accentColour: "#a855f7",
  onPrimary: "#ffffff", logoUrl: null,
};
const STORE = "fenrir.brand";
const COLOUR = /^#[0-9a-fA-F]{6}$/;

function remembered(): Brand {
  try {
    const value = JSON.parse(localStorage.getItem(STORE) || "null");
    return value && typeof value === "object" ? { ...DEFAULT_BRAND, ...value } : DEFAULT_BRAND;
  } catch {
    return DEFAULT_BRAND;
  }
}

export function applyBrand(brand: Brand) {
  const root = document.documentElement.style;
  if (COLOUR.test(brand.primaryColour)) root.setProperty("--blue", brand.primaryColour);
  if (COLOUR.test(brand.accentColour)) root.setProperty("--purple", brand.accentColour);
  if (COLOUR.test(brand.onPrimary)) root.setProperty("--on-primary", brand.onPrimary);
  document.title = brand.companyName;
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", brand.primaryColour);
}

const Ctx = createContext<{ brand: Brand; reload: () => void }>({ brand: DEFAULT_BRAND, reload: () => undefined });

export function BrandProvider({ children }: { children: ReactNode }) {
  const [brand, setBrand] = useState<Brand>(remembered);
  const reload = useCallback(() => {
    fetch("/api/console/auth/branding")
      .then((r) => (r.ok ? r.json() : null))
      .then((value: Brand | null) => {
        if (!value) return;
        const next = { ...DEFAULT_BRAND, ...value };
        setBrand(next);
        try { localStorage.setItem(STORE, JSON.stringify(next)); } catch { /* storage unavailable */ }
      })
      .catch(() => undefined);
  }, []);
  useEffect(() => { reload(); }, [reload]);
  useEffect(() => { applyBrand(brand); }, [brand]);
  return <Ctx.Provider value={{ brand, reload }}>{children}</Ctx.Provider>;
}

export function useBrand() {
  return useContext(Ctx);
}

// The logo, or the first letter of the name on the brand colour when there is no logo.
export function BrandMark({ size = 34 }: { size?: number }) {
  const { brand } = useBrand();
  const [broken, setBroken] = useState(false);
  if (brand.logoUrl && !broken) {
    return <img src={brand.logoUrl} alt="" onError={() => setBroken(true)}
                style={{ maxHeight: size, maxWidth: size * 4, objectFit: "contain", display: "block" }} />;
  }
  return <div className="brand-mark" style={{ width: size, height: size }} aria-hidden>{brand.companyName.slice(0, 1).toUpperCase()}</div>;
}

export function BrandTitle({ suffix }: { suffix?: string }) {
  const { brand } = useBrand();
  return <div><b>{brand.companyName}{suffix ? ` ${suffix}` : ""}</b><small>{brand.tagline}</small></div>;
}

// Sign-in page and menu header: a logo on its own (it normally carries the name), else the mark and the name.
export function BrandHeader({ size = 34 }: { size?: number }) {
  const { brand } = useBrand();
  const [broken, setBroken] = useState(false);
  if (brand.logoUrl && !broken) {
    return (
      <div style={{ minWidth: 0, flex: 1 }}>
        <img src={brand.logoUrl} alt={brand.companyName} onError={() => setBroken(true)}
             style={{ maxHeight: size + 6, maxWidth: "100%", objectFit: "contain", display: "block" }} />
        <small style={{ display: "block", marginTop: 4 }}>{brand.tagline}</small>
      </div>
    );
  }
  return <><BrandMark size={size} /><BrandTitle /></>;
}
