// Settings › Branding: the MSP's name, logo, colours and contact details on reports, the console and the agent window.
import { useEffect, useState } from "react";
import { api } from "../api";
import { useBrand } from "../brand";
import { ErrorNote, useAction, useData } from "./ui";

interface BrandSettings {
  companyName: string; tagline: string; primaryColour: string; accentColour: string; onPrimary: string;
  supportEmail: string; supportPhone: string; website: string; reportFooter: string; logoUrl: string | null; logoDataUrl: string | null; editable: boolean;
}

const FIELDS: { key: keyof BrandSettings; label: string; max: number; hint?: string; type?: string }[] = [
  { key: "companyName", label: "Company name", max: 80, hint: "Shown on reports, the sign-in page, the menu and the Windows agent window." },
  { key: "tagline", label: "Tagline", max: 120, hint: "Under the name on the sign-in page and menu." },
  { key: "supportEmail", label: "Support email", max: 200, type: "email" },
  { key: "supportPhone", label: "Support phone", max: 40 },
  { key: "website", label: "Website", max: 200, hint: "Starts with https://" },
  { key: "reportFooter", label: "Report footer", max: 400, hint: "For example a confidentiality line. Printed at the bottom of every report page." },
];

function readFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Could not read the file"));
    reader.readAsDataURL(file);
  });
}

export function BrandingSettings() {
  const { data, error, reload } = useData<BrandSettings>("branding");
  const { reload: reloadBrand } = useBrand();
  const [form, setForm] = useState<BrandSettings | null>(null);
  const { run, busy } = useAction();
  useEffect(() => { if (data) setForm(data); }, [data]);
  if (error) return <ErrorNote error={error} />;
  if (!form || !data) return <div className="empty">Loading…</div>;
  const editable = data.editable;
  const done = () => { reload(); reloadBrand(); };
  const save = () => run(() => api("branding", { method: "PUT", body: {
    companyName: form.companyName, tagline: form.tagline, primaryColour: form.primaryColour, accentColour: form.accentColour,
    supportEmail: form.supportEmail, supportPhone: form.supportPhone, website: form.website, reportFooter: form.reportFooter,
  } }), "Branding saved").then((ok) => { if (ok) done(); });
  const upload = async (file: File | undefined) => {
    if (!file) return;
    if (!/^image\/(png|jpeg)$/.test(file.type)) { await run(async () => { throw new Error("Choose a PNG or JPEG image"); }); return; }
    if (file.size > 2 * 1024 * 1024) { await run(async () => { throw new Error("The logo must be at most 2 MB"); }); return; }
    if (await run(async () => api("branding/logo", { method: "PUT", body: { data: await readFile(file) } }), "Logo saved")) done();
  };
  return (
    <div className="grid k2" style={{ alignItems: "start" }}>
      <div className="card">
        <h3>Brand</h3>
        {!editable && <p className="small muted">Your MSP manages this branding.</p>}
        <div className="form-grid">
          {FIELDS.map((f) => (
            <label key={f.key} className="field">{f.label}
              {f.key === "reportFooter"
                ? <textarea rows={2} maxLength={f.max} disabled={!editable} value={String(form[f.key] ?? "")}
                            onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />
                : <input type={f.type || "text"} maxLength={f.max} disabled={!editable} value={String(form[f.key] ?? "")}
                         onChange={(e) => setForm({ ...form, [f.key]: e.target.value })} />}
              {f.hint && <span className="small muted">{f.hint}</span>}
            </label>
          ))}
          <label className="field">Main colour
            <span className="row" style={{ gap: 8 }}>
              <input type="color" disabled={!editable} value={form.primaryColour} onChange={(e) => setForm({ ...form, primaryColour: e.target.value })} aria-label="Main colour picker" />
              <input disabled={!editable} value={form.primaryColour} maxLength={7} onChange={(e) => setForm({ ...form, primaryColour: e.target.value })} />
            </span>
            <span className="small muted">Buttons, headings and report accents.</span>
          </label>
          <label className="field">Accent colour
            <span className="row" style={{ gap: 8 }}>
              <input type="color" disabled={!editable} value={form.accentColour} onChange={(e) => setForm({ ...form, accentColour: e.target.value })} aria-label="Accent colour picker" />
              <input disabled={!editable} value={form.accentColour} maxLength={7} onChange={(e) => setForm({ ...form, accentColour: e.target.value })} />
            </span>
          </label>
        </div>
        {editable && <button className="primary" style={{ marginTop: 12 }} disabled={busy} onClick={save}>Save branding</button>}
      </div>
      <div className="card">
        <h3>Logo</h3>
        <p className="small muted">PNG or JPEG, up to 2 MB. It is resized to fit 600 × 200 pixels. A wide logo on a transparent background works best.</p>
        <div style={{ background: "#fff", borderRadius: 10, padding: 16, minHeight: 80, display: "grid", placeItems: "center" }}>
          {data.logoDataUrl ? <img src={data.logoDataUrl} alt="Current logo" style={{ maxHeight: 64, maxWidth: "100%" }} /> : <span className="small" style={{ color: "#5b6675" }}>No logo yet</span>}
        </div>
        {editable && <div className="row" style={{ gap: 8, marginTop: 12 }}>
          <label className="btn">Upload logo<input type="file" accept="image/png,image/jpeg" hidden onChange={(e) => { upload(e.target.files?.[0]); e.target.value = ""; }} /></label>
          {data.logoUrl && <button className="ghost" disabled={busy} onClick={() => run(() => api("branding/logo", { method: "DELETE" }), "Logo removed").then((ok) => { if (ok) done(); })}>Remove</button>}
        </div>}
        <h3 style={{ marginTop: 20 }}>Preview</h3>
        <div style={{ background: "#fff", color: "#1b2430", borderRadius: 10, padding: 16 }}>
          <div className="row" style={{ gap: 12, paddingBottom: 10, borderBottom: `4px solid ${form.primaryColour}` }}>
            {data.logoDataUrl ? <img src={data.logoDataUrl} alt="" style={{ maxHeight: 36, maxWidth: 160 }} />
              : <div style={{ width: 36, height: 36, borderRadius: 8, background: form.primaryColour, color: data.onPrimary, display: "grid", placeItems: "center", fontWeight: 800 }}>{form.companyName.slice(0, 1)}</div>}
            <b>{form.companyName}</b>
          </div>
          <h4 style={{ margin: "12px 0 4px", borderLeft: `4px solid ${form.primaryColour}`, paddingLeft: 8 }}>Security report: Example Ltd</h4>
          <div style={{ border: "1px solid #dde3ea", borderTop: `3px solid ${form.primaryColour}`, borderRadius: 8, padding: 10, width: 140, marginTop: 8 }}>
            <b style={{ color: form.primaryColour, fontSize: 22, display: "block" }}>42</b><span className="small" style={{ color: "#5b6675" }}>protected devices</span>
          </div>
          <div className="small" style={{ color: "#5b6675", marginTop: 12 }}>
            {[form.reportFooter, [form.supportEmail, form.supportPhone, form.website].filter(Boolean).join(" · ")].filter(Boolean).map((line) => <div key={line}>{line}</div>)}
          </div>
        </div>
      </div>
    </div>
  );
}
