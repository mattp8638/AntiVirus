import { displayValue } from "./DisplayValue";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { useApp } from "../app-context";
import { Modal, TenantSelect, useAction, useData } from "./ui";

// Connect a customer's Microsoft 365 by signing in as one of its administrators.
// "Sign in with Microsoft" (needs the platform's multi-tenant app) redirects to Microsoft and back.
// "Sign in with a code" works with no setup: Fenrir creates its own app registration in the customer's tenant.

export function M365Connect({ onClose, onManual }: { onClose: () => void; onManual: () => void }) {
  const { tenantId, toast } = useApp();
  const { data: options } = useData<any>("m365/signin/options");
  const [customer, setCustomer] = useState(tenantId);
  const [name, setName] = useState("");
  const [signin, setSignin] = useState<any>(null);
  const { run, busy } = useAction();
  const timer = useRef<number | null>(null);

  useEffect(() => () => { if (timer.current) window.clearTimeout(timer.current); }, []);
  useEffect(() => {
    if (!signin || signin.mode !== "device" || !["pending", "provisioning"].includes(signin.status)) return;
    timer.current = window.setTimeout(async () => {
      try {
        const next = await api<any>(`m365/signin/${signin.id}`);
        setSignin(next);
        if (next.status === "completed") { toast("Microsoft 365 connected. The first sync can take a minute while Microsoft applies the permissions."); onClose(); }
      } catch { /* keep polling */ }
    }, Math.max(2, signin.interval || 5) * 1000);
  }, [signin]);

  const start = async (mode: "device" | "redirect") => {
    const result = await run(() => api<any>("m365/signin", { body: { tenantId: customer, name, mode } }));
    if (!result) return;
    if (mode === "redirect") window.location.href = result.authorizeUrl;
    else setSignin(result);
  };

  return (
    <Modal title="Connect Microsoft 365" onClose={onClose} wide>
      {!signin && <>
        <p>Sign in as a <b>Global Administrator</b> of the customer's Microsoft 365. Fenrir gets read access to users, licences, Secure Score and
          MFA status, plus the account actions you run from here. No mail or files.</p>
        <label className="field">Customer<TenantSelect value={customer} onChange={setCustomer} allowAll={false} /></label>
        <label className="field">Name (optional)<input value={name} onChange={(e) => setName(e.target.value)} placeholder="Defaults to the Microsoft tenant name" /></label>
        <div className="grid k2" style={{ marginTop: 12 }}>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Sign in with Microsoft</h3>
            <p className="small muted">Uses your Fenrir app registration. A normal Microsoft sign-in, then Microsoft asks the admin to approve Fenrir's access.</p>
            {options?.redirect
              ? <button className="primary" disabled={busy || !customer} onClick={() => start("redirect")}>Sign in with Microsoft</button>
              : <p className="small">Not set up on this server. Register a multi-tenant app in your own Entra tenant, add these redirect URIs, and set
                  FENRIR_M365_CLIENT_ID and FENRIR_M365_CLIENT_SECRET:
                  {(options?.redirectUris || []).map((u: string) => <code key={u} className="mono" style={{ display: "block" }}>{u}</code>)}</p>}
          </div>
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Sign in with a code</h3>
            <p className="small muted">No setup. You enter a code at microsoft.com/devicelogin; Fenrir then creates its own app in the customer's tenant,
              grants it only the permissions below and keeps the secret encrypted.</p>
            <button className={options?.redirect ? "" : "primary"} disabled={busy || !customer} onClick={() => start("device")}>Get a sign-in code</button>
          </div>
        </div>
        <details style={{ marginTop: 12 }}><summary className="small">Permissions Fenrir asks for</summary>
          <div className="row small" style={{ flexWrap: "wrap" }}>{(options?.permissions || []).map((p: string) => <span key={p} className="chip mono">{p}</span>)}</div>
        </details>
        <p className="small" style={{ marginTop: 12 }}>Already have an app registration? <button className="link" onClick={onManual}>Enter its details instead</button></p>
      </>}
      {signin && signin.mode === "device" && (
        <div style={{ textAlign: "center", padding: "12px 0" }}>
          {signin.status === "pending" && <>
            <p>1. Open <a href={signin.verificationUri} target="_blank" rel="noreferrer"><b>{displayValue(signin.verificationUri)}</b></a></p>
            <p>2. Enter this code and sign in as the customer's administrator:</p>
            <div className="mono" style={{ fontSize: 32, letterSpacing: 4, margin: "12px 0" }}>{displayValue(signin.userCode)}</div>
            <button className="small" onClick={() => navigator.clipboard?.writeText(signin.userCode)}>Copy code</button>
            <p className="small muted" style={{ marginTop: 12 }}>Waiting for you to sign in… This window updates by itself.</p>
          </>}
          {signin.status === "provisioning" && <p>Signed in. Creating the Fenrir app in Microsoft 365 and granting its permissions…</p>}
          {["failed", "expired"].includes(signin.status) && <>
            <p style={{ color: "#fca5a5" }}>{displayValue(signin.error || "The sign-in did not complete.")}</p>
            <button className="primary" onClick={() => setSignin(null)}>Try again</button>
          </>}
        </div>
      )}
    </Modal>
  );
}
