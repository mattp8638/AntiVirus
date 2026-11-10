// Deploy agents from the tools MSPs already have: any RMM (Itarian, Level, NinjaOne...), Group Policy or Intune.
// One deployment token per customer; scripts are idempotent and return exit codes an RMM understands.
import { useState } from "react";
import { api, getToken } from "../api";
import { useApp } from "../app-context";
import { GroupSelect } from "./Groups";
import { TenantSelect, useAction } from "./ui";

interface Deployment {
  id: string; label: string; expiresAt: string; token: string; windowsPowerShell: string; unixShell: string;
  msi: { available: boolean; msiexec: string; gpo: string; intune: string };
}

function CodeBox({ title, text, file }: { title: string; text: string; file: string }) {
  const { run } = useAction();
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = file;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  };
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <b>{title}</b>
        <span className="row" style={{ gap: 6 }}>
          <button className="small" onClick={() => run(() => navigator.clipboard.writeText(text), "Copied")}>Copy</button>
          <button className="small" onClick={download}>Download</button>
        </span>
      </div>
      <pre style={{ maxHeight: 220, overflow: "auto", fontSize: 12 }}>{text}</pre>
    </div>
  );
}

export function RmmDeploy() {
  const { tenantId, can } = useApp();
  const [tenant, setTenant] = useState(tenantId);
  const [groupId, setGroupId] = useState("");
  const [label, setLabel] = useState("RMM deployment");
  const [days, setDays] = useState(90);
  const [made, setMade] = useState<Deployment | null>(null);
  const { run, busy } = useAction();
  if (!can("configure")) return null;
  const create = () => run(() => api<Deployment>("deploy-scripts", { body: { tenantId: tenant, groupId: groupId || null, label, expiresInDays: days } }))
    .then((value) => { if (value) setMade(value); });
  const msi = () => run(async () => {
    if (!made) return;
    const response = await fetch(`/api/console/deploy-scripts/${made.id}/msi`, {
      method: "POST", headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
      body: JSON.stringify({ token: made.token }), cache: "no-store",
    });
    if (!response.ok) throw new Error((await response.json().catch(() => ({})))?.detail || `MSI failed (HTTP ${response.status})`);
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = "FenrirAgent.msi";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  });
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>Deploy from your RMM, Group Policy or Intune</h3>
      <p className="small muted">Already using Itarian, Level, NinjaOne or another RMM? Run this script from it on every device to trial Fenrir
        alongside it. The scripts install the agent quietly as SYSTEM or root, do nothing where it is already installed (safe to schedule), and
        exit 0 on success or 1 on failure. One deployment token covers all of the customer's devices until it expires; revoke it below if it leaks.</p>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end" }}>
        <TenantSelect value={tenant} onChange={(id) => { setTenant(id); setGroupId(""); setMade(null); }} allowAll={false} label="Customer" />
        <label className="field">Device group<GroupSelect tenantId={tenant} value={groupId} onChange={setGroupId} /></label>
        <label className="field">Label<input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} /></label>
        <label className="field">Expires after
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}>{[7, 30, 90, 180, 365].map((d) => <option key={d} value={d}>{d} days</option>)}</select></label>
        <button className="primary" disabled={busy || !tenant} onClick={create}>Create deployment</button>
      </div>
      {made && <>
        <p className="small" style={{ marginTop: 12 }}>Deployment token ending <code>{made.token.slice(-6)}</code>, valid until {new Date(made.expiresAt).toLocaleDateString()}.
          Copy what you need now: the token is not shown again.</p>
        <CodeBox title="Windows: PowerShell (RMM script, Group Policy startup script or Intune platform script)" text={made.windowsPowerShell} file="Install-Fenrir.ps1" />
        <CodeBox title="Linux and macOS: shell script (run as root)" text={made.unixShell} file="install-fenrir.sh" />
        <div style={{ marginTop: 12 }}>
          <b>Windows MSI (Group Policy software installation, Intune line-of-business app)</b>
          <p className="small muted">{made.msi.gpo}<br />{made.msi.intune}<br />Silent install: <code>{made.msi.msiexec}</code><br />
            Removing the MSI leaves the agent in place (it is protected against tampering): remove agents from the console.</p>
          <button disabled={busy || !made.msi.available} onClick={msi} title={made.msi.available ? "" : "The server needs msitools (included in the Docker image)"}>Download MSI</button>
        </div>
      </>}
    </div>
  );
}
