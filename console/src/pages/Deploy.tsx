import { displayValue } from "../components/DisplayValue";
import { useEffect, useState } from "react";
import { fmtTime, getToken } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Table, TenantSelect, useData, useListData } from "../components/ui";
import { AddPhone } from "./AddPhone";

type OsName = "windows" | "linux" | "macos";
type InstallerStatus = Record<OsName, { ready: boolean; reason: string; extension: string; mode?: string; warning?: string; certificateUrl?: string }>;

const OS_LABEL: Record<OsName, string> = { windows: "Windows", linux: "Linux", macos: "macOS" };

export default function Deploy() {
  const { tenantId, tenantName, can } = useApp();
  const [target, setTarget] = useState(tenantId);
  const [os, setOs] = useState<OsName>("linux");
  const [label, setLabel] = useState("Rollout");
  const [groupId, setGroupId] = useState("");
  const [days, setDays] = useState("30");
  useEffect(() => { setTarget(tenantId); setGroupId(""); }, [tenantId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const { data: status, error: statusError, reload: reloadStatus } = useData<InstallerStatus>("enrollment-installers/status");
  const { data: tokens, error: tokensError, reload } = useListData<any>("enrollment-tokens", { tenant_id: tenantId });
  const { data: groups } = useListData<any>("groups", { tenant_id: target }, [target]);
  const selected = status?.[os];
  const expires = Number(days);

  const generate = async () => {
    if (busy || !target || !selected?.ready) return;
    setBusy(true);
    setError(null);
    setSuccess(null);
    try {
      const bearer = getToken();
      if (!bearer) throw new Error("Your session has expired. Sign in again.");
      const response = await fetch("/api/console/enrollment-installers", {
        method: "POST",
        headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
        body: JSON.stringify({ os, tenantId: target, groupId: groupId || null, label, expiresInDays: expires }),
        cache: "no-store",
      });
      if (!response.ok) {
        let reason = `Installer generation failed (HTTP ${response.status}).`;
        try {
          const body = await response.json();
          if (typeof body?.detail === "string") reason = body.detail;
        } catch { /* retain status-based message */ }
        throw new Error(reason);
      }
      const file = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const filename = /filename="([A-Za-z0-9._-]+)"/.exec(disposition)?.[1]
        || (os === "windows" ? "FenrirSetup.exe" : "Install-Fenrir-Linux.sh");
      const url = URL.createObjectURL(file);
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally {
        window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
      }
      setSuccess(`${OS_LABEL[os]} deployment package downloaded. It contains a customer enrollment secret—store it securely and remove it after installation. The enrollment token is listed below and can be revoked.`);
      reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHead title="Deploy agents" subtitle="Select an operating system and customer, then generate an enrollment-ready installation download." />
      {can("configure") && (
        <div className="card">
          <h3>Generate an agent installer</h3>
          <div className="form-grid">
            <label className="field">Operating system
              <select value={os} onChange={(e) => { setOs(e.target.value as OsName); setError(null); setSuccess(null); }}>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
              </select>
            </label>
            <label className="field">Customer / tenant
              <TenantSelect value={target} onChange={(value) => { setTarget(value); setGroupId(""); }} allowAll={false} />
            </label>
            <label className="field">Deployment label
              <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={200} />
            </label>
            <label className="field">Place devices in group
              <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                <option value="">None</option>
                {groups?.map((g) => <option key={g.id} value={g.id}>{displayValue(g.name)}</option>)}
              </select>
            </label>
            <label className="field">Token expiry (days, 1–365)
              <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />
            </label>
          </div>
          <div style={{ marginTop: 12 }}>
            {selected?.ready ? (
              <p>Ready: download the {OS_LABEL[os]} installer {selected.extension}. Install it on the target device with administrator privileges.</p>
            ) : (
              <p role="status" style={{ color: "#fbbf24" }}>
                {selected?.reason || "Checking installer availability…"}{" "}
                <button className="small" onClick={reloadStatus}>Refresh availability</button>
              </p>
            )}
            {selected?.warning && <p role="alert" style={{ color: "#fbbf24", fontWeight: 700 }}>{selected.warning}</p>}
            {selected?.certificateUrl && <p className="small"><a href={selected.certificateUrl} download>Download the code-signing certificate (.cer)</a> to deploy it to devices.</p>}
            <ErrorNote error={statusError || error} />
            {success && <div role="status" className="card">{success}</div>}
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="primary" disabled={busy || !selected?.ready || !target || !Number.isInteger(expires) || expires < 1 || expires > 365}
                    onClick={generate}>{busy ? "Generating installer…" : `Generate & download ${OS_LABEL[os]} installer`}</button>
          </div>
          <p style={{ marginTop: 12 }}>Every download creates a new customer-bound enrollment token. Treat downloaded files as credentials. Windows components are built automatically on the server; each request creates a self-contained customer installer; macOS stays unavailable until its installable agent is complete.</p>
        </div>
      )}
      <AddPhone />
      <div className="card">
        <h3>Enrollment tokens</h3>
        <ErrorNote error={tokensError} />
        <Table rows={tokens} empty="No enrollment tokens yet."
               columns={[{ key: "label", label: "Label" }, { key: "tenantId", label: "Tenant", render: (r) => tenantName(r.tenantId) },
                         { key: "tokenHint", label: "Ends with", render: (r) => <span className="mono">…{displayValue(r.tokenHint)}</span> },
                         { key: "uses", label: "Used", render: (r) => `${r.uses}${r.maxUses ? ` / ${r.maxUses}` : ""}` },
                         { key: "expiresAt", label: "Expires", render: (r) => fmtTime(r.expiresAt) },
                         { key: "revoked", label: "", render: (r) => r.revoked ? <Pill value="revoked" tone="muted" /> :
                           can("configure") && <button className="small danger" onClick={async () => {
                             if (!window.confirm("Revoke this enrollment token? Any unused installers containing it will stop enrolling devices.")) return;
                             try {
                               const response = await fetch(`/api/console/enrollment-tokens/${encodeURIComponent(r.id)}`, {
                                 method: "DELETE", headers: { Authorization: `Bearer ${getToken() ?? ""}` },
                               });
                               if (!response.ok) throw new Error("Could not revoke enrollment token.");
                               reload();
                             } catch (err) { setError((err as Error).message); }
                           }}>Revoke</button> }]} />
      </div>
    </>
  );
}
