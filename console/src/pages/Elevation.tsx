import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, Table, useAction, useListData } from "../components/ui";

const TONE: Record<string, string> = { pending: "warn", approved: "blue", granted: "good", denied: "muted", expired: "muted", revoked: "muted", failed: "bad" };

interface Request {
  id: string; deviceId: string; hostname: string; user: string; reason: string; minutes: number; status: string;
  decidedBy: string; note: string; createdAt: string; decidedAt: string | null; expiresAt: string | null;
}

// Temporary local admin rights that users ask for from the agent window (Privilege management → Elevation requests).
export default function Elevation() {
  const { tenantId, can } = useApp();
  const [onlyPending, setOnlyPending] = useState(true);
  const { data, error, reload } = useListData<Request>("elevation-requests", { tenant_id: tenantId, status: onlyPending ? "pending" : "" }, [onlyPending]);
  const { run, busy } = useAction();

  const approve = async (r: Request) => {
    const input = window.prompt(`Give ${r.user} admin rights on ${r.hostname} for how many minutes? (5–480)`, String(r.minutes));
    if (input === null) return;
    const minutes = Number.parseInt(input, 10);
    if (!Number.isFinite(minutes) || minutes < 5 || minutes > 480) { window.alert("Enter a number of minutes between 5 and 480."); return; }
    await run(() => api(`elevation-requests/${r.id}/approve`, { method: "POST", body: { minutes } }), "Approved; the device grants access at its next check-in");
    reload();
  };
  const deny = async (r: Request) => {
    const note = window.prompt("Reason for the user (optional)", "") ?? null;
    if (note === null) return;
    await run(() => api(`elevation-requests/${r.id}/deny`, { method: "POST", body: { note } }), "Request denied");
    reload();
  };
  const revoke = async (r: Request) => {
    if (!window.confirm(`Remove ${r.user}'s admin rights on ${r.hostname} now?`)) return;
    await run(() => api(`elevation-requests/${r.id}/revoke`, { method: "POST" }), "Admin rights will be removed at the next check-in");
    reload();
  };

  return (
    <>
      <PageHead title="Admin access requests"
                subtitle="Users ask for temporary local admin rights from the agent window. Approved users are added to the device's Administrators group for the time you choose and removed automatically afterwards."
                actions={<label className="small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input type="checkbox" checked={onlyPending} onChange={(e) => setOnlyPending(e.target.checked)} /> Waiting for a decision only</label>} />
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data} empty={onlyPending ? "No requests are waiting." : "No requests yet. Turn on Privilege management → Elevation requests in a policy to let users ask."}
               columns={[
                 { key: "status", label: "Status", render: (r) => <><Pill value={r.status} tone={TONE[r.status]} />{r.note && <div className="small muted">{r.note}</div>}</> },
                 { key: "user", label: "User", render: (r) => <><b>{r.user}</b><div className="small muted">{r.reason || "No reason given"}</div></> },
                 { key: "hostname", label: "Device", render: (r) => <Link to={`/devices/${r.deviceId}`}>{r.hostname}</Link> },
                 { key: "createdAt", label: "Asked", render: (r) => ago(r.createdAt) },
                 { key: "minutes", label: "Length", render: (r) => r.expiresAt ? <>until {fmtTime(r.expiresAt)}</> : `${r.minutes} min` },
                 { key: "decidedBy", label: "Decided by", render: (r) => r.decidedBy || "" },
                 { key: "actions", label: "", className: "right", render: (r) => (
                   <span style={{ display: "inline-flex", gap: 6 }}>
                     {r.status === "pending" && can("configure") && <button className="primary" disabled={busy} onClick={() => approve(r)}>Approve</button>}
                     {r.status === "pending" && can("respond") && <button disabled={busy} onClick={() => deny(r)}>Deny</button>}
                     {(r.status === "granted" || r.status === "approved") && can("configure") && <button className="danger" disabled={busy} onClick={() => revoke(r)}>Revoke</button>}
                   </span>) },
               ]} />
      </div>
    </>
  );
}
