import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Table, useAction, useListData } from "../components/ui";
import { confirmDialog, promptDialog, noticeDialog } from "../components/dialogs";

const TONE: Record<string, string> = { pending: "warn", approved: "blue", granted: "good", denied: "muted", expired: "muted", revoked: "muted", failed: "bad", ended: "muted" };
const EVENT_LABEL: Record<string, string> = { requested: "Requested", approved: "Approved", denied: "Denied", granted: "Temporary admin account created",
  launched: "Program started as the temporary admin", ended: "Account removed", revoked: "Revoked", failed: "Failed" };

interface Request {
  id: string; deviceId: string; hostname: string; user: string; userSid: string; reason: string; minutes: number; status: string;
  decidedBy: string; note: string; createdAt: string; decidedAt: string | null; expiresAt: string | null; kind: "session" | "run";
  target: string; arguments: string; account: string; grantedAt: string | null; endedAt: string | null; endReason: string;
  events: { at: string; type: string; by: string; [key: string]: unknown }[];
}

// Temporary local admin rights that users ask for from the agent window (Privilege management → Elevation requests).
export default function Elevation() {
  const { tenantId, can } = useApp();
  const [onlyPending, setOnlyPending] = useState(true);
  const { data, error, reload } = useListData<Request>("elevation-requests", { tenant_id: tenantId, status: onlyPending ? "pending" : "" }, [onlyPending]);
  const { run, busy } = useAction();
  const [open, setOpen] = useState<Request | null>(null);

  const approve = async (r: Request) => {
    const what = r.kind === "run" ? `run ${r.target.split("\\").pop()} as a temporary administrator` : "a temporary administrator account";
    const input = await promptDialog(`Give ${r.user} ${what} on ${r.hostname} for how many minutes? (5–480)`, String(r.minutes),
                                    { title: "Approve admin access", inputMode: "numeric", required: true });
    if (input === null) return;
    const minutes = Number.parseInt(input, 10);
    if (!Number.isFinite(minutes) || minutes < 5 || minutes > 480) { noticeDialog("Enter a number of minutes between 5 and 480."); return; }
    await run(() => api(`elevation-requests/${r.id}/approve`, { method: "POST", body: { minutes } }), "Approved; the device creates the temporary admin account at its next check-in");
    reload();
  };
  const deny = async (r: Request) => {
    const note = await promptDialog("Reason for the user (optional)", "", { title: `Deny ${r.user}'s request` });
    if (note === null) return;
    await run(() => api(`elevation-requests/${r.id}/deny`, { method: "POST", body: { note } }), "Request denied");
    reload();
  };
  const revoke = async (r: Request) => {
    if (!await confirmDialog(`End ${r.user}'s admin session on ${r.hostname} now? The temporary admin account is deleted.`)) return;
    await run(() => api(`elevation-requests/${r.id}/revoke`, { method: "POST" }), "The temporary admin account is deleted at the next check-in");
    reload();
  };

  return (
    <>
      <PageHead title="Admin access requests"
                subtitle="Users ask for admin access, or to run one program as an administrator, from the agent window or the PAM tray. Each approval creates a temporary local administrator account for that user, which is deleted when the time is up, the program closes or the user is done. Every step is recorded against the device and the user."
                actions={<label className="small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input type="checkbox" checked={onlyPending} onChange={(e) => setOnlyPending(e.target.checked)} /> Waiting for a decision only</label>} />
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data} onRow={setOpen} empty={onlyPending ? "No requests are waiting." : "No requests yet. Turn on Privilege management → Elevation requests in a policy to let users ask."}
               columns={[
                 { key: "status", label: "Status", render: (r) => <><Pill value={r.status} tone={TONE[r.status]} />{r.note && <div className="small muted">{r.note}</div>}</> },
                 { key: "user", label: "User", render: (r) => <><b>{r.user}</b><div className="small muted">{r.reason || "No reason given"}</div></> },
                 { key: "kind", label: "For", render: (r) => r.kind === "run" ? <span className="small mono">{displayValue(r.target.split("\\").pop())}</span> : <span className="small">Admin access</span> },
                 { key: "account", label: "Temporary admin", render: (r) => r.account ? <span className="mono small">{r.account}</span> : <span className="muted small">{r.status === "granted" ? "already an admin" : "-"}</span> },
                 { key: "hostname", label: "Device", render: (r) => <Link to={`/devices/${r.deviceId}`}>{r.hostname}</Link> },
                 { key: "createdAt", label: "Asked", render: (r) => ago(r.createdAt) },
                 { key: "minutes", label: "Length", render: (r) => r.endedAt ? <>ended {fmtTime(r.endedAt)}<div className="small muted">{r.endReason}</div></> : r.expiresAt ? <>until {fmtTime(r.expiresAt)}</> : `${r.minutes} min` },
                 { key: "decidedBy", label: "Decided by", render: (r) => r.decidedBy || "" },
                 { key: "actions", label: "", className: "right", render: (r) => (
                   <span style={{ display: "inline-flex", gap: 6 }}>
                     {r.status === "pending" && can("configure") && <button className="primary" disabled={busy} onClick={() => approve(r)}>Approve</button>}
                     {r.status === "pending" && can("respond") && <button disabled={busy} onClick={() => deny(r)}>Deny</button>}
                     {(r.status === "granted" || r.status === "approved") && can("configure") && <button className="danger" disabled={busy} onClick={() => revoke(r)}>Revoke</button>}
                   </span>) },
               ]} />
      </div>
      {open && (
        <Modal title={`${open.user} on ${open.hostname}`} onClose={() => setOpen(null)}>
          <p className="small muted">{open.kind === "run" ? <>Run <span className="mono">{open.target}</span> {open.arguments}</> : "Admin access"} · {open.reason || "No reason given"} · user SID <span className="mono">{open.userSid}</span></p>
          <Table rows={(open.events || []).map((e, i) => ({ ...e, id: i }))} empty="No activity recorded."
                 columns={[{ key: "at", label: "When", render: (e) => fmtTime(String(e.at)) },
                           { key: "type", label: "What", render: (e) => <b>{EVENT_LABEL[String(e.type)] || String(e.type)}</b> },
                           { key: "by", label: "By", render: (e) => <span className="small">{String(e.by)}</span> },
                           { key: "detail", label: "Detail", render: (e) => {
                             const ev = e as Record<string, unknown>;
                             return <span className="small mono">{["account", "target", "reason", "minutes", "note", "error", "pid"]
                               .filter((k) => ev[k] !== undefined && ev[k] !== null && ev[k] !== "").map((k) => `${k}: ${String(ev[k])}`).join(" · ")}</span>;
                           } }]} />
          <p className="small muted">The same steps are in the audit log, under this device and user.</p>
        </Modal>
      )}
    </>
  );
}
