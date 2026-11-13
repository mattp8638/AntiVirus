import { useState } from "react";
import { Link } from "react-router-dom";
import { ago, api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { displayValue } from "../components/DisplayValue";
import { ErrorNote, Modal, PageHead, Pill, Table, Tabs, useAction, useListData } from "../components/ui";
import { confirmDialog, promptDialog, noticeDialog } from "../components/dialogs";
import { ALLOW_KINDS, AllowanceForm } from "../components/AdminAllowance";

const TONE: Record<string, string> = { pending: "warn", approved: "blue", granted: "good", denied: "muted", expired: "muted", revoked: "muted", failed: "bad", ended: "muted" };
const EVENT_LABEL: Record<string, string> = { requested: "Requested", approved: "Approved", denied: "Denied", granted: "Temporary admin account created",
  launched: "Program started as administrator", ended: "Account removed", revoked: "Revoked", failed: "Failed", expired: "Lapsed" };

interface Request {
  id: string; deviceId: string; hostname: string; user: string; userSid: string; reason: string; minutes: number; status: string;
  decidedBy: string; note: string; createdAt: string; decidedAt: string | null; expiresAt: string | null; kind: "session" | "run";
  target: string; arguments: string; account: string; grantedAt: string | null; endedAt: string | null; endReason: string;
  publisher: string; sha256: string; approvedByRule: string;
  events: { at: string; type: string; by: string; [key: string]: unknown }[];
}

// Temporary local admin rights that users ask for from the agent window (Privilege management → Elevation requests).
export default function Elevation() {
  const [tab, setTab] = useState<"requests" | "allowances">("requests");
  return (
    <>
      <PageHead title="Admin access"
                subtitle="Users ask for admin access, or to run a program as administrator, from the agent window, the PAM tray or Explorer's 'Run as administrator with Fenrir'. Approved programs open already elevated, with no password and no Windows prompt; admin access uses a temporary local administrator account that is removed automatically. Every step is recorded against the device and the user."
                actions={<Tabs tabs={["Requests", "Allowed without approval"]} active={tab === "requests" ? "Requests" : "Allowed without approval"}
                              onChange={(t) => setTab(t === "Requests" ? "requests" : "allowances")} />} />
      {tab === "requests" ? <Requests /> : <Allowances />}
    </>
  );
}

// Standing permissions: these users get admin access straight away, without a technician approving each time.
function Allowances() {
  const { tenantId, can } = useApp();
  const [showEnded, setShowEnded] = useState(false);
  const { data, error, reload } = useListData<any>("elevation-allowances", { tenant_id: tenantId, include_ended: showEnded ? "true" : "" }, [showEnded]);
  const { run, busy } = useAction();
  const [adding, setAdding] = useState(false);
  const revoke = async (a: any) => {
    if (!await confirmDialog(`Stop ${a.anyUser ? "anyone" : a.user} getting admin access without approval?`)) return;
    if (await run(() => api(`elevation-allowances/${a.id}/revoke`, { method: "POST" }), "Allowance removed")) reload();
  };
  return (
    <>
      <ErrorNote error={error} />
      <div className="card">
        <div className="row" style={{ marginBottom: 8 }}>
          <p className="small muted" style={{ flex: 1, margin: 0 }}>Give one from a device (Admin access → Allow admin access without approval), or for
            every device of the selected customer here. Policies can also auto-approve named users, programs and publishers
            (Privilege management).</p>
          <label className="small" style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={showEnded} onChange={(e) => setShowEnded(e.target.checked)} /> Show ended</label>
          {can("configure") && can("approve") && tenantId &&
            <button className="primary" onClick={() => setAdding(true)}>Allow for this customer…</button>}
        </div>
        <Table rows={data} empty="No allowances. Requests follow the policy: approval by a technician, or auto-approve rules."
               columns={[
                 { key: "status", label: "Status", render: (a) => <Pill value={a.status} tone={a.active ? "good" : "muted"} /> },
                 { key: "user", label: "Who", render: (a) => <b>{a.anyUser ? "Anyone signed in" : a.user || a.userSid}</b> },
                 { key: "where", label: "Where", render: (a) => a.deviceId ? <Link to={`/devices/${a.deviceId}`}>{a.hostname || a.deviceId}</Link> : <span className="small">Every device of the customer</span> },
                 { key: "kinds", label: "For", render: (a) => <span className="small">{ALLOW_KINDS[a.kinds] || a.kinds}{a.programs?.length ? `: ${a.programs.join(", ")}` : ""}</span> },
                 { key: "minutes", label: "Each time", render: (a) => `${a.minutes} min` },
                 { key: "expiresAt", label: "Until", render: (a) => a.revokedAt ? `removed ${fmtTime(a.revokedAt)}` : a.expiresAt ? fmtTime(a.expiresAt) : "removed by hand" },
                 { key: "uses", label: "Used", render: (a) => <span className="small">{a.uses}×{a.lastUsedAt ? ` (last ${ago(a.lastUsedAt)})` : ""}</span> },
                 { key: "createdBy", label: "Given by", render: (a) => <><span className="small">{a.createdBy}</span><div className="small muted">{a.note}</div></> },
                 { key: "x", label: "", className: "right", render: (a) => a.active && can("configure") && <button className="danger small" disabled={busy} onClick={() => revoke(a)}>Remove</button> },
               ]} />
      </div>
      {adding && tenantId && <AllowanceForm tenantId={tenantId} onClose={() => setAdding(false)} onSaved={() => { setAdding(false); reload(); }} />}
    </>
  );
}

function Requests() {
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
    await run(() => api(`elevation-requests/${r.id}/approve`, { method: "POST", body: { minutes } }), "Approved; the device sets it up within seconds");
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
    await run(() => api(`elevation-requests/${r.id}/revoke`, { method: "POST" }), "Revoked; the device ends it within seconds");
    reload();
  };

  return (
    <>
      <label className="small" style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 8 }}>
        <input type="checkbox" checked={onlyPending} onChange={(e) => setOnlyPending(e.target.checked)} /> Waiting for a decision only</label>
      <ErrorNote error={error} />
      <div className="card">
        <Table rows={data} onRow={setOpen} empty={onlyPending ? "No requests are waiting." : "No requests yet. Set Privilege management → Admin access requests in a policy, or allow a user from a device."}
               columns={[
                 { key: "status", label: "Status", render: (r) => <><Pill value={r.status} tone={TONE[r.status]} />{r.note && <div className="small muted">{r.note}</div>}</> },
                 { key: "user", label: "User", render: (r) => <><b>{r.user}</b><div className="small muted">{r.reason || "No reason given"}</div></> },
                 { key: "kind", label: "For", render: (r) => r.kind === "run" ? <span className="small mono">{displayValue(r.target.split("\\").pop())}</span> : <span className="small">Admin access</span> },
                 { key: "account", label: "Temporary admin", render: (r) => r.account ? <span className="mono small">{r.account}</span> : <span className="muted small">{r.status === "granted" ? "already an admin" : "-"}</span> },
                 { key: "hostname", label: "Device", render: (r) => <Link to={`/devices/${r.deviceId}`}>{r.hostname}</Link> },
                 { key: "createdAt", label: "Asked", render: (r) => ago(r.createdAt) },
                 { key: "minutes", label: "Length", render: (r) => r.endedAt ? <>ended {fmtTime(r.endedAt)}<div className="small muted">{r.endReason}</div></> : r.expiresAt ? <>until {fmtTime(r.expiresAt)}</> : `${r.minutes} min` },
                 { key: "decidedBy", label: "Decided by", render: (r) => <span className="small">{r.approvedByRule || r.decidedBy || ""}</span> },
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
          {open.kind === "run" && <p className="small muted">Publisher: <b>{open.publisher || "unsigned or not verified"}</b>{open.sha256 && <> · SHA-256 <span className="mono">{open.sha256}</span></>}</p>}
          {open.approvedByRule && <p className="small">Approved automatically: {open.approvedByRule}</p>}
          <Table rows={(open.events || []).map((e, i) => ({ ...e, id: i }))} empty="No activity recorded."
                 columns={[{ key: "at", label: "When", render: (e) => fmtTime(String(e.at)) },
                           { key: "type", label: "What", render: (e) => <b>{EVENT_LABEL[String(e.type)] || String(e.type)}</b> },
                           { key: "by", label: "By", render: (e) => <span className="small">{String(e.by)}</span> },
                           { key: "detail", label: "Detail", render: (e) => {
                             const ev = e as Record<string, unknown>;
                             return <span className="small mono">{["account", "target", "publisher", "rule", "reason", "minutes", "note", "error", "pid"]
                               .filter((k) => ev[k] !== undefined && ev[k] !== null && ev[k] !== "").map((k) => `${k}: ${String(ev[k])}`).join(" · ")}</span>;
                           } }]} />
          <p className="small muted">The same steps are in the audit log, under this device and user.</p>
        </Modal>
      )}
    </>
  );
}
