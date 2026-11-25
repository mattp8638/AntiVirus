// Scheduled absences (M365-09): automatic replies, forwarding and calendar delegation switched on for a period and
// reverted at its end. Anything Fenrir could not revert stays listed here and raises an alert.
import { useState } from "react";
import { api, fmtTime } from "../api";
import { ErrorNote, Pill, Table, useAction, useData } from "../components/ui";

const TONE: Record<string, string> = { scheduled: "blue", active: "warn", ended: "good", cancelled: "neutral", start_failed: "bad", revert_failed: "bad" };

export default function M365Absences({ connection }: { connection: any }) {
  const { data, error, reload } = useData<any[]>(`m365/connections/${connection.id}/absences`);
  const { data: users } = useData<any[]>(`m365/connections/${connection.id}/inventory/users`);
  const { run, busy } = useAction();
  const [f, setF] = useState({ userId: "", startsAt: "", endsAt: "", reply: "", external: "", audience: "all", forwardTo: "", keepCopy: true, delegate: "", role: "read" });
  const set = (k: string, v: any) => setF({ ...f, [k]: v });
  const submit = async () => {
    const body: any = { userId: f.userId, startsAt: new Date(f.startsAt).toISOString(), endsAt: new Date(f.endsAt).toISOString(),
      keepCopy: f.keepCopy, delegates: f.delegate ? [{ email: f.delegate, role: f.role }] : [] };
    if (f.reply) body.autoReply = { internal: f.reply, external: f.external, externalAudience: f.audience };
    if (f.forwardTo) body.forwardTo = f.forwardTo;
    if (await run(() => api(`m365/connections/${connection.id}/absences`, { body }), "Absence scheduled")) reload();
  };
  return (
    <div style={{ marginTop: 12 }}>
      <div className="card">
        <h3>Schedule an absence</h3>
        <p className="small muted">Fenrir records what the mailbox and calendar look like when the absence starts. When it ends, Fenrir puts the automatic replies back, removes the forwarding rule it added, and removes only the calendar access it granted.</p>
        <div className="form-grid">
          <label className="field">User<select value={f.userId} onChange={(e) => set("userId", e.target.value)}><option value="">Choose…</option>
            {(users || []).map((u: any) => <option key={u.id} value={u.id}>{u.displayName} ({u.userPrincipalName})</option>)}</select></label>
          <label className="field">From<input type="datetime-local" value={f.startsAt} onChange={(e) => set("startsAt", e.target.value)} /></label>
          <label className="field">Until<input type="datetime-local" value={f.endsAt} onChange={(e) => set("endsAt", e.target.value)} /></label>
          <label className="field">Automatic reply (internal)<textarea value={f.reply} onChange={(e) => set("reply", e.target.value)} /></label>
          <label className="field">Automatic reply (external; empty = same)<textarea value={f.external} onChange={(e) => set("external", e.target.value)} /></label>
          <label className="field">External senders<select value={f.audience} onChange={(e) => set("audience", e.target.value)}>
            <option value="all">Everyone</option><option value="contactsOnly">Contacts only</option><option value="none">No one</option></select></label>
          <label className="field">Forward mail to<input value={f.forwardTo} onChange={(e) => set("forwardTo", e.target.value)} /></label>
          <label className="field"><span><input type="checkbox" checked={f.keepCopy} onChange={(e) => set("keepCopy", e.target.checked)} /> Keep a copy in the mailbox</span></label>
          <label className="field">Calendar delegate<input value={f.delegate} onChange={(e) => set("delegate", e.target.value)} /></label>
          <label className="field">Delegate access<select value={f.role} onChange={(e) => set("role", e.target.value)}><option value="read">Read</option><option value="write">Edit</option></select></label>
        </div>
        <button className="primary" disabled={busy || !f.userId || !f.startsAt || !f.endsAt} onClick={submit}>Schedule</button>
      </div>
      <ErrorNote error={error} />
      <Table rows={data || []} empty="No absences." columns={[
        { key: "userLabel", label: "User" },
        { key: "startsAt", label: "Period", render: (a: any) => `${fmtTime(a.startsAt)} – ${fmtTime(a.endsAt)}` },
        { key: "settings", label: "What", render: (a: any) => <span className="small">{[a.settings.autoReply && "automatic replies", a.settings.forwardTo && `forwarding to ${a.settings.forwardTo}`,
          ...(a.settings.delegates || []).map((d: any) => `${d.email} (${d.role})`)].filter(Boolean).join(", ")}</span> },
        { key: "status", label: "Status", render: (a: any) => <Pill value={a.status.replace("_", " ")} tone={TONE[a.status]} /> },
        { key: "stillInPlace", label: "Still in place", render: (a: any) => <span className="small">{a.stillInPlace.join(", ")}</span> },
        { key: "id", label: "", render: (a: any) => ["scheduled", "active", "start_failed", "revert_failed"].includes(a.status) ?
          <button className="link" disabled={busy} onClick={() => run(() => api(`m365/absences/${a.id}/end`, { method: "POST" }), a.status === "scheduled" ? "Cancelled" : "Ended").then(reload)}>
            {a.status === "scheduled" ? "Cancel" : a.status === "revert_failed" ? "Try reverting again" : "End now"}</button> : null },
      ]} />
    </div>
  );
}
