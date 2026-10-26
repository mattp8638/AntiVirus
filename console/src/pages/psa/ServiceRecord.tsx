import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Pill, useAction, useData } from "../../components/ui";

export const RECORD_TYPES: Record<string, string> = { incident: "Incident", service_request: "Service request", problem: "Problem", change: "Change" };
export const CHANGE_TONE: Record<string, string> = { Draft: "muted", Submitted: "warn", Approved: "blue", Rejected: "bad", Implemented: "good",
                                                     Failed: "bad", Closed: "muted" };

const toLocal = (value?: string | null) => (value ? String(value).slice(0, 16) : "");

/** Problem/change details, problem links and linked vulnerabilities for a ticket (right-hand column). */
export default function ServiceRecord({ ticket, onChange }: { ticket: any; onChange: () => void }) {
  const { can } = useApp();
  const { data: links, reload: reloadLinks } = useData<any>(`tickets/${ticket.id}/links`, {}, [ticket.updatedAt]);
  const { data: problems } = useData<any[]>(ticket.recordType === "incident" || !ticket.recordType ? "psa/problems" : null);
  const { run, busy } = useAction();
  const [draft, setDraft] = useState<any>({});
  useEffect(() => setDraft({ rootCause: ticket.rootCause || "", workaround: ticket.workaround || "", implementationPlan: ticket.implementationPlan || "",
                             backoutPlan: ticket.backoutPlan || "", testPlan: ticket.testPlan || "", plannedStart: toLocal(ticket.plannedStart),
                             plannedEnd: toLocal(ticket.plannedEnd) }), [ticket.id, ticket.updatedAt]);
  const type = ticket.recordType || "incident";
  const editable = can("respond") || can("crm");

  const save = async (body: any, message = "Saved") => {
    if (await run(() => api(`tickets/${ticket.id}/itil`, { method: "PATCH", body }), message)) { onChange(); reloadLinks(); }
  };
  const act = async (action: string, needsComment = false) => {
    const comment = needsComment || action === "approve" ? window.prompt(action === "approve" ? "Approval comment (optional)" : "Reason") : "";
    if (needsComment && !comment) return;
    if (await run(() => api(`tickets/${ticket.id}/change/${action}`, { body: { comment: comment || "" } }), `Change ${action}d`)) onChange();
  };
  const field = (key: string, label: string, rows = 3) => (
    <label className="field" style={{ marginTop: 8 }}>{label}
      <textarea rows={rows} value={draft[key] ?? ""} disabled={!editable} onChange={(e) => setDraft({ ...draft, [key]: e.target.value })} />
    </label>
  );

  return (
    <div className="card">
      <h3>Service record</h3>
      <label className="field">Record type
        <select value={type} disabled={!editable} onChange={(e) => save({ recordType: e.target.value }, "Record type changed")}>
          {Object.entries(RECORD_TYPES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </label>

      {type === "incident" && <>
        <label className="field" style={{ marginTop: 8 }}>Linked problem
          <select value={ticket.problemId || ""} disabled={!editable} onChange={(e) => save({ problemId: e.target.value || null }, "Problem link updated")}>
            <option value="">None</option>
            {problems?.map((p) => <option key={p.id} value={p.id}>#{p.number} {p.subject}</option>)}
            {links?.problem && !problems?.some((p) => p.id === links.problem.id) && <option value={links.problem.id}>#{links.problem.number} {links.problem.subject}</option>}
          </select>
        </label>
        {links?.problem && <div className="small" style={{ marginTop: 6 }}>
          <Link to={`/tickets/${links.problem.id}`}>Problem #{links.problem.number}</Link> {links.problem.knownError && <Pill value="known error" tone="warn" />}
          {links.problem.workaround && <div className="muted" style={{ marginTop: 4 }}>Workaround: {links.problem.workaround}</div>}
        </div>}
      </>}

      {type === "problem" && <>
        {field("rootCause", "Root cause")}
        {field("workaround", "Workaround")}
        <label className="small" style={{ display: "block", marginTop: 8 }}>
          <input type="checkbox" checked={!!ticket.knownError} disabled={!editable} onChange={(e) => save({ knownError: e.target.checked })} /> Known error</label>
        {editable && <div className="row" style={{ marginTop: 8, gap: 6 }}>
          <button disabled={busy} onClick={() => save({ rootCause: draft.rootCause, workaround: draft.workaround })}>Save</button>
          {links?.incidents.some((i: any) => !i.closed) && <button className="primary" disabled={busy} onClick={async () => {
            if (!window.confirm("Resolve every open linked incident with this problem's root cause as the resolution note?")) return;
            if (await run(() => api(`tickets/${ticket.id}/problem/resolve-linked`, { body: {} }), "Linked incidents resolved")) { onChange(); reloadLinks(); }
          }}>Resolve linked incidents</button>}
        </div>}
        <div style={{ marginTop: 10 }}>
          <b className="small">Linked incidents ({links?.incidents.length ?? 0})</b>
          {links?.incidents.map((i: any) => <div key={i.id} className="small"><Link to={`/tickets/${i.id}`}>#{i.number}</Link> {i.subject} <Pill value={i.status} tone={i.closed ? "muted" : "warn"} /></div>)}
        </div>
      </>}

      {type === "change" && <>
        <div className="row" style={{ marginTop: 8, gap: 6 }}>
          <Pill value={ticket.changeState || "Draft"} tone={CHANGE_TONE[ticket.changeState || "Draft"]} />
          <span className="small muted">{(ticket.changeApprovals || []).filter((a: any) => a.decision === "approve").length} of {ticket.changeRisk === "High" ? 2 : 1} approvals</span>
        </div>
        <label className="field" style={{ marginTop: 8 }}>Risk
          <select value={ticket.changeRisk || ""} disabled={!editable} onChange={(e) => save({ changeRisk: e.target.value })}>
            <option value="" disabled>Choose…</option>{["Low", "Medium", "High"].map((r) => <option key={r}>{r}</option>)}
          </select>
        </label>
        <div className="form-grid">
          <label className="field">Planned start<input type="datetime-local" value={draft.plannedStart} disabled={!editable} onChange={(e) => setDraft({ ...draft, plannedStart: e.target.value })} /></label>
          <label className="field">Planned end<input type="datetime-local" value={draft.plannedEnd} disabled={!editable} onChange={(e) => setDraft({ ...draft, plannedEnd: e.target.value })} /></label>
        </div>
        {field("implementationPlan", "Implementation plan")}
        {field("backoutPlan", "Backout plan")}
        {field("testPlan", "Test plan", 2)}
        {editable && <div className="row" style={{ marginTop: 8, gap: 6, flexWrap: "wrap" }}>
          <button disabled={busy} onClick={() => save({ implementationPlan: draft.implementationPlan, backoutPlan: draft.backoutPlan, testPlan: draft.testPlan,
                                                        plannedStart: draft.plannedStart || null, plannedEnd: draft.plannedEnd || null }, "Change plan saved")}>Save plan</button>
          {["Draft", "Rejected", ""].includes(ticket.changeState || "") && <button className="primary" disabled={busy} onClick={() => act("submit")}>Submit for approval</button>}
          {ticket.changeState === "Submitted" && can("configure") && <><button className="primary" disabled={busy} onClick={() => act("approve")}>Approve</button>
            <button className="danger" disabled={busy} onClick={() => act("reject", true)}>Reject</button></>}
          {ticket.changeState === "Approved" && <><button className="primary" disabled={busy} onClick={() => act("implement")}>Mark implemented</button>
            <button className="danger" disabled={busy} onClick={() => act("fail", true)}>Mark failed</button></>}
          {["Implemented", "Failed", "Rejected"].includes(ticket.changeState) && <button disabled={busy} onClick={() => act("close")}>Close change</button>}
        </div>}
        {(ticket.changeApprovals || []).length > 0 && <div style={{ marginTop: 10 }}>
          {ticket.changeApprovals.map((a: any, i: number) => <div key={i} className="small">
            <Pill value={a.decision === "approve" ? "approved" : "rejected"} tone={a.decision === "approve" ? "good" : "bad"} /> {a.by} · {fmtTime(a.at)}
            {a.comment && <div className="muted">{a.comment}</div>}</div>)}
        </div>}
      </>}

      {links?.vulnerabilities.length > 0 && <div style={{ marginTop: 12 }}>
        <b className="small">Vulnerabilities this ticket remediates ({links.vulnerabilities.length})</b>
        {links.vulnerabilities.map((v: any) => <div key={v.id} className="small" style={{ marginTop: 4 }}>
          <Link to="/vulnerabilities">{v.vulnId}</Link> {v.package} <Pill value={v.severity} /> <Pill value={v.status} tone={v.status === "fixed" ? "good" : "warn"} />
          {v.knownExploited && <> <Pill value="known exploited" tone="bad" /></>}
        </div>)}
      </div>}
    </div>
  );
}
