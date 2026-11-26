import { useState } from "react";
import { api, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Management review (ISO 27001 9.3): a pack from live data, the meeting record, and actions. */

const ddmmyyyy = (iso?: string | null) => iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}/${iso.slice(0, 4)}` : "";
const ACTION_WORD: Record<string, string> = { added: "Added", changed: "Changed", removed: "Removed" };

export function IsmsReviewTab() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const allowed = safeArray<string>(me?.permissions).includes("controls.view");
  const { data, error, reload } = useData<any>(tenantId && allowed ? "isms/reviews" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const [openId, setOpenId] = useState<string | null>(null);
  const [planning, setPlanning] = useState(false);
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its management reviews.</p>;
  if (!allowed) return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot see management reviews.</p> : null;
  const reviews = safeArray<any>(data?.reviews);
  const open = reviews.find((r) => r.id === openId);
  return <div className="card">
    <ErrorNote error={error} />
    <div className="row" style={{ marginBottom: 8, gap: 8 }}>
      <p className="small muted" style={{ flex: 1, margin: 0 }}>The pack gathers every input a management review must consider from the customer's live records. Recording the meeting freezes the pack with the minutes and decisions; actions are followed up afterwards and appear in the next review.</p>
      {data?.canManage && <button className="primary" onClick={() => setPlanning(true)}>Plan a review</button>}
    </div>
    <Table rows={reviews} empty="No management reviews yet." onRow={(r) => setOpenId(r.id)} columns={[
      { key: "ref", label: "Ref" }, { key: "title", label: "Review", render: (r) => <b>{displayValue(r.title)}</b> },
      { key: "plannedOn", label: "Date", render: (r) => r.heldOn ? `Held ${ddmmyyyy(r.heldOn)}` : `Planned ${ddmmyyyy(r.plannedOn)}` },
      { key: "periodStart", label: "Covers from", render: (r) => ddmmyyyy(r.periodStart) },
      { key: "actions", label: "Actions", render: (r) => { const left = r.actions.filter((a: any) => !a.doneAt).length; return r.actions.length ? `${left} open of ${r.actions.length}` : ""; } },
      { key: "status", label: "Status", render: (r) => r.status === "held" ? "Held" : "Draft" }]} />
    {open && <ReviewDetail r={open} inputs={safeArray<any>(data?.inputs)} manage={!!data?.canManage} userId={me?.userId} tenantId={tenantId} onChange={reload} onClose={() => setOpenId(null)} />}
    {planning && <PlanReview tenantId={tenantId} onClose={(id) => { setPlanning(false); reload(); if (id) setOpenId(id); }} />}
  </div>;
}

function PlanReview({ tenantId, onClose }: { tenantId: string; onClose: (id?: string) => void }) {
  const [f, setF] = useState({ title: "", plannedOn: "" });
  const { run, busy } = useAction();
  const save = async () => { const r: any = await run(() => api("isms/reviews", { body: { tenantId, ...f } }), "Review planned"); if (r) onClose(r.id); };
  return <Modal title="Plan a management review" onClose={() => onClose()} footer={<button className="primary" disabled={busy || f.title.trim().length < 3 || !f.plannedOn} onClick={save}>Plan</button>}>
    <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} placeholder="For example annual management review 2027" /></label>
    <label className="field">Planned for<input type="date" value={f.plannedOn} onChange={(e) => setF({ ...f, plannedOn: e.target.value })} /></label>
  </Modal>;
}

function ReviewDetail({ r, inputs, manage, userId, tenantId, onChange, onClose }: { r: any; inputs: any[]; manage: boolean; userId?: string; tenantId: string; onChange: () => void; onClose: () => void }) {
  const { run, busy } = useAction();
  const { data: people } = useData<any>(manage ? "isms/members" : null, { tenant_id: tenantId }, [tenantId]);
  const members = safeArray<any>(people?.members);
  const draft = r.status === "draft";
  const [feedback, setFeedback] = useState(r.interestedPartyFeedback ?? "");
  const [m, setM] = useState({ heldOn: "", chairId: "", attendees: "", minutes: "", decisions: "", changesNeeded: "" });
  const [action, setAction] = useState({ description: "", ownerId: "", dueOn: "" });
  const [doneNote, setDoneNote] = useState<Record<string, string>>({});
  const call = async (path: string, body: any, msg: string, method?: string) => { const x = await run(() => api(path, { method, body }), msg); if (x) onChange(); return x; };
  const base = `isms/reviews/${r.id}`;
  const set = (k: string) => (e: any) => setM({ ...m, [k]: e.target.value });
  return <Modal title={`${r.ref}: ${r.title}`} wide onClose={onClose}>
    <p className="small">{draft ? `Planned for ${ddmmyyyy(r.plannedOn)}` : `Held on ${ddmmyyyy(r.heldOn)}, chaired by ${displayValue(r.chairName ?? "nobody recorded")}`}. Reports on {ddmmyyyy(r.periodStart)} onwards.{r.packBuiltAt ? ` Pack built ${fmtTime(r.packBuiltAt)}.` : ""}</p>
    {draft && manage && <div className="row" style={{ gap: 8, alignItems: "end" }}>
      <label className="field" style={{ flex: 1 }}>Feedback from interested parties<textarea rows={2} value={feedback} onChange={(e) => setFeedback(e.target.value)} /></label>
      <button disabled={busy} onClick={() => call(`${base}/pack`, { feedback }, "Pack built from live data")}>{r.pack ? "Rebuild pack" : "Build pack"}</button>
    </div>}
    {r.pack ? <Pack pack={r.pack} inputs={inputs} /> : <p className="small muted">No pack yet.</p>}
    {!draft && <>
      <h3>Meeting</h3>
      <p className="small"><b>Attended:</b> {displayValue(r.attendees)}</p>
      <p className="small" style={{ whiteSpace: "pre-wrap" }}><b>Minutes:</b> {displayValue(r.minutes)}</p>
      <p className="small" style={{ whiteSpace: "pre-wrap" }}><b>Decisions:</b> {displayValue(r.decisions)}</p>
      {r.changesNeeded && <p className="small" style={{ whiteSpace: "pre-wrap" }}><b>Changes needed:</b> {displayValue(r.changesNeeded)}</p>}
      <p className="small muted">Recorded by {displayValue(r.recordedByName ?? "")} on {fmtTime(r.recordedAt)}. The review is frozen.</p>
    </>}
    {draft && manage && r.pack && <>
      <h3>Record the meeting</h3>
      <label className="field">Held on<input type="date" value={m.heldOn} onChange={set("heldOn")} /></label>
      <label className="field">Chair<select value={m.chairId} onChange={set("chairId")}><option value="">Not recorded</option>{members.map((x) => <option key={x.id} value={x.id}>{x.name || x.email}</option>)}</select></label>
      <label className="field">Attendees<input value={m.attendees} onChange={set("attendees")} /></label>
      <label className="field">Minutes<textarea rows={4} value={m.minutes} onChange={set("minutes")} /></label>
      <label className="field">Decisions on improvement<textarea rows={3} value={m.decisions} onChange={set("decisions")} /></label>
      <label className="field">Changes needed to the ISMS (optional)<textarea rows={2} value={m.changesNeeded} onChange={set("changesNeeded")} /></label>
      <div className="row" style={{ gap: 8 }}>
        <button className="primary" disabled={busy || !m.heldOn || !m.attendees.trim() || !m.minutes.trim() || !m.decisions.trim()} onClick={() => call(`${base}/held`, { ...m, chairId: m.chairId || null }, "Review recorded and frozen")}>Record and freeze</button>
        <button disabled={busy} onClick={async () => { if (confirm(`Delete ${r.ref}?`) && await run(() => api(base, { method: "DELETE" }), "Review deleted")) { onChange(); onClose(); } }}>Delete draft</button>
      </div>
    </>}
    <h3>Actions</h3>
    {r.actions.length === 0 && <p className="small muted">No actions yet.</p>}
    <ul className="small">{r.actions.map((a: any) => <li key={a.id}>
      {a.doneAt ? "Done: " : ""}{displayValue(a.description)} ({displayValue(a.ownerName ?? "nobody")}, due {ddmmyyyy(a.dueOn)}){a.overdue && <> <Pill value="overdue" tone="bad" /></>}
      {a.doneNote && <div className="muted">{displayValue(a.doneNote)}</div>}
      {!a.doneAt && (manage || a.ownerId === userId) && <div className="row" style={{ gap: 6, alignItems: "end" }}>
        <label className="field" style={{ flex: 1 }}>Note<input value={doneNote[a.id] ?? ""} onChange={(e) => setDoneNote({ ...doneNote, [a.id]: e.target.value })} /></label>
        <button disabled={busy} onClick={() => call(`isms/review-actions/${a.id}/done`, { note: doneNote[a.id] ?? "" }, "Action done")}>Mark done</button>
      </div>}
    </li>)}</ul>
    {manage && <div className="row" style={{ gap: 8, alignItems: "end", flexWrap: "wrap" }}>
      <label className="field" style={{ flex: 2 }}>New action<input value={action.description} onChange={(e) => setAction({ ...action, description: e.target.value })} /></label>
      <label className="field">Owner<select value={action.ownerId} onChange={(e) => setAction({ ...action, ownerId: e.target.value })}><option value="">Nobody yet</option>{members.map((x) => <option key={x.id} value={x.id}>{x.name || x.email}</option>)}</select></label>
      <label className="field">Due<input type="date" value={action.dueOn} onChange={(e) => setAction({ ...action, dueOn: e.target.value })} /></label>
      <button disabled={busy || action.description.trim().length < 3 || !action.dueOn} onClick={async () => { if (await call(`${base}/actions`, { ...action, ownerId: action.ownerId || null }, "Action added")) setAction({ description: "", ownerId: "", dueOn: "" }); }}>Add action</button>
    </div>}
  </Modal>;
}

function Pack({ pack, inputs }: { pack: any; inputs: any[] }) {
  const i = pack.inputs;
  const body: Record<string, JSX.Element> = {
    previous_actions: <>{i.previous_actions.open} open, {i.previous_actions.done} done.{i.previous_actions.items.length > 0 && <ul>{i.previous_actions.items.map((a: any, n: number) => <li key={n}>{a.review}: {displayValue(a.description)} ({a.done ? "done" : `due ${ddmmyyyy(a.dueOn)}`})</li>)}</ul>}</>,
    issue_changes: <Changes x={i.issue_changes} />,
    party_changes: <Changes x={i.party_changes} />,
    nonconformities: <>{i.nonconformities.raised} raised and {i.nonconformities.closed} closed in the period; {i.nonconformities.open} open ({i.nonconformities.majorOpen} major), {i.nonconformities.overdue} overdue.</>,
    monitoring: <>{i.monitoring.readiness.map((r: any) => <div key={r.framework}>{r.framework}: {r.score == null ? "no score yet" : `${r.score}%`} ({r.met} of {r.applicable} met)</div>)}
      {i.monitoring.objectives.map((o: any) => <div key={o.ref}>{o.ref} {displayValue(o.title)}: {o.latest == null ? "no result" : `${o.latest}${o.unit ? ` ${o.unit}` : ""}`} against {o.target}, {o.health.replace("_", " ")}</div>)}</>,
    audits: <>{i.audits.completed.length} completed in the period, {i.audits.planned} still planned.{i.audits.completed.map((a: any) => <div key={a.ref}>{a.ref} {displayValue(a.title)}: {a.major} major, {a.minor} minor, {a.observation} observations</div>)}
      {i.audits.coverage.map((c: any) => <div key={c.programme}>{displayValue(c.programme)}: {c.percent}% covered</div>)}</>,
    objectives: <>{i.objectives.met} on target, {i.objectives.notMet} off target, {i.objectives.noData} without data; {i.objectives.achieved} achieved, {i.objectives.dropped} retired.</>,
    party_feedback: <>{i.party_feedback.notes ? displayValue(i.party_feedback.notes) : "No feedback recorded."}{i.party_feedback.complaints.length > 0 && <div>Complaints: {i.party_feedback.complaints.map((c: any) => `${c.ref} ${c.title} (${c.status})`).join("; ")}</div>}</>,
    risk: <>{i.risk.total} open risks, {i.risk.aboveAppetite} above appetite, {i.risk.awaitingAcceptance} awaiting acceptance, {i.risk.accepted} accepted, {i.risk.reviewOverdue} overdue for review.{i.risk.lastSnapshot ? ` Last assessment snapshot ${fmtTime(i.risk.lastSnapshot)}.` : ""}</>,
    opportunities: <>{i.opportunities.open.length ? i.opportunities.open.map((o: any) => `${o.ref} ${o.title}`).join("; ") : "None open."}</>,
  };
  return <dl className="small">{inputs.map((x) => <div key={x.key} style={{ marginBottom: 8 }}><dt><b>{x.title}</b> <span className="muted">({x.clause})</span></dt><dd style={{ marginLeft: 0 }}>{body[x.key] ?? null}</dd></div>)}</dl>;
}

function Changes({ x }: { x: any }) {
  return <>{x.current} on the register now; {x.changes.length} changes in the period.{x.changes.length > 0 && <ul>{x.changes.slice(0, 20).map((c: any, n: number) => <li key={n}>{ACTION_WORD[c.action] ?? c.action} {ddmmyyyy(c.at)}: {displayValue(c.text)}</li>)}</ul>}</>;
}
