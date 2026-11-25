// Security questionnaires (GRC-15): answers suggested from an approved library, never filled in automatically;
// every answer reviewed by a person; stale and unverified answers flagged; hashed exports.
import { useState } from "react";
import { api, downloadFile, fmtTime } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Table, Tabs, useAction, useData, useListData } from "../../components/ui";
import { COMPLIANCE_SECTION, SectionTabs } from "../../components/sections";

const STATE: Record<string, string> = { unanswered: "muted", drafted: "warn", reviewed: "good" };

export default function Questionnaires() {
  const { tenantId } = useApp();
  const [tab, setTab] = useState("Questionnaires");
  return (
    <>
      <SectionTabs items={COMPLIANCE_SECTION} />
      <PageHead title="Security questionnaires" subtitle="Questionnaires from customers, answered from a library of approved answers: suggestions are offered, a person chooses and a reviewer signs off each answer. Stale or unevidenced answers are flagged." />
      <Tabs tabs={["Questionnaires", "Answer library"]} active={tab} onChange={setTab} />
      {!tenantId ? <div className="card empty">Choose a customer.</div> : tab === "Questionnaires" ? <List tenantId={tenantId} /> : <Library tenantId={tenantId} />}
    </>
  );
}

function List({ tenantId }: { tenantId: string }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data, reload } = useListData<any>("grc/questionnaires", { tenantId }, [tenantId]);
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ title: "", counterparty: "", due: "", questions: "" });
  return (
    <>
      {can("grc") && <button className="primary" style={{ marginBottom: 10 }} onClick={() => setAdding(true)}>Import a questionnaire</button>}
      <Table rows={data} onRow={(x) => setOpen(x.id)} empty="No questionnaires." columns={[
        { key: "title", label: "Questionnaire", render: (x) => <><b>{x.title}</b><div className="small muted">{x.counterparty}</div></> },
        { key: "status", label: "Status", render: (x) => <Pill value={x.status} tone={x.status === "completed" ? "good" : "warn"} /> },
        { key: "counts", label: "Answers", render: (x) => Object.entries(x.counts).map(([k, v]) => `${v} ${k}`).join(", ") },
        { key: "flagged", label: "Flagged", render: (x) => x.flagged ? <Pill value={x.flagged} tone="warn" /> : "—" },
        { key: "due", label: "Due", render: (x) => x.due ?? "—" }]} />
      {adding && <Modal title="Import a questionnaire" onClose={() => setAdding(false)} footer={<button className="primary" disabled={busy || !f.title.trim() || !f.questions.trim()} onClick={() => run(() => api("grc/questionnaires", { body: { tenantId, ...f, due: f.due || null } }), "Imported").then((r) => { if (r) { setAdding(false); reload(); } })}>Import</button>}>
        <div className="form-grid">
          <label className="field">Title<input value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
          <label className="field">From (customer)<input value={f.counterparty} onChange={(e) => setF({ ...f, counterparty: e.target.value })} /></label>
          <label className="field">Due<input type="date" value={f.due} onChange={(e) => setF({ ...f, due: e.target.value })} /></label>
        </div>
        <label className="field">Questions: paste CSV with a "question" column (and optionally "id", "section"), or one per line<textarea rows={10} value={f.questions} onChange={(e) => setF({ ...f, questions: e.target.value })} /></label>
      </Modal>}
      {open && <Detail id={open} onClose={() => { setOpen(null); reload(); }} />}
    </>
  );
}

function Detail({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data: x, reload } = useData<any>(`grc/questionnaires/${id}`);
  const [editing, setEditing] = useState<any>(null);
  if (!x) return null;
  return (
    <Modal wide title={x.title} onClose={onClose} footer={<>
      <button onClick={() => downloadFile(`grc/questionnaires/${id}/export.csv`, `${x.title}.csv`)}>Export (CSV)</button>
      {can("grc") && x.status !== "completed" && <button className="primary" disabled={busy} onClick={() => run(() => api(`grc/questionnaires/${id}/complete`, { body: {} }), "Completed").then(reload)}>Complete</button>}
    </>}>
      <p className="small">{x.counterparty} · {Object.entries(x.counts).map(([k, v]) => `${v} ${k}`).join(", ")}{x.exports.length > 0 && ` · last exported ${fmtTime(x.exports[x.exports.length - 1].at)}`}</p>
      <Table rows={x.questions} onRow={(q) => can("grc") && x.status !== "completed" && setEditing(q)} columns={[
        { key: "ref", label: "#" },
        { key: "text", label: "Question", render: (q) => <><span className="small">{q.text}</span>{q.answer && <div className="small muted">{q.answer.slice(0, 200)}</div>}</> },
        { key: "state", label: "State", render: (q) => <><Pill value={q.state} tone={STATE[q.state]} />{q.source && <Pill value="from library" tone="blue" />}</> },
        { key: "flags", label: "Flags", render: (q) => <span className="small" style={{ color: q.flags.length ? "#fbbf24" : undefined }}>{q.flags.join("; ") || "—"}</span> },
        { key: "assignee", label: "Assignee" }]} />
      {editing && <Answer qid={id} q={editing} onClose={() => { setEditing(null); reload(); }} />}
    </Modal>
  );
}

function Answer({ qid, q, onClose }: { qid: string; q: any; onClose: () => void }) {
  const { run, busy } = useAction();
  const { data: sug } = useListData<any>(`grc/questionnaires/${qid}/questions/${q.id}/suggestions`);
  const [answer, setAnswer] = useState(q.answer);
  const [assignee, setAssignee] = useState(q.assignee);
  const base = `grc/questionnaires/${qid}/questions/${q.id}`;
  return (
    <Modal wide title={`${q.ref} ${q.text}`} onClose={onClose} footer={<>
      <button disabled={busy} onClick={() => run(() => api(base, { method: "PATCH", body: { answer, assignee } }), "Saved").then((r) => r && onClose())}>Save</button>
      <button className="primary" disabled={busy || !answer.trim()} onClick={() => run(async () => { await api(base, { method: "PATCH", body: { answer, assignee } }); return api(base, { method: "PATCH", body: { review: true } }); }, "Reviewed").then((r) => r && onClose())}>Save and mark reviewed</button>
      {q.state === "reviewed" && <button onClick={() => run(() => api(`${base}/to-library`, { body: {} }), "Added to the library as a draft")}>Add to library</button>}
    </>}>
      {(sug ?? []).length > 0 && <div className="card" style={{ padding: 10 }}>
        <b className="small">Suggestions from the library (choose one; you can still edit it)</b>
        {(sug ?? []).map((s: any) => <div key={s.answerId} className="small" style={{ marginTop: 6 }}>
          <div className="muted">{s.question} · match {Math.round(s.score * 100)}% {s.stale && <Pill value="stale" tone="warn" />}{s.unverified && <Pill value="unverified" tone="warn" />}</div>
          <div>{s.answer}</div>
          <button className="small" onClick={() => run(() => api(base, { method: "PATCH", body: { fromAnswer: s.answerId } }), "Used: review it before signing off").then((r: any) => r && setAnswer(r.answer))}>Use this answer</button>
        </div>)}
      </div>}
      <label className="field">Answer<textarea rows={6} value={answer} onChange={(e) => setAnswer(e.target.value)} /></label>
      <label className="field">Assignee<input value={assignee} onChange={(e) => setAssignee(e.target.value)} /></label>
      {q.flags.length > 0 && <p className="small" style={{ color: "#fbbf24" }}>{q.flags.join("; ")}</p>}
    </Modal>
  );
}

function Library({ tenantId }: { tenantId: string }) {
  const { can } = useApp();
  const { run, busy } = useAction();
  const { data, reload } = useListData<any>("grc/answers", { tenantId }, [tenantId]);
  const [f, setF] = useState({ question: "", answer: "" });
  return (
    <>
      {can("grc") && <div className="card">
        <label className="field">Question<input value={f.question} onChange={(e) => setF({ ...f, question: e.target.value })} /></label>
        <label className="field">Answer<textarea rows={3} value={f.answer} onChange={(e) => setF({ ...f, answer: e.target.value })} /></label>
        <button className="primary" disabled={busy || f.question.trim().length < 5 || !f.answer.trim()} onClick={() => run(() => api("grc/answers", { body: { tenantId, ...f } }), "Added as a draft: approve it to use it").then(() => { setF({ question: "", answer: "" }); reload(); })}>Add answer</button>
        <p className="small muted">Link evidence and policies to an answer so it is not flagged as unverified. An edited answer goes back to draft.</p>
      </div>}
      <Table rows={data} empty="The library is empty." columns={[
        { key: "question", label: "Question", render: (a) => <><b className="small">{a.question}</b><div className="small muted">{a.answer.slice(0, 240)}</div></> },
        { key: "status", label: "Status", render: (a) => <><Pill value={a.status} tone={a.status === "approved" ? "good" : "muted"} />{a.stale && a.status === "approved" && <Pill value="review due" tone="warn" />}{a.unverified && <Pill value="no evidence" tone="warn" />}</> },
        { key: "approvedAt", label: "Approved", render: (a) => a.approvedAt ? `${fmtTime(a.approvedAt)} by ${a.approvedBy}` : "—" },
        { key: "id", label: "", render: (a) => can("grc") && <>{a.status !== "approved" || a.stale ? <button className="small" onClick={() => run(() => api(`grc/answers/${a.id}`, { method: "PATCH", body: { action: "approve" } }), "Approved").then(reload)}>Approve</button> : null}<button className="small ghost" onClick={() => run(() => api(`grc/answers/${a.id}`, { method: "PATCH", body: { action: "retire" } }), "Retired").then(reload)}>Retire</button></> }]} />
    </>
  );
}
