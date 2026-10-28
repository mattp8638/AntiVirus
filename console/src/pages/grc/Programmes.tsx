import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ago, api, downloadFile, fmtTime, uploadFile } from "../../api";
import { useApp } from "../../app-context";
import { Modal, PageHead, Pill, Stat, Table, TenantSelect, useAction, useData } from "../../components/ui";

// Compliance programmes per customer: pick frameworks, work through every requirement or question with an
// answer, status, owner and due date, attach evidence, and see which policies cover it.

export const STATUS_LABEL: Record<string, string> = { not_started: "Not started", in_progress: "In progress", implemented: "Done", not_applicable: "Not applicable" };
const STATUS_TONE: Record<string, string> = { not_started: "muted", in_progress: "warn", implemented: "good", not_applicable: "blue", needs_review: "bad" };
// "Needs review" is shown, never set: the requirement's wording changed since it was marked done.
const SHOWN_LABEL: Record<string, string> = { ...STATUS_LABEL, needs_review: "Needs review" };
const POLICY_TONE: Record<string, string> = { draft: "muted", in_review: "warn", approved: "good", retired: "muted" };

export function Progress({ value }: { value: number }) {
  return <div className="progress-bar" title={`${value}% complete`}><span style={{ width: `${value}%` }} /></div>;
}

export function ProgrammesTab() {
  const { tenantId, tenantName, can } = useApp();
  const { data, reload } = useData<any[]>("grc/programmes", { tenant_id: tenantId });
  const [adopt, setAdopt] = useState(false);
  const navigate = useNavigate();
  return (
    <>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <p className="muted small" style={{ margin: 0 }}>Each framework lists its requirements (or questions) for the customer to answer, evidence, and the policies that cover them.</p>
        {can("grc") && <button className="primary" onClick={() => setAdopt(true)}>Add framework</button>}
      </div>
      {data && data.length === 0 && <div className="card"><p className="muted">No frameworks yet. Add one (for example Cyber Essentials or ISO 27001) to start a programme; the matching policies are created as drafts for you.</p></div>}
      <div className="grid k3">
        {(data || []).map((p) => (
          <button key={p.tenantId + p.key} className="card domain-card" style={{ textAlign: "left", cursor: "pointer" }}
                  onClick={() => navigate(`/governance/${p.tenantId}/${p.key}`)}>
            <div className="row" style={{ alignItems: "baseline" }}><b style={{ flex: 1, fontSize: 16 }}>{p.short}</b><b>{p.progress}%</b></div>
            <div className="small muted" style={{ marginBottom: 8 }}>{tenantName(p.tenantId)}{p.targetDate ? ` · target ${fmtTime(p.targetDate).split(",")[0]}` : ""}</div>
            <Progress value={p.progress} />
            <div className="row small" style={{ marginTop: 8, flexWrap: "wrap" }}>
              <span>{p.counts.implemented} done</span><span className="muted">{p.counts.in_progress} in progress</span>
              <span className="muted">{p.counts.not_started} to do</span>{p.counts.not_applicable > 0 && <span className="muted">{p.counts.not_applicable} N/A</span>}
              {p.signals.overdue > 0 && <Pill value={`${p.signals.overdue} overdue`} tone="bad" />}
            </div>
          </button>
        ))}
      </div>
      {adopt && <AdoptModal onClose={() => { setAdopt(false); reload(); }} />}
    </>
  );
}

function AdoptModal({ onClose }: { onClose: () => void }) {
  const { tenantId, toast } = useApp();
  const [customer, setCustomer] = useState(tenantId);
  const { data: library } = useData<any>("grc/library", { tenant_id: customer || undefined }, [customer]);
  const [key, setKey] = useState("");
  const [owner, setOwner] = useState("");
  const [contact, setContact] = useState("");
  const [target, setTarget] = useState("");
  const [createPolicies, setCreatePolicies] = useState(true);
  const { run, busy } = useAction();
  const navigate = useNavigate();
  const chosen = library?.frameworks.find((f: any) => f.key === key);
  const save = async () => {
    const result = await run(() => api<any>("grc/programmes", { body: { tenantId: customer, frameworkKey: key, owner, securityContact: contact,
      targetDate: target ? new Date(target).toISOString() : null, createPolicies } }));
    if (result) {
      toast(result.policiesCreated.length ? `${chosen.short} added with ${result.policiesCreated.length} draft policies` : `${chosen.short} added`);
      onClose();
      navigate(`/governance/${customer}/${key}`);
    }
  };
  return (
    <Modal title="Add a framework" onClose={onClose} wide
           footer={<button className="primary" disabled={busy || !customer || !key} onClick={save}>Add framework</button>}>
      <label className="field">Customer<TenantSelect value={customer} onChange={setCustomer} allowAll={false} /></label>
      <div className="grid k2" style={{ margin: "10px 0" }}>
        {(library?.frameworks || []).map((f: any) => (
          <button key={f.key} className={`card domain-card ${key === f.key ? "active" : ""}`} style={{ textAlign: "left", cursor: "pointer" }} onClick={() => setKey(f.key)}>
            <b>{f.name}</b> {f.source !== "built-in" && <Pill value={f.source} tone="blue" />}
            <div className="small muted" style={{ margin: "4px 0" }}>{f.requirements} {f.questionSet ? "questions" : "requirements"} · {f.policies} matching policies{f.version ? ` · ${f.version}` : ""}</div>
            <div className="small">{f.description}</div>
          </button>
        ))}
      </div>
      {key && <div className="grid k2">
        <label className="field">Policy owner (named in the policies)<input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="e.g. Jo Bloggs, Operations Director" /></label>
        <label className="field">Who staff report incidents to<input value={contact} onChange={(e) => setContact(e.target.value)} placeholder="e.g. it@customer.co.uk or 01234 567890" /></label>
        <label className="field">Target date (optional)<input type="date" value={target} onChange={(e) => setTarget(e.target.value)} /></label>
        <label className="field row" style={{ alignItems: "center", gap: 8 }}><input type="checkbox" checked={createPolicies} onChange={(e) => setCreatePolicies(e.target.checked)} />
          Create the {chosen?.policies} matching policies as drafts</label>
      </div>}
    </Modal>
  );
}

export function ProgrammeDetail() {
  const { tenantId: tid = "", framework = "" } = useParams();
  const { can, tenantName } = useApp();
  const { data, reload } = useData<any>(`grc/programmes/${tid}/${framework}`, undefined, [tid, framework]);
  const [open, setOpen] = useState<any>(null);
  const [filter, setFilter] = useState("");
  const [q, setQ] = useState("");
  const [importing, setImporting] = useState(false);
  const [history, setHistory] = useState(false);
  const { run } = useAction();
  const navigate = useNavigate();
  const matches = (r: any) => (!filter || (filter === "overdue" ? r.dueDate && new Date(r.dueDate) < new Date() && !["implemented", "not_applicable"].includes(r.status)
    : filter === "no-evidence" ? !r.evidence.some((e: any) => !e.expired) : r.status === filter))
    && (!q || `${r.id} ${r.title} ${r.text} ${r.answer}`.toLowerCase().includes(q.toLowerCase()));
  useEffect(() => {
    if (open && data) {
      const fresh = data.sections.flatMap((s: any) => s.requirements).find((r: any) => r.id === open.id);
      if (fresh) setOpen(fresh);
    }
  }, [data]);
  if (!data) return null;
  return (
    <>
      <PageHead title={data.name} subtitle={<>{tenantName(tid)} · <Link to="/governance">All programmes</Link>{data.source !== "built-in" && <> · <Pill value={data.source} tone="blue" /></>}</>}
                actions={<div className="row">
                  <button onClick={() => run(() => downloadFile(`grc/programmes/${tid}/${framework}/export`, `${framework}.csv`))}>Export answers (CSV)</button>
                  <button onClick={() => setHistory(true)}>History</button>
                  {can("grc") && <button onClick={() => setImporting(true)}>Import exact question set</button>}
                  {can("grc") && data.adopted && <button className="danger" onClick={async () => { if (confirm("Stop tracking this framework? Answers, evidence and policies are kept.") && await run(() => api(`grc/programmes/${tid}/${framework}`, { method: "DELETE" }), "Framework paused")) navigate("/governance"); }}>Pause</button>}
                </div>} />
      <div className="grid k4" style={{ marginBottom: 14 }}>
        <Stat label="Complete" value={`${data.progress}%`} hint={<Progress value={data.progress} />} />
        <Stat label="Done" value={data.counts.implemented} hint={`${data.counts.not_applicable} not applicable${data.counts.needs_review ? ` · ${data.counts.needs_review} need review after a wording change` : ""}`} />
        <Stat label="In progress" value={data.counts.in_progress} hint={`${data.counts.not_started} not started`} />
        <Stat label="With evidence" value={data.signals.withEvidence} hint={`${data.signals.withApprovedPolicy} covered by an approved policy${data.signals.overdue ? ` · ${data.signals.overdue} overdue` : ""}`} />
      </div>
      {data.description && <p className="small muted">{data.description}</p>}
      <div className="row" style={{ marginBottom: 10 }}>
        <input placeholder="Search requirements and answers" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 260 }} />
        <select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter">
          <option value="">Everything</option>{Object.entries(SHOWN_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          <option value="no-evidence">No evidence yet</option><option value="overdue">Overdue</option>
        </select>
      </div>
      {data.sections.map((section: any) => {
        const rows = section.requirements.filter(matches);
        if (!rows.length) return null;
        const done = section.requirements.filter((r: any) => ["implemented", "not_applicable"].includes(r.status)).length;
        return (
          <details key={section.id} className="card" open style={{ marginBottom: 10 }}>
            <summary className="row" style={{ cursor: "pointer" }}><b style={{ flex: 1 }}>{section.title}</b><span className="small muted">{done}/{section.requirements.length}</span></summary>
            {rows.map((r: any) => (
              <div key={r.id} className="req-row" onClick={() => setOpen(r)}>
                <span className="mono small" style={{ minWidth: 64 }}>{r.id}</span>
                <span style={{ flex: 1 }}>{r.title}{data.questionSet && r.answer && <div className="small muted ellipsis">{r.answer}</div>}</span>
                <span className="req-signals">
                  {r.policies.length > 0 && <span className={r.policies.every((p: any) => p.status === "approved") ? "ok" : ""} title="Policies">📄 {r.policies.filter((p: any) => p.status === "approved").length}/{r.policies.length}</span>}
                  {r.evidence.length > 0 && <span className={r.evidence.some((e: any) => !e.expired) ? "ok" : "bad"} title="Evidence">📎 {r.evidence.length}</span>}
                  {r.checks.length > 0 && <span className={r.checks.every((c: any) => c.passed) ? "ok" : "bad"} title="Fenrir's automatic check">⚙ {r.checks.every((c: any) => c.passed) ? "pass" : "fail"}</span>}
                </span>
                <Pill value={SHOWN_LABEL[r.status]} tone={STATUS_TONE[r.status]} />
              </div>
            ))}
          </details>
        );
      })}
      {open && <RequirementDrawer tenantId={tid} framework={data} requirement={open} onClose={() => setOpen(null)} onChanged={reload} />}
      {importing && <ImportModal tenantId={tid} framework={data} onClose={() => { setImporting(false); reload(); }} />}
      {history && <HistoryModal tenantId={tid} framework={data} onClose={() => setHistory(false)} />}
    </>
  );
}

function RequirementDrawer({ tenantId, framework, requirement: r, onClose, onChanged }: { tenantId: string; framework: any; requirement: any; onClose: () => void; onChanged: () => void }) {
  const { can, toast } = useApp();
  const [form, setForm] = useState({ status: r.recordedStatus ?? r.status, answer: r.answer, notes: r.notes, naReason: r.naReason, owner: r.owner, dueDate: r.dueDate ? r.dueDate.slice(0, 10) : "" });
  const [adding, setAdding] = useState(false);
  const { run, busy } = useAction();
  useEffect(() => setForm({ status: r.recordedStatus ?? r.status, answer: r.answer, notes: r.notes, naReason: r.naReason, owner: r.owner, dueDate: r.dueDate ? r.dueDate.slice(0, 10) : "" }), [r.id]);
  const editable = can("grc");
  const save = async () => {
    const body: any = { status: form.status, answer: form.answer, notes: form.notes, naReason: form.naReason, owner: form.owner };
    if (form.dueDate) body.dueDate = new Date(form.dueDate).toISOString(); else body.clearDueDate = true;
    if (await run(() => api(`grc/programmes/${tenantId}/${framework.key}/requirements/${encodeURIComponent(r.id)}`, { method: "PATCH", body }), "Saved")) onChanged();
  };
  const adoptPolicy = async (key: string) => {
    if (await run(() => api("grc/policies", { body: { tenantId, templateKey: key } }), "Policy added as a draft")) onChanged();
  };
  return (
    <Modal title={`${r.id} ${r.title}`} onClose={onClose} wide
           footer={editable && <button className="primary" disabled={busy} onClick={save}>{r.needsReview ? "Confirm against the new wording" : "Save"}</button>}>
      {r.needsReview && <div className="card" style={{ borderColor: "var(--bad)", marginBottom: 10 }}>
        <b>The wording of this requirement changed after it was answered.</b> It no longer counts as done until someone checks the
        answer still holds and saves it again.
        {r.previousWording && <details><summary className="small">Wording that was answered</summary><p className="small" style={{ whiteSpace: "pre-wrap" }}>{r.previousWording}</p></details>}
      </div>}
      <p style={{ marginTop: 0 }}>{r.text}</p>
      {r.guidance && <p className="small muted">{r.guidance}</p>}
      <div className="grid k2">
        <div>
          {r.type === "yesno" && <div className="field">Answer<div className="row">{["Yes", "No"].map((v) => <button key={v} className={form.answer === v ? "primary" : ""} disabled={!editable}
                                                                                                   onClick={() => setForm({ ...form, answer: v })}>{v}</button>)}</div></div>}
          {(r.type === "text" || r.type === "yesno" || framework.questionSet) && <label className="field">{r.type === "yesno" ? "Explanation (what the assessor will read)" : "Answer"}
            <textarea rows={4} value={r.type === "yesno" && ["Yes", "No"].includes(form.answer) ? form.notes : form.answer} disabled={!editable}
                      onChange={(e) => r.type === "yesno" && ["Yes", "No"].includes(form.answer) ? setForm({ ...form, notes: e.target.value }) : setForm({ ...form, answer: e.target.value })} /></label>}
          <label className="field">Status<select value={form.status} disabled={!editable} onChange={(e) => setForm({ ...form, status: e.target.value })}>
            {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
          {form.status === "not_applicable" && <label className="field">Why it does not apply<textarea rows={2} value={form.naReason} disabled={!editable} onChange={(e) => setForm({ ...form, naReason: e.target.value })} /></label>}
          <div className="grid k2">
            <label className="field">Owner<input value={form.owner} disabled={!editable} onChange={(e) => setForm({ ...form, owner: e.target.value })} /></label>
            <label className="field">Due<input type="date" value={form.dueDate} disabled={!editable} onChange={(e) => setForm({ ...form, dueDate: e.target.value })} /></label>
          </div>
          {!(r.type === "yesno" && ["Yes", "No"].includes(form.answer)) && <label className="field">Notes<textarea rows={3} value={form.notes} disabled={!editable} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>}
          {r.updatedAt && <p className="small muted">Last updated {ago(r.updatedAt)} by {r.updatedBy}</p>}
        </div>
        <div>
          <h4 style={{ marginTop: 0 }}>Policies</h4>
          {r.policies.map((p: any) => <div key={p.id} className="row small"><Link to={`/governance/policies/${p.id}`} style={{ flex: 1 }}>{p.title}</Link><Pill value={p.status.replace("_", " ")} tone={POLICY_TONE[p.status]} /></div>)}
          {r.suggestedPolicies.map((t: any) => <div key={t.key} className="row small"><span style={{ flex: 1 }} className="muted">{t.title}</span>{editable && <button className="small" onClick={() => adoptPolicy(t.key)}>Add policy</button>}</div>)}
          {!r.policies.length && !r.suggestedPolicies.length && <p className="small muted">No policy is mapped to this requirement.</p>}
          {r.checks.length > 0 && <>
            <h4>Checked automatically by Fenrir</h4>
            {r.checks.map((c: any) => <div key={c.ref} className="small" style={{ marginBottom: 6 }}><Pill value={c.passed ? "pass" : "fail"} tone={c.passed ? "good" : "bad"} /> <b>{c.title}</b>
              <div className="muted">{c.evidence.join(" · ")}</div></div>)}
          </>}
          <h4>Evidence</h4>
          {r.evidence.map((e: any) => <EvidenceLine key={e.id} evidence={e} />)}
          {!r.evidence.length && <p className="small muted">Nothing attached yet.{r.evidenceHints?.length ? ` Suggested: ${r.evidenceHints.join(", ")}.` : ""}</p>}
          {editable && <button className="small" onClick={() => setAdding(true)}>Add evidence</button>}
        </div>
      </div>
      {adding && <AddEvidence tenantId={tenantId} links={[`${framework.key}:${r.id}`]} onClose={() => { setAdding(false); onChanged(); toast("Evidence attached"); }} />}
    </Modal>
  );
}

export function EvidenceLine({ evidence: e }: { evidence: any }) {
  const { run } = useAction();
  return (
    <div className="row small" style={{ marginBottom: 4 }}>
      <span style={{ flex: 1 }}>{e.kind === "file" ? "📎" : e.kind === "link" ? "🔗" : "📝"} {e.kind === "link" ? <a href={e.url} target="_blank" rel="noreferrer">{e.title}</a>
        : e.kind === "file" ? <button className="link" onClick={() => run(() => downloadFile(`grc/evidence/${e.id}/download`, e.filename))}>{e.title}</button> : e.title}</span>
      {e.expired ? <Pill value="expired" tone="bad" /> : e.validUntil && <span className="muted">valid to {fmtTime(e.validUntil).split(",")[0]}</span>}
    </div>
  );
}

export function AddEvidence({ tenantId, links, onClose }: { tenantId: string; links: string[]; onClose: () => void }) {
  const [kind, setKind] = useState<"file" | "link" | "note">("file");
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const { run, busy } = useAction();
  const save = async () => {
    const until = validUntil ? new Date(validUntil).toISOString() : undefined;
    const ok = kind === "file"
      ? file && await run(() => uploadFile("grc/evidence/upload", file, { tenant_id: tenantId, filename: file.name, title, description, valid_until: until, links: links.join(",") }))
      : await run(() => api("grc/evidence", { body: { tenantId, title, kind, url, description, validUntil: until ?? null, links } }));
    if (ok) onClose();
  };
  return (
    <Modal title="Add evidence" onClose={onClose}
           footer={<button className="primary" disabled={busy || (kind === "file" ? !file : !title)} onClick={save}>Add</button>}>
      <div className="row" style={{ marginBottom: 10 }}>{(["file", "link", "note"] as const).map((k) => <button key={k} className={kind === k ? "primary" : ""} onClick={() => setKind(k)}>{k === "file" ? "Upload a file" : k === "link" ? "Link" : "Written note"}</button>)}</div>
      {kind === "file" && <label className="field">File (up to 25 MB, stored encrypted)<input type="file" onChange={(e) => { const f = e.target.files?.[0] || null; setFile(f); if (f && !title) setTitle(f.name); }} /></label>}
      <label className="field">Title<input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Firewall rule export March 2026" /></label>
      {kind === "link" && <label className="field">Link (https)<input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://" /></label>}
      <label className="field">{kind === "note" ? "Note" : "Description (optional)"}<textarea rows={kind === "note" ? 5 : 2} value={description} onChange={(e) => setDescription(e.target.value)} /></label>
      <label className="field">Valid until (optional - e.g. a yearly test)<input type="date" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} /></label>
      <p className="small muted">Attached to {links.join(", ")}.</p>
    </Modal>
  );
}

function ImportModal({ tenantId, framework, onClose }: { tenantId: string; framework: any; onClose: () => void }) {
  const { me } = useApp();
  const [content, setContent] = useState("");
  const [format, setFormat] = useState<"csv" | "json" | "yaml">("csv");
  const [name, setName] = useState(framework.name);
  const [version, setVersion] = useState(framework.version);
  const [everyone, setEveryone] = useState(false);
  const [preview, setPreview] = useState<any>(null);
  const { run, busy } = useAction();
  const body = (dryRun: boolean) => ({ body: { tenantId: everyone ? null : tenantId, key: framework.key, name, version, questionSet: framework.questionSet, format, content, dryRun } });
  useEffect(() => setPreview(null), [content, format, everyone]);
  const check = async () => setPreview(await run(() => api<any>("grc/library/frameworks/import", body(true))));
  const save = async () => {
    const result = await run(() => api<any>("grc/library/frameworks/import", body(false)), "Question set imported");
    if (result) onClose();
  };
  return (
    <Modal title="Import the exact question set" onClose={onClose} wide
           footer={<div className="row"><button disabled={busy || !content} onClick={check}>Preview changes</button>
             <button className="primary" disabled={busy || !preview} onClick={save}>Import</button></div>}>
      <p className="small">Paste the official questions (for example from the current IASME Cyber Essentials booklet) to replace Fenrir's
        paraphrased set for {everyone ? "every customer" : "this customer"}. Answers, evidence and policy links carry over wherever the
        question IDs match (A4.1, A7.11…).</p>
      <div className="grid k2">
        <label className="field">Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="field">Version<input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="e.g. Willow (April 2025)" /></label>
      </div>
      <label className="field">Format<select value={format} onChange={(e) => setFormat(e.target.value as any)}><option value="csv">CSV: section,id,title,text,type</option><option value="json">JSON (Fenrir framework format)</option><option value="yaml">YAML (Fenrir framework format)</option></select></label>
      <label className="field">Content<textarea rows={12} className="mono" value={content} onChange={(e) => setContent(e.target.value)}
        placeholder={"section,id,title,text,type\nA4 Firewalls,A4.1,Do you have firewalls at the boundaries...,,yesno"} /></label>
      <label className="field"><input type="file" accept=".csv,.json,.yml,.yaml,.txt" onChange={async (e) => { const f = e.target.files?.[0]; if (f) { setContent(await f.text()); if (f.name.endsWith(".json")) setFormat("json"); else if (/\.ya?ml$/.test(f.name)) setFormat("yaml"); } }} /></label>
      {me?.user.role === "platform_admin" && <label className="field row" style={{ gap: 8 }}><input type="checkbox" checked={everyone} onChange={(e) => setEveryone(e.target.checked)} />Use for every customer</label>}
      {preview && <div className="card">
        <b>{preview.requirements} requirements</b> · {preview.diff.added.length} new · {preview.diff.changed.length} reworded · {preview.diff.removed.length} removed · {preview.diff.unchanged} unchanged
        {preview.affectedCustomers > 0 && <> · affects {preview.affectedCustomers} customer{preview.affectedCustomers === 1 ? "" : "s"}</>}
        <p className="small muted">Each affected assessment is saved to its history first. Reworded requirements that were done are marked for review; removed ones stay in the saved history.</p>
        {preview.diff.changedDetail.map((c: any) => <details key={c.id}><summary className="small mono">{c.id} reworded</summary>
          <div className="grid k2 small"><div><b>Before</b><p style={{ whiteSpace: "pre-wrap" }}>{c.before}</p></div><div><b>After</b><p style={{ whiteSpace: "pre-wrap" }}>{c.after}</p></div></div></details>)}
        {preview.diff.removed.length > 0 && <p className="small">Removed: <span className="mono">{preview.diff.removed.join(", ")}</span></p>}
      </div>}
    </Modal>
  );
}

function HistoryModal({ tenantId, framework, onClose }: { tenantId: string; framework: any; onClose: () => void }) {
  const { can } = useApp();
  const { data, reload } = useData<any[]>(`grc/programmes/${tenantId}/${framework.key}/snapshots`, {}, [tenantId, framework.key], true);
  const [label, setLabel] = useState("");
  const { run, busy } = useAction();
  const save = async () => { if (await run(() => api(`grc/programmes/${tenantId}/${framework.key}/snapshots`, { body: { label } }), "Saved to history")) { setLabel(""); reload(); } };
  return (
    <Modal title={`${framework.short || framework.name} history`} onClose={onClose} wide>
      <p className="small muted">The assessment is saved here automatically before the framework is replaced, and whenever you save it (for example on submission).</p>
      {can("grc") && <div className="row" style={{ marginBottom: 10 }}><input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Submitted to IASME, March 2026" style={{ flex: 1 }} />
        <button disabled={busy || !label.trim()} onClick={save}>Save current assessment</button></div>}
      <Table rows={data ?? []} empty="Nothing saved yet" columns={[
        { key: "createdAt", label: "Saved", render: (s: any) => fmtTime(s.createdAt) },
        { key: "label", label: "Label", render: (s: any) => <>{s.label}<div className="small muted">{s.reason} · {s.createdBy}</div></> },
        { key: "progress", label: "Complete", render: (s: any) => `${s.progress}%` },
        { key: "export", label: "", render: (s: any) => <button onClick={() => run(() => downloadFile(`grc/programmes/${tenantId}/${framework.key}/export?snapshot=${s.id}`, `${framework.key}-${s.id}.csv`))}>Export</button> },
      ]} />
    </Modal>
  );
}

export function EvidenceTab() {
  const { tenantId, tenantName, can } = useApp();
  const { data, reload } = useData<any[]>("grc/evidence", { tenant_id: tenantId });
  const { run } = useAction();
  const [adding, setAdding] = useState(false);
  const expired = useMemo(() => (data || []).filter((e) => e.expired).length, [data]);
  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <span className="small muted">{(data || []).length} items{expired ? ` · ${expired} expired` : ""}</span>
        {can("grc") && tenantId && <button className="small" onClick={() => setAdding(true)}>Add evidence</button>}
      </div>
      <Table rows={data} empty="No evidence yet. Attach evidence from a requirement in a programme."
             columns={[{ key: "title", label: "Evidence", render: (e) => <EvidenceLine evidence={e} /> },
                       { key: "tenantId", label: "Customer", render: (e) => tenantName(e.tenantId) },
                       { key: "links", label: "Supports", render: (e) => e.links.map((l: string) => <span key={l} className="chip mono">{l}</span>) },
                       { key: "uploadedBy", label: "Added", render: (e) => <span className="small">{ago(e.createdAt)}<div className="muted">{e.uploadedBy}</div></span> },
                       { key: "actions", label: "", render: (e) => can("grc") && <button className="small danger" onClick={async () => { if (confirm(`Delete ${e.title}?`) && await run(() => api(`grc/evidence/${e.id}`, { method: "DELETE" }), "Deleted")) reload(); }}>Delete</button> }]} />
      {adding && <AddEvidence tenantId={tenantId} links={[]} onClose={() => { setAdding(false); reload(); }} />}
    </div>
  );
}
