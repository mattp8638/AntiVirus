import { useEffect, useState } from "react";
import { api, downloadFile } from "../../api";
import { useApp } from "../../app-context";
import { displayValue } from "../../components/DisplayValue";
import { ErrorNote, Modal, Pill, Table, useAction, useData } from "../../components/ui";
import { safeArray } from "../../data-shapes";

/** Programme setup: frameworks, onboarding questions, then a reviewed change to applicability. */

type Option = { framework: string; name: string; version: string; packVersion: string; pinnedVersion: string | null; certifiable: boolean; requirementCount: number; selected: boolean; status: string | null; targetDate: string | null; licence: string };
type Question = { ref: string; text: string; help: string | null; type: "bool" | "single" | "multi" | "number"; options: { value: string; label: string }[]; value: unknown };
type Preview = { changes: { key: string; type: string; item: string; from: boolean | null; to: boolean | null; reason: string }[]; rejectedOverrides: { key: string; problem: string }[]; counts: Record<string, { applicable: number; excluded: number }> };

const STATE_LABEL: Record<string, string> = { not_started: "Not started", in_progress: "In progress", implemented: "Implemented", implemented_evidenced: "Implemented with evidence", not_applicable: "Not applicable" };
const STATE_TONE: Record<string, string> = { not_started: "bad", in_progress: "warn", implemented: "good", implemented_evidenced: "good", not_applicable: "muted" };
const onOff = (v: boolean | null) => (v === null ? "not in programme" : v ? "applies" : "excluded");

function useIsms() {
  const { tenantId } = useApp();
  const { data: me } = useData<any>(tenantId ? "isms/me" : null, { tenant_id: tenantId }, [tenantId]);
  const perms = safeArray<string>(me?.permissions);
  return { tenantId, me, perms };
}

function NoAccess({ me, what }: { me: any; what: string }) {
  return me ? <p className="muted">Your ISMS role in this customer ({displayValue(me.role ?? "none")}) cannot {what}. Ask an ISMS administrator for a role on the ISMS roles tab.</p> : null;
}

export function IsmsProgrammeTab() {
  const { tenantId, me, perms } = useIsms();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to set up its ISMS programme.</p>;
  if (!perms.includes("programme.manage")) return <NoAccess me={me} what="set up the programme" />;
  return <ProgrammeSetup tenantId={tenantId} />;
}

function ProgrammeSetup({ tenantId }: { tenantId: string }) {
  const { data, error, reload } = useData<{ frameworks: Option[] }>("isms/programme/frameworks", { tenant_id: tenantId }, [tenantId]);
  const { data: qs, reload: reloadQuestions } = useData<{ questions: Question[] }>("isms/programme/questions", { tenant_id: tenantId }, [tenantId]);
  const [answers, setAnswers] = useState<Record<string, unknown>>({});
  const [preview, setPreview] = useState<Preview | null>(null);
  const { run, busy } = useAction();
  const options = safeArray<Option>(data?.frameworks);
  const questions = safeArray<Question>(qs?.questions);
  useEffect(() => { setAnswers(Object.fromEntries(questions.map((q) => [q.ref, q.value]))); }, [qs]);  // eslint-disable-line react-hooks/exhaustive-deps

  const choose = async (framework: string, selected: boolean) => {
    const current = Object.fromEntries(options.filter((o) => o.selected && o.framework !== framework).map((o) => [o.framework, { status: o.status ?? "target_certification", targetDate: o.targetDate }]));
    if (selected) current[framework] = { status: "target_certification", targetDate: null };
    await run(() => api("isms/programme/frameworks", { method: "PUT", body: { tenantId, frameworks: current } }), selected ? "Framework added" : "Framework removed");
    reload(); reloadQuestions();
  };
  const changed = Object.fromEntries(questions.filter((q) => JSON.stringify(answers[q.ref] ?? null) !== JSON.stringify(q.value ?? null)).map((q) => [q.ref, answers[q.ref] ?? null]));
  const review = async () => { const p = await run(() => api<Preview>("isms/programme/preview", { body: { tenantId, answers: changed } })); if (p) setPreview(p); };
  const applyNow = async () => {
    const p = await run(() => api<Preview>("isms/programme/apply", { body: { tenantId, answers: changed } }), "Applicability applied");
    if (p) { setPreview(null); reloadQuestions(); }
  };

  return <>
    <EarlierRecords tenantId={tenantId} onDone={() => { reload(); reloadQuestions(); }} />
    <div className="card">
      <h3 style={{ marginTop: 0 }}>1. Frameworks</h3>
      <ErrorNote error={error} />
      <p className="small muted">Each framework stays on the content version chosen until an upgrade is reviewed. Requirement wording is not reproduced; ISO and Crown copyright frameworks show identifiers and short titles only.</p>
      <Table rows={options} empty="No frameworks are published yet." columns={[
        { key: "name", label: "Framework", render: (o) => <><b>{displayValue(o.name)}</b> <span className="small muted">{displayValue(o.version)}</span>{o.certifiable && <> <Pill value="certifiable" tone="good" /></>}</> },
        { key: "requirementCount", label: "Requirements" },
        { key: "pinnedVersion", label: "Content version", render: (o) => <span className="small">{o.selected ? o.pinnedVersion : o.packVersion}{o.selected && o.pinnedVersion !== o.packVersion ? ` (${o.packVersion} available)` : ""}</span> },
        { key: "selected", label: "In the programme", render: (o) => <label className="row" style={{ gap: 6 }}><input type="checkbox" checked={o.selected} disabled={busy} onChange={(e) => choose(o.framework, e.target.checked)} aria-label={`Include ${o.name}`} />{o.selected ? "Yes" : "No"}</label> }]} />
    </div>
    <div className="card">
      <h3 style={{ marginTop: 0 }}>2. About the organization</h3>
      {!questions.length && <p className="muted">Choose a framework to see its questions.</p>}
      {questions.map((q) => <QuestionField key={q.ref} q={q} value={answers[q.ref]} onChange={(v) => setAnswers({ ...answers, [q.ref]: v })} />)}
      {!!options.some((o) => o.selected) && <button className="primary" disabled={busy} onClick={review}>Review the changes</button>}
    </div>
    {preview && <Modal title="Review applicability changes" wide onClose={() => setPreview(null)} footer={<button className="primary" disabled={busy} onClick={applyNow}>Apply</button>}>
      <p className="small">After applying: {preview.counts.requirement?.applicable ?? 0} requirements apply and {preview.counts.requirement?.excluded ?? 0} are excluded; {preview.counts.control?.applicable ?? 0} controls apply.</p>
      {preview.rejectedOverrides.length > 0 && <div role="alert"><b>Manual decisions that will not take effect:</b><ul>{preview.rejectedOverrides.map((r) => <li key={r.key}>{r.key}: {displayValue(r.problem)}</li>)}</ul></div>}
      {preview.changes.length === 0 ? <p>Nothing changes.</p> : <Table rows={preview.changes.map((c) => ({ ...c, id: c.key }))} columns={[
        { key: "item", label: "Item", render: (c) => <><span className="small muted">{c.type.replace("_", " ")}</span> <b>{displayValue(c.item)}</b></> },
        { key: "from", label: "Now", render: (c) => onOff(c.from) },
        { key: "to", label: "After", render: (c) => <Pill value={onOff(c.to)} tone={c.to ? "good" : "warn"} /> },
        { key: "reason", label: "Why", render: (c) => <span className="small">{displayValue(c.reason)}</span> }]} />}
    </Modal>}
  </>;
}

/** Moving the customer's records from the earlier Governance programmes (shown while there is anything to move). */
function EarlierRecords({ tenantId, onDone }: { tenantId: string; onDone: () => void }) {
  const { data, reload } = useData<any>("isms/governance-import", { tenant_id: tenantId }, [tenantId]);
  const [result, setResult] = useState<any>(null);
  const { run, busy } = useAction();
  if (!data) return null;
  const total = data.answers + data.policies + data.evidence + data.records + safeArray<string>(data.frameworks).length;
  if (!total) return null;
  const move = async () => {
    const r = await run(() => api<any>("isms/governance-import", { body: { tenantId } }), "Earlier records moved");
    if (r) { setResult(r); reload(); onDone(); }
  };
  return <div className="card">
    <h3 style={{ marginTop: 0 }}>Earlier Governance records</h3>
    <p className="small">This customer has records in the earlier Governance programmes: {safeArray<string>(data.frameworks).join(", ") || "no frameworks"}, {data.answers} answers, {data.policies} policies, {data.evidence} pieces of evidence and {data.records} register entries.
      {data.alreadyMoved ? ` ${data.alreadyMoved} have been moved already; moving again only adds what is new.` : ""}</p>
    <p className="small muted">Moving brings the frameworks, answers (kept beside the Statement of Applicability, with "not applicable" answers as justified exclusions), policies (as documents, every approved version kept), evidence and risks into the ISMS. The earlier records are not changed.</p>
    {safeArray<string>(data.frameworksNotMoved).length > 0 && <p className="small">Not moved (not in the ISMS): {safeArray<string>(data.frameworksNotMoved).join(", ")}.</p>}
    <button className="primary" disabled={busy} onClick={move}>{data.alreadyMoved ? "Move what is new" : "Move them into the ISMS"}</button>
    {result && <p role="status" className="small">Moved {result.frameworks} framework(s), {result.answers} answer(s), {result.documents} document(s), {result.evidence} piece(s) of evidence, {result.risks} risk(s) and {result.notes} note(s).{safeArray<string>(result.skipped).length ? ` Not moved: ${safeArray<string>(result.skipped).slice(0, 5).join("; ")}.` : ""}</p>}
  </div>;
}

function QuestionField({ q, value, onChange }: { q: Question; value: unknown; onChange: (v: unknown) => void }) {
  const id = `q-${q.ref}`;
  const help = q.help ? <span className="small muted" id={`${id}-help`}>{q.help}</span> : null;
  if (q.type === "bool") return <fieldset className="field"><legend>{q.text}</legend>{help}
    <label className="row" style={{ gap: 6 }}><input type="radio" name={id} checked={value === true} onChange={() => onChange(true)} />Yes</label>
    <label className="row" style={{ gap: 6 }}><input type="radio" name={id} checked={value === false} onChange={() => onChange(false)} />No</label></fieldset>;
  if (q.type === "single") return <label className="field">{q.text}{help}<select value={(value as string) ?? ""} onChange={(e) => onChange(e.target.value || null)}>
    <option value="">Not answered</option>{q.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></label>;
  if (q.type === "multi") {
    const chosen = safeArray<string>(value);
    return <fieldset className="field"><legend>{q.text}</legend>{help}{q.options.map((o) => <label key={o.value} className="row" style={{ gap: 6 }}>
      <input type="checkbox" checked={chosen.includes(o.value)} onChange={(e) => onChange(e.target.checked ? [...chosen, o.value] : chosen.filter((x) => x !== o.value))} />{o.label}</label>)}</fieldset>;
  }
  return <label className="field">{q.text}{help}<input type="number" min={0} value={value === null || value === undefined ? "" : String(value)} onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))} /></label>;
}

export function IsmsControlsTab() {
  const { tenantId, me, perms } = useIsms();
  const { data, error, reload } = useData<any>(tenantId && perms.includes("controls.view") ? "isms/controls" : null, { tenant_id: tenantId }, [tenantId, perms.join()]);
  const { data: people } = useData<any>(tenantId && perms.includes("programme.manage") ? "isms/members" : null, { tenant_id: tenantId }, [tenantId, perms.join()]);
  const [open, setOpen] = useState<any>(null);
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its ISMS controls.</p>;
  if (!perms.includes("controls.view")) return <NoAccess me={me} what="view controls" />;
  const rows = safeArray<any>(data?.controls);
  return <div className="card">
    <ErrorNote error={error} />
    <p className="small muted">{rows.filter((c) => c.applicable).length} of {rows.length} controls apply. A control is not applicable when no applicable requirement needs it; its owner and notes are kept.</p>
    <Table rows={rows} empty="No controls yet. Set up the programme and apply applicability first." onRow={setOpen} columns={[
      { key: "ref", label: "Control", render: (c) => <><b>{displayValue(c.ref)}</b> {displayValue(c.title)}</> },
      { key: "state", label: "State", render: (c) => <Pill value={STATE_LABEL[c.state] ?? c.state} tone={STATE_TONE[c.state]} /> },
      { key: "ownerName", label: "Owner", render: (c) => displayValue(c.ownerName ?? "None") },
      { key: "requirements", label: "Requirements", render: (c) => <span className="small">{safeArray<string>(c.requirements).length}</span> }]} />
    {open && <ControlEditor control={open} members={safeArray<any>(people?.members)} canEditAll={perms.includes("controls.edit")} isOwner={open.ownerId === me?.userId}
      manualStates={safeArray<string>(data?.manualStates)} onClose={() => { setOpen(null); reload(); }} />}
  </div>;
}

const ANSWERS: [string, string][] = [["yes", "Yes, it is in place"], ["partly", "Partly"], ["no", "No, not yet"], ["not_relevant", "It does not apply to us"]];

function Assessment({ control, canExclude, onDone }: { control: any; canExclude: boolean; onDone: () => void }) {
  const [answer, setAnswer] = useState(control.assessment ?? "");
  const [implementation, setImplementation] = useState(control.implementation ?? "");
  const [justification, setJustification] = useState("");
  const { run, busy } = useAction();
  const options = ANSWERS.filter(([v]) => v !== "not_relevant" || canExclude);
  const save = async () => {
    const body: any = { answer, implementation };
    if (answer === "not_relevant") body.justification = justification;
    if (await run(() => api(`isms/controls/${control.id}/assessment`, { body }), "Answer saved")) onDone();
  };
  const needsText = answer === "yes" || answer === "partly";
  return <fieldset className="field"><legend>Is this in place today?</legend>
    {options.map(([v, label]) => <label key={v} className="row" style={{ gap: 6 }}><input type="radio" name={`assess-${control.id}`} checked={answer === v} onChange={() => setAnswer(v)} />{label}</label>)}
    {answer && answer !== "not_relevant" && <label className="field">{needsText ? "How it is done today (required, shown in the Statement of Applicability)" : "Notes on what is missing (optional)"}<textarea rows={3} value={implementation} onChange={(e) => setImplementation(e.target.value)} /></label>}
    {answer === "not_relevant" && <><p className="small muted">This excludes the control and the requirements it fully satisfies: {safeArray<string>(control.satisfies).join(", ") || "none"}.</p>
      <label className="field">Why it does not apply (required, shown in the Statement of Applicability)<textarea rows={3} value={justification} onChange={(e) => setJustification(e.target.value)} /></label></>}
    <button disabled={busy || !answer || (needsText && !implementation.trim()) || (answer === "not_relevant" && !justification.trim())} onClick={save}>Save answer</button>
  </fieldset>;
}

function ControlEditor({ control, members, canEditAll, isOwner, manualStates, onClose }: { control: any; members: any[]; canEditAll: boolean; isOwner: boolean; manualStates: string[]; onClose: () => void }) {
  const [state, setState] = useState(control.state);
  const [owner, setOwner] = useState(control.ownerId ?? "");
  const [notes, setNotes] = useState(control.notes ?? "");
  const { run, busy } = useAction();
  const canEdit = canEditAll || isOwner;
  const save = async () => {
    const body: any = { notes };
    if (control.applicable && manualStates.includes(state)) body.state = state;
    if (canEditAll) body.ownerId = owner || null;
    if (await run(() => api(`isms/controls/${control.id}`, { method: "PATCH", body }), "Control saved")) onClose();
  };
  return <Modal title={`${control.ref} ${control.title}`} wide onClose={onClose} footer={canEdit && <button className="primary" disabled={busy} onClick={save}>Save</button>}>
    <p>{displayValue(control.statement)}</p>
    <p className="small"><b>{control.applicable ? "Applies" : "Not applicable"}:</b> {displayValue(control.reason)}</p>
    {control.testProcedure && <p className="small"><b>How to test it:</b> {displayValue(control.testProcedure)}</p>}
    <p className="small"><b>Requirements it serves:</b> {safeArray<string>(control.requirements).join(", ") || "None"}</p>
    {canEdit && <Assessment control={control} canExclude={canEditAll} onDone={onClose} />}
    {canEdit && control.applicable && <label className="field">State<select value={manualStates.includes(state) ? state : ""} onChange={(e) => setState(e.target.value)}>
      {!manualStates.includes(state) && <option value="">{STATE_LABEL[state] ?? state}</option>}
      {manualStates.map((s) => <option key={s} value={s}>{STATE_LABEL[s]}</option>)}</select></label>}
    {canEditAll && <label className="field">Owner<select value={owner} onChange={(e) => setOwner(e.target.value)}>
      <option value="">None</option>{members.map((m) => <option key={m.id} value={m.id}>{m.name ? `${m.name} (${m.email})` : m.email}</option>)}</select></label>}
    {canEdit && <label className="field">Notes<textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} /></label>}
  </Modal>;
}

const SOA_TONE: Record<string, string> = { "Not applicable": "muted", "Not started": "bad", "In progress": "warn", Implemented: "good", "Implemented and evidenced": "good" };

/** The Statement of Applicability for one framework, with readiness and the Excel download. */
export function IsmsSoaTab() {
  const { tenantId, me, perms } = useIsms();
  const allowed = perms.includes("controls.view");
  const { data: ready, error: readyError } = useData<any>(tenantId && allowed ? "isms/readiness" : null, { tenant_id: tenantId }, [tenantId, allowed]);
  const frameworks = safeArray<any>(ready?.frameworks);
  const [framework, setFramework] = useState("");
  const current = framework || frameworks[0]?.framework || "";
  const { data, error } = useData<any>(tenantId && allowed && current ? "isms/soa" : null, { tenant_id: tenantId, framework: current }, [tenantId, current, allowed]);
  const [filter, setFilter] = useState("all");
  const { run, busy } = useAction();
  if (!tenantId) return <p className="muted">Choose a customer in the tenant picker to see its Statement of Applicability.</p>;
  if (!allowed) return <NoAccess me={me} what="view the Statement of Applicability" />;
  if (ready && !frameworks.length) return <p className="muted">No frameworks yet. Choose one on the Programme setup tab and apply applicability.</p>;
  const r = frameworks.find((f) => f.framework === current);
  const rows = safeArray<any>(data?.rows).filter((x) => filter === "all" || (filter === "excluded" ? !x.applicable : x.applicable && x.status !== "Implemented and evidenced"));
  const download = () => run(() => downloadFile(`isms/soa/export?tenant_id=${encodeURIComponent(tenantId)}&framework=${encodeURIComponent(current)}`, "statement-of-applicability.xlsx"), "Statement of Applicability downloaded");
  return <div className="card">
    <ErrorNote error={readyError || error} />
    <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "end", marginBottom: 8 }}>
      {frameworks.length > 1 && <label className="field">Framework<select value={current} onChange={(e) => setFramework(e.target.value)}>
        {frameworks.map((f) => <option key={f.framework} value={f.framework}>{f.framework}</option>)}</select></label>}
      <label className="field">Show<select value={filter} onChange={(e) => setFilter(e.target.value)}>
        <option value="all">Everything</option><option value="open">Applicable and not yet evidenced</option><option value="excluded">Excluded</option></select></label>
      <span style={{ flex: 1 }} />
      <button disabled={busy || !current} onClick={download}>Download (Excel)</button>
    </div>
    {r && <p className="small"><b>Readiness {r.score === null ? "not yet measurable" : `${r.score}%`}</b>: {r.met} of {r.applicable} applicable requirements met, {r.partial} partly met, {r.notApplicable} excluded. Controls evidenced: {r.coverage.score === null ? "none apply yet" : `${r.coverage.evidenced} of ${r.coverage.applicable} (${r.coverage.score}%)`}.
      <span className="muted"> {displayValue(r.formula)}</span></p>}
    <Table rows={rows.map((x) => ({ ...x, id: x.ref }))} empty="Nothing to show." columns={[
      { key: "ref", label: "Control", render: (x) => <><b>{displayValue(x.ref)}</b> {displayValue(x.title)}<div className="small muted">{displayValue(x.group)}</div></> },
      { key: "applicable", label: "Applicable", render: (x) => <><Pill value={x.applicable ? "yes" : "no"} tone={x.applicable ? "good" : "muted"} /><div className="small">{displayValue(x.justification ?? x.reason)}</div></> },
      { key: "controls", label: "Implemented by", render: (x) => <span className="small">{safeArray<any>(x.controls).map((c) => c.ref).join(", ") || "None"}</span> },
      { key: "status", label: "Status", render: (x) => <Pill value={x.status} tone={SOA_TONE[x.status]} /> },
      { key: "owners", label: "Owner", render: (x) => <span className="small">{safeArray<string>(x.owners).join(", ")}</span> },
      { key: "earlierAnswers", label: "Earlier answer", render: (x) => <span className="small">{safeArray<any>(x.earlierAnswers).map((a) => `${a.sourceRef}: ${a.status.replace("_", " ")}${a.answer ? `, "${a.answer}"` : ""}`).join("; ")}</span> }]} />
  </div>;
}
