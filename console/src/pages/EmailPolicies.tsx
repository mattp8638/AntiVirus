import { useEffect, useMemo, useState } from "react";
import { ago, api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, Pill, Table, Tabs, useAction, useData } from "../components/ui";

type Doc = {
  antispam: { suspiciousScore: number; phishScore: number; highPhishScore: number; bulkThreshold: number; actions: Record<string, string>; subjectPrefix: string };
  antiphish: { protectPeople: boolean; protectedNames: string[]; protectedDomains: string[]; lookalike: string; honourDmarc: boolean; firstContactTag: boolean; actions: Record<string, string> };
  antimalware: { blockedTypes: string[]; scanArchives: boolean; encryptedArchives: string; macros: string; zeroHour: boolean; action: string };
  connection: { ipAllow: string[]; ipBlock: string[] };
  quarantine: { userRelease: string[]; keepContent: string };
  rules: Rule[];
};
type Condition = { field: string; operator: string; value: string | string[] | number };
type RuleAction = { type: string; value: string | number };
export type Rule = { id: string; name: string; enabled: boolean; priority: number; mode: string; match: string; conditions: Condition[]; exceptions: Condition[]; actions: RuleAction[]; stop: boolean; comment: string };
interface Version { id: string; version: number; createdBy: string; createdAt: string; comment: string; preset: string; inherit: boolean }
interface PolicyView { tenantId: string; tenantName: string; document: Doc; effective: { tenantId: string | null; version: number; inherited: boolean; preset: string; sourceName: string }; isRoot: boolean; versions: Version[] }
interface Schema { presets: Record<string, Doc>; fields: Record<string, string>; operators: string[]; ruleActions: string[]; actions: string[]; classes: string[]; defaultBlockedTypes: string[] }
interface Trail { source: string; detail: string; action?: string }
export interface Decision { action: string; classification: string; decidedBy: string; trail: Trail[]; tag: string; headers: string[]; categories: string[]; audit: { rule: string; actions: RuleAction[] }[]; scoreChange: number; policy: { version?: number | string; tenantId?: string | null; inherited?: boolean } }

const ACTION_TEXT: Record<string, string> = { deliver: "Deliver", tag: "Tag (subject or category)", junk: "Move to Junk", quarantine: "Quarantine", reject: "Reject (gateway; quarantine in mailboxes)" };
const CLASS_TEXT: Record<string, string> = { bulk: "Bulk", spam: "Spam", suspicious: "Suspicious", phish: "Phishing", highphish: "High-confidence phishing", impersonation: "Impersonation", spoof: "Spoofing", malware: "Malware", clean: "Clean" };
const RULE_ACTION_TEXT: Record<string, string> = { quarantine: "Quarantine", reject: "Reject", junk: "Move to Junk", deliver: "Deliver", bypass: "Bypass spam and phishing checks", tag: "Tag (prefix)", addHeader: "Add header", addCategory: "Add Outlook category", score: "Change score by", notify: "Notify (email)" };
const OP_TEXT: Record<string, string> = { is: "is", isNot: "is not", contains: "contains", notContains: "does not contain", startsWith: "starts with", endsWith: "ends with", matches: "matches pattern", in: "is any of", greaterThan: "is greater than", lessThan: "is less than", inRange: "is in IP range", isTrue: "is true", isFalse: "is false" };
const lines = (v: string[]) => v.join("\n");
const unlines = (v: string) => v.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

/** The policy editor: one scope (the MSP default or a customer), its sections, its rules and its history. */
export default function EmailPolicies({ initialTab = "Anti-spam" }: { initialTab?: string }) {
  const { me, tenantId } = useApp();
  const tenants = me?.tenants ?? [];
  const root = tenants.find((t) => !t.parentId)?.id ?? tenants[0]?.id ?? "";
  const [scope, setScope] = useState(tenantId || root);
  useEffect(() => { if (tenantId) setScope(tenantId); }, [tenantId]);
  const { data, error, reload } = useData<PolicyView>(scope ? `email-security/policy/${scope}` : null, {}, [scope]);
  const { data: schema } = useData<Schema>("email-security/policy-schema");
  const [draft, setDraft] = useState<Doc | null>(null);
  const [tab, setTab] = useState(initialTab);
  const [saving, setSaving] = useState(false);
  const [history, setHistory] = useState<number | null>(null);
  useEffect(() => { setDraft(data ? structuredClone(data.document) : null); }, [data]);
  const dirty = useMemo(() => data && draft && JSON.stringify(draft) !== JSON.stringify(data.document), [data, draft]);
  const update = (section: keyof Doc, value: object) => setDraft((d) => d ? { ...d, [section]: { ...(d[section] as object), ...value } } as Doc : d);
  if (!scope) return <div className="card muted">No customers.</div>;
  return (
    <>
      <ErrorNote error={error} />
      <div className="card" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <label className="small">Policy for{" "}
          <select value={scope} onChange={(e) => setScope(e.target.value)}>
            {tenants.map((t) => <option key={t.id} value={t.id}>{t.id === root ? `${t.name} (MSP default for every customer)` : t.name}</option>)}
          </select>
        </label>
        {data && <span className="small">
          {data.effective.inherited ? <>Following <b>{data.effective.sourceName}</b>{data.effective.version ? ` (version ${data.effective.version})` : ""}. Saving here gives this customer its own policy.</>
            : <>Own policy, <b>version {data.effective.version}</b>{data.effective.preset ? ` (from the ${data.effective.preset} preset)` : ""}.</>}
        </span>}
        <span style={{ flex: 1 }} />
        {data && <button onClick={() => setHistory(data.versions[0]?.version ?? 0)} disabled={!data.versions.length}>History ({data.versions.length})</button>}
      </div>
      {draft && schema && <>
        <Tabs tabs={["Anti-spam", "Anti-phishing", "Anti-malware", "Connection filter", "Quarantine & content", "Mail flow rules", "Test"]} active={tab} onChange={setTab} />
        {tab === "Anti-spam" && <AntiSpam doc={draft} update={update} />}
        {tab === "Anti-phishing" && <AntiPhish doc={draft} update={update} />}
        {tab === "Anti-malware" && <AntiMalware doc={draft} update={update} defaults={schema.defaultBlockedTypes} />}
        {tab === "Connection filter" && <Connection doc={draft} update={update} />}
        {tab === "Quarantine & content" && <QuarantineSettings doc={draft} update={update} />}
        {tab === "Mail flow rules" && <RulesEditor rules={draft.rules} schema={schema} onChange={(rules) => setDraft({ ...draft, rules })} />}
        {tab === "Test" && <TestPolicy draft={draft} />}
        {tab !== "Test" && <SaveBar scope={scope} draft={draft} dirty={!!dirty} isRoot={!!data?.isRoot} inherited={!!data?.effective.inherited}
                                     saving={saving} setSaving={setSaving} onSaved={reload} onReset={() => data && setDraft(structuredClone(data.document))} />}
      </>}
      {history !== null && data && <History scope={scope} versions={data.versions} start={history} onClose={() => setHistory(null)} onRestored={reload} />}
    </>
  );
}

function SaveBar({ scope, draft, dirty, isRoot, inherited, saving, setSaving, onSaved, onReset }: {
  scope: string; draft: Doc; dirty: boolean; isRoot: boolean; inherited: boolean; saving: boolean; setSaving: (b: boolean) => void; onSaved: () => void; onReset: () => void;
}) {
  const { can, toast } = useApp();
  const [comment, setComment] = useState("");
  const save = async (body: Record<string, unknown>, done: string) => {
    setSaving(true);
    try {
      const saved = await api<{ version: number }>(`email-security/policy/${scope}`, { method: "PUT", body: { comment, ...body } });
      toast(`${done} (version ${saved.version}).`);
      setComment("");
      onSaved();
    } catch (err) { toast((err as Error).message, true); } finally { setSaving(false); }
  };
  if (!can("configure")) return <p className="small muted">You can view this policy; changing it needs the configure permission.</p>;
  return (
    <div className="card" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", position: "sticky", bottom: 0 }}>
      <input placeholder="What changed and why (kept with the version)" value={comment} onChange={(e) => setComment(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
      <button className="primary" disabled={saving || (!dirty && !inherited)} onClick={() => save({ document: draft }, "Saved")}>{dirty ? "Save as new version" : inherited ? "Save as this customer's own policy" : "No changes"}</button>
      {dirty && <button disabled={saving} onClick={onReset}>Discard changes</button>}
      <button disabled={saving} onClick={() => save({ preset: "standard", document: draft }, "Standard preset applied")}>Apply Standard preset</button>
      <button disabled={saving} onClick={() => save({ preset: "strict", document: draft }, "Strict preset applied")}>Apply Strict preset</button>
      {!isRoot && !inherited && <button disabled={saving} onClick={() => save({ inherit: true }, "Now following the MSP default")}>Follow the MSP default</button>}
      <span className="small muted">Presets keep your mail flow rules.</span>
    </div>
  );
}

function ActionSelect({ value, onChange, options = ["deliver", "tag", "junk", "quarantine", "reject"] }: { value: string; onChange: (v: string) => void; options?: string[] }) {
  return <select value={value} onChange={(e) => onChange(e.target.value)}>{options.map((o) => <option key={o} value={o}>{ACTION_TEXT[o] ?? o}</option>)}</select>;
}

function Field({ label, help, children }: { label: string; help?: string; children: React.ReactNode }) {
  return <div style={{ display: "grid", gridTemplateColumns: "minmax(180px, 280px) 1fr", gap: 12, padding: "8px 0", borderBottom: "1px solid rgba(148,163,184,.12)" }}>
    <div><b className="small">{label}</b>{help && <div className="small muted">{help}</div>}</div><div>{children}</div></div>;
}

function AntiSpam({ doc, update }: { doc: Doc; update: (s: keyof Doc, v: object) => void }) {
  const a = doc.antispam;
  const num = (key: keyof Doc["antispam"], min: number, max: number) =>
    <input type="number" min={min} max={max} value={a[key] as number} onChange={(e) => update("antispam", { [key]: Number(e.target.value) })} style={{ width: 90 }} />;
  return (
    <div className="card">
      <h3>Thresholds</h3>
      <Field label="Suspicious from score" help="Fenrir's score (0-100) at which mail counts as suspicious">{num("suspiciousScore", 1, 99)}</Field>
      <Field label="Phishing from score">{num("phishScore", 1, 100)}</Field>
      <Field label="High-confidence phishing from score">{num("highPhishScore", 1, 100)}</Field>
      <Field label="Bulk from Microsoft bulk level" help="Microsoft's BCL (1-9); lower catches more newsletters">{num("bulkThreshold", 1, 9)}</Field>
      <h3>Actions</h3>
      {(["bulk", "spam", "suspicious", "phish", "highphish"] as const).map((c) => (
        <Field key={c} label={CLASS_TEXT[c]} help={c === "spam" || c === "bulk" ? "From Microsoft's verdict (mailbox scanning)" : undefined}>
          <ActionSelect value={a.actions[c]} onChange={(v) => update("antispam", { actions: { ...a.actions, [c]: v } })} />
        </Field>))}
      <Field label="Subject prefix for tagged mail" help="Added at the gateway when the domain allows subject changes; mailboxes get an Outlook category">
        <input value={a.subjectPrefix} maxLength={40} onChange={(e) => update("antispam", { subjectPrefix: e.target.value })} />
      </Field>
    </div>
  );
}

function AntiPhish({ doc, update }: { doc: Doc; update: (s: keyof Doc, v: object) => void }) {
  const p = doc.antiphish;
  return (
    <div className="card">
      <h3>Impersonation protection</h3>
      <Field label="Protect everyone in the directory" help="Outside senders using a colleague's display name">
        <input type="checkbox" checked={p.protectPeople} onChange={(e) => update("antiphish", { protectPeople: e.target.checked })} />
      </Field>
      <Field label="Also protect these names" help="One per line: directors, finance staff, suppliers">
        <textarea rows={4} value={lines(p.protectedNames)} onChange={(e) => update("antiphish", { protectedNames: unlines(e.target.value) })} style={{ width: "100%" }} />
      </Field>
      <Field label="Also protect these domains" help="Partners and suppliers whose lookalikes should be caught; the customer's own domains are always protected">
        <textarea rows={3} value={lines(p.protectedDomains)} onChange={(e) => update("antiphish", { protectedDomains: unlines(e.target.value) })} style={{ width: "100%" }} />
      </Field>
      <Field label="Lookalike sensitivity">
        <select value={p.lookalike} onChange={(e) => update("antiphish", { lookalike: e.target.value })}><option value="off">Off</option><option value="standard">Standard</option><option value="strict">Strict</option></select>
      </Field>
      <Field label="Impersonation action"><ActionSelect value={p.actions.impersonation} onChange={(v) => update("antiphish", { actions: { ...p.actions, impersonation: v } })} /></Field>
      <h3>Spoofing</h3>
      <Field label="Honour the sender's DMARC policy" help="When a domain says quarantine or reject and the message fails DMARC">
        <input type="checkbox" checked={p.honourDmarc} onChange={(e) => update("antiphish", { honourDmarc: e.target.checked })} />
      </Field>
      <Field label="Spoofing action"><ActionSelect value={p.actions.spoof} onChange={(v) => update("antiphish", { actions: { ...p.actions, spoof: v } })} /></Field>
      <Field label="Tag first contact" help="Adds the category 'Fenrir: first contact' to the first message from a new sender domain">
        <input type="checkbox" checked={p.firstContactTag} onChange={(e) => update("antiphish", { firstContactTag: e.target.checked })} />
      </Field>
    </div>
  );
}

function AntiMalware({ doc, update, defaults }: { doc: Doc; update: (s: keyof Doc, v: object) => void; defaults: string[] }) {
  const m = doc.antimalware;
  const [adding, setAdding] = useState("");
  const add = () => { const t = adding.trim().replace(/^\./, "").toLowerCase(); if (t && !m.blockedTypes.includes(t)) update("antimalware", { blockedTypes: [...m.blockedTypes, t].sort() }); setAdding(""); };
  return (
    <div className="card">
      <Field label="Action for malware"><ActionSelect value={m.action} options={["quarantine", "reject"]} onChange={(v) => update("antimalware", { action: v })} /></Field>
      <Field label={`Blocked file types (${m.blockedTypes.length})`} help="Attachments with these extensions are treated as malware">
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 6 }}>
          {m.blockedTypes.map((t) => <span key={t} className="badge" style={{ cursor: "pointer" }} title="Remove" onClick={() => update("antimalware", { blockedTypes: m.blockedTypes.filter((x) => x !== t) })}>.{t} ✕</span>)}
        </div>
        <span style={{ display: "inline-flex", gap: 6 }}>
          <input placeholder="e.g. iso" value={adding} onChange={(e) => setAdding(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} style={{ width: 120 }} />
          <button onClick={add}>Add type</button>
          <button onClick={() => update("antimalware", { blockedTypes: defaults })}>Reset to defaults</button>
        </span>
      </Field>
      <Field label="Look inside archives" help="Checks file names inside .zip attachments against the blocked types">
        <input type="checkbox" checked={m.scanArchives} onChange={(e) => update("antimalware", { scanArchives: e.target.checked })} />
      </Field>
      <Field label="Password-protected archives" help="Fenrir cannot see inside them, which is why attackers use them">
        <ActionSelect value={m.encryptedArchives} onChange={(v) => update("antimalware", { encryptedArchives: v })} />
      </Field>
      <Field label="Office files with macros"><ActionSelect value={m.macros} onChange={(v) => update("antimalware", { macros: v })} /></Field>
      <Field label="Zero-hour re-check" help="Re-scores the last 48 hours of mail when new threat intel names a file or link, and acts on it">
        <input type="checkbox" checked={m.zeroHour} onChange={(e) => update("antimalware", { zeroHour: e.target.checked })} />
      </Field>
    </div>
  );
}

function Connection({ doc, update }: { doc: Doc; update: (s: keyof Doc, v: object) => void }) {
  const c = doc.connection;
  return (
    <div className="card">
      <p className="small muted">Applies to mail arriving through Fenrir's gateway. Blocked addresses are refused before the message is accepted.</p>
      <Field label="Always allow these IPs" help="One address or range per line (203.0.113.0/24). Skips spam and phishing checks, never malware checks.">
        <textarea rows={5} value={lines(c.ipAllow)} onChange={(e) => update("connection", { ipAllow: unlines(e.target.value) })} style={{ width: "100%" }} />
      </Field>
      <Field label="Always block these IPs"><textarea rows={5} value={lines(c.ipBlock)} onChange={(e) => update("connection", { ipBlock: unlines(e.target.value) })} style={{ width: "100%" }} /></Field>
    </div>
  );
}

function QuarantineSettings({ doc, update }: { doc: Doc; update: (s: keyof Doc, v: object) => void }) {
  const q = doc.quarantine;
  const toggle = (c: string) => update("quarantine", { userRelease: q.userRelease.includes(c) ? q.userRelease.filter((x) => x !== c) : [...q.userRelease, c] });
  return (
    <div className="card">
      <Field label="Users may ask for these back" help="Shown with an 'ask for it back' link in their digest. Malware never is.">
        <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 10 }}>
          {["bulk", "spam", "suspicious", "phish", "highphish", "impersonation", "spoof"].map((c) =>
            <label key={c} className="small"><input type="checkbox" checked={q.userRelease.includes(c)} onChange={() => toggle(c)} /> {CLASS_TEXT[c]}</label>)}
        </span>
      </Field>
      <Field label="Keep message bodies" help="Encrypted, for technicians to read in the console. Deleted with the scan.">
        <select value={q.keepContent} onChange={(e) => update("quarantine", { keepContent: e.target.value })}>
          <option value="flagged">For flagged mail (anything not clean, acted on, or matched by a rule)</option>
          <option value="all">For all mail</option>
          <option value="none">Never (mailbox bodies are still readable on demand)</option>
        </select>
      </Field>
    </div>
  );
}

function blankRule(priority: number): Rule {
  return { id: `rule-${Date.now()}`, name: "New rule", enabled: true, priority, mode: "enforce", match: "all",
           conditions: [{ field: "subject", operator: "contains", value: "" }], exceptions: [], actions: [{ type: "quarantine", value: "" }], stop: false, comment: "" };
}

function RulesEditor({ rules, schema, onChange }: { rules: Rule[]; schema: Schema; onChange: (r: Rule[]) => void }) {
  const [editing, setEditing] = useState<number | null>(null);
  const sorted = [...rules].sort((a, b) => a.priority - b.priority);
  const renumber = (list: Rule[]) => onChange(list.map((r, i) => ({ ...r, priority: i })));
  const move = (i: number, d: number) => { const list = [...sorted]; const [r] = list.splice(i, 1); list.splice(i + d, 0, r); renumber(list); };
  return (
    <div className="card">
      <p className="small muted">Rules run in order, before the policies, like Exchange mail flow rules. A rule in audit mode only records what it would have done (see a message's Decision tab), so you can try a rule safely.
        Save the policy to apply changes.</p>
      <Table rows={sorted.map((r, i) => ({ ...r, id: r.id, idx: i }))} empty="No mail flow rules yet."
             columns={[
               { key: "idx", label: "Order", render: (r) => <span style={{ display: "inline-flex", gap: 4 }}>{r.idx + 1}
                 <button className="ghost" disabled={r.idx === 0} onClick={() => move(r.idx, -1)} aria-label="Move up">↑</button>
                 <button className="ghost" disabled={r.idx === sorted.length - 1} onClick={() => move(r.idx, 1)} aria-label="Move down">↓</button></span> },
               { key: "name", label: "Rule", render: (r) => <><b>{r.name}</b><div className="small muted">{describe(r, schema)}</div></> },
               { key: "mode", label: "Mode", render: (r) => !r.enabled ? <Pill value="off" tone="muted" /> : r.mode === "audit" ? <Pill value="audit only" tone="warn" /> : <Pill value="enforce" tone="good" /> },
               { key: "actions", label: "", className: "right", render: (r) => <span style={{ display: "inline-flex", gap: 6 }}>
                 <button onClick={() => setEditing(r.idx)}>Edit</button>
                 <button onClick={() => onChange(sorted.map((x, i) => i === r.idx ? { ...x, enabled: !x.enabled } : x))}>{r.enabled ? "Turn off" : "Turn on"}</button>
                 <button className="danger" onClick={() => renumber(sorted.filter((_, i) => i !== r.idx))}>Delete</button></span> },
             ]} />
      <p><button className="primary" onClick={() => { onChange([...sorted, blankRule(sorted.length)]); setEditing(sorted.length); }}>Add a rule</button></p>
      {editing !== null && sorted[editing] && <RuleModal rule={sorted[editing]} schema={schema} onClose={() => setEditing(null)}
        onSave={(rule) => { onChange(sorted.map((x, i) => i === editing ? rule : x)); setEditing(null); }} />}
    </div>
  );
}

function describe(r: Rule, schema: Schema): string {
  const c = r.conditions.map((x) => `${schema.fields[x.field] ?? x.field} ${OP_TEXT[x.operator] ?? x.operator} ${Array.isArray(x.value) ? x.value.join(", ") : x.value}`.trim());
  return `If ${c.join(r.match === "any" ? " or " : " and ")}${r.exceptions.length ? " (with exceptions)" : ""} → ${r.actions.map((a) => RULE_ACTION_TEXT[a.type] ?? a.type).join(", ")}${r.stop ? "; stop" : ""}`;
}

function ConditionRows({ items, schema, onChange }: { items: Condition[]; schema: Schema; onChange: (c: Condition[]) => void }) {
  return <>{items.map((c, i) => (
    <div key={i} style={{ display: "flex", gap: 6, marginBottom: 6, flexWrap: "wrap" }}>
      <select value={c.field} onChange={(e) => onChange(items.map((x, j) => j === i ? { ...x, field: e.target.value } : x))}>
        {Object.entries(schema.fields).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
      <select value={c.operator} onChange={(e) => onChange(items.map((x, j) => j === i ? { ...x, operator: e.target.value } : x))}>
        {schema.operators.map((o) => <option key={o} value={o}>{OP_TEXT[o] ?? o}</option>)}</select>
      {!["isTrue", "isFalse"].includes(c.operator) && <input style={{ flex: 1, minWidth: 160 }} placeholder={c.operator === "in" || c.operator === "inRange" ? "values, comma separated" : c.field === "header" ? "X-Header: value" : "value"}
        value={Array.isArray(c.value) ? c.value.join(", ") : String(c.value ?? "")} onChange={(e) => onChange(items.map((x, j) => j === i ? { ...x, value: e.target.value } : x))} />}
      <button className="ghost" onClick={() => onChange(items.filter((_, j) => j !== i))} aria-label="Remove">✕</button>
    </div>))}</>;
}

function RuleModal({ rule, schema, onClose, onSave }: { rule: Rule; schema: Schema; onClose: () => void; onSave: (r: Rule) => void }) {
  const [r, setR] = useState<Rule>(structuredClone(rule));
  return (
    <Modal title={`Mail flow rule: ${r.name}`} onClose={onClose} wide footer={<><button onClick={onClose}>Cancel</button><button className="primary" onClick={() => onSave(r)}>Done</button></>}>
      <div style={{ display: "grid", gap: 10 }}>
        <label className="small">Name <input value={r.name} onChange={(e) => setR({ ...r, name: e.target.value })} style={{ width: "100%" }} /></label>
        <div><b className="small">Apply this rule if</b>{" "}
          <select value={r.match} onChange={(e) => setR({ ...r, match: e.target.value })}><option value="all">all of these are true</option><option value="any">any of these is true</option></select>
          <div style={{ marginTop: 6 }}><ConditionRows items={r.conditions} schema={schema} onChange={(conditions) => setR({ ...r, conditions })} /></div>
          <button onClick={() => setR({ ...r, conditions: [...r.conditions, { field: "subject", operator: "contains", value: "" }] })}>Add condition</button>
        </div>
        <div><b className="small">Except if any of these is true</b>
          <div style={{ marginTop: 6 }}><ConditionRows items={r.exceptions} schema={schema} onChange={(exceptions) => setR({ ...r, exceptions })} /></div>
          <button onClick={() => setR({ ...r, exceptions: [...r.exceptions, { field: "sender", operator: "is", value: "" }] })}>Add exception</button>
        </div>
        <div><b className="small">Do the following</b>
          {r.actions.map((a, i) => (
            <div key={i} style={{ display: "flex", gap: 6, margin: "6px 0" }}>
              <select value={a.type} onChange={(e) => setR({ ...r, actions: r.actions.map((x, j) => j === i ? { ...x, type: e.target.value } : x) })}>
                {schema.ruleActions.map((t) => <option key={t} value={t}>{RULE_ACTION_TEXT[t] ?? t}</option>)}</select>
              {["tag", "addHeader", "addCategory", "score", "notify"].includes(a.type) &&
                <input style={{ flex: 1 }} placeholder={a.type === "addHeader" ? "X-Name: value" : a.type === "score" ? "+20 or -20" : a.type === "notify" ? "someone@example.com" : a.type === "tag" ? "[External]" : "Category"}
                       value={String(a.value ?? "")} onChange={(e) => setR({ ...r, actions: r.actions.map((x, j) => j === i ? { ...x, value: e.target.value } : x) })} />}
              <button className="ghost" onClick={() => setR({ ...r, actions: r.actions.filter((_, j) => j !== i) })} aria-label="Remove">✕</button>
            </div>))}
          <button onClick={() => setR({ ...r, actions: [...r.actions, { type: "tag", value: "" }] })}>Add action</button>
        </div>
        <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
          <label className="small"><input type="checkbox" checked={r.mode === "audit"} onChange={(e) => setR({ ...r, mode: e.target.checked ? "audit" : "enforce" })} /> Audit only (record, don't act)</label>
          <label className="small"><input type="checkbox" checked={r.stop} onChange={(e) => setR({ ...r, stop: e.target.checked })} /> Stop processing more rules</label>
          <label className="small"><input type="checkbox" checked={r.enabled} onChange={(e) => setR({ ...r, enabled: e.target.checked })} /> On</label>
        </div>
        <label className="small">Comment <input value={r.comment} onChange={(e) => setR({ ...r, comment: e.target.value })} style={{ width: "100%" }} /></label>
      </div>
    </Modal>
  );
}

function History({ scope, versions, start, onClose, onRestored }: { scope: string; versions: Version[]; start: number; onClose: () => void; onRestored: () => void }) {
  const [selected, setSelected] = useState(start);
  const { data } = useData<Version & { changes: { path: string; from: unknown; to: unknown }[] }>(`email-security/policy/${scope}/versions/${selected}`, {}, [selected]);
  const { run, busy } = useAction();
  const { can } = useApp();
  const restore = async () => { await run(() => api(`email-security/policy/${scope}/versions/${selected}/restore`, { method: "POST" }), `Version ${selected} restored as a new version.`); onRestored(); onClose(); };
  const show = (v: unknown) => v === undefined || v === null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
  return (
    <Modal title="Policy history" onClose={onClose} wide>
      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 16 }}>
        <div style={{ maxHeight: 460, overflow: "auto" }}>
          {versions.map((v) => <div key={v.id} onClick={() => setSelected(v.version)} className="card" style={{ cursor: "pointer", padding: 8, marginBottom: 6, borderColor: v.version === selected ? "rgba(59,130,246,.7)" : undefined }}>
            <b>Version {v.version}</b> <span className="small muted">{ago(v.createdAt)}</span>
            <div className="small">{v.comment || (v.inherit ? "Follow the MSP default" : v.preset ? `${v.preset} preset` : "No comment")}</div>
            <div className="small muted">{v.createdBy}</div></div>)}
        </div>
        <div>
          {data && <>
            <p className="small">Version {data.version} by {data.createdBy}, {ago(data.createdAt)}{data.inherit ? ": follows the MSP default." : "."}</p>
            <Table rows={data.changes.map((c, i) => ({ ...c, id: String(i) }))} empty="No differences from the version before."
                   columns={[{ key: "path", label: "Setting", render: (c) => <span className="mono small">{c.path}</span> },
                             { key: "from", label: "Before", render: (c) => <span className="mono small" style={{ color: "#fca5a5", wordBreak: "break-all" }}>{show(c.from)}</span> },
                             { key: "to", label: "After", render: (c) => <span className="mono small" style={{ color: "#86efac", wordBreak: "break-all" }}>{show(c.to)}</span> }]} />
            {can("configure") && selected !== versions[0]?.version && <p><button className="primary" disabled={busy} onClick={restore}>Restore version {selected}</button></p>}
          </>}
        </div>
      </div>
    </Modal>
  );
}

function TestPolicy({ draft }: { draft: Doc }) {
  const [scanId, setScanId] = useState("");
  const [result, setResult] = useState<{ decision: Decision; current: Decision | null } | null>(null);
  const { run, busy } = useAction();
  const test = async () => { const r = await run(() => api<{ decision: Decision; current: Decision | null }>("email-security/policy/test", { method: "POST", body: { scanId, document: draft } })); if (r) setResult(r); };
  return (
    <div className="card">
      <p className="small muted">Run a message Fenrir has already checked through this draft (unsaved changes included) and see what would happen. Nothing is changed.
        Copy a message's ID from its Decision tab in the Explorer.</p>
      <div style={{ display: "flex", gap: 8 }}><input placeholder="Message ID (emsc…)" value={scanId} onChange={(e) => setScanId(e.target.value.trim())} style={{ flex: 1 }} />
        <button className="primary" disabled={busy || !scanId} onClick={test}>Test</button></div>
      {result && <div className="grid k2" style={{ marginTop: 12 }}>
        <div><h3>With this draft</h3><DecisionView decision={result.decision} /></div>
        <div><h3>What actually happened</h3>{result.current ? <DecisionView decision={result.current} /> : <p className="muted small">Not recorded.</p>}</div>
      </div>}
    </div>
  );
}

export function DecisionView({ decision }: { decision: Decision }) {
  return (
    <>
      <p><Pill value={ACTION_TEXT[decision.action]?.split(" (")[0] ?? decision.action} tone={["quarantine", "reject"].includes(decision.action) ? "bad" : decision.action === "deliver" ? "good" : "warn"} />{" "}
        <b>{CLASS_TEXT[decision.classification] ?? decision.classification}</b> · decided by <b>{decision.decidedBy || "—"}</b>
        {decision.policy?.version !== undefined && <span className="small muted"> · policy {decision.policy.version === 0 ? "Standard preset" : `version ${decision.policy.version}`}{decision.policy.inherited ? " (MSP default)" : ""}</span>}</p>
      <ol className="small">{decision.trail.map((t, i) => <li key={i}><b>{t.source}</b>: {t.detail}{t.action && <span className="muted"> → {t.action}</span>}</li>)}</ol>
      {decision.audit?.length > 0 && <p className="small" style={{ color: "#fbbf24" }}>Audit-only rules that matched: {decision.audit.map((a) => a.rule).join(", ")}</p>}
      {(decision.headers?.length > 0 || decision.categories?.length > 0 || decision.tag) && <p className="small muted">
        {decision.tag && <>Subject tag: {decision.tag}. </>}{decision.categories?.length > 0 && <>Categories: {decision.categories.join(", ")}. </>}{decision.headers?.length > 0 && <>Headers: {decision.headers.join("; ")}.</>}</p>}
    </>
  );
}
