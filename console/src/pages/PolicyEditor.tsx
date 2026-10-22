import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, PageHead, Pill, useAction, useData } from "../components/ui";

type Settings = Record<string, Record<string, any>>;

export default function PolicyEditor() {
  const { id } = useParams();
  const { can, tenantName } = useApp();
  const { data, error, reload } = useData<any>(`policies/${id}`);
  const { data: schema } = useData<any>("policy-schema");
  const [settings, setSettings] = useState<Settings>({});
  const [locks, setLocks] = useState<string[]>([]);
  const [section, setSection] = useState("antimalware");
  const [filter, setFilter] = useState("");
  const [dirty, setDirty] = useState(false);
  const { run, busy } = useAction();

  useEffect(() => {
    if (data) {
      setSettings(structuredClone(data.policy.settings || {}));
      setLocks([...(data.policy.locks || [])]);
      setDirty(false);
    }
  }, [data]);

  const inherited: Settings = data?.inherited.settings ?? {};
  const inheritedOrigin: Record<string, string> = data?.inherited.origin ?? {};
  const inheritedLocks: Record<string, string> = data?.inherited.locked ?? {};
  const editable = can("configure");

  const overrideCount = useMemo(() => Object.values(settings).reduce((n, s) => n + Object.keys(s).length, 0), [settings]);

  if (error) return <ErrorNote error={error} />;
  if (!data || !schema) return <div className="empty">Loading…</div>;

  const setValue = (sectionKey: string, key: string, value: any) => {
    setSettings((prev) => ({ ...prev, [sectionKey]: { ...(prev[sectionKey] || {}), [key]: value } }));
    setDirty(true);
  };
  const clearValue = (sectionKey: string, key: string) => {
    setSettings((prev) => {
      const next = { ...prev, [sectionKey]: { ...(prev[sectionKey] || {}) } };
      delete next[sectionKey][key];
      if (!Object.keys(next[sectionKey]).length) delete next[sectionKey];
      return next;
    });
    setDirty(true);
  };
  const toggleLock = (path: string) => {
    setLocks((prev) => (prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path]));
    setDirty(true);
  };
  const save = async () => {
    await run(() => api(`policies/${id}`, { method: "PUT", body: { settings, locks, name: data.policy.name, description: data.policy.description } }), "Policy saved. Devices pick it up on their next check-in.");
    reload();
  };

  const current = schema.sections.find((s: any) => s.key === section);
  const fields = (filter
    ? schema.sections.flatMap((s: any) => s.fields.map((f: any) => ({ ...f, section: s.key })))
        .filter((f: any) => `${f.label} ${f.help} ${f.path}`.toLowerCase().includes(filter.toLowerCase()))
    : current.fields.map((f: any) => ({ ...f, section: current.key })));

  return (
    <>
      <PageHead title={data.policy.name}
                subtitle={<>{data.policy.tenantId ? tenantName(data.policy.tenantId) : "Global"} · v{data.policy.version} · {overrideCount} settings set here · {locks.length} locked</>}
                actions={editable && <button className="primary" disabled={!dirty || busy} onClick={save}>{dirty ? "Save changes" : "Saved"}</button>} />
      <div className="grid" style={{ gridTemplateColumns: "220px minmax(0,1fr)" }}>
        <div className="card" style={{ padding: 8, alignSelf: "start" }}>
          <input placeholder="Search all settings" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: "100%", marginBottom: 8 }} />
          {schema.sections.map((s: any) => {
            const count = Object.keys(settings[s.key] || {}).length;
            return (
              <button key={s.key} className={`ghost ${section === s.key && !filter ? "active" : ""}`}
                      style={{ width: "100%", justifyContent: "space-between", textAlign: "left", color: section === s.key && !filter ? "#fff" : undefined }}
                      onClick={() => { setSection(s.key); setFilter(""); }}>
                <span>{s.title}</span>{count > 0 && <span className="badge tone-blue">{count}</span>}
              </button>
            );
          })}
        </div>
        <div className="card">
          {!filter && <><h2>{current.title}</h2><p className="muted" style={{ marginTop: -6 }}>{current.description}</p></>}
          <div className="policy-field" style={{ borderBottom: "1px solid var(--line-2)" }}>
            <span className="small muted">Setting</span><span className="small muted">Value in this policy</span><span className="small muted right">Lock</span>
          </div>
          {fields.map((f: any) => {
            const own = settings[f.section]?.[f.key];
            const isSet = own !== undefined;
            const inheritedValue = inherited[f.section]?.[f.key];
            const lockedAbove = inheritedLocks[f.path] || inheritedLocks[f.section];
            return (
              <div key={f.path} className={`policy-field ${isSet ? "overridden" : ""}`}>
                <div className="meta">
                  <b>{f.label}</b> {f.platforms.length < 3 && <span className="chip">{f.platforms.join(", ")}</span>}
                  {f.help && <small>{f.help}</small>}
                  <small>Inherited: <span className="mono">{JSON.stringify(inheritedValue)}</span> from {inheritedOrigin[f.path] ?? "default"}</small>
                  {lockedAbove && <Pill value={`locked by ${lockedAbove}`} tone="blue" />}
                </div>
                <div>
                  <FieldInput field={f} value={isSet ? own : inheritedValue} disabled={!editable || !!lockedAbove}
                              onChange={(v) => setValue(f.section, f.key, v)} />
                  {isSet && editable && <button className="small ghost" onClick={() => clearValue(f.section, f.key)}>Reset to inherited</button>}
                </div>
                <div className="right">
                  <label className="small"><input type="checkbox" disabled={!editable} checked={locks.includes(f.path)} onChange={() => toggleLock(f.path)} /> lock</label>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}

function FieldInput({ field, value, onChange, disabled }: { field: any; value: any; onChange: (v: any) => void; disabled: boolean }) {
  if (field.kind === "bool") {
    return <label className="row"><input type="checkbox" checked={!!value} disabled={disabled} onChange={(e) => onChange(e.target.checked)} /> {value ? "On" : "Off"}</label>;
  }
  if (field.kind === "int") {
    return <input type="number" value={value ?? ""} min={field.min ?? undefined} max={field.max ?? undefined} disabled={disabled}
                  onChange={(e) => onChange(Number(e.target.value))} style={{ width: 120 }} />;
  }
  if (field.kind === "enum") {
    return <select value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)}>{field.options.map((o: string) => <option key={o}>{o}</option>)}</select>;
  }
  if (field.kind === "list" && field.options.length) {
    const set = new Set<string>(value || []);
    return (
      <div>{field.options.map((o: string) => (
        <label key={o} className="chip"><input type="checkbox" disabled={disabled} checked={set.has(o)}
               onChange={() => { const next = new Set(set); if (next.has(o)) next.delete(o); else next.add(o); onChange([...next]); }} />{o}</label>
      ))}</div>
    );
  }
  if (field.kind === "list") {
    return <textarea style={{ minHeight: 70 }} disabled={disabled} value={(value || []).join("\n")} placeholder="One per line"
                     onChange={(e) => onChange(e.target.value.split("\n"))} />;
  }
  return <input value={value ?? ""} disabled={disabled} onChange={(e) => onChange(e.target.value)} />;
}
