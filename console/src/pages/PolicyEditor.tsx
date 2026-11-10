import { displayValue } from "../components/DisplayValue";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { confirmDialog, promptDialog } from "../components/dialogs";
import { api } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Modal, PageHead, Pill, Table, useAction, useData, useListData } from "../components/ui";
import { flattenSettings, settingDifferences, showSetting } from "./Policies";

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
  const navigate = useNavigate();
  const [problem, setProblem] = useState<string | null>(null);
  const [previewing, setPreviewing] = useState(false);

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
                subtitle={<>{data.policy.tenantId ? tenantName(data.policy.tenantId) : "Global"} · v{displayValue(data.policy.version)} · {overrideCount} settings set here · {locks.length} locked</>}
                actions={editable && <>
                  <button disabled={busy} onClick={async () => {
                    const name = await promptDialog("Policy name", data.policy.name, { title: "Rename policy", required: true });
                    if (name?.trim() && await run(() => api(`policies/${id}`, { method: "PUT", body: { settings: data.policy.settings, locks: data.policy.locks, name: name.trim(), description: data.policy.description } }), "Renamed")) reload();
                  }}>Rename</button>
                  <button className="danger" disabled={busy} onClick={async () => {
                    if (!(await confirmDialog(`Delete the policy "${data.policy.name}"? Fenrir refuses if a customer, group or device still uses it.`, { confirmLabel: "Delete policy" }))) return;
                    setProblem(null);
                    try { await api(`policies/${id}`, { method: "DELETE" }); navigate("/policies"); } catch (err) { setProblem((err as Error).message); }
                  }}>Delete</button>
                  <button disabled={busy} onClick={() => setPreviewing(true)} title="See what a device would end up with if these settings applied, before saving">Preview on a device</button>
                  <button className="primary" disabled={!dirty || busy} onClick={save}>{dirty ? "Save changes" : "Saved"}</button></>} />
      {previewing && <PolicyPreview tenantId={data.policy.tenantId} settings={settings} locks={locks} onClose={() => setPreviewing(false)} />}
      <ErrorNote error={problem} />
      <div className="grid" style={{ gridTemplateColumns: "220px minmax(0,1fr)" }}>
        <div className="card" style={{ padding: 8, alignSelf: "start" }}>
          <input placeholder="Search all settings" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: "100%", marginBottom: 8 }} />
          {schema.sections.map((s: any) => {
            const count = Object.keys(settings[s.key] || {}).length;
            return (
              <button key={s.key} className={`ghost ${section === s.key && !filter ? "active" : ""}`}
                      style={{ width: "100%", justifyContent: "space-between", textAlign: "left", color: section === s.key && !filter ? "#fff" : undefined }}
                      onClick={() => { setSection(s.key); setFilter(""); }}>
                <span>{displayValue(s.title)}</span>{count > 0 && <span className="badge tone-blue">{count}</span>}
              </button>
            );
          })}
        </div>
        <div className="card">
          {!filter && <><h2>{displayValue(current.title)}</h2><p className="muted" style={{ marginTop: -6 }}>{displayValue(current.description)}</p></>}
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
                  <b>{displayValue(f.label)}</b> {f.platforms.length < 3 && <span className="chip">{displayValue(f.platforms.join(", "))}</span>}
                  {f.enforcedOn && f.enforcedOn.length === 0 && <Pill value="not enforced by agents yet" tone="warn" />}
                  {f.enforcedOn && f.enforcedOn.length > 0 && f.enforcedOn.length < f.platforms.length &&
                    <Pill value={`enforced on ${f.enforcedOn.join(", ")} only`} tone="muted" />}
                  {f.help && <small>{displayValue(f.help)}</small>}
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

// "What if": the chosen device's effective policy now, against what it would be with these (unsaved) settings on top.
function PolicyPreview({ tenantId, settings, locks, onClose }: { tenantId: string | null; settings: Settings; locks: string[]; onClose: () => void }) {
  const { data: devices } = useListData<any>("devices", { tenant_id: tenantId || undefined });
  const [deviceId, setDeviceId] = useState("");
  const { data: device } = useData<any>(deviceId ? `devices/${deviceId}` : null, {}, [deviceId]);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setResult(null); setError(null);
    if (!deviceId) return;
    api<any>("policies/preview", { body: { deviceId, settings, locks } }).then(setResult).catch((err) => setError((err as Error).message));
  }, [deviceId, settings, locks]);
  const rows = device && result ? settingDifferences(flattenSettings(device.policy.settings), flattenSettings(result.resolution.settings)) : [];
  return (
    <Modal wide title="Preview on a device" onClose={onClose}>
      <label className="field">Device
        <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">Choose a device…</option>
          {(devices || []).filter((d) => !d.retired).map((d) => <option key={d.id} value={d.id}>{displayValue(d.hostname)}</option>)}
        </select></label>
      <ErrorNote error={error} />
      {deviceId && !result && !error && <div className="empty">Working it out…</div>}
      {result && device && <>
        <p className="small muted">Compared with what {displayValue(device.device.hostname)} has now. Settings locked by a higher policy cannot change, so they do not appear.</p>
        <Table rows={rows} empty="No difference: this device would end up with exactly what it has now."
               columns={[{ key: "setting", label: "Setting", render: (r) => <span className="mono small">{r.setting}</span> },
                         { key: "before", label: "Now", render: (r) => <span className="small">{displayValue(showSetting(r.before))}</span> },
                         { key: "after", label: "With these settings", render: (r) => <span className="small"><b>{displayValue(showSetting(r.after))}</b></span> }]} />
      </>}
    </Modal>
  );
}
