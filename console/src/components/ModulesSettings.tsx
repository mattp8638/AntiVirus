// Settings > Modules: the core menu is always there; switch on the parts of Fenrir this MSP uses.
import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorNote, useAction, useData } from "./ui";

interface Modules { enabled: string[]; modules: { key: string; label: string; description: string }[]; essentials: string[]; editable: boolean }

export function ModulesSettings() {
  const { data, error, reload } = useData<Modules>("modules");
  const [chosen, setChosen] = useState<string[]>([]);
  const { run, busy } = useAction();
  useEffect(() => { if (data) setChosen(data.enabled); }, [data]);
  if (error) return <ErrorNote error={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const save = (enabled: string[]) => run(() => api("modules", { method: "PUT", body: { enabled } }), "Menu updated").then((ok) => {
    if (ok) { reload(); window.dispatchEvent(new Event("fenrir:modules-changed")); }
  });
  const toggle = (key: string) => setChosen(chosen.includes(key) ? chosen.filter((k) => k !== key) : [...chosen, key]);
  return (
    <div className="card" style={{ maxWidth: 820 }}>
      <h3>Modules</h3>
      <p className="small muted">The core menu (dashboard, devices, monitoring, patching, software, scripts, jobs, alerts, deployment, companies, reports
        and settings) is always there. Switch on the parts you use. Switching one off only hides its pages from the menu and search: nothing is
        deleted, background work carries on, and its pages still open from links.</p>
      <div style={{ display: "grid", gap: 8 }}>
        {data.modules.map((m) => (
          <label key={m.key} className="row" style={{ gap: 10, alignItems: "flex-start" }}>
            <input type="checkbox" checked={chosen.includes(m.key)} disabled={!data.editable} onChange={() => toggle(m.key)} style={{ marginTop: 3 }} />
            <span><b>{m.label}</b><br /><span className="small muted">{m.description}</span></span>
          </label>
        ))}
      </div>
      {data.editable ? <div className="row" style={{ gap: 8, marginTop: 14 }}>
        <button className="primary" disabled={busy} onClick={() => save(chosen)}>Save</button>
        <button disabled={busy} onClick={() => save(data.essentials)}>Essentials only</button>
        <button className="ghost" disabled={busy} onClick={() => save(data.modules.map((m) => m.key))}>Everything</button>
      </div> : <p className="small muted">Your MSP chooses these.</p>}
    </div>
  );
}
