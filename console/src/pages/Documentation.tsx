import { displayValue } from "../components/DisplayValue";
import { api, fmtTime } from "../api";
import { useApp } from "../app-context";
import { ErrorNote, Table, useAction, useListData } from "../components/ui";

export function DocumentTemplates({ onSelect }: { onSelect: (row: any) => void }) {
  const { data } = useListData<any>("documentation/templates");
  return <select value="" aria-label="Document template" onChange={e => {
    const template = data?.find(t => t.id === e.target.value);
    if (template) onSelect({ title: template.title, body: template.body, category: template.category, public: false });
  }}><option value="">Create from template…</option>{data?.map(t => <option key={t.id} value={t.id}>{displayValue(t.title)}</option>)}</select>;
}

export function DocumentHistory({ articleId, onRestore }: { articleId: string; onRestore: (row: any) => void }) {
  const { can } = useApp();
  const { data, error, reload } = useListData<any>("documentation/" + articleId + "/revisions");
  const { run, busy } = useAction();
  return <details><summary>Revision history</summary><ErrorNote error={error} /><Table rows={data} columns={[
    { key: "createdAt", label: "Saved", render: r => fmtTime(r.createdAt) },
    { key: "author", label: "Author" },
    { key: "snapshot", label: "Preview", render: r => <details><summary>{displayValue(r.snapshot.title)}</summary><pre style={{whiteSpace:"pre-wrap"}}>{displayValue(r.snapshot.body)}</pre></details> },
    { key: "restore", label: "", render: r => can("crm") && <button disabled={busy} onClick={async () => {
      if (!confirm("Restore this revision? The current document will remain in history.")) return;
      const row = await run(() => api("documentation/" + articleId + "/restore/" + r.id, { method: "POST" }), "Revision restored");
      if (row) { onRestore(row); reload(); }
    }}>Restore</button> }
  ]} /></details>;
}
