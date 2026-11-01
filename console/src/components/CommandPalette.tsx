// Ctrl+K (Cmd+K on a Mac): one box to jump to any page, device, customer, ticket, person, CVE or script.
import { KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Modal } from "./ui";

export interface PageLink { to: string; label: string; group: string }
interface Result { kind: string; id: string; title: string; subtitle?: string; link: string }

const KIND_LABEL: Record<string, string> = {
  page: "Page", device: "Device", company: "Customer", ticket: "Ticket", user: "Staff", contact: "Contact",
  vulnerability: "Vulnerability", script: "Script",
};

export function useSearchShortcut(open: () => void) {
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        open();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);
}

export function CommandPalette({ pages, onClose }: { pages: PageLink[]; onClose: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [found, setFound] = useState<Result[]>([]);
  const [searching, setSearching] = useState(false);
  const [active, setActive] = useState(0);
  const latest = useRef(0);

  useEffect(() => {
    const query = q.trim();
    if (query.length < 2) { setFound([]); return; }
    const ticket = ++latest.current;
    setSearching(true);
    const timer = window.setTimeout(() => {
      api<{ results: Result[] }>("search", { query: { q: query } })
        .then((r) => { if (ticket === latest.current) setFound(r.results); })
        .catch(() => { if (ticket === latest.current) setFound([]); })
        .finally(() => { if (ticket === latest.current) setSearching(false); });
    }, 150);
    return () => window.clearTimeout(timer);
  }, [q]);

  const results = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const pageHits: Result[] = (needle ? pages.filter((p) => `${p.label} ${p.group}`.toLowerCase().includes(needle)) : pages.slice(0, 8))
      .slice(0, 6).map((p) => ({ kind: "page", id: p.to, title: p.label, subtitle: p.group, link: p.to }));
    return [...pageHits, ...found];
  }, [q, pages, found]);
  useEffect(() => setActive(0), [results.length]);

  const go = (result: Result | undefined) => {
    if (!result) return;
    onClose();
    navigate(result.link);
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(i + 1, results.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); go(results[active]); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };
  return (
    <Modal title="Search" onClose={onClose}>
      <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} style={{ width: "100%" }}
             placeholder="Devices, customers, tickets (#1234), people, CVEs, scripts or pages" aria-label="Search"
             role="combobox" aria-expanded={results.length > 0} aria-controls="palette-results"
             aria-activedescendant={results[active] ? `palette-${active}` : undefined} />
      <ul id="palette-results" role="listbox" style={{ listStyle: "none", margin: "10px 0 0", padding: 0, maxHeight: 420, overflow: "auto" }}>
        {results.map((r, i) => (
          <li key={`${r.kind}:${r.id}`} id={`palette-${i}`} role="option" aria-selected={i === active}
              className={i === active ? "active-row" : ""} onMouseEnter={() => setActive(i)} onClick={() => go(r)}
              style={{ padding: "7px 8px", borderRadius: 6, cursor: "pointer", display: "flex", gap: 10, alignItems: "baseline" }}>
            <span className="small muted" style={{ width: 90, flexShrink: 0 }}>{KIND_LABEL[r.kind] ?? r.kind}</span>
            <span style={{ flex: 1, minWidth: 0 }}><b>{r.title}</b>{r.subtitle && <span className="small muted"> · {r.subtitle}</span>}</span>
          </li>
        ))}
      </ul>
      {q.trim().length >= 2 && !searching && results.length === 0 && <p className="small muted">Nothing matches “{q.trim()}”.</p>}
      <p className="small muted" style={{ marginTop: 8 }}>↑ ↓ to move · Enter to open · Esc to close · Ctrl+K from anywhere</p>
    </Modal>
  );
}
