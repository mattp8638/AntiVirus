import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getToken } from "../api";
import { ErrorNote, PageHead } from "../components/ui";

interface RecordEntry { ms: number; kind: number; payload: Uint8Array }

const MAGIC = "FENREC1\n";
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07/g;

export function parseRecording(buffer: ArrayBuffer): RecordEntry[] {
  const bytes = new Uint8Array(buffer);
  if (new TextDecoder().decode(bytes.subarray(0, 8)) !== MAGIC) throw new Error("This is not a Fenrir session recording.");
  const view = new DataView(buffer);
  const out: RecordEntry[] = [];
  let offset = 8;
  while (offset + 9 <= bytes.length) {
    const ms = view.getUint32(offset), kind = bytes[offset + 4], size = view.getUint32(offset + 5);
    if (offset + 9 + size > bytes.length) break; // truncated tail
    out.push({ ms, kind, payload: bytes.subarray(offset + 9, offset + 9 + size) });
    offset += 9 + size;
  }
  return out;
}

const clock = (ms: number) => { const s = Math.floor(ms / 1000); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };

export default function RecordingPlayer() {
  const { id } = useParams();
  const canvas = useRef<HTMLCanvasElement>(null);
  const [records, setRecords] = useState<RecordEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [position, setPosition] = useState(0);
  const [terminal, setTerminal] = useState("");
  const state = useRef({ index: 0, time: 0, queue: Promise.resolve() as Promise<void> });

  useEffect(() => {
    (async () => {
      try {
        const response = await fetch(`/api/console/artifacts/${id}/download`, { headers: { Authorization: `Bearer ${getToken() ?? ""}` }, cache: "no-store" });
        if (!response.ok) throw new Error(response.status === 403 ? "Only incident responders can play recordings." : `Could not load the recording (HTTP ${response.status}).`);
        setName(/filename="?([^";]+)"?/.exec(response.headers.get("Content-Disposition") || "")?.[1] ?? "Recording");
        setRecords(parseRecording(await response.arrayBuffer()));
      } catch (e) { setError((e as Error).message); }
    })();
  }, [id]);

  const duration = records?.length ? records[records.length - 1].ms : 0;

  // Apply every record up to `until`; tiles decode in order through a promise queue.
  const applyUntil = (until: number) => {
    if (!records) return;
    const s = state.current;
    let text = "";
    while (s.index < records.length && records[s.index].ms <= until) {
      const r = records[s.index++];
      if (r.kind === 1 && r.payload.length > 13) {
        const view = new DataView(r.payload.buffer, r.payload.byteOffset, r.payload.byteLength);
        const x = view.getUint16(1), y = view.getUint16(3), sw = view.getUint16(9), sh = view.getUint16(11);
        const jpeg = r.payload.slice(13);
        s.queue = s.queue.then(async () => {
          const c = canvas.current;
          if (!c) return;
          if (c.width !== sw || c.height !== sh) { c.width = sw; c.height = sh; }
          try {
            const bitmap = await createImageBitmap(new Blob([jpeg], { type: "image/jpeg" }));
            c.getContext("2d")!.drawImage(bitmap, x, y);
            bitmap.close();
          } catch { /* corrupt tile */ }
        });
      } else if (r.kind === 0) {
        try {
          const m = JSON.parse(new TextDecoder().decode(r.payload));
          if (m.ch === "term" && m.t === "out" && m.data) text += new TextDecoder().decode(Uint8Array.from(atob(m.data), (ch) => ch.charCodeAt(0)));
        } catch { /* ignore */ }
      }
    }
    if (text) setTerminal((prev) => (prev + text.replace(ANSI, "")).slice(-50000));
  };

  const seek = (target: number) => {
    state.current = { index: 0, time: target, queue: Promise.resolve() };
    const c = canvas.current;
    c?.getContext("2d")?.clearRect(0, 0, c.width, c.height);
    setTerminal("");
    applyUntil(target);
    setPosition(target);
  };

  useEffect(() => {
    if (!playing || !records) return;
    let last = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const s = state.current;
      s.time = Math.min(duration, s.time + (now - last) * speed);
      last = now;
      applyUntil(s.time);
      setPosition(s.time);
      if (s.time >= duration) { setPlaying(false); return; }
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, speed, records]); // eslint-disable-line react-hooks/exhaustive-deps

  const hasScreen = records?.some((r) => r.kind === 1);
  return (
    <>
      <PageHead title="Session recording" subtitle={<>{name} · {clock(duration)} long. Viewer keystrokes are never recorded. <Link to="/devices">Back to devices</Link></>} />
      <ErrorNote error={error} />
      {!records && !error && <div className="empty">Loading recording…</div>}
      {records && <>
        <div className="row" style={{ gap: 8, marginBottom: 10, alignItems: "center" }}>
          <button className="primary" onClick={() => { if (position >= duration) seek(0); setPlaying(!playing); }}>{playing ? "Pause" : position >= duration && duration ? "Replay" : "Play"}</button>
          <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))} aria-label="Speed">{[1, 2, 4, 8, 16].map((x) => <option key={x} value={x}>{x}×</option>)}</select>
          <input type="range" min={0} max={duration || 1} value={position} style={{ flex: 1 }} aria-label="Position"
                 onChange={(e) => seek(Number(e.target.value))} />
          <span className="mono small">{clock(position)} / {clock(duration)}</span>
        </div>
        <div className={terminal && hasScreen ? "grid side" : ""}>
          {hasScreen && <div className="card" style={{ padding: 8 }}><canvas ref={canvas} style={{ width: "100%", height: "auto", background: "#000" }} /></div>}
          {(terminal || !hasScreen) && <div className="card"><h3>Terminal output</h3>
            <pre className="mono small" style={{ whiteSpace: "pre-wrap", maxHeight: 520, overflow: "auto" }}>{terminal || "No terminal output yet."}</pre></div>}
        </div>
      </>}
    </>
  );
}
