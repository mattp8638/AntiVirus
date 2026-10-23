// Pop-out remote session window: desktop, terminal, files, processes, services and chat.
// Protocol: docs/REMOTE_PROTOCOL.md. Opened with window.open("/remote/<sessionId>").
import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api } from "../api";

type Tab = "Desktop" | "Terminal" | "Files" | "Processes" | "Services" | "Chat";
type Msg = { ch: string; t: string; [key: string]: any };

const TILE = 0x01, FILE_DOWN = 0x02, FILE_UP = 0x03;
const CHUNK = 60 * 1024;

function b64encode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64decodeBytes(data: string): Uint8Array {
  const bin = atob(data);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

export default function RemoteViewer() {
  const { id } = useParams();
  const [session, setSession] = useState<any>(null);
  const [state, setState] = useState<"connecting" | "waiting" | "live" | "ended" | "error">("connecting");
  const [status, setStatus] = useState("Connecting to the relay…");
  const [hello, setHello] = useState<any>(null);
  const [info, setInfo] = useState<any>(null);
  const [tab, setTab] = useState<Tab>("Desktop");
  const [latency, setLatency] = useState<number | null>(null);
  const [fps, setFps] = useState(0);
  const [quality, setQuality] = useState(70);
  const [maxFps, setMaxFps] = useState(15);
  const [monitor, setMonitor] = useState(0);
  const [fit, setFit] = useState(true);
  const [viewOnly, setViewOnly] = useState(false);
  const [blank, setBlank] = useState(false);
  const [showEnd, setShowEnd] = useState(false);
  const [chat, setChat] = useState<{ from: string; text: string; at: string }[]>([]);
  const [unreadChat, setUnreadChat] = useState(0);
  const ws = useRef<WebSocket | null>(null);
  const canvas = useRef<HTMLCanvasElement | null>(null);
  const decodeQueue = useRef<Promise<void>>(Promise.resolve());
  const frames = useRef(0);
  const pressed = useRef<Set<string>>(new Set());
  const listeners = useRef<Map<string, (m: Msg) => void>>(new Map());
  const binaryListeners = useRef<Map<number, (data: Uint8Array) => void>>(new Map());
  const pendingMove = useRef<{ x: number; y: number } | null>(null);
  const tabRef = useRef<Tab>("Desktop");
  tabRef.current = tab;

  const send = useCallback((message: Msg) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(JSON.stringify(message));
  }, []);
  const sendBinary = useCallback((data: Uint8Array) => {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(data);
  }, []);
  const on = useCallback((key: string, fn: (m: Msg) => void) => {
    listeners.current.set(key, fn);
    return () => { listeners.current.delete(key); };
  }, []);

  // ------------------------------------------------------------------ connect
  useEffect(() => {
    let closed = false;
    let pingTimer = 0;
    let fpsTimer = 0;
    if (id === "starting") {
      setStatus("Starting the session…");  // the opener fills in the real session id in a moment
      return;
    }
    (async () => {
      try {
        const detail = await api(`remote/sessions/${id}`);
        setSession(detail);
        document.title = `${detail.hostname} · Fenrir remote`;
        if (["ended", "failed", "denied"].includes(detail.status)) {
          setState("ended");
          setStatus(`This session has ${detail.status}. Start a new one from the device page.`);
          return;
        }
        const { token, path } = await api(`remote/sessions/${id}/viewer-token`, { method: "POST" });
        const proto = window.location.protocol === "https:" ? "wss" : "ws";
        const socket = new WebSocket(`${proto}://${window.location.host}${path}?token=${encodeURIComponent(token)}`);
        socket.binaryType = "arraybuffer";
        ws.current = socket;
        socket.onmessage = (event) => {
          if (typeof event.data === "string") {
            let message: Msg;
            try { message = JSON.parse(event.data); } catch { return; }
            handleText(message);
          } else {
            handleBinary(new Uint8Array(event.data as ArrayBuffer));
          }
        };
        socket.onclose = (event) => {
          if (closed) return;
          setState((s) => (s === "ended" ? s : "ended"));
          setStatus((s) => (event.reason ? `Disconnected: ${event.reason}` : s.startsWith("Session ended") ? s : "Disconnected from the relay."));
        };
        socket.addEventListener("open", () => window.setTimeout(() => send({ ch: "sys", t: "ping", ts: performance.now() }), 500));
        pingTimer = window.setInterval(() => send({ ch: "sys", t: "ping", ts: performance.now() }), 5000);
        fpsTimer = window.setInterval(() => { setFps(frames.current); frames.current = 0; }, 1000);
      } catch (err) {
        setState("error");
        setStatus((err as Error).message);
      }
    })();
    return () => {
      closed = true;
      window.clearInterval(pingTimer);
      window.clearInterval(fpsTimer);
      ws.current?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  // While waiting for the device, keep checking the session: if the device could not start it (helper
  // missing, consent refused, policy), say why instead of waiting forever.
  const [waitedSeconds, setWaitedSeconds] = useState(0);
  useEffect(() => {
    if (state !== "waiting") return;
    const started = Date.now();
    const timer = window.setInterval(async () => {
      setWaitedSeconds(Math.round((Date.now() - started) / 1000));
      try {
        const detail = await api<any>(`remote/sessions/${id}`);
        if (["ended", "failed", "denied"].includes(detail.status)) {
          const reason = [...(detail.events || [])].reverse().find((e: any) => e.detail)?.detail;
          setState("ended");
          setStatus(detail.status === "denied" ? "The user declined the connection."
            : `The device could not start the session${reason ? `: ${reason}` : "."}`);
        }
      } catch { /* keep waiting */ }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [state, id]);

  const startScreen = useCallback(() => send({ ch: "screen", t: "start", quality, fps: maxFps, monitor }), [send, quality, maxFps, monitor]);

  const handleText = (m: Msg) => {
    if (m.ch === "sys") {
      switch (m.t) {
        case "hello":
          setHello(m);
          setViewOnly(!!m.viewOnly);
          if (m.agentConnected) { setState("live"); setStatus("Connected"); }
          else { setState("waiting"); setStatus("Waiting for the device to connect…"); }
          return;
        case "agent.connected":
          setState("live"); setStatus("Connected");
          return;
        case "info":
          setInfo(m);
          if (m.quality) setQuality(m.quality);
          if (m.maxFps) setMaxFps(m.maxFps);
          if (tabRef.current === "Desktop" && (m.capabilities || []).includes("desktop")) {
            send({ ch: "screen", t: "start", quality: m.quality || 70, fps: m.maxFps || 15, monitor: 0 });
          }
          return;
        case "consent":
          setStatus(m.state === "pending" ? "Waiting for the user to accept the connection…" : m.state === "denied" ? "The user declined the connection." : "Connected");
          if (m.state === "denied") setState("ended");
          return;
        case "pong":
          setLatency(Math.round(performance.now() - Number(m.ts)));
          return;
        case "error":
          setStatus(`Device: ${m.message}`);
          return;
        case "agent.disconnected":
        case "end":
          setState("ended");
          setStatus(`Session ended${m.reason ? ` (${m.reason})` : ""}.`);
          return;
      }
    }
    if (m.ch === "screen" && m.t === "frame.end") {
      decodeQueue.current = decodeQueue.current.then(() => { frames.current += 1; send({ ch: "screen", t: "ack", seq: m.seq }); });
      return;
    }
    if (m.ch === "chat" && m.t === "msg") {
      setChat((c) => [...c, { from: m.from || "User", text: m.text, at: new Date().toLocaleTimeString() }]);
      if (tabRef.current !== "Chat") setUnreadChat((n) => n + 1);
      return;
    }
    if (m.ch === "clip" && m.t === "text" && m.text) {
      navigator.clipboard?.writeText(m.text).catch(() => undefined);
      return;
    }
    const key = `${m.ch}:${m.req ?? m.id ?? ""}`;
    (listeners.current.get(key) || listeners.current.get(`${m.ch}:*`))?.(m);
  };

  const handleBinary = (data: Uint8Array) => {
    const kind = data[0];
    if (kind === TILE && data.length > 13) {
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const x = view.getUint16(1), y = view.getUint16(3), sw = view.getUint16(9), sh = view.getUint16(11);
      const jpeg = data.subarray(13);
      decodeQueue.current = decodeQueue.current.then(async () => {
        const c = canvas.current;
        if (!c) return;
        if (c.width !== sw || c.height !== sh) { c.width = sw; c.height = sh; }
        try {
          const bitmap = await createImageBitmap(new Blob([jpeg], { type: "image/jpeg" }));
          c.getContext("2d")!.drawImage(bitmap, x, y);
          bitmap.close();
        } catch { /* corrupt tile: the next refresh repaints it */ }
      });
      return;
    }
    if (kind === FILE_DOWN && data.length >= 5) {
      const id = new DataView(data.buffer, data.byteOffset).getUint32(1);
      binaryListeners.current.get(id)?.(data.subarray(5));
    }
  };

  // ------------------------------------------------------------------ desktop input
  const toRemote = (event: { clientX: number; clientY: number }) => {
    const c = canvas.current!;
    const rect = c.getBoundingClientRect();
    return { x: Math.max(0, Math.min(c.width - 1, Math.round(((event.clientX - rect.left) / rect.width) * c.width))),
             y: Math.max(0, Math.min(c.height - 1, Math.round(((event.clientY - rect.top) / rect.height) * c.height))) };
  };
  const controlling = state === "live" && !viewOnly && tab === "Desktop";

  useEffect(() => {
    let raf = 0;
    const flush = () => {
      if (pendingMove.current) { send({ ch: "input", t: "mm", ...pendingMove.current }); pendingMove.current = null; }
      raf = requestAnimationFrame(flush);
    };
    raf = requestAnimationFrame(flush);
    return () => cancelAnimationFrame(raf);
  }, [send]);

  const releaseAll = useCallback(() => {
    for (const code of pressed.current) send({ ch: "input", t: "ku", code, key: "" });
    pressed.current.clear();
  }, [send]);

  useEffect(() => {
    window.addEventListener("blur", releaseAll);
    return () => window.removeEventListener("blur", releaseAll);
  }, [releaseAll]);

  const onKey = (event: React.KeyboardEvent, down: boolean) => {
    if (!controlling) return;
    event.preventDefault();
    const { code, key } = event;
    if (down) pressed.current.add(code); else pressed.current.delete(code);
    send({ ch: "input", t: down ? "kd" : "ku", code, key });
  };

  const goFullscreen = async () => {
    const el = document.documentElement as any;
    if (!document.fullscreenElement) {
      await el.requestFullscreen?.();
      try { await (navigator as any).keyboard?.lock?.(); } catch { /* not supported */ }
    } else {
      await document.exitFullscreen();
    }
  };

  const screenshot = () => {
    const link = document.createElement("a");
    link.download = `${session?.hostname || "screen"}-${new Date().toISOString().replace(/[:.]/g, "-")}.png`;
    link.href = canvas.current!.toDataURL("image/png");
    link.click();
  };

  const sendClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text) return;
      send({ ch: "input", t: "clip.set", text });
      send({ ch: "input", t: "type", text });
    } catch {
      const text = window.prompt("Text to type on the remote machine:");
      if (text) send({ ch: "input", t: "type", text });
    }
  };

  const changeScreen = (patch: { quality?: number; fps?: number; monitor?: number }) => {
    const next = { quality, fps: maxFps, monitor, ...patch };
    if (patch.quality !== undefined) setQuality(patch.quality);
    if (patch.fps !== undefined) setMaxFps(patch.fps);
    if (patch.monitor !== undefined) setMonitor(patch.monitor);
    send({ ch: "screen", t: "settings", ...next });
  };

  const switchTab = (next: Tab) => {
    if (next === tab) return;
    if (tab === "Desktop") send({ ch: "screen", t: "stop" });
    if (next === "Desktop") startScreen();
    if (next === "Chat") setUnreadChat(0);
    setTab(next);
  };

  const caps: string[] = info?.capabilities || [];
  const tabs: Tab[] = (["Desktop", "Terminal", "Files", "Processes", "Services", "Chat"] as Tab[]).filter((t) => {
    if (t === "Terminal") return hello?.allowTerminal !== false && (!info || caps.includes("terminal"));
    if (t === "Files") return hello?.allowFileTransfer !== false && (!info || caps.includes("files"));
    if (t === "Desktop") return !info || caps.includes("desktop");
    if (t === "Processes") return !info || caps.includes("processes");
    if (t === "Services") return !info || caps.includes("services");
    if (t === "Chat") return !info || caps.includes("chat");
    return true;
  });
  useEffect(() => {
    if (info && !tabs.includes(tab) && tabs.length) setTab(tabs[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [info]);

  return (
    <div className="rv">
      <header className="rv-bar">
        <div className="rv-title">
          <span className={`dot ${state === "live" ? "on" : "off"}`} />
          <b>{session?.hostname || "Remote session"}</b>
          <span className="muted small">{info?.user ? `${info.user} · ` : ""}{session?.tenantName}</span>
        </div>
        <nav className="rv-tabs">
          {tabs.map((t) => (
            <button key={t} className={t === tab ? "active" : ""} onClick={() => switchTab(t)} disabled={state !== "live"}>
              {t}{t === "Chat" && unreadChat > 0 && <span className="rv-badge">{unreadChat}</span>}
            </button>
          ))}
        </nav>
        {tab === "Desktop" && state === "live" && (
          <div className="rv-tools">
            {caps.includes("cad") && <button title="Send Ctrl+Alt+Del" disabled={viewOnly} onClick={() => send({ ch: "input", t: "cad" })}>Ctrl+Alt+Del</button>}
            <button title="Paste your clipboard as keystrokes" disabled={viewOnly} onClick={sendClipboard}>Send clipboard</button>
            <select title="Monitor" value={monitor} onChange={(e) => changeScreen({ monitor: Number(e.target.value) })}>
              {(info?.monitors?.length ? info.monitors : [{ index: 0 }]).map((m: any) => (
                <option key={m.index} value={m.index}>Screen {m.index + 1}{m.primary ? " (primary)" : ""}</option>
              ))}
            </select>
            <select title="Image quality" value={quality} onChange={(e) => changeScreen({ quality: Number(e.target.value) })}>
              {[30, 50, 70, 85, 95].map((q) => <option key={q} value={q}>Quality {q}%</option>)}
            </select>
            <select title="Frame rate" value={maxFps} onChange={(e) => changeScreen({ fps: Number(e.target.value) })}>
              {[5, 10, 15, 20, 30].map((f) => <option key={f} value={f}>{f} fps</option>)}
            </select>
            <button onClick={() => setFit(!fit)}>{fit ? "1:1" : "Fit"}</button>
            <label className="rv-check"><input type="checkbox" checked={viewOnly} disabled={!!hello?.viewOnly}
                                               onChange={(e) => { releaseAll(); setViewOnly(e.target.checked); }} /> View only</label>
            {hello?.allowBlank && caps.includes("blank") && (
              <button onClick={() => { send({ ch: "input", t: "blank", on: !blank }); setBlank(!blank); }}>{blank ? "Unblank" : "Blank screen"}</button>
            )}
            <button title="Lock the remote workstation" disabled={viewOnly} onClick={() => send({ ch: "input", t: "lock" })}>Lock</button>
            <button onClick={screenshot}>Screenshot</button>
            <button onClick={goFullscreen}>Fullscreen</button>
          </div>
        )}
        <span className="spacer" />
        <span className="muted small">{state === "live" ? `${latency ?? "–"} ms${tab === "Desktop" ? ` · ${fps} fps` : ""}` : status}</span>
        {state !== "ended" ? <button className="danger" onClick={() => setShowEnd(true)}>End session</button>
                           : <button onClick={() => window.close()}>Close window</button>}
      </header>

      <main className="rv-body">
        {state !== "live" && (
          <div className="rv-wait">
            <div className="rv-spinner" hidden={state === "ended" || state === "error"} />
            <h2>{status}</h2>
            {state === "waiting" && <p className="muted">Online devices answer within a few seconds. Offline devices connect the next time they check in.</p>}
            {state === "waiting" && waitedSeconds >= 30 && (
              <p className="muted small" style={{ maxWidth: 560 }}>
                Still waiting after {waitedSeconds} seconds. If the device is online, check that it can reach this server, and on
                Windows look at <code>C:\ProgramData\FenrirAgent\runtime\remote\{id}.log</code> for the reason.
              </p>
            )}
          </div>
        )}
        <div className="rv-screen" hidden={tab !== "Desktop" || state !== "live"} style={{ overflow: fit ? "hidden" : "auto" }}>
          <canvas ref={canvas} width={1280} height={720} tabIndex={0} className={fit ? "fit" : ""}
                  style={{ cursor: controlling ? "default" : "not-allowed" }}
                  onMouseMove={(e) => { if (controlling) pendingMove.current = toRemote(e); }}
                  onMouseDown={(e) => { if (!controlling) return; e.preventDefault(); canvas.current?.focus(); send({ ch: "input", t: "md", b: e.button, ...toRemote(e) }); }}
                  onMouseUp={(e) => { if (controlling) send({ ch: "input", t: "mu", b: e.button, ...toRemote(e) }); }}
                  onWheel={(e) => { if (controlling) send({ ch: "input", t: "wh", dy: Math.sign(e.deltaY), dx: Math.sign(e.deltaX), ...toRemote(e) }); }}
                  onContextMenu={(e) => e.preventDefault()}
                  onKeyDown={(e) => onKey(e, true)} onKeyUp={(e) => onKey(e, false)} />
        </div>
        {state === "live" && tab === "Terminal" && <TerminalPane send={send} on={on} shells={info?.shells || []} />}
        {state === "live" && tab === "Files" && <FilesPane send={send} sendBinary={sendBinary} on={on} binaryListeners={binaryListeners.current}
                                                           home={info?.home || ""} />}
        {state === "live" && tab === "Processes" && <ProcessesPane send={send} on={on} />}
        {state === "live" && tab === "Services" && <ServicesPane send={send} on={on} />}
        {state === "live" && tab === "Chat" && <ChatPane chat={chat} onSend={(text) => {
          send({ ch: "chat", t: "msg", text });
          setChat((c) => [...c, { from: "You", text, at: new Date().toLocaleTimeString() }]);
        }} supported={caps.includes("chat")} />}
      </main>
      {showEnd && <EndDialog session={session} onCancel={() => setShowEnd(false)} onEnded={() => {
        send({ ch: "sys", t: "end" });
        setState("ended");
        setStatus("Session ended.");
        setShowEnd(false);
        window.setTimeout(() => window.close(), 600);
      }} />}
    </div>
  );
}

// ------------------------------------------------------------------ terminal

function TerminalPane({ send, on, shells }: { send: (m: Msg) => void; on: (k: string, fn: (m: Msg) => void) => () => void; shells: string[] }) {
  const host = useRef<HTMLDivElement | null>(null);
  const [shell, setShell] = useState(shells[0] || "");
  const [exited, setExited] = useState<number | null>(null);
  const [generation, setGeneration] = useState(0);
  useEffect(() => {
    if (!host.current) return;
    const term = new Terminal({ cursorBlink: true, fontFamily: '"Cascadia Code", "JetBrains Mono", monospace', fontSize: 14,
                                theme: { background: "#05080f" }, scrollback: 5000 });
    const fitter = new FitAddon();
    term.loadAddon(fitter);
    term.open(host.current);
    fitter.fit();
    setExited(null);
    const off = on("term:*", (m) => {
      if (m.t === "out" && m.data) term.write(b64decodeBytes(m.data));
      if (m.t === "opened") term.writeln(`\x1b[90m[${m.shell || "shell"} on the remote device]\x1b[0m`);
      if (m.t === "exit") { term.writeln(`\r\n\x1b[90m[process exited with code ${m.code}]\x1b[0m`); setExited(Number(m.code)); }
      if (m.t === "error") term.writeln(`\r\n\x1b[31m${m.message}\x1b[0m`);
    });
    send({ ch: "term", t: "open", cols: term.cols, rows: term.rows, shell });
    const input = term.onData((data) => send({ ch: "term", t: "in", data: b64encode(data) }));
    const resize = () => { fitter.fit(); send({ ch: "term", t: "resize", cols: term.cols, rows: term.rows }); };
    window.addEventListener("resize", resize);
    term.focus();
    return () => {
      window.removeEventListener("resize", resize);
      input.dispose();
      off();
      send({ ch: "term", t: "close" });
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generation]);
  return (
    <div className="rv-pane">
      <div className="row" style={{ marginBottom: 8 }}>
        {shells.length > 1 && (
          <select value={shell} onChange={(e) => { setShell(e.target.value); setGeneration((g) => g + 1); }}>
            {shells.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        )}
        {exited !== null && <button onClick={() => setGeneration((g) => g + 1)}>Start a new shell</button>}
        <span className="muted small">Runs with the agent's privileges. Every session is recorded in the audit log.</span>
      </div>
      <div ref={host} className="rv-term" />
    </div>
  );
}

// ------------------------------------------------------------------ files

let requestCounter = 1;
function nextReq() { requestCounter += 1; return requestCounter; }

function FilesPane({ send, sendBinary, on, binaryListeners, home }: {
  send: (m: Msg) => void; sendBinary: (d: Uint8Array) => void; on: (k: string, fn: (m: Msg) => void) => () => void;
  binaryListeners: Map<number, (d: Uint8Array) => void>; home: string;
}) {
  const [path, setPath] = useState(home);
  const [parentPath, setParentPath] = useState<string | null>(null);
  const [sep, setSep] = useState("/");
  const [entries, setEntries] = useState<any[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [transfers, setTransfers] = useState<{ id: number; name: string; done: number; size: number; dir: "down" | "up"; state: string }[]>([]);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const request = useCallback((message: Msg) => new Promise<Msg>((resolve) => {
    const req = nextReq();
    const off = on(`files:${req}`, (m) => { off(); resolve(m); });
    send({ ...message, req });
  }), [on, send]);

  const list = useCallback(async (target: string) => {
    setEntries(null);
    const result = await request({ ch: "files", t: "ls", path: target });
    if (result.error) { setError(result.error); setEntries([]); return; }
    setError(null);
    setPath(result.path ?? target);
    setParentPath(result.parent ?? null);
    if (result.sep) setSep(result.sep);
    setEntries([...(result.entries || [])].sort((a, b) => (Number(b.dir) - Number(a.dir)) || a.name.localeCompare(b.name)));
  }, [request]);

  useEffect(() => { list(home); }, [list, home]);

  const join = (name: string) => (!path ? name : path.endsWith(sep) ? path + name : path + sep + name);
  const parent = () => { if (parentPath !== null) list(parentPath); };
  const update = (id: number, patch: any) => setTransfers((all) => all.map((t) => (t.id === id ? { ...t, ...patch } : t)));

  const download = (entry: any) => {
    const id = nextReq();
    const chunks: Uint8Array[] = [];
    let received = 0;
    setTransfers((all) => [{ id, name: entry.name, done: 0, size: entry.size, dir: "down", state: "downloading" }, ...all]);
    binaryListeners.set(id, (data) => { chunks.push(data.slice()); received += data.length; update(id, { done: received }); });
    const off = on(`files:${id}`, (m) => {
      if (m.t === "get.end" || m.error) {
        off();
        binaryListeners.delete(id);
        if (m.error) { update(id, { state: `failed: ${m.error}` }); return; }
        const blob = new Blob(chunks as BlobPart[]);
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = entry.name;
        link.click();
        window.setTimeout(() => URL.revokeObjectURL(link.href), 10000);
        update(id, { state: "done", done: received });
      }
    });
    send({ ch: "files", t: "get", path: join(entry.name), id });
  };

  const upload = async (file: File) => {
    const id = nextReq();
    setTransfers((all) => [{ id, name: file.name, done: 0, size: file.size, dir: "up", state: "uploading" }, ...all]);
    const done = new Promise<Msg>((resolve) => { const off = on(`files:${id}`, (m) => { off(); resolve(m); }); });
    send({ ch: "files", t: "put", path: join(file.name), id, size: file.size });
    for (let offset = 0; offset < file.size; offset += CHUNK) {
      const slice = new Uint8Array(await file.slice(offset, offset + CHUNK).arrayBuffer());
      const frame = new Uint8Array(5 + slice.length);
      frame[0] = FILE_UP;
      new DataView(frame.buffer).setUint32(1, id);
      frame.set(slice, 5);
      sendBinary(frame);
      update(id, { done: Math.min(file.size, offset + CHUNK) });
      if ((offset / CHUNK) % 16 === 15) await new Promise((r) => setTimeout(r, 5));
    }
    send({ ch: "files", t: "put.end", id });
    const result = await done;
    update(id, { state: result.error ? `failed: ${result.error}` : "done" });
    list(path);
  };

  const remove = async (entry: any) => {
    if (!window.confirm(`Delete ${entry.name} on the remote device?`)) return;
    const result = await request({ ch: "files", t: "delete", path: join(entry.name) });
    if (result.error) window.alert(result.error);
    list(path);
  };
  const mkdir = async () => {
    const name = window.prompt("New folder name");
    if (!name) return;
    const result = await request({ ch: "files", t: "mkdir", path: join(name) });
    if (result.error) window.alert(result.error);
    list(path);
  };

  return (
    <div className="rv-pane">
      <div className="row" style={{ marginBottom: 10 }}>
        <button onClick={parent} disabled={parentPath === null}>↑ Up</button>
        <input style={{ flex: 1 }} value={path} onChange={(e) => setPath(e.target.value)} onKeyDown={(e) => e.key === "Enter" && list(path)}
               placeholder="Drives" />
        <button onClick={() => list(path)}>Go</button>
        <button onClick={mkdir} disabled={!path}>New folder</button>
        <button className="primary" onClick={() => fileInput.current?.click()} disabled={!path}>Upload…</button>
        <input ref={fileInput} type="file" multiple hidden onChange={(e) => { Array.from(e.target.files || []).forEach(upload); e.target.value = ""; }} />
      </div>
      {error && <div className="card" style={{ color: "#fecaca", marginBottom: 10 }}>{error}</div>}
      <div className="grid side">
        <div className="card" style={{ padding: 0, maxHeight: "calc(100vh - 170px)", overflow: "auto" }}
             onDragOver={(e) => e.preventDefault()} onDrop={(e) => { e.preventDefault(); Array.from(e.dataTransfer.files).forEach(upload); }}>
          {!entries ? <div className="empty">Loading…</div> : (
            <table>
              <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th /></tr></thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.name} className="clickable" onDoubleClick={() => (entry.dir ? list(join(entry.name)) : download(entry))}>
                    <td>{entry.dir ? "📁" : "📄"} {entry.name}</td>
                    <td>{entry.dir ? "" : fmtSize(entry.size)}</td>
                    <td className="small muted">{entry.mtime ? new Date(entry.mtime * 1000).toLocaleString() : ""}</td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      {!entry.dir && <button className="small" onClick={() => download(entry)}>Download</button>}{" "}
                      {path && <button className="small danger" onClick={() => remove(entry)}>Delete</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {entries && !entries.length && <div className="empty">Empty folder. Drop files here to upload.</div>}
        </div>
        <div className="card">
          <h3>Transfers</h3>
          {!transfers.length && <p className="muted small">Double-click a file to download it. Drag files onto the list to upload.</p>}
          {transfers.map((t) => (
            <div key={t.id} style={{ marginBottom: 10 }}>
              <div className="small">{t.dir === "down" ? "⇩" : "⇧"} {t.name} <span className="muted">{t.state}</span></div>
              <div className="bar"><span style={{ width: `${t.size ? Math.min(100, (100 * t.done) / t.size) : 100}%` }} /></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ processes & services

function useListing(send: (m: Msg) => void, on: (k: string, fn: (m: Msg) => void) => () => void, ch: string) {
  const [items, setItems] = useState<any[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const request = useCallback((message: Msg) => new Promise<Msg>((resolve) => {
    const req = nextReq();
    const off = on(`${ch}:${req}`, (m) => { off(); resolve(m); });
    send({ ...message, ch, req });
  }), [ch, on, send]);
  const reload = useCallback(async () => {
    const result = await request({ ch, t: "list" });
    if (result.error) setError(result.error); else { setError(null); setItems(result.items || []); }
  }, [ch, request]);
  useEffect(() => { reload(); }, [reload]);
  return { items, error, reload, request };
}

function ProcessesPane({ send, on }: { send: (m: Msg) => void; on: (k: string, fn: (m: Msg) => void) => () => void }) {
  const { items, error, reload, request } = useListing(send, on, "procs");
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState<"cpu" | "mem" | "name">("cpu");
  useEffect(() => { const t = window.setInterval(reload, 5000); return () => window.clearInterval(t); }, [reload]);
  const kill = async (p: any) => {
    if (!window.confirm(`End ${p.name} (PID ${p.pid}) on the remote device?`)) return;
    const result = await request({ ch: "procs", t: "kill", pid: p.pid });
    if (result.error) window.alert(result.error);
    reload();
  };
  const rows = (items || []).filter((p) => !filter || `${p.name} ${p.user} ${p.pid}`.toLowerCase().includes(filter.toLowerCase()))
    .sort((a, b) => (sort === "name" ? a.name.localeCompare(b.name) : sort === "mem" ? b.memMb - a.memMb : b.cpu - a.cpu));
  return (
    <div className="rv-pane">
      <div className="row" style={{ marginBottom: 10 }}>
        <input placeholder="Filter processes" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <select value={sort} onChange={(e) => setSort(e.target.value as any)}><option value="cpu">Sort by CPU</option><option value="mem">Sort by memory</option><option value="name">Sort by name</option></select>
        <button onClick={reload}>Refresh</button>
        <span className="muted small">{items ? `${items.length} processes` : ""}</span>
      </div>
      {error && <div className="card" style={{ color: "#fecaca" }}>{error}</div>}
      <div className="card" style={{ padding: 0, maxHeight: "calc(100vh - 160px)", overflow: "auto" }}>
        <table>
          <thead><tr><th>Name</th><th>PID</th><th>User</th><th>CPU %</th><th>Memory</th><th /></tr></thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.pid}>
                <td title={p.path}>{p.name}</td><td className="mono">{p.pid}</td><td className="small">{p.user}</td>
                <td>{Number(p.cpu).toFixed(1)}</td><td>{Number(p.memMb).toFixed(0)} MB</td>
                <td><button className="small danger" onClick={() => kill(p)}>End</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ServicesPane({ send, on }: { send: (m: Msg) => void; on: (k: string, fn: (m: Msg) => void) => () => void }) {
  const { items, error, reload, request } = useListing(send, on, "svc");
  const [filter, setFilter] = useState("");
  const control = async (s: any, action: string) => {
    const result = await request({ ch: "svc", t: "control", name: s.name, action });
    if (result.error) window.alert(result.error);
    reload();
  };
  const rows = (items || []).filter((s) => !filter || `${s.name} ${s.display}`.toLowerCase().includes(filter.toLowerCase()));
  return (
    <div className="rv-pane">
      <div className="row" style={{ marginBottom: 10 }}>
        <input placeholder="Filter services" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <button onClick={reload}>Refresh</button>
      </div>
      {error && <div className="card" style={{ color: "#fecaca" }}>{error}</div>}
      <div className="card" style={{ padding: 0, maxHeight: "calc(100vh - 160px)", overflow: "auto" }}>
        <table>
          <thead><tr><th>Service</th><th>Name</th><th>Status</th><th>Start type</th><th /></tr></thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.name}>
                <td>{s.display || s.name}</td><td className="mono small">{s.name}</td>
                <td><span className={`badge tone-${s.status === "running" ? "good" : s.status === "failed" ? "bad" : "muted"}`}>{s.status}</span></td>
                <td className="small">{s.startType}</td>
                <td style={{ whiteSpace: "nowrap" }}>
                  <button className="small" onClick={() => control(s, "start")} disabled={s.status === "running"}>Start</button>{" "}
                  <button className="small" onClick={() => control(s, "stop")} disabled={s.status !== "running"}>Stop</button>{" "}
                  <button className="small" onClick={() => control(s, "restart")}>Restart</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ChatPane({ chat, onSend, supported }: { chat: { from: string; text: string; at: string }[]; onSend: (t: string) => void; supported: boolean }) {
  const [text, setText] = useState("");
  return (
    <div className="rv-pane" style={{ maxWidth: 720 }}>
      {!supported && <p className="muted">This device cannot show chat messages (no signed-in desktop).</p>}
      <div className="card" style={{ minHeight: 300, maxHeight: "calc(100vh - 220px)", overflow: "auto" }}>
        {!chat.length && <p className="muted">Messages appear in a window on the user's screen.</p>}
        {chat.map((m, i) => <p key={i}><b>{m.from}</b> <span className="muted small">{m.at}</span><br />{m.text}</p>)}
      </div>
      <form className="row" style={{ marginTop: 10 }} onSubmit={(e) => { e.preventDefault(); if (text.trim()) { onSend(text.trim()); setText(""); } }}>
        <input style={{ flex: 1 }} value={text} onChange={(e) => setText(e.target.value)} placeholder="Message the user" disabled={!supported} />
        <button className="primary" disabled={!supported}>Send</button>
      </form>
    </div>
  );
}

function EndDialog({ session, onCancel, onEnded }: { session: any; onCancel: () => void; onEnded: () => void }) {
  const [logTime, setLogTime] = useState(!!session?.ticketId);
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const end = async () => {
    setBusy(true);
    try {
      await api(`remote/sessions/${session.id}/end`, { body: { logTime, notes, workType: "Remote Support" } });
    } finally {
      setBusy(false);
      onEnded();
    }
  };
  return (
    <div className="modal-back" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>End remote session</h2>
        <label className="rv-check"><input type="checkbox" checked={logTime} onChange={(e) => setLogTime(e.target.checked)} />
          Log the session time {session?.ticketId ? "to the linked ticket" : "as a time entry"}</label>
        {logTime && <label className="field" style={{ marginTop: 10 }}>Notes<textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)}
                                                                                   placeholder="What did you do?" /></label>}
        <div className="foot"><button onClick={onCancel}>Keep working</button><button className="danger" disabled={busy} onClick={end}>End session</button></div>
      </div>
    </div>
  );
}
