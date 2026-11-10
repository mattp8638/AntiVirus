// Direct (peer-to-peer) screen sharing for the remote viewer. See docs/REMOTE_PROTOCOL.md, "Direct connections".
// The viewer offers a WebRTC data channel through the relay; once it opens, screen frames and ordinary input use it and
// everything audited (Ctrl+Alt+Del, lock, clipboard, terminal, files, chat) stays on the relay. If it fails to open
// within a few seconds, or closes later, the session simply carries on over the relay.

export type DirectMsg = { ch: string; t: string; [key: string]: any };
export type DirectState = "relay" | "connecting" | "direct";

export const CHUNK_MARKER = 0xfe;
export const CHUNK_HEADER = 9;
export const DIRECT_TIMEOUT_MS = 8000;
const DIRECT_INPUT = new Set(["mm", "md", "mu", "wh", "kd", "ku", "type", "nav"]);

/** Whether a message from the viewer may travel over the data channel (the agent applies the same rule). */
export function directAllowed(m: DirectMsg): boolean {
  if (m.ch === "screen") return true;
  if (m.ch === "input") return DIRECT_INPUT.has(m.t);
  return false;
}

/** Puts chunked frames back together. The channel is ordered and reliable, so chunks arrive in order. */
export class Reassembler {
  private id = -1;
  private parts: Uint8Array[] = [];

  add(msg: Uint8Array): Uint8Array | null {
    if (msg.length < CHUNK_HEADER || msg[0] !== CHUNK_MARKER) return null;
    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
    const id = view.getUint32(1), index = view.getUint16(5), count = view.getUint16(7);
    if (index === 0) { this.id = id; this.parts = []; }
    if (id !== this.id || index !== this.parts.length || count === 0 || index >= count) { this.parts = []; this.id = -1; return null; }
    this.parts.push(msg.subarray(CHUNK_HEADER));
    if (this.parts.length < count) return null;
    const size = this.parts.reduce((n, p) => n + p.length, 0);
    const frame = new Uint8Array(size);
    let at = 0;
    for (const p of this.parts) { frame.set(p, at); at += p.length; }
    this.parts = [];
    return frame;
  }
}

/** Splits a frame the way the agent does (used by tests). */
export function splitChunks(id: number, frame: Uint8Array, payload = 16000): Uint8Array[] {
  const count = Math.max(1, Math.ceil(frame.length / payload));
  const out: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const part = frame.subarray(i * payload, Math.min(frame.length, (i + 1) * payload));
    const msg = new Uint8Array(CHUNK_HEADER + part.length);
    const view = new DataView(msg.buffer);
    msg[0] = CHUNK_MARKER;
    view.setUint32(1, id);
    view.setUint16(5, i);
    view.setUint16(7, count);
    msg.set(part, CHUNK_HEADER);
    out.push(msg);
  }
  return out;
}

type Handlers = {
  signal: (m: DirectMsg) => void;      // sends over the relay
  text: (m: DirectMsg) => void;        // a JSON message that arrived directly
  binary: (data: Uint8Array) => void;  // a whole screen frame that arrived directly
  state: (s: DirectState, detail?: string) => void;
};

/** The viewer's end of a direct connection. */
export class DirectLink {
  private pc: RTCPeerConnection | null = null;
  private dc: RTCDataChannel | null = null;
  private timer = 0;
  private reassembler = new Reassembler();
  private started = 0;
  private stateNow: DirectState = "relay";

  private iceServers: RTCIceServer[];
  private on: Handlers;

  constructor(iceServers: RTCIceServer[], on: Handlers) {
    this.iceServers = iceServers;
    this.on = on;
  }

  static supported(): boolean {
    return typeof window !== "undefined" && typeof window.RTCPeerConnection === "function";
  }

  get state(): DirectState { return this.stateNow; }

  async start(): Promise<void> {
    if (this.pc || !DirectLink.supported()) return;
    this.started = performance.now();
    this.setState("connecting");
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    this.pc = pc;
    const dc = pc.createDataChannel("fenrir", { ordered: true });
    dc.binaryType = "arraybuffer";
    this.dc = dc;
    dc.onopen = () => {
      window.clearTimeout(this.timer);
      this.setState("direct", `connected in ${Math.round(performance.now() - this.started)} ms`);
    };
    dc.onclose = () => this.stop("the direct channel closed");
    dc.onmessage = (event) => {
      if (typeof event.data === "string") {
        try { this.on.text(JSON.parse(event.data)); } catch { /* ignore malformed */ }
        return;
      }
      const frame = this.reassembler.add(new Uint8Array(event.data as ArrayBuffer));
      if (frame) this.on.binary(frame);
    };
    pc.onicecandidate = (event) => {
      if (!event.candidate) return;
      const c = event.candidate.toJSON();
      this.on.signal({ ch: "rtc", t: "candidate", candidate: c.candidate, sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex });
    };
    pc.onconnectionstatechange = () => {
      if (["failed", "closed", "disconnected"].includes(pc.connectionState)) this.stop(`connection ${pc.connectionState}`);
    };
    this.timer = window.setTimeout(() => this.stop("no direct path (firewall or NAT)"), DIRECT_TIMEOUT_MS);
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      this.on.signal({ ch: "rtc", t: "offer", sdp: offer.sdp });
    } catch (err) {
      this.stop((err as Error).message);
    }
  }

  /** Handles an rtc message from the agent (answer, candidate, open, closed, unavailable). */
  async handle(m: DirectMsg): Promise<void> {
    const pc = this.pc;
    if (!pc) return;
    try {
      if (m.t === "answer") await pc.setRemoteDescription({ type: "answer", sdp: m.sdp });
      else if (m.t === "candidate" && m.candidate) {
        await pc.addIceCandidate({ candidate: m.candidate, sdpMid: m.sdpMid ?? null, sdpMLineIndex: m.sdpMLineIndex ?? null });
      } else if (m.t === "closed" || m.t === "unavailable") this.stop(m.reason || "the device closed the direct channel", false);
    } catch (err) {
      this.stop((err as Error).message);
    }
  }

  /** Sends over the data channel when it is open and the message may go direct. Returns false to use the relay. */
  send(m: DirectMsg): boolean {
    if (this.stateNow !== "direct" || this.dc?.readyState !== "open" || !directAllowed(m)) return false;
    try { this.dc.send(JSON.stringify(m)); return true; } catch { return false; }
  }

  /** Tears the link down; the session continues over the relay. */
  stop(reason = "", tellAgent = true): void {
    window.clearTimeout(this.timer);
    if (!this.pc) return;
    const pc = this.pc, dc = this.dc;
    this.pc = null;
    this.dc = null;
    if (dc) { dc.onclose = null; dc.onmessage = null; dc.close(); }
    pc.onconnectionstatechange = null;
    pc.close();
    if (tellAgent) this.on.signal({ ch: "rtc", t: "close" });
    this.setState("relay", reason);
  }

  private setState(s: DirectState, detail?: string) {
    this.stateNow = s;
    this.on.state(s, detail);
  }
}
