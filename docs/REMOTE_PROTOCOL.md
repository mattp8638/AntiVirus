# Remote access protocol (v1)

Fenrir's remote desktop, terminal and file transfer run over two WebSockets that meet at the cloud relay:

```
 browser pop-out ──wss──► /ws/remote/<session>/viewer ─┐
                                                       ├─ relay (Fenrir Cloud)
 agent / desktop helper ──wss──► /ws/remote/<session>/agent ─┘
```

1. A technician presses **Connect**. The cloud creates a session and queues `remote.session.start` for the device.
   The payload carries `relayUrl`, a one-time `token` (valid 10 minutes), the mode and the device's remote-access policy.
   Agents holding the realtime channel (`/api/v1/devices/<id>/realtime`) receive `{"type":"commands"}` and poll at once.
2. The agent dials `relayUrl?token=…`. On Windows the service starts `fenrir-remote.exe` in the active console session, and that helper dials the relay.
3. The pop-out viewer gets its own short-lived token from `POST /api/console/remote/sessions/<id>/viewer-token`.
4. The relay forwards every frame. It reads only small JSON control messages to enforce view-only and policy (terminal and file transfer), and to write the audit trail.

Both sockets close when either side sends `{"ch":"sys","t":"end"}` or disconnects.

## Frames

**Text frames** are JSON objects: `{"ch": <channel>, "t": <type>, ...}`.

**Binary frames** start with a kind byte. Integers are big-endian.

| Kind | Direction | Layout |
|---|---|---|
| `0x01` screen tile | agent → viewer | `01 x:u16 y:u16 w:u16 h:u16 screenW:u16 screenH:u16 <JPEG>` |
| `0x02` download chunk | agent → viewer | `02 transferId:u32 <bytes>` |
| `0x03` upload chunk | viewer → agent | `03 transferId:u32 <bytes>` |
| `0x05` tunnel data | both | `05 streamId:u32 <bytes>` (tunnel sessions only) |

## Channels

### `sys`
| Type | From | Fields |
|---|---|---|
| `hello` | relay → viewer | `agentConnected`, `viewOnly`, `allowTerminal`, `allowFileTransfer`, `allowBlank` |
| `viewer.joined` | relay → agent | `by`, `viewOnly` |
| `agent.connected` / `agent.disconnected` | relay → viewer | |
| `info` | agent → viewer | `hostname`, `os`, `user`, `home`, `monitors: [{index,x,y,w,h,primary}]`, `capabilities: ["desktop","terminal","files","processes","services","chat","blank"]`, `shells`, `quality`, `maxFps` |
| `consent` | agent → viewer | `state`: `pending`, `granted` or `denied` |
| `ping` / `pong` | viewer ↔ agent | `ts` (echoed back) |
| `error` | agent → viewer | `message` |
| `action.result` | Windows helper → viewer | `action: "cad"`, `req` (echoed), `ok`, `message` |
| `end` | either | `reason` |

### `screen`
- Viewer sends `start {quality, fps, monitor}`, `settings {...}`, `refresh`, `stop` and `ack {seq}`.
- Agent sends tiles (binary `0x01`) and then `frame.end {seq}`.
- **Flow control:** the agent keeps at most two frames unacknowledged, so a slow link lowers the frame rate instead of building a queue.
- The agent splits the screen into 128×128 tiles and sends only tiles that changed since the last frame. `refresh` forces a full frame.

### `input` (dropped by the relay in view-only sessions)
- `mm {x,y}`: move the mouse. Coordinates are pixels in the captured screen.
- `md {b,x,y}` / `mu {b,x,y}`: button down/up. `b` is 0 left, 1 middle, 2 right.
- `wh {dy,dx,x,y}`: wheel, one notch per message.
- `kd {code,key}` / `ku {code,key}`: key down/up. `code` is the browser's physical key code (`KeyA`, `ShiftLeft`, `F5`…). Agents map it to a scan code or keysym, so the remote keyboard layout applies.
- `type {text}`: type a string as keystrokes.
- `clip.set {text}`: set the remote clipboard.
- `cad {req}`: Ctrl+Alt+Del. On Windows, the helper asks the Fenrir service over a per-session pipe. The service validates the caller's process, session, SYSTEM identity and impersonation level, then calls `SendSAS(FALSE)` as itself for the console session. Calling it while impersonating the helper was accepted and silently ignored on Windows Server 2025, so that is used only for a non-console session. `remote.cad.selftest` proves it on a machine: acceptance `remote_cad` saw the session switch to the secure desktop (Default to Winlogon) on Windows Server 2025. The helper replies with `sys/action.result {action:"cad", req, ok, message}`. `ok:true` means the service issued the request; Windows provides no API result proving that the sign-in screen changed. The viewer shows failures and a 10-second acknowledgement timeout. See [Windows Ctrl+Alt+Del](REMOTE_CTRL_ALT_DEL.md) for deployment and validation.
- `lock`: lock the workstation.
- `blank {on}`: blank the user's screen (Windows only, when policy allows).

### `term`
- Viewer sends `open {cols, rows, shell}`, `in {data}`, `resize {cols, rows}` and `close`.
- Agent sends `opened {shell}`, `out {data}`, `exit {code}` and `error {message}`.
- `data` is base64 of the raw byte stream. Linux uses a PTY; Windows uses ConPTY.

### `files`
- Viewer sends:
  - `ls {path, req}`: an empty path lists drives (Windows) or `/`.
  - `get {path, id}`
  - `put {path, id, size}`, then binary `0x03` chunks, then `put.end {id}`
  - `delete {path, req}`, `mkdir {path, req}`
- Agent sends:
  - `ls {req, path, parent, sep, entries: [{name, dir, size, mtime}]}`
  - `get.start {id, size}`, binary `0x02` chunks, then `get.end {id}`
  - `put.ok {id}`
  - `done {req}` or `{req, error}`

### `procs` and `svc`
- `procs`: `list {req}` → `list {req, items: [{pid, name, user, cpu, memMb, path}]}`; `kill {pid, req}`.
- `svc`: `list {req}` → `list {req, items: [{name, display, status, startType}]}`; `control {name, action, req}`, where `action` is `start`, `stop` or `restart`.

### `tunnel` (tunnel sessions only)
- A tunnel session relays TCP from the agent to one private LAN address and port (`targetHost`, `targetPort` in the start payload). Several streams share the session.
- Viewer sends `open {id}` and `close {id}`.
- Agent sends `opened {id}`, `error {id, message}` and `close {id}`.
- Data in both directions is binary `0x05 id:u32 <bytes>`.
- The relay forwards only `sys` and `tunnel` messages and `0x05` frames in a tunnel session, and drops `tunnel` messages in every other mode.
- `fenrir-tunnel` (`agent/linux/cmd/fenrir-tunnel`) is the technician-side client. It listens on a local port and turns each local connection into a stream.

### `chat`
- `msg {text}` in both directions. The Windows helper shows a small chat window to the signed-in user.

## Backstage desktop (`backstage` channel, Windows)

When a backstage helper has created its hidden desktop, its `info` capabilities include `desktop` and `backstage-desktop`,
and `screen` / `input` work as in a desktop session, on that desktop only.

- `launch {tool, command?, req}` (viewer → agent): start a tool on the hidden desktop as SYSTEM. `tool` is one of
  `taskmgr`, `services`, `eventvwr`, `regedit`, `compmgmt`, `devmgmt`, `cmd`, `powershell`, or `run` with `command`
  (up to 2048 characters). Audited as `backstage.launch` with the tool or command.
- `done {req, error?}` (agent → viewer): started, or why not.

## Direct connections (`rtc` channel, WebRTC)

Screen sharing can go peer-to-peer instead of through the relay, which is faster and takes load off the server. It is
tried automatically and falls back to the relay on its own; technicians see **Direct** or **Relayed** in the viewer's
toolbar.

- **When.** The start payload carries `direct` (true when policy `remoteAccess.allowDirect` is on, the default, and
  `remoteAccess.recordSessions` is off, because recordings are made at the relay) and `iceServers`. An agent that
  supports it adds `webrtc` to its `info` capabilities. Today that is the Linux and macOS agent; the Windows helper stays
  on the relay.
- **Finding a path.** The Fenrir server answers STUN itself on UDP 3478 (`FENRIR_STUN_PORT`, 0 turns it off), so no
  outside service is involved. Open UDP 3478 to the server for this to work; without it both sides still connect
  directly on the same network, and otherwise use the relay. There is no TURN server: when no direct path exists
  (symmetric NAT, strict firewalls), the relay is the fallback.
- **Set-up, over the relay.** Viewer → agent `offer {sdp}`; agent → viewer `answer {sdp}`; both ways
  `candidate {candidate, sdpMid?, sdpMLineIndex?}`. Agent → viewer `open` when the data channel is up,
  `closed {reason}` when it drops and `unavailable {reason}` when it cannot start. Viewer → agent `close` to stop.
  The viewer gives up after 8 seconds without `open`.
- **What goes direct.** One ordered, reliable data channel labelled `fenrir`. Agent → viewer: screen tiles (the `0x01`
  frame, cut into chunks of `0xFE id:u32 index:u16 count:u16 <bytes>` with at most 16,000 bytes each) and the
  `screen` `frame.end` that follows them. Viewer → agent: `screen` messages and `input` `mm`, `md`, `mu`, `wh`, `kd`,
  `ku`, `type` and `nav`. The agent drops anything else that arrives on the data channel.
- **What stays on the relay.** Everything audited or sensitive: Ctrl+Alt+Del, lock, blank, clipboard, terminal, files,
  processes, services, chat, and session start and end. Policy is still enforced and audited there.
- When the path changes in either direction the agent resends the whole screen, so no stale tile survives.

## Modes

The start payload's `mode` decides which channels a session may use. The relay enforces this, and the agent enforces it again.

| Mode | Channels | Where it runs |
|---|---|---|
| `desktop` | all | Windows: helper in the signed-in user's session. Consent and banner follow policy. |
| `terminal` / `files` | all | Windows: helper in the user's session, with the banner per policy but no consent prompt. |
| `backstage` | `sys`, `term`, `files`, `procs`, `svc`, `screen`, `input`, `backstage` | Windows: helper as SYSTEM in session 0. Works with nobody signed in. No prompt, banner or chat. `screen` and `input` are a hidden desktop in session 0, never the user's; `input` `cad`, `lock` and `blank` are refused. Linux/macOS: the agent (root), no screen. |
| `tunnel` | `sys`, `tunnel` | As `backstage`. |

## Security
- Tokens are HMAC-signed, scoped to one session and one audience (`remote-agent` or `remote-viewer`), and short-lived.
- The agent token is bound to the device id. A viewer token cannot be used as an agent token, and an agent token cannot be used as a viewer token.
- Policy (`remoteAccess.*`) is enforced twice: by the cloud before the session starts and by the relay on every message. The agent applies consent, the banner and the idle timeout.
- Every session start and end, file transfer, Ctrl+Alt+Del, terminal open and screen blank is written to the session's event list and to the hash-chained audit log.
- Direct connections are encrypted end to end by WebRTC (DTLS) and are only set up through an authenticated relay session; the data channel carries screen and ordinary input only (see "Direct connections").
- **Backstage and tunnel sessions** are silent, so they carry extra checks:
  - Each needs a fresh sign-in check (`X-Fenrir-Reauth`) and a stated reason or linked ticket.
  - Analyst roles cannot open them.
  - Both are off by default (`remoteAccess.backstage`, `remoteAccess.allowTunnels`). The cloud and the device's own agent both check the policy, so a compromised console alone cannot open one.
  - Backstage sessions are always recorded (the hidden desktop's screen and the terminal output).
  - Tunnels reach private addresses on allowed ports only (`remoteAccess.tunnelPorts`). The agent checks the target again before connecting, and every stream open is audited.
