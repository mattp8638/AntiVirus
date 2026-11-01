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
- `cad {req}`: Ctrl+Alt+Del. On Windows, the helper asks the Fenrir service to call `SendSAS(FALSE)` while impersonating that helper in its Windows session. The service validates the caller's process, session, SYSTEM identity and impersonation level. The helper replies with `sys/action.result {action:"cad", req, ok, message}`. `ok:true` means the service issued the request; Windows provides no API result proving that the sign-in screen changed. The viewer shows failures and a 10-second acknowledgement timeout. See [Windows Ctrl+Alt+Del](REMOTE_CTRL_ALT_DEL.md) for deployment and validation.
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

## Modes

The start payload's `mode` decides which channels a session may use. The relay enforces this, and the agent enforces it again.

| Mode | Channels | Where it runs |
|---|---|---|
| `desktop` | all | Windows: helper in the signed-in user's session. Consent and banner follow policy. |
| `terminal` / `files` | all | Windows: helper in the user's session, with the banner per policy but no consent prompt. |
| `backstage` | `sys`, `term`, `files`, `procs`, `svc` | Windows: helper as SYSTEM in session 0. Works with nobody signed in. No prompt, banner, screen, input or chat. Linux/macOS: the agent (root). |
| `tunnel` | `sys`, `tunnel` | As `backstage`. |

## Security
- Tokens are HMAC-signed, scoped to one session and one audience (`remote-agent` or `remote-viewer`), and short-lived.
- The agent token is bound to the device id. A viewer token cannot be used as an agent token, and an agent token cannot be used as a viewer token.
- Policy (`remoteAccess.*`) is enforced twice: by the cloud before the session starts and by the relay on every message. The agent applies consent, the banner and the idle timeout.
- Every session start and end, file transfer, Ctrl+Alt+Del, terminal open and screen blank is written to the session's event list and to the hash-chained audit log.
- **Backstage and tunnel sessions** are silent, so they carry extra checks:
  - Each needs a fresh sign-in check (`X-Fenrir-Reauth`) and a stated reason or linked ticket.
  - Analyst roles cannot open them.
  - Both are off by default (`remoteAccess.backstage`, `remoteAccess.allowTunnels`). The cloud and the device's own agent both check the policy, so a compromised console alone cannot open one.
  - Backstage sessions are always recorded (terminal output).
  - Tunnels reach private addresses on allowed ports only (`remoteAccess.tunnelPorts`). The agent checks the target again before connecting, and every stream open is audited.
