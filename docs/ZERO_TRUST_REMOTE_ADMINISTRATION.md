# Zero-trust remote administration

Three ways to reach a customer machine beyond the remote desktop. All of them are gated, audited and enforced by the device as well as the cloud.

## Backstage access

A silent administrative session: a SYSTEM (Windows) or root (Linux/macOS) terminal, plus file transfer, processes and services.

- **Nothing appears on the user's screen.** There is no consent prompt, no banner, no screen capture and no input.
- **It works when nobody is signed in,** or when the desktop is hung.
- **On Windows,** the service starts `fenrir-remote.exe` with its own token in session 0 instead of the user's console session.
- **Turn it on per policy:** Policies → Remote access → Backstage access (`remoteAccess.backstage = "on"`). It is off by default.
- **Both sides check the policy.** The Windows service and the Linux/macOS agent refuse a backstage start that their own policy does not allow.
- **Each session needs** a fresh password (and MFA) check and a reason or a linked ticket. Analyst roles cannot open one.
- **Backstage sessions are always recorded,** whatever `recordSessions` says. The recording is kept with the device's artifacts.
- **In the console,** use the **Backstage** button next to Connect on the device page.

## Cross-platform session routing

**Device → All routes** (or a node on **Network topology**) lists every way to reach a machine, best first:

| Route | When | What you get |
|---|---|---|
| Fenrir agent | The device's agent is online | Desktop (Windows, macOS, Linux X11), terminal, files and backstage, as policy allows |
| Tunnel via a peer | Another agent on the same LAN has seen the target (topology) | TCP to RDP, SSH, VNC, a web UI or Intel AMT on the target, through that peer |
| Intel AMT | An AMT endpoint is registered for the machine | Power control whatever state the OS is in |

**Tunnels.** A tunnel session asks the peer agent to connect to one private LAN address and port, and relays the bytes through the session (channel `tunnel`, binary frames `0x05`).

- **Client.** The technician runs `fenrir-tunnel` (built from `agent/linux/cmd/fenrir-tunnel` for Windows, macOS and Linux) with the URL the console shows, then points the usual client at the local port: `mstsc /v:127.0.0.1:13389`, `ssh -p 2222 …`, a VNC viewer or a browser. Each local connection becomes its own stream, so web UIs work too.
- **Policy.** Tunnels are off by default (`remoteAccess.allowTunnels`). Only ports in `remoteAccess.tunnelPorts` can be reached; the default list is SSH, Telnet, HTTP/S, RDP, VNC, 8080/8443 and the Intel AMT ports.
- **Targets.** Tunnels reach private (RFC 1918 / ULA) addresses only, never the internet, loopback or link-local (cloud metadata) addresses.
- **Checks.** The peer agent checks the target and port against its own policy before every connection.
- **Audit.** Opening a tunnel needs a fresh sign-in check and a reason. Each stream open is audited on the session.

## Intel AMT / vPro out-of-band management

**MSP operations → Out-of-band (Intel AMT)** manages AMT engines over WS-Management.

- **Check** reads the AMT version (`Identify`), the power state (`CIM_AssociatedPowerManagementService`) and AMT's own host name (`AMT_GeneralSettings`).
- **Power** calls `CIM_PowerManagementService.RequestPowerStateChange`: on, graceful restart, reset, power cycle, graceful shut-down or off.
  - Anything other than power-on needs the destructive permission.
  - Every action is audited.

**Routes**

- **Direct.** The Fenrir server talks to the engine itself, for example over a site VPN. It uses HTTP Digest authentication on 16992, or TLS on 16993; AMT's self-signed certificate is accepted only when the endpoint says so.
- **Through an agent on the same LAN** (`amt.wsman`). The command carries only the WS-Management bodies.
  - The agent fetches the host, user and password once for that command from `POST /api/v1/devices/<id>/commands/<command>/amt-credential`.
  - The credential is released only to the device the command was sent to, only while the command is pending, and only once. The release is audited.
  - The agent uses the AMT ports only, so the credential cannot be pointed at another service.
  - Windows uses WinHTTP's Digest support; Linux/macOS use a built-in RFC 7616 MD5 Digest client.

**Storage and discovery**

- The AMT password is stored encrypted (vault envelope with associated data `amt:<tenant>:<endpoint>`).
- Network discovery now sweeps 16992/16993, so routing suggests registering machines that answer there.

**Hardware KVM.** AMT KVM is reached by opening a tunnel to the AMT address on port 5900 (when AMT's standard VNC port is enabled) or 16994/16995 for a redirection-aware viewer.

**Not yet covered.**
- Boot-to-BIOS and IDE-R/USB-R boot options.
- AMT provisioning (ACM/CCM); configure AMT with Intel's tools or the OEM's first.
