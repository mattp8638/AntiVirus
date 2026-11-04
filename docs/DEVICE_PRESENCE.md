# Device presence: how often devices check in, and when they show as online

Every page (device list, device page, dashboard, RMM, Client 360, compliance, Active Directory, the customer portal)
uses one rule, in `cloud/fenrir_cloud/presence.py`.

## How often each device is heard from

| Device | Live connection | Without it | Heard from at least every |
|---|---|---|---|
| Windows agent | WebSocket, ping every 30 s | command poll every 15 s, sync cycle every 60 s | 30 s |
| Linux and macOS agent | WebSocket, ping every 30 s | command poll every 15 s, heartbeat every 60 s | 30 s |
| Android phone, awake | none | check every 30 s, heartbeat every 60 s, and at once when the screen turns on or the phone leaves power saving | 60 s |
| Android phone, asleep | none | Android's power saving (Doze) lets a wake-up alarm through about every 10 minutes | ~10 min |
| iPhone, iPad, Mac with the web protection profile | none | every website lookup | while in use |

Each ping on the live connection counts as a check-in. Before this change only heartbeats and API calls counted, so an
agent busy with a long scan could look offline while it was connected. A check-in is written at most every 20 seconds
per device.

## States

| State | Rule | Counts as up |
|---|---|---|
| Online | heard from in the last 2 minutes (four missed pings) | yes |
| Asleep | a phone heard from in the last 30 minutes | yes: a sleeping phone is not a fault, and it runs queued actions when it wakes |
| Idle | a profile-only Apple device with no lookups in 15 minutes | no, but it does not alert (web protection has its own 72-hour alert) |
| Offline | anything else | no |

The previous rules varied by page (5, 10 or 15 minutes), which is why the same device could show online on one page and
offline on another. Phones were marked offline between Doze wake-ups.

The device list and device page refresh every 15 seconds while they are on screen.

## Offline alerts

"Offline for N minutes" monitor conditions measure from the last check-in, so they now see agents within 30 seconds of
the truth. Profile-only Apple devices are left out of offline monitors.

## Windows: how the agent keeps itself connected

Several independent layers, so a Windows agent that is running never stays silent:

1. **Keep-alive thread.** Separate from the agent's main work, it tells the server "still here" whenever nothing else
   has reached it for a minute. A long scan, script, patch install or a live connection stuck reconnecting no longer
   makes the device show offline.
2. **Liveness record.** The agent writes `liveness.json` in its runtime folder every 30 seconds: when its main loop
   last made progress, when the server last answered, the last HTTP status and error.
3. **Self-restart.** A thread in the agent ends the process (Windows then restarts it) when the main loop has made no
   progress for 45 minutes, or when the server has not answered for 30 minutes while the agent keeps trying (at most
   once every 2 hours). Supervised waits (a script or patch install within its own time limit) and inline scans count
   as progress.
4. **Watchdog task** (`Fenrir\Agent watchdog`: `fenrir-agent-service.exe --watchdog`, as SYSTEM, every 5 minutes and 3
   minutes after boot). The agent registers it every time it starts, so existing installs get it with the next agent
   update. Each run it:
   - starts the service if it is stopped (or resumes it if paused);
   - ends and restarts it if it is stuck starting or stopping for over 10 minutes;
   - ends and restarts it if it is running but frozen (no liveness update for 10 minutes), its main loop has been
     stuck for an hour, or the server has not answered for 20 minutes **while this machine can reach the server**
     itself (so a laptop that is simply offline is left alone);
   - repairs the service registration if it is missing, and after 3 restarts in 6 hours that did not help (at most
     every 12 hours);
   - re-applies Windows' restart-on-failure settings.

   Forced restarts are at most one every 30 minutes, nothing happens during an install or upgrade, and every action
   is written to `watchdog.log` in the runtime folder.
5. **Backup watchdog task** (`Fenrir\Agent watchdog (backup)`, PowerShell, every 5 minutes), registered by the
   installer and independent of the agent program: starts a stopped agent, and restarts one whose liveness record has
   not changed for 20 minutes.
6. **Windows restart-on-failure**: restart after 5, 15 and 60 seconds for every crash or error exit.

When the agent comes back after a watchdog action or a self-restart it reports why
(`agent.watchdog.recovered`, `agent.self_restarted`) in the device's activity.
