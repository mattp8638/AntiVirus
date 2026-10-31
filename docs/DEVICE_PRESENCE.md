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
