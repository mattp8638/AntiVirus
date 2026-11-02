# Go-live checklist

The order to take a Fenrir server from a fresh VPS to a customer relying on it. Each step links to the detail; this
page only says what to do and how you know it is done.

## 1. Before you start

- [ ] A Linux server that meets the [requirements](../README.md#requirements), with SSH restricted to your addresses.
- [ ] A DNS name (for example `rmm.yourmsp.co.uk`) pointing at it, and TCP 80 and 443 open to the internet.
- [ ] Your Windows code-signing certificate (`.pfx`) and its password. See [code signing](CODE_SIGNING.md).
- [ ] An SMTP account for alert and ticket emails.
- [ ] Somewhere off the server for backups (another server, object storage), and a password manager or safe for the
  secrets in `deploy/.env` and the signing files.

## 2. Install

- [ ] Follow the README's [new HTTPS installation](../README.md#new-https-installation), steps 1 to 5.
- [ ] Copy `deploy/.env` and `deploy/signing/` to your password manager or safe **now**. The vault key in `.env` is the
  only way to read stored credentials after a restore, and agents only accept updates signed with the release key.

Done when `https://<your name>/ready` answers `{"ready": true}` and you can sign in.

## 3. Backups

- [ ] Schedule the daily backup ([README step 6](../README.md#6-schedule-backups-and-run-the-go-live-check)) and run
  it once by hand.
- [ ] Copy each night's backup folder off the server, encrypted. For example, with an rclone remote set up as `crypt`:
  `17 3 * * * root rclone copy /var/backups/fenrir offsite-crypt:fenrir --max-age 26h`
- [ ] Once, on a separate machine, restore a backup by following [backup and restore](BACKUP_AND_RESTORE.md). CI does
  this on every change (from an empty server to background jobs healthy), but you need to have done it yourself with
  your own files before you need it.

## 4. Go-live check

- [ ] Run `sudo deploy/preflight.sh` until it reports no FAIL.
- [ ] Decide on each WARN. Typical ones on a new server:
  - Open enrolment: set `FENRIR_OPEN_ENROLLMENT=false`.
  - Legacy vault keys: set `FENRIR_VAULT_ALLOW_DERIVED_LEGACY=false`.
  - No SMTP.

Done when preflight ends with "Ready." or "Ready, with the warnings above to decide on." and you have decided on each
warning.

## 5. Monitoring

- [ ] Point an uptime monitor (UptimeRobot, Better Stack, your own) at `/ready` and `/health/background`.
- [ ] In **Settings → Webhooks**, add your on-call channel (Slack, Teams or a generic URL) for **Fenrir platform
  degraded** and **Fenrir platform recovered**. Fenrir sends these itself, even when its background worker is down.
- [ ] Optional: set `FENRIR_METRICS_TOKEN` and scrape `/metrics` with Prometheus
  ([README](../README.md#background-worker-and-telemetry-volume)).

## 6. Lock down staff access

In **Settings → Platform → Security** ([README](../README.md#staff-sign-in-and-the-emergency-stop)):

- [ ] Leave **Require MFA for staff** on, and set up your own MFA or passkey.
- [ ] Add your office and VPN ranges to the **console networks** list.
- [ ] Decide on **script review** and **two-person approvals** (Settings → Approvals) for scripts run on many devices.
- [ ] Give each technician their own account and the least role they need. Never share the bootstrap admin.

## 7. Windows protection

Fenrir does not ship a Windows kernel driver (decision D-06), so Microsoft Defender is what blocks programs before they
run.

- [ ] In the policy your Windows devices use, decide on **Microsoft Defender → Manage Microsoft Defender**. When it is
  on, Fenrir keeps Defender's real-time protection on and sets its attack surface rules. Start the rules in audit for a
  week if the customer runs unusual software.
- [ ] After enrolling devices, check that **Protection health → Blocks before it runs** says **Defender** for every
  Windows device. Where it says **None**, find out what is holding Defender off.

## 8. Prove it before customers rely on it

- [ ] Run the [acceptance lab](ACCEPTANCE_LAB.md) against your server: a few VMs, one command, plus the hand checks
  (remote desktop and Ctrl+Alt+Del, admin elevation, patching, isolation, switch-port topology).
- [ ] Put the agent on your own team's machines for a week or two first.

## 9. First customer

- [ ] Create the customer, then an **enrolment token** for them (Deploy agents). Do not use open enrolment.
- [ ] If the customer's network needs a web proxy, see [networks with a web proxy](../README.md#agent-installation)
  before installing.
- [ ] Install on two or three pilot machines and check each one: it checks in, takes policy, reports inventory, and
  shows **Defender** under Blocks before it runs.
- [ ] Roll out the rest. Give your pilot machines a policy whose **Updates → channel** is canary or beta: new agent
  versions reach that ring first, and a failure there pauses the rollout before anyone else gets it (**Settings → Agent
  rollouts**, [updates](AUTO_UPDATE.md)).
- [ ] If they use Microsoft 365, connect their tenant ([Microsoft 365 administration](M365_ADMINISTRATION.md)).

## Running it

| When | Do |
|---|---|
| Daily | Look at the inbox and **Protection health**. Your monitor and the platform webhooks tell you if the server itself is unwell. |
| Weekly | Check the off-site copy has new backups in it. |
| Before every upgrade | Take a backup. Afterwards, run `sudo deploy/preflight.sh` and, ideally, the acceptance lab. |
| Every few months | Restore a backup onto a spare machine. |

| If | Then |
|---|---|
| A staff account, a script or the server may be compromised | **Emergency stop** (Settings → Platform → Security): cancels queued work, ends remote sessions and refuses new commands everywhere. Then rotate the affected credentials. |
| A device's API key may have leaked | Decommission the device (it revokes the key at once), then reinstate it with a reinstatement installer. For routine hygiene, keys rotate themselves every 90 days. |
| The server is lost | Build a new one from steps 1 and 2 with the same `.env` and `deploy/signing`, then restore the latest backup ([backup and restore](BACKUP_AND_RESTORE.md)). |
| A platform-degraded alert arrives | **Settings → Platform** names the job or check that is failing, with its last error. |
