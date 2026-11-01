# Stop commands, remove jobs and decommission devices

**Device → Activity → Remote actions → Stop action** cancels one command. **Automation → open a job → Stop job** stops its outstanding commands. **Remove job** also removes it from the activity list; its command outcomes and audit history remain available. Deleting a schedule stops the outstanding jobs created by that schedule and prevents future runs.

Decommissioning a device no longer refuses the request when work is dispatched. It removes the device from the active list, revokes its ordinary agent access, cancels queued commands, requests a stop for dispatched commands and ends remote support sessions. History is retained. It does not uninstall antivirus protection or release network isolation.

## What the statuses mean

| State when stopped | Behaviour |
| --- | --- |
| Queued | Cancelled immediately; it cannot be dispatched. |
| Dispatched or running | Shown as **Stopping** until the agent acknowledges it has stopped. |
| Already finished | The actual completed/failed outcome is retained. Applied changes are not undone. |
| Offline endpoint | Removal succeeds; stop confirmation waits for the endpoint. A current agent checks command state before executing a previously fetched batch item. |
| Older agent | Queued work can still be cancelled and the device removed. Running work remains unconfirmed until it reports an outcome; update agents before relying on remote process cancellation. |

Updated Windows agents check for cancellation independently of the running command, normally every two seconds while connected. The executor terminates the command's Windows job object, including its child processes. Linux/macOS command executors pass a cancellation context through scripts, package-manager operations and services, and terminate their process groups. Remote scans remain attached to their command and stop cooperatively between scan operations. The independent AV service and unrelated work continue running.

Stopping an executor does not roll back changes already applied. An OS-managed installer or update transaction may finish independently of the cancelled launcher; shared operating-system installer services are not killed. Stop acknowledgement refers to the agent's command execution, not reversal of those changes.

## Retirement and acknowledgement

Normal device credentials are revoked as soon as the device is decommissioned. For seven days, a command-specific grant lets the former device key read that command's stop state and submit its final outcome. It cannot poll for new commands, send heartbeats, upload telemetry, access another device or read unrelated commands. The stored key hash is excluded from console/API serialization.

Cancelled outcomes are written to the agent's durable command journal before acknowledgement. Lost acknowledgements can be retried after a reconnect or service restart without rerunning the action. If a device is permanently purged, a current executor treats an authenticated state request's missing/revoked command response as a stop; the removed server records can no longer receive an acknowledgement.

The device page reports outstanding stop acknowledgements. It also identifies an agent that has not yet reported cancellation support. Do not treat an unreachable endpoint or an unconfirmed older agent as proof that its process stopped.

## Deploy and verify

After merging this change, pull the updated deployment branch and rebuild with your usual Compose files. Database migration 30 adds three nullable cancellation fields to existing command rows automatically at cloud startup; it preserves command and device history. No database reset is required.

Allow endpoint agents to install the updated build before testing cancellation of running work. For an endpoint already stuck on an older build, update/reinstall it locally or through an existing remote session before decommissioning it, so the new cancellation monitor is available.

For a functional check, run a harmless long script on a test endpoint, stop its job and verify the sequence **running → Stopping → cancelled**. Confirm that its child process exits, then decommission a device with queued work: removal should succeed immediately and no cancelled queued action should start on its next check-in.
