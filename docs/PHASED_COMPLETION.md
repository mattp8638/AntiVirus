# Phased completion: what works and what is still open

This records the gap-closing work done module by module (Devices, Protection, CRM, PSA, then the other
modules). Each item was tested in the cloud test suite, and agent changes were built (Windows with MinGW and
tested under Wine; Linux/macOS with Go tests and cross-builds).

## 1. Devices (RMM)

Done:
- macOS agent: launchd service control, pf firewall anchor, `softwareupdate` patching, `system_profiler`
  inventory, Homebrew and SHA-256-verified `.pkg` installs, persistence and process sensors.
- macOS deployment: `Install-Fenrir-macOS.sh` from Deploy agents (LaunchDaemon, both architectures
  embedded); self-update via `/api/v1/agent/update/macos`.
- Linux self-update via `/api/v1/agent/update/linux`.
- Inventory from the Windows agent's nested snapshot; protection-policy patch settings (maintenance
  window, deferrals, reboot behaviour, automatic install in the window).
- Windows: background scans that no longer block commands; telemetry queue that no longer loses events;
  `inventory.refresh`, `policy.refresh`, `scan.quick/full`, `forensics.collect` commands.

Open:
- macOS has not been run on a real Mac; no screen sharing on macOS; needs Full Disk Access granted by hand.
- Forensic bundles stay on the device (no upload yet).

## 2. Protection

Done:
- Malware findings, real-time blocks, ML verdicts, behaviour chains and ransomware canaries raise alerts,
  graded by whether the threat was remediated. AMSI blocks count as remediated.
- Quarantine page with restore/delete through the device.
- Windows vulnerabilities from missing security updates (MSRC severity, CVEs, KEV flag), verified fixed by
  the next patch scan.
- Web/destination protection settings now reach the Windows agent; quick/full scan schedules are honoured on
  Windows, Linux and macOS (new scheduled scans on Linux/macOS).
- AMSI findings from ordinary user processes reach the cloud through the service's local pipe.
- The policy editor marks settings no agent enforces yet, and compliance no longer counts them as evidence.

Open:
- About 55 policy settings are still not enforced by any agent (marked in the editor; see
  `AGENT_SUPPORT` in `cloud/fenrir_cloud/policy_schema.py`).
- Ransomware rollback is withdrawn: no agent keeps file snapshots.

## 3. CRM

Done: opportunities (new business, upsell, renewal) with weighted pipeline and win rate; activities and
follow-up tasks; account owner; account view with timeline, contracted MRR, profitability (revenue against
labour cost, `crm.labourCostPerHour` in the MSP tenant settings, default 40/hour) and Microsoft 365 licence use.

## 4. PSA

Done: problem records (root cause, workaround, known error, linked incidents resolved in one step); change
records (risk, window, plans, independent approval, two approvers for high risk); workload view; richer
customer service report; tickets show the vulnerabilities they remediate.

## 5. Other modules

Done:
- Network monitoring can probe LAN services from an enrolled device (`network.probe`, Windows and Go agents).
- Backup tools push results with a per-plan token; failed and overdue backups raise alerts.
- GRC statement of applicability linking register evidence to the built-in control libraries.
- Microsoft 365 insights: unused licences, disabled accounts holding licences, MFA coverage (admins without
  MFA), Secure Score.

Open:
- No direct API integrations with specific backup vendors (results arrive by push or by hand).
- Network probes are TCP only (no ICMP/SNMP).

## Upgrading

Database migrations 6–10 run automatically on start-up and only add tables and nullable columns.
Migration 6 also fixes databases upgraded before `devices.patch_window_run` existed, which otherwise failed
every device request.
