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

Later additions:
- macOS remote screen and control (helper in the user's session, CoreGraphics via purego), display selection,
  Homebrew patching, network connection sensor.
- Forensic and support bundles upload to the cloud (Windows tar, Linux/macOS tar.gz); responder-only, audited
  download; 30-day retention.
- Remote session recording and playback; multi-monitor selection, with "All screens" on Windows.

Open:
- macOS has not been run on a real Mac. It needs Full Disk Access, Screen Recording and Accessibility granted by
  hand (an MDM profile can pre-approve them).
- No "all screens" view on macOS; Linux remote control needs X11 (Wayland blocks it).

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

Later additions (enforcing settings that were previously ignored):
- Batch 1: EDR collection switches and minimal telemetry (Windows, Linux, macOS); automatic quarantine of
  unremediated malware; terminal sessions for analysts only when `response.remoteShell` allows; break-glass refused
  when `privilege.breakGlassAllowed` is off; end-user restores from the Windows tray only when
  `experience.allowQuarantineRestore` is on.
- Batch 2, firewall: the managed firewall, default inbound/outbound action and custom rules are applied on all
  three platforms. Rules are checked when the policy is saved (`allow|block in|out tcp|udp|any [ports]
  [from|to addresses]`); block rules win over allow rules.
  - Windows: Windows Firewall profiles, rules in the "Fenrir policy" group, the agent's own programs allowed out
    when outbound is blocked. SMBv1 server off and LLMNR/NetBIOS off (`blockSmbV1`, `blockLlmnrNetbios`).
    Turning LLMNR/NetBIOS blocking off undoes it; turning SMBv1 blocking off stops enforcing but never re-enables
    SMBv1.
  - Linux: a separate nftables table (`inet fenrir_policy`), so ufw/firewalld are untouched. macOS: a pf anchor
    (`com.apple/fenrir-policy`) and the application firewall (on, stealth mode when inbound is blocked).
  - On Linux and macOS the default inbound/outbound action only applies once "Apply default actions on Linux and
    macOS" is turned on, so upgrading never cuts off services a server offers; custom rules apply regardless.
  - Safeguards on Linux and macOS: loopback, replies, DHCP, ICMP and DNS always pass; the Fenrir Cloud address
    stays reachable when outbound is blocked; inbound SSH stays open unless a custom rule blocks port 22.
- Batch 3, scanning:
  - Scheduled scans keep to `scanCpuLimitPercent` of one core (Windows measures the scan thread's processor time
    and lowers its priority; Linux/macOS rest between files). Scans an analyst starts run at full speed.
  - `scanNetworkDrives`: Windows full scans add network drive letters; Linux/macOS skip NFS, SMB, AFP, sshfs and
    similar mounts unless it is on. On Windows, drives mapped in a user's session are not visible to the
    service, so only drives mapped for the system account are scanned.
  - Linux/macOS look inside zip (and jar/apk/docx), tar, gzip and tar.gz archives, nested up to `archiveMaxDepth`,
    with limits against archive bombs; a match quarantines the whole archive and names the member.
  - PUA: the cloud tags signatures for potentially unwanted applications (indicator category, or names such as
    `PUA:`, `Adware.`, `not-a-virus:`). Linux/macOS ignore them when `puaProtection` is off and report without
    quarantining or stopping the process when it is audit. Windows does not separate PUA yet.

Open:
- About 35 policy settings are still not enforced by any agent (marked in the editor; see
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
