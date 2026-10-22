# Roadmap

## Done in this consolidation

- **Fenrir Cloud.** Implements the Windows agent's full control-plane contract, plus SIEM, detection, response, DNS, intel, exposure, compliance, CRM/PSA/billing, RBAC and the audit chain. 41 tests pass on SQLite and PostgreSQL.
- **Fenrir Console.** 22 screens covering every module.
- **Managed Linux agent.** Verified end to end: real-time block and quarantine, alerting, remote scan, isolation, inventory, triage.
- **Packaging.** Docker image, docker-compose + PostgreSQL, `.deb` packages, install script and CI.

## Done in round two

- **Static ML engine:** trained on SOREL-20M (700k samples), with bit-identical feature extraction in Python, Go and C++, and on-device scoring on Windows and Linux. The model is distributed from the cloud with checksum verification. See `ml/README.md`.
- **Windows agent:**
  - Attack surface reduction, application control and shadow-copy tamper blocking on every process start.
  - Device control via Windows policies.
  - PID-targeted kills.
  - Cross-compiles from Linux, with portable unit tests run under Wine.
- **Linux agent:** behaviour rules, app control, udev/rfkill device control, ML scanning of Windows executables, model updates.
- **Cloud safety fix:** automatic "kill process" is now PID-targeted and skipped when the agent has already stopped the process. Previously it could kill every copy of a shared program such as `bash` or `powershell.exe`.

## Next (highest value first)

1. **Windows enrollment tokens.** Read `HKLM\SOFTWARE\FenrirAgent\EnrollmentToken` and send it as `X-Fenrir-Token` in `ControlPlaneClient::Enroll`. Devices then land in the right tenant without approval.
2. **Windows executors** for `ransomware.rollback`, `scan.quick` / `scan.full` and `forensics.collect`.
3. **Pre-execution blocking** once the minifilter is attestation-signed (see DRIVER_SIGNING.md); per-device USB exceptions and printer control on Windows; fanotify-based pre-exec checks on Linux.
4. **Telemetry at scale.** Move `events` to ClickHouse or OpenSearch and run detection workers from a queue (Redis Streams/NATS). Target 50k endpoints per region.
5. **ML v2:** retrain on newer samples, add an ELF model for Linux, and track scores in telemetry to monitor drift.
6. **Patch catalogue UI** and approval rings, built on the existing Windows patch orchestrator.
7. **Identity/M365 posture module.** Graph API: MFA coverage, risky sign-ins, mailbox rules.
8. **Network discovery.** Agents ARP/mDNS-scan their subnets to find unmanaged devices.
9. **SSO** (OIDC/SAML) and **MFA** for console users. Customer self-service portal.
10. **Migrate** the remaining SIEM-Work-Dev microservices (RMM scripts, compliance evidence) into Fenrir Cloud modules, then retire them.

## Commercial readiness

- **Microsoft:** WHQL-sign the minifilter and get ELAM certification. **Apple:** notarise the macOS agent.
- **Independent testing:** enter AV-Comparatives Business and AV-Test once the ML engine is in.
- **The service itself:** pen test, SOC 2 Type I, data-processing agreements, UK/EU data residency.
