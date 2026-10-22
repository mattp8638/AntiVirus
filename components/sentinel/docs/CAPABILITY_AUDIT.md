# Sentinel Capability Audit

This audit maps the locked build manifest to the current implementation surface.
The canonical list lives in `modules/build_manifest.py`; the API exposes the
same list at `/api/security-suite/manifest` and coverage at
`/api/security-suite/audit`.

## Current Coverage Summary

- Built before this pass: AV Scanner, IOC Scanner, endpoint investigation,
  persistence/process/network investigation collectors, timeline, evidence
  export, incident reporting, case management, threat feeds, CVE, and endpoint
  health scoring.
- Hardened in this pass: endpoint investigation artifacts, Windows event logs,
  PowerShell activity, process command lines, network connections, persistence
  evidence, local user/admin parsing.
- Added in this pass: canonical manifest lock, suite runner, DNS monitoring and
  protection, ransomware behaviour checks, backup readiness, patch status,
  browser/USB/firewall/account/logon/privilege/mailbox/OAuth/M365 checks,
  email/header/attachment/URL analysis, YARA/Sigma validation, MITRE mapping,
  Mini-SIEM search, alert correlation, remediation guidance, risk export,
  secrets/repo/container/cloud audit import, report signing/integrity, role
  modes, and signed update/rule package verification.

## Operating Rule

New product work should either improve one of the 50 locked capabilities or be
explicitly added to the manifest with a deliberate versioned decision. The tests
in `tests/test_canonical_security_suite.py` enforce that all locked capabilities
remain represented by the application.
