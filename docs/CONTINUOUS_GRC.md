# Continuous GRC automation

**Cloud, network & compliance → Compliance & GRC → Continuous assurance** brings four pieces together on top of the GRC programmes (frameworks, requirements, policies and evidence):

- one control set mapped across frameworks;
- evidence collected automatically, with drift alerts;
- endpoint baselines checked, and optionally enforced, on devices;
- third-party (supplier) risk management.

## Cross-framework control mapping

`grc_library/crosswalk.yml` defines 22 Fenrir common controls, such as malware protection, MFA, patching, backup and supplier risk. Each one lists the requirements it satisfies in every framework in the library:

- Cyber Essentials and CE+
- CIS IG1
- ISO/IEC 27001:2022
- NIST CSF 2.0
- NCSC CAF
- SOC 2
- PCI DSS
- NIS2
- DORA
- UK and EU GDPR
- GovS 007
- DEF STAN 05-138

The tests fail if a mapping names a requirement that does not exist.

**How it is used**

- **Controls tab.** Each control shows its live checks, and the requirements it covers in the customer's adopted frameworks with their status.
- **Apply across frameworks.** On an implemented requirement, this marks the requirements the same control covers in the customer's other adopted frameworks as implemented. It also links the same evidence and records where the status came from.
  - Requirements already implemented, not applicable or needing review are left alone.

## Real-time evidence collection and drift

**Live signals**

| Signal | Source |
|---|---|
| Endpoint and policy checks | `compliance.py`: devices reporting, real-time protection, web/DNS filtering, firewall, secure configuration, automatic patching, exploitable vulnerabilities, least privilege, application control, logging, incident response |
| Microsoft 365 MFA | Registration of at least 95% |
| Backups | A recent successful run per plan |
| Policies | Approved security policies with reviews not overdue |
| Supplier risk | Third-party risk status (below) |
| Endpoint baselines | Results for the relevant control |

**Collection.** When continuous collection is on for a customer (hourly), or when **Collect now** is pressed:

- An `automated` evidence record is written per control, whenever that control's signals changed or at least daily. Each record:
  - holds the captured signals as JSON, with a SHA-256;
  - stays valid for 30 days;
  - is linked to every mapped requirement of the customer's adopted frameworks.
- A signal that goes from passing to failing is compliance drift. Fenrir then:
  - writes an audit entry (`grc.drift`);
  - publishes the event (`grc.drift`);
  - opens a P2 ticket naming the affected controls and the failing evidence.

## Endpoint baseline enforcement

Three built-in baselines (`grc_baselines.py`) are built from condition packages with detection and remediation scripts:

- **Windows.**
  - Fixed automatically: firewall profiles on; SMBv1 server, LLMNR, PowerShell 2.0 and AutoRun off; Guest disabled; Remote Desktop requires NLA; 15-minute inactivity lock; Windows Update service enabled.
  - Reported only: BitLocker.
  - Also expects Fenrir policy settings: real-time protection, tamper protection, firewall, web protection.
- **Linux.**
  - SSH root password login off. The change is rolled back if `sshd -t` rejects it.
  - Host firewall reported.
  - Time synchronisation and disk space.
- **macOS.**
  - Gatekeeper and the application firewall turned on.
  - FileVault reported.

**Modes**

- **Audit** only detects.
- **Enforce** fixes drift silently and checks again. A ticket opens if the fix does not hold. Enforce needs the `scripts` permission.

The report shows each device against each check and the policy settings. Results feed the `baseline:<control>` signals, and so the automated evidence.

## Automated third-party risk management

The supplier register is kept per customer (`tprm.py`).

- **Inherent risk** comes from criticality (low to critical) and the data the supplier can reach (none, internal, personal, special category).
- **Questionnaire.** 15 weighted questions covering governance, access control, data protection, operations, resilience, incident response, supply chain and people.
  - The questionnaire goes out as a single-use link (`/vendor-assessment/<token>`). The supplier answers in the browser without an account; the page is rate limited and the link expires.
  - Weak answers become findings. A "no" to a 3-weight question is high severity.
- **External posture scan** of the supplier's domain:
  - SPF and DMARC (via DNS-over-HTTPS);
  - HTTPS and HSTS;
  - the TLS certificate's validity and expiry;
  - `security.txt`;
  - breaches reported for the domain in the last 3 years (Have I Been Pwned's public breach list).
- **Residual risk** is the inherent risk reduced by the questionnaire score (70%) and the posture score (30%), giving a tier.
- **Schedule.** Reviews fall due every 6, 12, 24 or 36 months by criticality. When one falls due, Fenrir:
  - opens a ticket;
  - sends the questionnaire again (unless `tprm.autoReassess` is off for the customer).
- **Certificates and contracts.** Those expiring within 30 days open a ticket once. Posture is rescanned weekly.
- **Signal.** The third-party risk signal passes when every high and critical supplier is assessed on schedule, none is at critical residual risk, and no supplier document has expired.
