# Fenrir Platform architecture

```
 Endpoints                         Fenrir Cloud (cloud/)                                  People
 ─────────                         ─────────────────────                                  ──────
 Windows service (C++)  ─┐        ┌──────────────────────────────────────────────┐
  minifilter, AMSI, ETW, │ HTTPS  │ Agent API  /api/v1/*                          │
  WFP, quarantine,       ├──────► │  enroll · heartbeat · policy-check-in ·       │
  patching, PAM          │        │  telemetry · commands · update-check · bundle │
 Linux agent (Go)       ─┤        ├──────────────────────────────────────────────┤      Fenrir Console
  procfs sensors, hash   │  DoH   │ Detection pipeline                            │ ◄──── (console/)
  blocking, nftables     ├──────► │  normalise → Sigma rules → correlation →      │      MSP staff,
 macOS agent (Swift)    ─┘ /dns/* │  alerts → incidents → playbooks → response    │      SOC analysts,
                                  ├──────────────────────────────────────────────┤      customer admins
                                  │ Policy engine · DNS resolver · Threat intel   │
                                  │ Vulnerabilities · Attack surface · Compliance │ ────► Slack / Teams /
                                  │ CRM · PSA tickets · Billing · Reports · Audit │       webhooks
                                  └───────────────┬──────────────────────────────┘
                                                  │ SQLAlchemy (SQLite or PostgreSQL)
 signaturedb-fenrir (Cloudflare Worker) ──────────┘ hourly feed sync: MalwareBazaar, URLhaus, YARAify
 OSV.dev · CISA KEV ─────────────────────────────── vulnerability data
```

## Tenancy and access

- **Tenants form a tree.** The MSP (root) contains its customers. A customer can contain its own sites.
- **Users belong to one tenant** and see that tenant's whole subtree. Platform admins see everything.
- **Roles map to permissions** (`read`, `respond`, `configure`, `manage_tenants`, `billing`, `crm`, `platform`). See `cloud/fenrir_cloud/security.py`. Customer admins cannot create MSP roles.
- **Every change is written to a hash-chained audit log.** `GET /api/console/audit/verify` detects edits and deletions.

## Policy engine (`policy_schema.py`)

- **One declaration covers 169 settings in 15 modules:** anti-malware, EDR, attack surface reduction, ransomware, web, DNS, firewall, device control, application control, privilege management, patching, tamper protection, automated response, end-user experience and updates. The same declaration produces defaults, validation, the console editor and the agent document.
- **Layers stack** global → tenant → group chain → device. Each layer stores only what it changes.
- **Locks.** Any layer can lock a setting or a whole section, and lower layers cannot override it. Blocked overrides are reported so admins can see why a device behaves as it does.
- **Templates:** balanced, home, strict, lockdown/kiosk, server, developer, audit-only.
- **Agent compatibility.** `to_agent_policy` emits exactly the keys the Windows service's `ParsePolicySnapshot` reads. Newer modules travel under `modules` so older agents ignore them safely.

## Detection pipeline (`detection.py`, `sigma.py`, `normalize.py`)

1. **Normalise.** Telemetry from every agent generation maps onto Sigma/Sysmon field names (`Image`, `CommandLine`, `TargetFilename`, `DestinationIp`, `QueryName` ...).
2. **Detect.** The built-in Sigma engine supports selections, keyword lists, the modifiers `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `windash`, `exists` and `gt/gte/lt/lte`, full boolean conditions, and `1 of` / `all of`. It ships 42 rules in `rules/sigma/`, and tenants can add their own.
3. **Correlate.** Sigma v2 correlation rules (`event_count`, `value_count`, `temporal`) catch behaviour such as mass encryption or brute-force bursts.
4. **Alert.** Hits are de-duplicated per rule and device over 10 minutes.
5. **Group into incidents.** Alerts on a device within 2 hours share an incident. The incident gets a guided playbook (from Sentinel) and upgrades to a more specific one (ransomware, credential theft) as evidence arrives. Closure gates block closing an incident until its checklist is done.
6. **Respond.**
   - Policy-driven: kill the process tree, isolate, roll back ransomware, open a ticket.
   - Per-rule response lists.
   - SOAR automation rules.
   - Webhooks.
7. **Tune.** Marking an alert a false positive with "suppress" creates a tenant-scoped tuned copy of the rule. Other customers are unaffected.
8. **Hunt.** Search stored events with a small query language, or replay any Sigma rule over history (retro-hunt).

## DNS protection (`dnsfilter.py`)

- **Every device gets a private RFC 8484 DoH URL** (`/dns/<token>/dns-query`), so filtering follows laptops off-network.
- **Decision order:** policy allow list → policy block list → threat intel (tenant beats global; an allow indicator wins) → external blocklists → categories → DGA heuristic → SafeSearch rewrite → forward upstream.
- **External blocklists** (`blocklists.py`): HaGeZi TIF (mini on by default, full optional), HaGeZi Multi PRO and OISD big, plus custom HTTPS lists. The hourly maintenance loop refreshes each list on its own period (default 24 h) with ETag revalidation. A failed, empty or oversized download keeps the previous copy, and a list that shrinks by more than half in one refresh is held back. Lists are stored compressed in `dns_blocklists`, never as malware indicators, so they do not reach agent malware bundles. Malware lists block wherever DNS protection is on; other lists only where the policy blocks their category. Set `FENRIR_DNS_BLOCKLISTS=false` to stop refreshes.
- **Blocked lookups** are sinkholed (or NXDOMAIN/REFUSED, per policy) and logged.

## Exposure management (`exposure.py`, `compliance.py`)

- **Vulnerabilities.** Agents report software inventory, which is matched against OSV.dev. CVEs on CISA's KEV catalogue are flagged and prioritised P1.
- **Attack surface.** External scans check common risky ports, banners and TLS. They only run against assets a named user attests the customer owns.
- **Compliance.** Cyber Essentials, CIS v8 IG1, NIST CSF 2.0, Essential Eight and ISO 27001 controls are scored from live policy and fleet evidence. Every result shows its evidence.

## Business suite (`routers/business.py`)

- **CRM:** leads (kanban), contacts and projects. **Convert** turns a won lead into a customer tenant with a default policy, primary contact and contract.
- **PSA:** tickets with contract-based SLAs, time tracking and internal notes. Security incidents open tickets automatically per policy.
- **Billing:** per-device pricing that follows the live device count, plus monthly fees and billable time over an allowance. Invoices are generated monthly.
- **Reports:** an executive report per customer (JSON and printable HTML).

## Data and scale

- **Databases.** SQLite for single-node and dev; PostgreSQL for production. The test suite runs on both.
- **Telemetry** is stored in the `events` table with tenant/time, device/time and time indexes. Everything is kept for `FENRIR_TELEMETRY_RETENTION_DAYS` (90); routine activity (process, image-load, network, DNS, file and registry events at "info") for `FENRIR_ROUTINE_RETENTION_DAYS` (30) unless a detection rule matched it. The hourly purge deletes in batches of 5,000 rows so it never holds one long lock.
- **Per-device cap.** Past `FENRIR_ROUTINE_EVENTS_PER_DEVICE_MINUTE` (600), a device's routine events are still evaluated by every detection rule but stored only if one matches, so a misbehaving agent cannot fill the database. `GET /api/console/platform/telemetry-volume` shows the noisiest devices and event types; the acceptance harness's `telemetry_volume` check holds real agents to a budget.
- **Processes.** `FENRIR_ROLE=web` serves the console and the agent API and holds the agents' live connections; `python -m fenrir_cloud.worker` (`FENRIR_ROLE=worker`) runs the 30-second scheduler (RMM, automations, the event outbox and webhooks, the PSA mailbox), hourly maintenance and vulnerability intel. The default Compose file runs both; `FENRIR_ROLE=all` keeps the single-process mode. PostgreSQL advisory locks give each set of jobs one owner and the outbox claims events with `SKIP LOCKED`, so extra workers are safe. Because agents connect to the web process, it wakes them within two seconds for commands the worker queued.
- **Health.** `/health` (alive), `/ready` (database and schema) and `/health/background` (scheduler and maintenance passes completing, no job running over 30 minutes, outbox not behind). The worker container's healthcheck is `python -m fenrir_cloud.worker --check`.
- **Scaling path:** move `events` to a columnar store (ClickHouse/OpenSearch) behind the same interface, and run detection off a queue. See the roadmap.
