# RMM & PSA intelligence

Five features that make the RMM and PSA work as one: the network map, background self-healing, ticket triage, billing that follows what is actually managed, and documentation that writes itself.

## Network topology discovery (`topology.py`, Network → Topology)

- **What runs.**
  - Linux and macOS agents run `network.discover`, built into the agent (`pkg/fleet/topology.go`). It reads interfaces, the default gateway and the ARP/neighbour table, then optionally does a light TCP connect sweep of the local /24 (16 common service ports: SSH, Telnet, DNS, HTTP/S, SMB/NetBIOS, LPD/IPP/9100 printing, RTSP, RDP, VNC and alternate web ports).
  - Windows agents run an equivalent PowerShell script through `script.run` (`Get-NetNeighbor`, `Get-NetRoute`, a bounded `TcpClient` sweep).
  - Both report the same JSON shape.
- **Ingestion.**
  - Only private addresses are kept.
  - A neighbour is linked to a managed device when its MAC (or failing that its IP) matches the device inventory.
  - Unmanaged nodes are classified by vendor OUI and open ports: gateway, server, workstation, printer, camera, virtual, network, IoT.
  - Engineers can reclassify or ignore a node.
- **Schedule.** Pick probe devices per customer. They re-map the network every *n* hours (24 by default).
- **From the map.**
  - One click turns an unmanaged printer, switch or NAS into a TCP service monitor, checked from a device on the same LAN.
  - The "could take an agent" count shows unmanaged workstations and servers.

## Condition-based remediation packages (`condition_remediation.py`, RMM → Remediation packages)

A package is a detection script and a remediation script.

- **Exit codes.** Detection exits 0 when healthy, 1 when the condition is present, and anything else when it cannot tell.
- **Cycle.** detect → remediate (only if exit 1 and auto-fix is on) → detect again to verify. All of it runs silently through `script.run`.
- **Outcome.** A fix that holds is recorded as `remediated`. One that does not becomes `failed` and, if enabled, opens a ticket with both outputs attached.
- **Built-in templates**, copied per customer when enabled:
  - Print Spooler running
  - Windows Firewall on for all profiles
  - Windows Update service healthy
  - Time sync
  - Low disk cleanup (Windows)
  - Disk space (Linux)
  - NTP (Linux)
- **Custom packages** need both the `configure` and `scripts` permissions.

## AI helpdesk triage (`ai_helpdesk.py`, Service settings → AI triage)

Every ticket opened by a person (email, portal, phone) publishes `ticket.created`, and the triage handler runs on it.

- **Local engine** (default): keyword rules. Nothing leaves Fenrir.
- **Claude engine** (opt-in): sends ticket text to the Claude API with structured JSON output and a strict schema. Before anything is sent:
  - passwords and other secrets, card-like numbers, National Insurance numbers and long tokens are redacted;
  - only knowledge-base titles and remediation package names go as context.
  - Any API failure falls back to local rules.
  - Set `FENRIR_ANTHROPIC_API_KEY` (or `ANTHROPIC_API_KEY`); `FENRIR_AI_TRIAGE_MODEL` overrides the model.
- **Output.** Category, priority, impact, urgency, a possible-security flag, matching KB articles, a matching remediation package and a suggested reply.
  - Model output is checked against known ids; anything unknown is dropped.
  - The result is written as an internal note. The suggested reply is never sent.
- **Modes.**
  - `suggest` only writes the note.
  - `apply` also sets type, impact and urgency, and may *raise* priority (never lower it), re-applying the SLA.

## Billing synchronisation (`billing_sync.py`, Agreements & billing → Reconciliation / Accounting)

- **Auto-counted agreement lines.**
  - `autoCount: "m365:<SKU>"` bills the number of that SKU assigned in the customer's Microsoft 365 tenant.
  - `autoCount: "m365-users"` bills enabled, licensed users.
  - Invoices use the live count.
- **Reconciliation.** Per agreement and period, compares billed against actual for:
  - devices,
  - counted additions,
  - Microsoft 365 SKUs assigned but billed on no line.
  
  It shows the monthly revenue gap.
- **Xero.**
  - OAuth2 (authorization code with a single-use state; refresh tokens rotate and are stored encrypted).
  - Sent invoices are pushed as ACCREC drafts with the same number and lines.
  - Hourly, invoice status is pulled back, so payments recorded in Xero mark invoices Paid in Fenrir.
  - Paid and void invoices are never pushed again.
  - The redirect URI is `<public URL>/api/billing/xero/callback`.

## Documentation sync (`autodoc.py`, Knowledge base → Generated documentation)

- **Pages.** Per customer, Fenrir writes four knowledge-base pages (category "Documentation (auto)") from live data:
  - Environment overview: contacts, platforms, servers, subnets, backup
  - Network: subnets and equipment from topology
  - Microsoft 365: domains, licences, MFA and standards state
  - Devices
- **Refresh.** Daily when turned on, or on demand.
- **Revisions.** A new revision is stored only when the content changed, so the revision history is a change log of the environment.
- **Notes.** Text below `--- Notes (kept when this page refreshes) ---` survives refreshes.
