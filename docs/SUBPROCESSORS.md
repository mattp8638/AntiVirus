# Outside services and what is sent to them

For a self-hosted server, these are the services your Fenrir server and agents contact. List the ones you use as
subprocessors in your privacy notice and data processing agreements. Nothing else is sent anywhere: there is no
telemetry back to the Fenrir project.

| Service | Used for | What is sent | Turn off / change |
|---|---|---|---|
| **Your hosting provider** | Runs the server, database and backups | Everything stored (encrypted secrets stay encrypted) | Your choice of host |
| **Microsoft** (Graph, Entra sign-in, Partner Center, Exchange) | Microsoft 365, Intune, email security, Microsoft sign-in | API calls with the customer's tenant credentials; mailbox reads for email security | Only when a customer is connected to Microsoft 365 |
| **Upstream DNS resolver** (Cloudflare `cloudflare-dns.com` by default) | Answering DNS lookups that DNS protection allows | The domain names devices look up (not who asked) | `FENRIR_DNS_UPSTREAM` |
| **CIRCL hashlookup** (`hashlookup.circl.lu`) | File reputation in Windows scans | SHA-256 hashes of scanned files (not the files) | Reputation lookup settings in the policy |
| **abuse.ch** (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar), IPsum, OISD lists on GitHub | Threat intelligence and DNS block lists | Nothing about customers: the lists are downloaded | `FENRIR_INTEL_FEEDS=false`; DNS block lists in DNS protection |
| **NVD, FIRST (EPSS), CISA (KEV), OSV** | Vulnerability intelligence | Product/package names and versions being checked (OSV); nothing for NVD/EPSS/KEV downloads | Vulnerability settings |
| **Have I Been Pwned** | Dark-web and supplier breach checks | Customer email domains being checked | Only when those features are used |
| **Xero** | Accounting sync | Invoices and contacts being synced | Only when Xero is connected |
| **Browser push services** (the browser maker's, e.g. Google, Mozilla, Apple) | Console push notifications | Encrypted notification payloads | Users choose whether to allow notifications |
| **OpenStreetMap tiles** (loaded by the browser) | Device location maps in the console | Map tile requests from the technician's browser | Only when a map is shown |
| **Your email provider** (SMTP/IMAP) | Notifications, digests, email-to-ticket | Notification emails; reading the support mailbox | `FENRIR_SMTP_*`, IMAP settings |
| **Your off-site backup storage** (if set) | Copies of backups | Encrypted backup files only | `FENRIR_BACKUP_RCLONE_REMOTE` |

Customers can ask for everything held about them: **Customers → Export data** produces a zip of JSON files
(secrets left out), recorded in the audit log. **Delete** removes a customer and everything it owns.
