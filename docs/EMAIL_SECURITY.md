# Email security

Fenrir checks each customer's mail for phishing and malware in two places, and every verdict says why:

| | Where | What it does | Needs |
|---|---|---|---|
| **Shadow mode** | In the Microsoft 365 mailbox, after delivery | Scores new mail and compares with Microsoft's verdict. Changes nothing. | Graph `Mail.Read` |
| **Protect mode** | In the Microsoft 365 mailbox, after delivery | Also quarantines, moves to Junk or tags new mail, within about a minutes | Graph `Mail.ReadWrite` |
| **Mail gateway** | In front of Microsoft 365 (the domain's MX points at Fenrir) | Checks mail **before** it reaches the mailbox; holds threats back | Port 25, an MX change, Exchange admin for the connector |

All three use the same detection engine, the same versioned **threat policies and mail flow rules**, allow/block lists,
threat intel and learned model, and they share one console page: **Email security** (switch it on under **Settings →
Modules**). The page is laid out like Microsoft Defender:

| Investigate | Policies & rules | Settings |
|---|---|---|
| Overview, Explorer, Quarantine, Campaigns | Threat policies, Mail flow rules, Allow / block lists | Mailbox scanning, Gateway, Model |

**Setting it up step by step:** [EMAIL_SECURITY_SETUP.md](EMAIL_SECURITY_SETUP.md).

A sensible rollout per customer: shadow mode for one to two weeks while you label what the two sides disagree on, then
protect mode, then (optionally) the gateway.

---

## 1. Connecting a customer

1. **Settings → Modules:** switch on **Email security**.
2. **Permissions.** The customer's Microsoft 365 app connection needs `Mail.Read` (shadow) or `Mail.ReadWrite`
   (protect). New admin sign-in and Fenrir-app connections ask for both. Existing connections: open the customer under
   **Microsoft 365 → Update permissions**, and a customer admin approves. Partner (GDAP) connections cannot read mail
   (Microsoft does not allow it): use an admin sign-in connection for those customers.
   To limit which mailboxes Fenrir can reach, add an Exchange Online *application access policy* for the app.
3. **Email security → Customers:** choose **Shadow** or **Protect**. The first scan looks back 24 hours; then new
   Inbox and Junk Email messages are checked every minute (set `FENRIR_EMAIL_SCAN_SECONDS` to change it). **Scan now** runs one straight away.

## 2. The verdicts

### Microsoft's

Read from the headers Microsoft stamps on delivered mail: spam confidence (SCL), bulk (BCL), the category it gave
(phish, malware, spam, bulk…), and SPF, DKIM, DMARC and composite authentication. Junk Email counts as at least spam.

### Fenrir's

A score from named checks:

| Check | Points |
|---|---|
| Sender or domain on the customer's block list | 100 |
| Attachment hash is known malware (MalwareBazaar or your indicators) | 100 |
| ClamAV found malware (gateway, when configured) | 100 |
| Link to a domain or URL in threat intelligence (URLhaus, ThreatFox, your indicators) | 70 each, up to three |
| Sender domain imitates the customer's own domain (`acrne.co.uk` for `acme.co.uk`) | 50 |
| Attachment is a program or script (`.exe`, `.js`, `.lnk`…) | 45, plus 30 if disguised (`invoice.pdf.exe`) |
| Outside address using a colleague's display name | 40, plus 15 from free mail |
| Sender domain imitates a well-known brand (Microsoft, DocuSign, PayPal, HMRC…) | 40 |
| Disk image attachment (`.iso`, `.img`, `.vhd`) | 40 |
| Claims to be from the customer's own domain but fails authentication | 35 |
| Link to a site imitating a brand or the customer's domain | 35 |
| Web page attachment (`.html`, `.svg`): a common fake sign-in form | 30 |
| Looks like the phishing flagged here before (the learned model, when active) | 20, or 30 when very sure |
| Scam wording (account expiry, changed bank details, gift cards, CEO fraud…) | 10 per phrase, up to 30 |
| DMARC failed · link text shows one site but goes to another · Office file with macros | 25 each |
| Composite authentication failed · link to a bare IP address | 20 each |
| Replies go to a different domain | 10, or 20 for free mail |
| SPF failed with no valid DKIM · display name suggests IT or Microsoft from outside | 15 each |
| Link shortener · first message from this domain (only alongside something else) | 5 each |

**50 or more** is phish (malware when the evidence is an attachment), **25–49** suspicious, below 25 clean.
Microsoft's real domains (`onmicrosoft.com`, `microsoftonline.com`, `docusign.net`…) never count as lookalikes.

### The comparison

Each mailbox message is put in one bucket: both flagged, only Fenrir, only Microsoft, or neither. **Label** messages
(phish, malware, spam, safe) in the Explorer, starting with the disagreements; the Overview then shows how often
each side was right. Labels also train the model (section 5).

## 3. Threat policies and mail flow rules

Fenrir's verdict (score and reasons) is evidence; **the policy decides what happens**. Policies are like Defender's
anti-spam, anti-phishing and anti-malware policies, plus Exchange mail flow rules, in one versioned document.

**Where a policy applies.** Each customer follows the **MSP default** (the policy on your own tenant) until someone saves
a policy for that customer; from then on it has its own. With no policy saved anywhere the built-in **Standard** preset
applies. *Follow the MSP default* puts a customer back. The banner at the top of **Threat policies** always says which
policy is in force and its version.

**Sections**

| Section | Settings |
|---|---|
| Anti-spam | Score thresholds for suspicious, phishing and high-confidence phishing; Microsoft bulk level (BCL); action per class (bulk, spam, suspicious, phish, high-confidence phish); subject prefix for tagged mail |
| Anti-phishing | Protect everyone in the directory from display-name impersonation; extra protected names and partner domains; lookalike sensitivity; honour the sender's DMARC policy; first-contact tag; actions for impersonation and spoofing |
| Anti-malware | Blocked file types (editable; defaults include exe, js, iso, lnk and the usual others); look inside zip archives; password-protected archives; Office macros; zero-hour re-check; malware action |
| Connection filter | IP allow and block lists (single addresses or ranges). At the gateway a blocked IP is refused at RCPT with *550 5.7.1* |
| Quarantine & content | Which classes users may ask for back from their digest; whether bodies are kept (none / flagged / all) |

**Actions:** deliver, tag (subject prefix at the gateway, Outlook category in mailboxes), move to Junk, quarantine,
reject (refused at the gateway; quarantined in mailboxes, which can't refuse mail already delivered). When more than one
step applies, the stronger action wins.

**Presets:** *Standard* and *Strict* (lower thresholds, more types blocked, junk becomes quarantine). Applying a preset
keeps your mail flow rules.

**Mail flow rules** run before the policies, in order. Each has:

- **Conditions** (all or any): sender, sender domain, recipient, subject, body, header (`X-Name: value`), attachment
  name, extension or hash, link domain, originating IP or range, country, SPF/DKIM/DMARC result, Fenrir score or
  verdict, Microsoft verdict, message size, external sender, first contact and more. Operators include is, contains,
  starts/ends with, matches pattern (safe patterns only; back-references and nested repeats are refused), is any of,
  greater/less than, in IP range.
- **Exceptions** (any).
- **Actions**: quarantine, reject, junk, deliver, bypass spam and phishing checks (never malware), tag, add a header,
  add an Outlook category, change the score, notify someone by email.
- **Stop processing more rules**, on/off, and **audit mode**: the rule only records what it would have done (shown on
  each message's Decision tab), so a new rule can be tried on real mail first.

**Order of evaluation** (each step is shown on the message's Decision tab): connection filter → mail flow rules →
allow/block lists → anti-malware → anti-phishing → anti-spam.

**Versioning.** Every save creates a new version with who, when and a comment; nothing is overwritten. **History**
lists the versions and shows exactly what changed (setting by setting, rule by rule), and **Restore** makes an older
version current again as a new version. Every save is in the audit log.

**Test before saving.** **Threat policies → Test** runs any message Fenrir has already checked through the draft
(unsaved changes included) and shows the decision next to what actually happened. Nothing is changed.

In **shadow mode** the decision is recorded but not carried out, so you can watch a policy for weeks before protect mode.

## 4. Investigating

- **Explorer** searches every checked message: free text, date range, verdict, status, and under *More filters* sender,
  sender domain, recipient, subject, Message-ID, originating IP, country, attachment name or SHA-256, link, the rule or
  policy that decided, classification, action, source (mailbox or gateway), Microsoft's verdict, agreement, label and
  minimum score. Select messages for bulk **release, label, block senders/domains, allow senders or delete**, and
  **Export CSV** (cells are escaped so a hostile subject can't become a spreadsheet formula).
- **Quarantine** is the same view fixed to held mail, with release requests and bulk release/delete.
- **Campaigns** groups messages by sender domain and subject (numbers ignored), with recipients, verdicts and what was
  done. **Remove from mailboxes** previews how many messages in how many mailboxes, then moves them all to Fenrir's
  quarantine or deletes them for good (Microsoft 365 mailboxes; needs Mail.ReadWrite).
- **The message view** has: **Summary** (verdicts, origin, key authentication); **Decision** (the action, the
  classification, the step-by-step trail, which policy version and rule decided, audit-mode rules that matched, and
  every check with its points); **Body** (see below); **Origin & path** (originating IP, reverse DNS, network owner and
  AS number, country, every Received hop in UTC with delays, all addresses with mismatch warnings); **Headers** (all,
  filterable, copyable); **Authentication** (SPF, DKIM, DMARC with the published record, composite authentication,
  ARC); **Links & attachments** (every link with what it is shown as and why it is flagged; attachments with type,
  size, SHA-256 and zip members); **Delivery** (gateway: where it was handed, Microsoft's reply, attempts, errors).
  **Download original (.eml)** for deeper analysis.
- **The body viewer** shows the message made safe: no scripts, styles or forms, images replaced by a placeholder naming
  their host, and links shown as text with their real destination next to them (suspicious hosts in red), inside a
  sandboxed frame that can run nothing. Wording often used in phishing is highlighted and listed. Opening it cannot
  alert the sender. It uses Fenrir's encrypted copy when one was kept, else the gateway quarantine, else reads the
  mailbox there and then. Every view is audited.

## 5. Protect mode

Protect mode carries out the policy's decision (section 3). In a mailbox the actions are:

| Action | What happens |
|---|---|
| **quarantine** (default for malware and phish) | Moved to a hidden "Fenrir Quarantine" folder in the same mailbox. The user cannot see it. |
| **junk** | Moved to Junk Email, where the user can still see it. |
| **tag** (default for suspicious) | The Outlook category "Fenrir: suspicious" is added; nothing moves. |
| **deliver** | Recorded only. |

- Only mail received **after** protect mode is switched on is ever touched.
- **The brake:** if one scan would quarantine or junk more than 40 messages for one customer, Fenrir stops acting
  for that customer, keeps scanning, raises a high alert and waits for someone to press **Resume**.
- **Release** from the message's detail (back to the Inbox), optionally allowing the sender from then on.
- **Alerts:** one alert per scan that moved mail, listing what and why. Per customer you can also email a contact and
  open a ticket.
- **Daily digest** (optional): each user is emailed a list of what was held back for them, each with an
  "ask for it back" link. The link opens a page with a button, so link scanners (Safe Links and the like) cannot
  request releases. A request raises a low alert; a technician decides.
- **Zero-hour re-check:** messages from the last 48 hours are re-scored when new threat intel names one of their
  attachment hashes or link domains, and acted on (like Microsoft's zero-hour auto purge).

## 6. Allow and block lists

**Allow / block lists**: allow or block a **sender address, sender domain, IP address or range, URL or link domain, file
SHA-256 or subject text**, for one customer, or on your own MSP tenant for every customer, optionally until an expiry
date. Each entry counts its **hits** and when it last matched, so stale entries are easy to find. Allow skips spam and
phishing checks (never malware checks), **unless** the message fails DMARC or composite authentication, so a forged
sender is never trusted. Block quarantines (a blocked IP at the gateway is refused). Releasing a message can add its
sender to the allow list; the message view and the Explorer's bulk bar have block and allow buttons.

## 7. The learned model

- **Learns from** the checks Fenrir records for each message (never the content), using your labels (counted three
  times) and Microsoft's verdicts (its phish/malware, and confident clean mail, at most ten good per bad). Microsoft's
  own scores are not inputs, so the model works the same at the gateway.
- **Becomes active only** with 200+ examples, 30+ of them phishing or malware, and, on 20% of examples held back from
  training, at least 90% precision and 30% recall. Otherwise it is kept with the reason, and the rules work alone.
- **Can only add** evidence (20–30 points), never lower a score.
- Retrains daily when there is something new; MSP admins can **Train now** on the Model tab. One model serves all
  customers of the installation (features only, no content, cross the customer boundary).

## 8. The mail gateway

The gateway receives mail for a customer's domain, checks it, and passes clean mail to the customer's Microsoft 365.
Threats are held back before they reach anyone.

### What it does

- Accepts mail only for domains added under **Email security → Gateway** ("550 relaying denied" for anything else:
  it can never be an open relay). Refuses senders whose IP is in threat intel, rate limits each IP, and can refuse
  recipients that do not exist in the tenant.
- Writes each message to a disk queue before saying "250 queued", so nothing is lost on restart. Delivery is retried
  with back-off for up to three days, then raises an alert. It never sends bounces (no backscatter).
- Checks SPF, DKIM and DMARC itself, runs the same engine as protect mode, and, if configured, ClamAV.
- Per domain: **quarantine** (the original is kept encrypted with the vault key until released or purged), **tag**
  (`X-Fenrir-Verdict` header, optionally `[Suspicious]` in the subject), or **deliver**. Delivered mail carries
  `X-Fenrir-Verdict`, `X-Fenrir-Scan-Id` and `Authentication-Results`, and goes to Microsoft 365 over TLS.
- Microsoft verdict headers that a sender adds themselves are ignored.

### Setting it up

1. **A host name and port 25.** Create an A record (for example `mx.yourmsp.co.uk`) pointing at the server, and a
   matching reverse DNS (PTR) record with your hosting provider. Make sure inbound **TCP 25** is open; many VPS
   providers block port 25 until you ask.
2. **Settings** in `deploy/.env`:
   ```
   FENRIR_GATEWAY_HOSTNAME=mx.yourmsp.co.uk
   FENRIR_GATEWAY_PUBLIC_IPS=203.0.113.10
   # optional: your certificate (otherwise a self-signed one is used for STARTTLS)
   FENRIR_GATEWAY_TLS_CERT=/certs/fullchain.pem
   FENRIR_GATEWAY_TLS_KEY=/certs/privkey.pem
   # optional: ClamAV (start with --profile clamav)
   FENRIR_CLAMD_HOST=clamav
   ```
3. **Start it:**
   ```
   docker compose -f docker-compose.yml -f docker-compose.mailgateway.yml up -d
   # with ClamAV:
   docker compose -f docker-compose.yml -f docker-compose.mailgateway.yml --profile clamav up -d
   ```
   The Gateway tab shows it as **running**.
4. **Add the customer's domain** on the Gateway tab. It must be a verified domain in that customer's Microsoft 365.
   Fenrir fills in where clean mail goes from the domain's current Microsoft MX record; check it before going further.
5. **Create the Microsoft 365 connector:** **Create connector** (needs Exchange admin access on the customer's
   connection). This makes a partner inbound connector from the gateway's IPs, requires TLS, and turns on *Enhanced
   Filtering* so Microsoft sees the real sender's IP rather than the gateway's.
6. **Test** by sending to the domain through the gateway directly (`swaks --server mx.yourmsp.co.uk --to user@domain`),
   and check the message arrives with an `X-Fenrir-Verdict` header and appears in the Explorer.
7. **Change the MX record** to `10 mx.yourmsp.co.uk` (keep a low TTL for the first days).
8. **Lock down** once mail is flowing: **Create and lock down**. Microsoft 365 then refuses internet mail for this
   tenant that did not come through the gateway, so attackers cannot bypass it by sending straight to Microsoft.

To stop using the gateway: point the MX record back at Microsoft 365, wait for the TTL, re-create the connector
without lock-down (or delete it in Exchange admin), then remove the domain.

### Running more than one gateway

For resilience, run the gateway on two servers sharing the same database and publish two MX records. Each keeps its
own queue.

### Not done (yet)

Outbound filtering (Microsoft 365 still sends outbound mail itself), attachment sandboxing, click-time link checks,
ARC sealing (adding `[Suspicious]` to subjects can break the sender's DKIM; leave it off unless you need it).

---

## 9. Privacy and access

- For every message Fenrir keeps the sender, subject, recipients, headers, path, links, attachment names and hashes, both
  verdicts, the reasons and the decision. **Bodies** are kept only as the policy's *keep message content* says (default:
  flagged mail only), **encrypted** with the vault key; the gateway also keeps quarantined originals, encrypted, until
  released or purged. The learned model never sees content.
- Scans (and quarantined originals) are deleted after each customer's or domain's retention (default 90 days, 7–730).
- Viewing, labelling and releasing need the *respond* permission; policies, rules, lists, bulk delete and campaign
  removal need *configure*; the Microsoft
  365 connector needs *m365_admin*; retraining the shared model needs an MSP administrator. Users only see their own
  customers. Every policy version, setting change, label, list entry, release, release request, body view, download,
  bulk action and campaign removal is in the audit log.
- You are processing your customers' email: say so in your agreements and data-processing terms.

## 10. Testing checklist

Before relying on it for a customer:

- [ ] Shadow mode on a test tenant: the first scan lists the last 24 hours; Microsoft's verdicts look right.
- [ ] Send a test phish to a test mailbox (a lookalike sender domain and a link whose text shows another site):
      Fenrir flags it with reasons.
- [ ] Protect mode: a fresh test phish is moved to the hidden quarantine folder within a minute or two; **Release** brings
      it back to the Inbox.
- [ ] Turn on the digest, check the email arrives, and that "Ask IT to release it" raises a release request.
- [ ] Missing `Mail.ReadWrite` shows "action failed" with the reason.
- [ ] Gateway: `swaks` to an unknown domain is refused with 550; to the customer's domain it is delivered with Fenrir's
      headers; an EICAR attachment (with ClamAV) or an `.exe` is quarantined and can be released.
- [ ] Gateway: stop Microsoft 365 delivery (wrong destination) and check mail stays queued and is delivered once fixed.
- [ ] Lock-down: mail sent straight to `<tenant>.mail.protection.outlook.com` is refused.
- [ ] Policies: add a mail flow rule in **audit mode** (subject contains "fenrir test"), send a matching message, and see
      the rule listed on its Decision tab with nothing done; switch it to enforce and see it act. Check **History** shows
      both versions and **Restore** works.
- [ ] **Threat policies → Test** with a message ID gives the expected decision.
- [ ] The Body tab of a flagged message shows highlighted wording, links as text and no images.
- [ ] Explorer: filter by sender domain, select, **Export CSV**; **Campaigns → Remove from mailboxes** preview counts match.
