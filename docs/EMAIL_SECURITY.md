# Email security

Fenrir checks each customer's mail for phishing and malware in two places, and every verdict says why:

| | Where | What it does | Needs |
|---|---|---|---|
| **Shadow mode** | In the Microsoft 365 mailbox, after delivery | Scores new mail and compares with Microsoft's verdict. Changes nothing. | Graph `Mail.Read` |
| **Protect mode** | In the Microsoft 365 mailbox, after delivery | Also quarantines, moves to Junk or tags new mail, within about five minutes | Graph `Mail.ReadWrite` |
| **Mail gateway** | In front of Microsoft 365 (the domain's MX points at Fenrir) | Checks mail **before** it reaches the mailbox; holds threats back | Port 25, an MX change, Exchange admin for the connector |

All three use the same detection engine, allow/block lists, threat intel and learned model, and they share one console
page: **Email security** (switch it on under **Settings → Modules**).

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
   Inbox and Junk Email messages are checked every five minutes. **Scan now** runs one straight away.

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
(phish, malware, spam, safe) on the Messages tab, starting with the disagreements; the Overview then shows how often
each side was right. Labels also train the model (section 5).

## 3. Protect mode

Per customer, choose what happens to each verdict (**Customers** tab):

| Action | What happens |
|---|---|
| **quarantine** (default for malware and phish) | Moved to a hidden "Fenrir Quarantine" folder in the same mailbox. The user cannot see it. |
| **junk** | Moved to Junk Email, where the user can still see it. |
| **tag** (default for suspicious) | The Outlook category "Fenrir: suspicious" is added; nothing moves. |
| **none** | Recorded only. |

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

## 4. Allow and block lists

**Lists** tab: allow or block a sender address or a whole domain, for one customer, or on your own MSP tenant for every
customer. Allow skips Fenrir's checks, **unless** the message fails DMARC or composite authentication, so a forged
sender is never trusted. Block treats the message as malicious. Releasing a message can add its sender to the allow list;
a message's detail has **Block sender** and **Block domain** buttons.

## 5. The learned model

- **Learns from** the checks Fenrir records for each message (never the content), using your labels (counted three
  times) and Microsoft's verdicts (its phish/malware, and confident clean mail, at most ten good per bad). Microsoft's
  own scores are not inputs, so the model works the same at the gateway.
- **Becomes active only** with 200+ examples, 30+ of them phishing or malware, and, on 20% of examples held back from
  training, at least 90% precision and 30% recall. Otherwise it is kept with the reason, and the rules work alone.
- **Can only add** evidence (20–30 points), never lower a score.
- Retrains daily when there is something new; MSP admins can **Train now** on the Model tab. One model serves all
  customers of the installation (features only, no content, cross the customer boundary).

## 6. The mail gateway

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
   and check the message arrives with an `X-Fenrir-Verdict` header and appears on the Messages tab.
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

## 7. Privacy and access

- Message bodies are **never stored** by the mailbox scanner. Fenrir keeps the sender, subject, mailbox, link domains,
  attachment names and hashes, both verdicts and the reasons. The gateway also keeps quarantined originals, encrypted,
  until they are released or purged.
- Scans (and quarantined originals) are deleted after each customer's or domain's retention (default 90 days, 7–730).
- Viewing, labelling and releasing need the *respond* permission; settings and lists need *configure*; the Microsoft
  365 connector needs *m365_admin*; retraining the shared model needs an MSP administrator. Users only see their own
  customers. Every setting change, label, list entry, release and release request is in the audit log.
- You are processing your customers' email: say so in your agreements and data-processing terms.

## 8. Testing checklist

Before relying on it for a customer:

- [ ] Shadow mode on a test tenant: the first scan lists the last 24 hours; Microsoft's verdicts look right.
- [ ] Send a test phish to a test mailbox (a lookalike sender domain and a link whose text shows another site):
      Fenrir flags it with reasons.
- [ ] Protect mode: a fresh test phish is moved to the hidden quarantine folder within five minutes; **Release** brings
      it back to the Inbox.
- [ ] Turn on the digest, check the email arrives, and that "Ask IT to release it" raises a release request.
- [ ] Missing `Mail.ReadWrite` shows "action failed" with the reason.
- [ ] Gateway: `swaks` to an unknown domain is refused with 550; to the customer's domain it is delivered with Fenrir's
      headers; an EICAR attachment (with ClamAV) or an `.exe` is quarantined and can be released.
- [ ] Gateway: stop Microsoft 365 delivery (wrong destination) and check mail stays queued and is delivered once fixed.
- [ ] Lock-down: mail sent straight to `<tenant>.mail.protection.outlook.com` is refused.
