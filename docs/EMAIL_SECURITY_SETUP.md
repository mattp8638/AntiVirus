# Email security: setup guide

A step-by-step guide to switching on Fenrir's email security on a live Fenrir server, from deploying the update to
routing a customer's mail through the gateway. For what each feature does and how verdicts are scored, see
[EMAIL_SECURITY.md](EMAIL_SECURITY.md).

The commands assume the server install at `~/AntiVirus` with HTTPS through Caddy, and this helper from the main README,
defined in each new shell:

```bash
cd ~/AntiVirus
dc() {
  sudo env COMPOSE_BAKE=false docker compose \
    -f deploy/docker-compose.yml \
    -f deploy/docker-compose.https.yml \
    --env-file deploy/.env "$@"
}
```

**Recommended order, per customer:** shadow mode (1–2 weeks, labelling disagreements) → protect mode → gateway
(optional). Parts A and B are done once for the whole server.

| Part | What | Time |
|---|---|---|
| A | Deploy the update | 20 min |
| B | Switch on the module, mail sending and Microsoft 365 permissions | 15 min |
| C | Shadow mode for a customer | 10 min, then 1–2 weeks of labelling |
| D | Protect mode | 15 min |
| E | Allow and block lists | 5 min |
| F | The learned model | nothing to do; check it weekly |
| G | The mail gateway | 1–2 hours, plus DNS waiting time |
| H | Day-to-day running | |
| I | Troubleshooting | |
| J | Moving customers off Heimdal | |

---

## A. Deploy the update

### A1. Back up first

```bash
cd ~/AntiVirus
sudo deploy/backup.sh          # or your usual backup routine
```

### A2. Get the code

The email security work is on the branch `claude/jolly-goodall-5kpl2t` until it is merged into `main`. Merge it
(through a pull request on GitHub), then on the server:

```bash
git status --short             # must be empty: no local edits to tracked files
git pull --ff-only origin main
```

### A3. Add the new settings to `deploy/.env`

Open `deploy/.env` (`sudo nano deploy/.env`) and add:

```bash
# Keep your existing signature feed (the default changed to "off" in this update)
FENRIR_FEED_URL=https://feed.example.com
FENRIR_FEED_SYNC=true

# Email security mail gateway (leave empty until Part G)
FENRIR_GATEWAY_HOSTNAME=
FENRIR_GATEWAY_PUBLIC_IPS=
```

The first two lines matter even if you never use email security: without them, the server stops pulling your hosted
signature feed.

### A4. Rebuild and restart

```bash
dc build cloud
dc up -d
dc logs --tail=50 cloud
```

The log should show the database moving up to migration **68**. Then refresh the console with **Ctrl+F5**.

**Check:** `dc ps` shows `cloud` and `worker` healthy.

---

## B. One-off settings

### B1. Switch on the module

**Settings → Modules →** tick **Email security → Save.** It appears in the menu under *Identity, cloud & network*.

### B2. Let Fenrir send email (for alerts and user digests)

If `FENRIR_SMTP_HOST` is already set in `deploy/.env` (the service desk uses it), skip this. Otherwise add an SMTP
account that may send as your support address, for example Microsoft 365 with SMTP AUTH, or any relay:

```bash
FENRIR_SMTP_HOST=smtp.office365.com
FENRIR_SMTP_PORT=587
FENRIR_SMTP_USER=alerts@yourmsp.co.uk
FENRIR_SMTP_PASSWORD=...
FENRIR_SMTP_FROM=alerts@yourmsp.co.uk
```

then `dc up -d`. Without it, alerts still appear in Fenrir, but no emails or digests are sent.

### B3. Microsoft 365 permissions

Fenrir needs to read mail (`Mail.Read`, for shadow mode) and change it (`Mail.ReadWrite`, for protect mode). How you
grant them depends on how each customer is connected; the customer's connection page under **Microsoft 365** shows
which.

**Customers connected with the Fenrir app** (`FENRIR_M365_CLIENT_ID` in `.env`, *platform* mode):

1. In **your own** Entra admin centre: **App registrations →** the Fenrir app **→ API permissions → Add a permission
   → Microsoft Graph → Application permissions →** tick **Mail.Read** and **Mail.ReadWrite → Add permissions.**
2. In Fenrir, for each customer: **Microsoft 365 →** the customer **→ Permissions → Update permissions.** Fenrir
   gives you the consent link; a customer Global Administrator signs in and accepts.

**Customers connected by admin sign-in** (*provisioned* mode): **Microsoft 365 →** the customer **→ Permissions →
Update permissions,** and a customer admin approves. Fenrir adds the permissions to the app in their tenant.

**Customers connected by hand** (*app* mode, an app registration you typed in): add **Mail.Read** and
**Mail.ReadWrite** (Application) to that app registration in the customer's tenant and grant admin consent.

**Partner (GDAP) connections cannot read mail.** Microsoft doesn't allow it. For those customers, add a second
connection by admin sign-in.

**Check:** on the customer's connection page, **Check permissions** lists *Email security: scan mail* and *Email
security: quarantine and tag mail* as available. The Email security → Mailbox scanning page shows Mail.Read and Mail.ReadWrite
as **granted**.

> Optional: to limit which mailboxes the app can reach, a customer admin can add an Exchange Online *application access
> policy* (`New-ApplicationAccessPolicy`) scoped to a mail-enabled security group. Unscoped is simpler and is what
> Heimdal-style products use.

---

## C. Shadow mode (compare only)

Shadow mode reads new mail every minute and records Fenrir's and Microsoft's verdicts. **Nothing in any mailbox
changes.**

1. **Email security → Mailbox scanning →** the customer **→** set the mode to **Shadow (compare only).**
2. Press **Scan now.** The first scan looks back 24 hours. Under *Last scan* you should see a count of new messages
   and no red error.
3. **Overview** shows messages checked, how many each side flagged, and the agreement.
4. **Explorer** lists what Fenrir flagged; open one to see every reason, with Microsoft's verdict beside it.

### The labelling routine (1–2 weeks)

Every day or two, in the **Explorer**:

1. Under *More filters*, set the agreement to **Only Fenrir**. Open each message and label it **phish**, **malware**, **spam** or
   **safe**. Safe ones are false positives: if a sender keeps appearing, allow it (Part E).
2. Set it to **Only Microsoft** and label those too. These are what Fenrir misses.
3. Glance at **Both flagged**; label a few.

The Overview's **Who is right** box then shows, on your labels, how often each side was right. When Fenrir is right on
the messages it flags and its false positives are rare and allow-listed, the customer is ready for protect mode.

**Send yourself a test phish** to check detection end to end. From an outside account (Gmail, for example) to a
mailbox at the customer:

- Subject: `Verify your account within 24 hours`
- Body: a link whose **text** is `https://www.microsoft.com` but whose **address** is `http://192.0.2.1/login`

Within a minute or two it should show as **phish**, with reasons such as *A link shows microsoft.com but goes to
192.0.2.1*, *Links to a bare IP address* and *Wording typical of scams*.

---

## D. Protect mode (act on threats)

1. Confirm **Mail.ReadWrite** shows as granted (B3).
2. **Mailbox scanning →** the customer **→ Protect (act).** Only mail that arrives from now on is ever touched.
3. **Decide what happens** under **Threat policies** (Part D1). Shadow mode has already been recording what the policy
   would do, so look at the Explorer's **Done** column and a few Decision tabs before switching.
4. **Notifications:**
   - **Daily digest to users:** each user gets a daily list of what was held back, with an "ask for it back" link
     (needs B2).
   - **Alert email:** a person or shared mailbox told every time mail is quarantined.
   - **Open a ticket:** a service desk ticket per quarantine run.
   Press **Save** after changing them.

**Test it:** send the test phish from Part C again. Within a minute or two it disappears from the Inbox, the Explorer
shows **Quarantined**, and an alert appears under **Alerts**. Open the message and press **Release to Inbox**: it comes
back.

### D1. Threat policies and mail flow rules

**Email security → Threat policies.** Choose *My MSP (MSP default for every customer)* to set the policy every customer
follows, or a customer to give that customer its own.

1. Start from a preset: **Apply Standard preset** (balanced) or **Apply Strict preset** (catches more, more to review).
2. Adjust the sections (anti-spam thresholds and actions, anti-phishing protected names and partner domains, blocked
   file types, IP allow/block, what users may ask back, whether bodies are kept).
3. Type what changed and why, then **Save as new version**. Every save is kept: **History** shows what changed in each
   version and can **Restore** an older one.
4. **Test** runs a message Fenrir already checked through your draft before you save (copy its ID from the message's
   Decision tab).

**Mail flow rules** (same page, or **Mail flow rules** in the menu): **Add a rule**, give it conditions ("Subject
contains invoice" and "Sender is external"), exceptions, and actions ("Add header", "Quarantine", "Notify"). New rules:
tick **Audit only** first, save, watch the Decision tab of matching mail for a few days, then untick it. Use the arrows to
order rules and *Stop processing more rules* where one should win.

Examples:

| Goal | Conditions | Actions |
|---|---|---|
| Hold invoices with macros from outside | Attachment extension is any of `docm, xlsm` and external sender is true | Quarantine |
| Warn on first contact | First contact is true | Tag `[New sender]` |
| Trust a supplier's portal that fails DMARC | Sender domain is `portal.supplier.co.uk` and originating IP in range `81.2.69.0/24` | Bypass spam and phishing checks |
| Copy finance on payment-change requests | Body contains `bank details` and recipient ends with `@acme.co.uk` | Notify `finance-lead@acme.co.uk`, Add category `Payment change` |

### When protect mode pauses itself

If one scan would move more than 40 messages for a customer, Fenrir stops acting for that customer, keeps scanning,
and raises a high alert: **Email protection paused itself.** This protects against a bad rule or bad intel emptying
inboxes. Look at the Explorer; if the messages really are a phishing campaign, press **Resume** on the Customers
tab. Mail from before the resume is not touched retrospectively.

### Release requests from users

When a user presses **Ask IT to release it** in their digest, a low alert appears, and the message shows **release
requested** on the Overview and **Quarantine**. Open it, read the **Body** and **Decision** tabs, decide, and press
**Release to Inbox** (or select several and release them together). Tick *and allow this
sender* if it was legitimate mail from a sender who will keep sending.

---

## E. Allow and block lists

**Email security → Allow / block lists.**

- Match on a **sender address, sender domain, IP or range, URL or link domain, file SHA-256 or subject text**.
- **Allow** a supplier who keeps getting flagged. Allow is ignored if a message fails DMARC, so attackers can't exploit
  it by forging the address, and it never skips malware checks.
- **Block**: their mail is quarantined (a blocked IP is refused at the gateway).
- Set **Expires** for temporary entries (a supplier's one-off campaign); expired entries stay listed, greyed, until removed.
- **Hits** and *last* show which entries are still doing anything.
- An entry on **your own MSP tenant** applies to every customer.
- From a message: **Block sender** / **Block <domain>**, *and allow this sender* when releasing, or select several in the
  Explorer and use the bulk bar.

---

## E2. Investigating a message (the technician's routine)

1. **Explorer** (or **Quarantine**): filter, open the message.
2. **Decision**: why this happened, which policy version or rule, and every check with its points.
3. **Body**: what the user saw, made safe. Highlighted wording and red link destinations are the indicators.
4. **Origin & path** and **Authentication**: where it really came from (IP, network, country, hops) and whether
   SPF/DKIM/DMARC passed for the domain shown.
5. **Links & attachments**: real destinations and hashes; search a hash or domain in the Explorer to see who else got it.
6. Act: release, label, block or allow, or **Campaigns → Remove from mailboxes** if it went to many people.
7. If a rule or threshold was wrong: change the policy, **Test** it on this message, save with a comment.

---

## F. The learned model

Nothing to set up. Fenrir trains a model daily from your labels and Microsoft's verdicts.

- **Email security → Model** shows whether a model is in use, how accurate it was on messages held back from training,
  and what it needs to switch on (by default 200 examples, 30 of them phishing, 90% precision, 30% recall).
- Until then it shows *Not enough examples yet* or *Not accurate enough*, and the rules work alone. Labelling (Part C)
  is what gets it there.
- Once in use, it can only **add** to a message's score, and every verdict names it.
- MSP admins can press **Train now** after a labelling session.

---

## G. The mail gateway (optional)

The gateway receives mail for a customer's domain **before** Microsoft 365, checks it, holds threats back and passes
clean mail on. It needs port 25 and a change to the customer's MX record. Do it after the customer has run happily in
shadow or protect mode.

### G1. Before you start

- [ ] **Port 25 inbound** reaches the server. Many hosting providers block it until you ask; check your provider's
      control panel or ask support. Nothing else on the server may use port 25: `sudo ss -ltnp | grep ':25 '` should
      print nothing.
- [ ] **A host name for the gateway**, for example `mx.example.com`, with an **A record** pointing at the
      server's public IP.
- [ ] **Reverse DNS (PTR)** for the server's IP set to that same name, in your hosting provider's control panel.
      Senders' servers check it.
- [ ] Optional: a firewall rule allowing TCP 25 in (`sudo ufw allow 25/tcp` if you use ufw).

Check from your PC:

```bash
nslookup mx.example.com          # -> the server's IP
nslookup <server IP>                       # -> mx.example.com
```

### G2. Settings

In `deploy/.env`:

```bash
FENRIR_GATEWAY_HOSTNAME=mx.example.com
FENRIR_GATEWAY_PUBLIC_IPS=<the server's public IP>
# Optional virus scanning with ClamAV (uses about 1.5 GB of memory)
FENRIR_CLAMD_HOST=clamav
```

STARTTLS works out of the box with a certificate the gateway makes for itself. Servers sending mail to you accept that.
To use your own certificate instead, set `FENRIR_GATEWAY_TLS_CERT` and `FENRIR_GATEWAY_TLS_KEY` to files mounted into
the container.

### G3. Start it

```bash
dc -f deploy/docker-compose.mailgateway.yml up -d                     # without ClamAV
dc -f deploy/docker-compose.mailgateway.yml --profile clamav up -d    # with ClamAV
dc up -d cloud worker        # so the console knows the gateway's name and IPs
dc -f deploy/docker-compose.mailgateway.yml logs --tail=30 mailgateway
```

The log shows `mail gateway listening on port 2525 as mx.example.com` (port 25 outside the container maps to
2525 inside). **Email security → Gateway** shows **running** within a minute.

Remember to include `-f deploy/docker-compose.mailgateway.yml` in future `dc up -d` and `dc pull` commands, or the
gateway is left on the old version. A shortcut:

```bash
dcm() { dc -f deploy/docker-compose.mailgateway.yml "$@"; }
```

**Check from outside** (any machine with `swaks`: `sudo apt install swaks`):

```bash
swaks --server mx.example.com --to someone@gmail.com --from test@example.com
# expect: 550 5.7.1 Relaying denied   (the gateway refuses domains it doesn't serve)
```

### G4. Add the customer's domain

**Gateway → Add a domain →** choose the customer, enter the domain (for example `acme.co.uk`), **Add domain.**

- The domain must be verified in the customer's Microsoft 365, and the Microsoft 365 connection must have synced.
- Fenrir fills in where clean mail goes by reading the domain's current Microsoft MX record (for example
  `acme-co-uk.mail.protection.outlook.com`). **Check it matches** what the domain's MX record shows today.
- The defaults are malware and phish quarantined, suspicious tagged, TLS to Microsoft 365 required. Leave
  *Refuse unknown recipients* off until mail is flowing, then turn it on to drop mail to non-existent addresses at the
  door.

### G5. Create the Microsoft 365 connector

Press **Create connector** on the domain. This needs Exchange admin access on the customer's connection. If it fails
with an access message, follow it: for app connections, add the *Office 365 Exchange Online* permission
**Exchange.ManageAsApp** and give the app the **Exchange Administrator** role.

The connector tells Microsoft 365 to accept mail from the gateway, require TLS, and use *Enhanced Filtering*, so
Microsoft still sees the original sender's IP and its own protection keeps working.

**Doing it by hand instead** (Exchange admin centre → Mail flow → Connectors → Add a connector): from *Partner
organisation* to *Office 365*; identify by the gateway's IP; reject unless TLS. Then under **Security → Threat policies →
Enhanced Filtering**, enable it for that connector with *Automatically detect and skip the last IP address*.

### G6. Test before changing DNS

Send through the gateway directly, while the MX still points at Microsoft:

```bash
swaks --server mx.example.com --to jo@acme.co.uk --from test@example.com \
      --header "Subject: Gateway test"
# expect: 250 2.0.0 Queued as ...
```

- The message arrives in Jo's mailbox. In Outlook, *View message source* shows `X-Fenrir-Verdict: clean` and
  `X-Fenrir-Scan-Id`.
- **Explorer** shows it with *through the gateway* and **Delivered**.

Test a threat:

```bash
printf 'MZ test' > /tmp/invoice.pdf.exe
swaks --server mx.example.com --to jo@acme.co.uk --from test@example.com \
      --header "Subject: Invoice" --attach /tmp/invoice.pdf.exe
```

It should **not** arrive. **Explorer** shows it **Quarantined** (malware: *a program pretending to be a .pdf*). Press
**Release to Inbox** to check release works; it then arrives with `X-Fenrir-Released-By`.

With ClamAV: test with the EICAR test file (`https://www.eicar.org/download-anti-malware-testfile/`) attached. The
reason reads *ClamAV found Eicar…*.

### G7. Switch the MX record

At the customer's DNS host:

1. Lower the TTL of the current MX record to 300 seconds a day beforehand if you can.
2. Replace the MX record with: **`acme.co.uk  MX  10  mx.example.com`**.
3. Leave the SPF record alone. Outbound mail still goes straight from Microsoft 365.

Over the next hour, the Gateway tab shows *last message* updating and the Explorer fills with gateway mail.

### G8. Lock down (after a day of normal mail)

Press **Create and lock down**. Microsoft 365 then refuses internet mail for the tenant that didn't come through the
gateway, so attackers can't bypass it by sending straight to `acme-co-uk.mail.protection.outlook.com`.

**Check:** sending straight to Microsoft is now refused:

```bash
swaks --server acme-co-uk.mail.protection.outlook.com --to jo@acme.co.uk --from test@example.com
# expect a 5.7.x rejection
```

### G9. Going back (if ever needed)

1. Point the MX record back at the Microsoft host (the domain's *destination* on the Gateway tab).
2. Wait for the old TTL to pass.
3. Press **Create connector** (without lock-down), or delete the "Fenrir mail gateway" connector in the Exchange admin
   centre.
4. Remove the domain on the Gateway tab.

### Resilience

One gateway is a single point of failure. While it is down, sending servers queue mail and retry, usually for up to
five days, so short outages lose nothing. For production, run a second gateway on another server sharing the same
database, and publish two MX records with the same priority.

---

## H. Day-to-day running

- **Alerts** (the main Alerts page): *Email security quarantined N messages*, *Release requested*, *Email protection
  paused itself*, *Gateway could not deliver mail*. Treat them like any other alert.
- **Email security → Overview**, weekly: release requests waiting, actions that failed, the two "only one side
  flagged" counts.
- **Labels:** a few minutes a week on disagreements keeps the model improving.
- **Logs:** `dc logs --tail=100 worker` (mailbox scanning), `dcm logs --tail=100 mailgateway` (gateway).
- **Gateway queue:** `dcm exec mailgateway ls /data/mail-spool | grep -c json` shows messages waiting. A growing number means
  Microsoft 365 is refusing or deferring delivery; the reason is on each message's detail.
- **Settings → Platform** shows the background jobs `email.shadow-scan` and `email.gateway`, their last run and any
  error.
- **Retention:** scans and quarantined originals are kept 90 days by default (per customer or domain, 7–730).

---

## I. Troubleshooting

| You see | Cause and fix |
|---|---|
| Mailbox scanning: *Fenrir does not have permission to read mail (Mail.Read)* | B3: add the permission and have a customer admin approve **Update permissions**. |
| A message shows **action failed**: *…permission to change mail (Mail.ReadWrite)…* | Same, for Mail.ReadWrite. The message stays where it was. |
| *No licensed mailboxes found yet* | The Microsoft 365 connection hasn't synced. Microsoft 365 → the customer → **Sync**. |
| *Microsoft is throttling mail reads* | Very busy tenant; it carries on next run. Normal at first scan of large tenants. |
| *Reading mail needs an app connection* | The customer is connected through GDAP only. Add an admin sign-in connection. |
| *Fenrir could not read this connection's stored credentials* | The vault key changed or the secret is damaged. Reconnect the customer. |
| No user digests arrive | B2 not set up, or *Daily digest* not ticked. Digests go once a day, only when something was quarantined. |
| Gateway tab: **never started** / **not running** | `dcm ps` and `dcm logs mailgateway`. Usually `FENRIR_GATEWAY_HOSTNAME` is missing or port 25 is taken. |
| Outside servers can't connect to the gateway | Port 25 blocked by the provider or firewall. Test with `swaks --server mx… --quit-after RCPT` from outside. |
| Add a domain: *not a verified domain in this customer's Microsoft 365* | Verify the domain in Microsoft 365, then **Sync** the connection. |
| Gateway messages stay **queued** | Microsoft 365 refuses or defers them. Check the destination host, and that the connector exists and allows the gateway IP. The reason is on the message. |
| *Gateway could not deliver mail* alert | Microsoft 365 refused it permanently, or it failed for 3 days. Fix the destination or connector, then ask the sender to resend. |
| Gateway message shows **action failed** with *550 5.4.1 Recipient address rejected: Access denied* | Microsoft 365 says the recipient doesn't exist in the tenant at the destination host. Check the address is a real mailbox or alias in that tenant, and that the domain's destination (Gateway tab) is that tenant's Microsoft host. Fenrir keeps the message: fix the cause, then press **Retry delivery**. |
| Gateway messages have no evidence on their tabs, or errors without Microsoft's reason | The gateway container is still on an older build. Run updates with the mailgateway file included (`dcm up -d --build`), not plain `dc up`. |
| Legitimate mail quarantined | Read its **Decision** tab to see what decided. Release it with *and allow this sender*, add an allow entry, or fix the rule or threshold (use **Test**); label it **safe**. |
| Body tab: *Fenrir did not keep this message's body* | Gateway mail that was delivered clean, with *keep message content* on *flagged*. Set it to *all* under Threat policies → Quarantine & content to keep more. |
| Body tab: *no longer in the mailbox* | The user deleted it and no copy was kept. |
| Saving a policy: *that pattern uses features not allowed in rules* | A "matches pattern" condition used back-references or nested repeats, which could stall the scanner. Simplify it or use "contains". |
| A rule does nothing | Check it is **On** and not **Audit only**, that an earlier rule doesn't *stop processing*, and the Decision tab of a matching message. |

---

## J. Moving customers off Heimdal

For each customer:

1. **Week 1–2:** Part C (shadow mode) **alongside Heimdal**. Label disagreements. Fenrir changes nothing, so both can
   run together.
2. **Switch to protect mode** (Part D), with *junk* for phish for the first week if you want a softer start, then
   *quarantine*. Turn on the daily digest so users see what was held back.
3. **Turn Heimdal's email protection off** for the customer, once Fenrir has run in protect mode for a week with no
   surprises. If Heimdal routes mail (MX pointing at Heimdal), point the MX back at Microsoft 365 first, or straight at
   Fenrir's gateway (Part G).
4. **Optionally**, move the customer onto the gateway (Part G) for pre-delivery blocking.
5. Remove Heimdal's connector or transport rules from the customer's Exchange Online (Exchange admin centre → Mail flow
   → Connectors and Rules), so mail doesn't take two paths.
