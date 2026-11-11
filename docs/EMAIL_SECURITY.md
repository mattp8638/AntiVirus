# Email security (shadow mode)

Fenrir reads each customer's new Microsoft 365 mail and gives its own verdict next to Microsoft's. In shadow mode it
**only compares**: nothing in any mailbox is moved, deleted or changed. Use it to see how Fenrir performs on real mail
before it is allowed to act, and to build up the labels a model will learn from.

## Turning it on

1. **Settings → Modules:** switch on **Email security**. It then appears in the menu under *Identity, cloud & network*.
2. **Give Fenrir permission to read mail.** It needs the Microsoft Graph application permission `Mail.Read`.
   - New connections made by admin sign-in or with the Fenrir app ask for it automatically.
   - Existing connections: open the customer under **Microsoft 365** and choose **Update permissions**; a customer
     admin approves it.
   - Partner (GDAP) connections cannot read mail: Microsoft doesn't allow it. Use an admin sign-in connection for
     those customers.
   - To limit which mailboxes Fenrir can read, add an Exchange Online *application access policy* for the app.
3. **Email security → Customers:** choose **Turn on (shadow)** for the customer. The first scan looks back 24 hours;
   after that, new mail is scanned every five minutes. **Scan now** runs one straight away.

## What it reads

For every licensed, enabled member mailbox: new messages in **Inbox** and **Junk Email**, with their headers and body,
and the names, sizes and SHA-256 hashes of up to three attachments of 5 MB or less per message.

## Microsoft's verdict

Read from the headers Microsoft stamps on every message it delivers:

| Header | What Fenrir takes from it |
|---|---|
| `X-Forefront-Antispam-Report` | Spam confidence (SCL), the category Microsoft gave it (CAT: phish, malware, spam, bulk...), sending country |
| `X-Microsoft-Antispam` | Bulk complaint level (BCL) |
| `Authentication-Results` | SPF, DKIM, DMARC and composite authentication results |

A message in Junk Email counts as at least spam.

## Fenrir's verdict

A score from named checks, so every verdict says why:

| Check | Points |
|---|---|
| Attachment hash is known malware (MalwareBazaar or your own indicators) | 100 |
| Link to a domain or URL in threat intelligence (URLhaus, ThreatFox, your indicators) | 70 each, up to three |
| Sender domain imitates the customer's own domain (`acrne.co.uk` for `acme.co.uk`) | 50 |
| Attachment is a program or script (`.exe`, `.js`, `.lnk`...) | 45, plus 30 if disguised (`invoice.pdf.exe`) |
| Outside address using a colleague's display name | 40, plus 15 from a free mail account |
| Sender domain imitates a well-known brand (Microsoft, DocuSign, PayPal, HMRC...) | 40 |
| Disk image attachment (`.iso`, `.img`, `.vhd`) | 40 |
| Claims to be from the customer's own domain but fails authentication | 35 |
| Link to a site imitating a brand or the customer's domain | 35 |
| Web page attachment (`.html`, `.svg`): a common fake sign-in form | 30 |
| Scam wording (account expiry, changed bank details, gift cards, CEO fraud...) | 10 per phrase, up to 30 |
| DMARC failed | 25 |
| Link text shows one site but goes to another | 25 |
| Office file with macros | 25 |
| Composite authentication failed | 20 |
| Link to a bare IP address | 20 |
| Replies go to a different domain | 10, or 20 for free mail |
| SPF failed with no valid DKIM | 15 |
| Display name suggests IT or Microsoft from an outside domain | 15 |
| Link shortener | 5 |
| First message from this domain to the customer (only when something else was found) | 5 |

**50 or more** is phish (or malware if the evidence is an attachment), **25 to 49** is suspicious, below 25 is clean.
Microsoft's real domains (`onmicrosoft.com`, `microsoftonline.com`, `docusign.net`...) never count as lookalikes, and
indicators marked *allow* (Threat intel) are never flagged.

## The comparison

Every message is put in one bucket: **both flagged**, **only Fenrir**, **only Microsoft**, or **neither** (phish and
malware count as flagged). The Overview shows how often they agree and lists what each side caught alone.

**Label messages** (phish, malware, spam or safe) on the Messages tab, starting with the ones only one side flagged.
The Overview then shows how often Fenrir and Microsoft were each right on the messages you labelled. These labels and
Microsoft's verdicts are the training data for the next step.

## Privacy

- The message body is **never stored**. Fenrir keeps the sender, subject, mailbox, link domains, attachment names and
  hashes, both verdicts and the reasons.
- Scans are deleted after each customer's retention period (default 90 days, 7 to 730).
- Viewing and labelling scans needs the *respond* permission; turning scanning on or off needs *configure*. Users only
  see their own customers. Turning it on or off and every label are recorded in the audit log.
- You are processing your customers' email: say so in your agreements and data processing terms.

## Limits

- Shadow mode never acts. Moving mail to Junk or quarantine needs `Mail.ReadWrite` and comes in the next phase.
- Mail is scanned after Microsoft delivers it, so it sits in the mailbox for up to five minutes before Fenrir sees it.
- Internal mail between the customer's own users is scanned only if Microsoft files it in Inbox or Junk Email.
- No attachment sandbox and no click-time link checks yet.
- The checks are rules, tuned to avoid false positives; the model trained from your labels comes later.
