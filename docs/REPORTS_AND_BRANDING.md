# Reports and branding

Fenrir can carry your own branding (white-label), and makes customer reports as PDFs or printable pages. Reports can be emailed on a schedule.

## Branding

**Where:** Settings › Branding. Only staff of the MSP itself who can manage tenants (platform and MSP admins) can change it.

| Setting | Where it shows |
|---|---|
| Company name | Reports, the sign-in page, the menu, the browser tab and the Windows agent window |
| Tagline | Under the name on the sign-in page and in the menu |
| Main and accent colours | Buttons, links, the menu mark and report headings, cards and rules |
| Support email, phone and website | Every report's footer and the settings page; never on the public sign-in page |
| Report footer | The bottom of every report page, for example a confidentiality line |
| Logo | Report headers, the sign-in page and the menu |

How it behaves:

- **Who inherits it.** Each MSP has one brand, and its customers inherit it. A customer's own users see it but cannot change it.
- **Text on the main colour.** Button text switches between white and near-black automatically. White is used whenever it meets the 3:1 contrast that WCAG requires for buttons and large text.
- **Windows agent.** The agent window shows your company name, unless the policy sets **Brand name** (`experience.brandName`) to something other than the default.
- **Sign-in page.** It reads `GET /api/console/auth/branding` without signing in. That endpoint returns only the name, tagline, colours and a logo link. The console also remembers the brand, so the next visit opens already branded.

### Logos

Logos can be PNG or JPEG, up to 2 MB. SVG is refused, because an SVG file can contain script.

Every upload is decoded and redrawn on the server as a new PNG, at most 600 × 200 pixels. Only that redrawn copy is kept and served. So the uploaded file itself never reaches a browser or a PDF: not its metadata, not anything hidden inside it, and not an image built to exhaust memory. Images over 4000 × 4000 pixels are refused.

## Reports

**Where:** Reports. Pick the customer and the report, then choose **Download PDF** or **Open printable page**. Saved reports also have a **PDF** button: open a customer, then Health.

| Report | Covers |
|---|---|
| Executive summary | IT health score and its parts, the key numbers, recommended next steps, alerts, open vulnerabilities, patching, compliance and the service desk, for the last 7, 30 or 90 days |
| What we did for you (monthly) | Last month's work (or a chosen month) and the customer's health today. It is also kept automatically at the start of each month. |
| Quarterly business review | Health and how it moved over the quarter, the work done, and the recommended next steps |
| Vulnerability report | Every open vulnerability, highest risk first, with ageing by severity, overdue fixes, the most exposed devices and accepted risks |

How the reports work:

- **Recommended next steps** come straight from the data. In order: known-exploited vulnerabilities first, then critical and high ones, missing security updates, devices waiting for a restart, high-risk devices, compliance frameworks under 70%, then service-desk SLA under 90%. Weak areas of the health score follow.
- **Accepted risks** are not counted as work to do, but they stay in the open counts. That matches how compliance counts them.
- **Vulnerability ranking.** Known-exploited (CISA KEV) issues come first, then severity, CVSS score and EPSS (the estimated chance of exploitation). The report shows the top 60, and says how many there are in total.
- **One source for both formats.** Each report is built once as structured data. The PDF and the page are drawn from that same data, so they always match. A saved report keeps that data, so its PDF is exactly what was sent. Reports saved before this change have only their HTML: open that and print it.
- **Fonts.** PDFs use DejaVu Sans, which is bundled with the server, so accents and symbols print correctly. Scripts the font does not cover, such as Chinese, Japanese and Korean, print as blanks.

### API

| Call | What it does |
|---|---|
| `GET /api/console/reports/kinds` | The report kinds |
| `GET /api/console/reports/{kind}.pdf?tenant_id=…` | A report as a PDF download (at most 30 a minute per user) |
| `GET /api/console/reports/{kind}.html?tenant_id=…` | The same report as a printable page |
| `GET /api/console/reports/executive?tenant_id=…&days=30` | The executive figures as JSON |
| `GET /api/console/clients/{tenant}/reports/{id}.pdf` | A saved report as a PDF |

Optional parameters: `days=7|30|90` for the executive summary, and `period=2026-09` (monthly) or `period=2026-Q3` (quarterly).

## Scheduled reports

**Where:** Reports, then the **Scheduled reports** card for the chosen customer. You need the *configure* permission to change schedules. Anyone who can see the customer can view them.

A customer can have up to 10 schedules, each with up to 20 recipients. Each schedule sends one report weekly, monthly or quarterly.

- **When they send.** The hourly maintenance job sends each schedule once in each week, month or quarter. A restart or a second server never sends it twice.
- **What period they cover.** Monthly and quarterly reports cover the last complete month or quarter. The executive summary covers the last 7, 30 or 90 days, matching how often it is sent.
- **The email.** The report arrives as a PDF attachment, with your company name in the subject and your contact details in the message.
- **Failures.** If a report fails to build, the schedule shows the reason and tries again next period. The other schedules still send. Every send and failure is written to the audit log.
- **Send now.** This emails a report straight away, to check it, without changing when the schedule next sends. It is limited to 10 an hour per customer.

Emails go through the server's SMTP settings (`FENRIR_SMTP_*`). With no SMTP configured, they are only logged.

API: `GET`/`PUT /api/console/reports/schedules?tenant_id=…` with `{"schedules": [{"kind", "every", "to": [...]}]}`, and
`POST /api/console/reports/schedules/{id}/send?tenant_id=…`. The server keeps track of when each schedule last sent, and ignores any such value a client sends.
