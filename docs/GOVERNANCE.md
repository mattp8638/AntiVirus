# UK governance programmes

Open **Governance → Programmes → Add framework**, choose a customer, then select a framework. The picker shows the owner, assessment method, UK applicability, version and link to official guidance.

The built-in catalogue contains these 15 programmes (Cyber Essentials and CE+ are separate):

| Programme | Intended use for UK organisations |
| --- | --- |
| Cyber Essentials | Preparation for the applicable NCSC / IASME assessment |
| Cyber Essentials Plus | Independent technical verification and remediation tracking |
| Def Stan 05-138 / CSM | Applicable MOD contract, risk level, supplier assurance and flow-down |
| NCSC CAF | Essential-function and sector-profile assessment |
| GovAssure | Government systems, CAF self-assessment, independent review and improvement plan |
| GovS 007 | Government security governance and functional-standard assurance |
| UK GDPR / DPA 2018 | Data-protection accountability, rights, risk assessment and evidence |
| EU GDPR | UK organisations whose activities fall within EU GDPR territorial scope |
| ISO/IEC 27001:2022 | ISMS clauses and Annex A readiness |
| NIST CSF 2.0 | Voluntary cyber-risk profiles used by UK organisations |
| SOC 2 Type I / Type II | Service-organisation assurance preparation |
| PCI DSS v4.0.1 | Applicable payment-card scope, SAQ or QSA assessment |
| CIS Controls v8.1 IG1 | The 56 essential cyber-hygiene safeguards |
| NIS 2 | Applicable EU national-law obligations affecting a UK organisation |
| DORA | Applicable EU financial-entity or ICT supplier obligations |

## Work through a programme

1. Record the assessment scope, accountable owner, security contact and target date.
2. Choose whether to create the matching policy drafts. Review and tailor them before approval.
3. Open each requirement and record an answer, implementation status, owner and due date. Explain any non-applicable requirement.
4. Attach evidence links or upload supporting files. Evidence expiry and policy approval are shown separately from the answer.
5. Use **History** to save a review or submission snapshot. **Export answers (CSV)** exports the current assessment; each historical snapshot also has an export.
6. Repeat the review after scope, control or framework changes. A changed requirement whose previous answer no longer matches its wording is flagged **Needs review**.

Built-in text is a readiness and evidence guide, with paraphrased requirements and selected automatic technical signals. Completion records the organisation's assessment; certification, regulatory decisions, independent testing and official submissions follow the applicable scheme. The new programme guides cover key workstreams rather than reproducing every licensed standard or sector-specific test.

For the exact question set or control set applicable to an engagement, use **Import exact question set**. JSON, YAML and CSV imports support customer-specific wording and versioning. Import under the same framework key to replace its guide for that customer. Review the proposed changes before saving; existing answers, policy links and evidence retain their identifiers. Imported versions are preserved, including an older version that legitimately applies to an assessment.

## Existing assessments

ACSC Essential Eight has been retired from the active UK catalogue, controls, risk selectors and policy mappings. It cannot be newly adopted or imported. Previous assessment records remain readable and exportable through their existing programme URLs and history; answers are not deleted. Existing risk-register records remain available.

CAF now uses version 4.0 with 41 contributing outcomes. In particular, A2.b is now Understanding Threat, A2.c covers Assurance, and A4.b covers secure software development and support. Existing A2.b answers require review rather than being treated as answers to the new outcome. Newly added outcomes start unanswered. The current CE guide is labelled against requirements v3.3; it does not claim to be the exact current IASME booklet.

## ISMS roles

Governance is gaining a full information security management system (ISMS), ported from the standalone ISMS Platform (see [the plan](ISMS_REWRITE_PLAN.md)). Every person who works in a customer's ISMS needs an ISMS role for that customer, whatever their Fenrir role, including MSP administrators.

Open **Governance → ISMS roles** with a customer chosen in the tenant picker.

| ISMS role | Can |
| --- | --- |
| ISMS administrator | Everything, including the customer's ISMS settings and roles |
| ISMS manager | Run the programme: risks, controls, Statement of Applicability, documents, audits |
| Control and risk owner | View, upload evidence, complete tasks, and edit the controls and risks they own |
| Approver | View, approve documents, accept risks |
| Staff | Read and acknowledge policies (in the client portal) |
| Auditor | Read-only, log findings and view the audit log; access always ends on a set date, at most a year away |
| Executive viewer | Read-only, with the executive dashboard |

- Fenrir users with the **grc** permission, and ISMS administrators, can give and remove roles for the customers they can see. Giving roles does not grant access to the ISMS data itself.
- A person can only be given a role in a customer they can already see in Fenrir. Client portal accounts can only be staff.
- Every role given, changed or removed is recorded in the audit log.

## Hosting update

After merging the governance change into the branch deployed on the VPS:

```bash
cd ~/AntiVirus
git pull --ff-only
sudo docker compose \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.https.yml \
  --env-file deploy/.env \
  up -d --build
sudo docker compose \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.https.yml \
  --env-file deploy/.env \
  ps
```

This catalogue change needs no new database migration or volume reset. Check that the cloud service is healthy, refresh the browser, and reopen **Add framework**. If an old list persists, confirm the VPS pulled the merged commit and that the cloud image was rebuilt. See the main README for health checks and log collection.

## Business continuity

**Compliance & GRC › Business continuity** holds each customer's continuity plans. A plan lists the business
services with their impact if lost, how critical they are, how long the business can be without them (RTO) and how
much recent data it can afford to lose (RPO), what each depends on, and the backed-up machines and DR runbook that
recover it. Dependency cycles are refused, and the plan shows the recovery order the dependencies imply.

Approving a plan records the version, the approver and a hash of what was approved; a later change shows as
"changed since approval" until approved again. Approval is not proof. Each service is also measured, live:

* the age of its machines' newest backups against its RPO;
* whether those backups were boot-verified in the last 90 days;
* the recovery time of its DR runbook's latest run against its RTO, and whether every machine came up;
* whether a dependency has a longer RTO than the service itself.

A service shows as **exercised** only when a technical exercise in the last year met its RTO and nothing has
slipped since; **measured** when a DR run met the target but no exercise was recorded; **gap** when any finding is
open; **planned** otherwise. A technical exercise takes its numbers from a DR runbook run, never from typed values;
a tabletop exercise records its outcome, lessons and actions. Actions are ticked off as they are done, and the
**review pack** collects the approved plan, the current assessment, the exercises and the open actions.

## Staff acknowledgement of policies

On a policy, **Ask all portal users** asks the customer's people (their client-portal accounts) to read and accept
it. They see it under **Policies** in the portal once a version is approved, read the approved text and tick that
they accept it. Each acceptance is kept and never changed: the person, the version, the SHA-256 of the exact title
and text they were shown, the time and the address it came from. Accepting fails if a newer version was approved
meanwhile or the text differs from the approved one.

Approving a new version asks everyone again. People are **outstanding** until their due date (14 days from being
asked or from the new version), then **overdue**, and are reminded by email every 7 days (at most six times). An
**exception** (a reason and an end date) excuses someone until that date; **Remove** stops asking someone who left,
keeping their record. **Evidence (CSV)** lists every acceptance of every version with its hash.

## Registers, objectives and management reviews

**Compliance & GRC › Registers & reviews** keeps each customer's context registers: **business risks** and
**opportunities** (likelihood and impact 1 to 5, inherent and residual score, a treatment and its plan), **interested
parties** (their needs and expectations), **internal and external issues**, a **PESTEL analysis** and the
**improvement register**. Each entry has an owner, a review date (flagged when overdue), linked requirements and
actions; every change keeps a version, and **Save as reviewed** records who reviewed it. **Export a version** keeps
the register as it is now with its SHA-256, so the same export can be downloaded later unchanged.

**Objectives** carry a KPI, a target (higher or lower is better) and their measurements over time.

A **management review** is planned, then **Build the input pack** collects the records as they are: programme
progress, policies (approved, review overdue, acknowledgements current), open register entries and the top risks,
improvements, objectives against target, continuity capability, incidents since the previous review and that
review's open actions. **Record the meeting** keeps the attendees, decisions and actions with owners; from then on
the pack is fixed, with its hash.

## Security questionnaires

**Compliance & GRC › Questionnaires** answers the security questionnaires a customer's own customers send them.
Keep approved answers in the **Answer library**, each with the evidence and policies behind it and a review period
(12 months by default). Import a questionnaire by pasting its questions (CSV with a `question` column, optionally
`id` and `section`, or one per line). For each question the library's closest approved answers are **suggested**;
nothing is filled in until a person chooses or writes an answer, and every answer must be **marked reviewed** by a
person before the questionnaire can be completed.

Answers are flagged, live: **stale** when the library answer is past its review date, **unverified** when there is no
current evidence or approved policy behind it, and **edited** when it differs from the library text. The export (CSV)
includes the flags and reviewers, and each export is recorded with its SHA-256. A reviewed answer can be added to the
library as a draft, to be approved like any other.

## Trust centre

**Compliance & GRC › Trust centre** publishes a customer's security documents at `/trust/<address>`, a page anyone
can open without an account. Add documents from an approved policy version, an evidence file or a written note:
each is **copied as it is now**, so the page shows the date it is as of and its SHA-256, and later edits to the
source do not change it. A document appears only after its **disclosure is approved**.

**Public** documents can be downloaded by anyone. **On request** documents need access: the visitor gives their
name, work email, company and reason and accepts the non-disclosure agreement shown (its hash is recorded with the
request). Approving the request emails a link that works until it **expires** (30 days by default); **Revoke**
stops it at once, and **Withdraw** stops a document for everyone. Every download, and every refused attempt, is in
the **access log** with the requester and address. The page states when it was generated, and each document its
as-of date, so customers and auditors see exactly how current each document is.

## Gaps

**Compliance & GRC › Gaps** tracks what is wrong until it is fixed. With continuous compliance on, every failing
common control opens a gap by itself (also **Check controls now**), naming the customer's devices that its evidence
mentions; a gap can also be raised from a policy-acknowledgement exception, a business risk, or by hand. Give it an
owner and a due date, **open a ticket** for the work on the service desk, choose the treatment (remediate, a
compensating control, or accept the risk with a justification) and attach evidence, then **submit for review**.

A reviewer **closes** it only when the evidence is attached and, for a remediated control gap, the control's
signals pass **now**; otherwise it is refused, or the reviewer **sends it back**. If the control fails again later,
its gap reopens with its history. Every step is on the gap's timeline and in the audit log.

## AI governance

**Compliance & GRC › AI governance** keeps an inventory of the AI systems and use-cases a customer runs or plans:
purpose, owner, the model and its supplier (linked to the third-party register when data goes to it), deployment and
the data used. A short assessment (our own questions, written with ISO/IEC 42001 and the EU AI Act in mind) suggests a
risk tier, from unacceptable to minimal; a person confirms the tier, and must explain a tier lower than suggested.
Approval is refused while points are open: unanswered questions, an unconfirmed tier, too few human-oversight measures
for the tier (two for high risk), no impact assessment when personal data is used, an unlinked supplier, or no
evidence for a high-risk system. Changing how an approved system is used withdraws its approval. The suggested tier
is guidance, not a legal classification; expert review and certification remain outside services.

## Agreements and e-signature

**Compliance & GRC › Agreements** sends agreements for signature. Write templates with `{{variable}}` blanks, or the
full text; the agreement's text is fixed when it is created, with its SHA-256, which every signer sees. Signers sign
one after another or in any order, each through a personal link sent by email that stops working once used, when the
agreement expires, or when it is voided.

A typed name is not enough: the signer asks for a **one-time code** sent to their email address and enters it within
15 minutes (five attempts), ticks their consent to sign electronically, and types their name as it appears on the
agreement. Signers can also decline. Every event (created, sent, viewed, code sent, signed, declined, completed,
voided, expired) is added to a **hash chain**: each event's hash covers the one before, so altering or removing any
event is detected. When everyone has signed, all parties receive the **completion record** (the document hash, the
signers with times and addresses, and the chain), which can be checked later with **verify**.
