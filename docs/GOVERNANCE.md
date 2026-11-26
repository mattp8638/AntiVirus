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

## Moving the earlier Governance records

While a customer still has records in the earlier Governance programmes, **Programme setup** offers **Move them into the ISMS** (Fenrir users with the grc permission who also run the customer's ISMS):

- Adopted frameworks become ISMS frameworks (all 15 programmes have an ISMS pack; the retired Essential Eight stays in the earlier module, read-only), and an adoption's scope fills an empty ISMS scope.
- Requirement answers are kept, read-only, beside the matching rows of the Statement of Applicability. A "not applicable" answer becomes a justified exclusion when it matches directly or covers several ISMS requirements (for example a NIST CSF category); mandatory clauses are never excluded.
- Policies become documents: the approved version published (withdrawn if the policy was retired), earlier approved versions superseded, and a newer draft kept as a draft.
- Evidence files are copied, encrypted, into the ISMS store; evidence is linked to the controls that satisfy the requirements it was linked to. Risk register entries become ISMS risks, exceptions become retained risks, and other register entries become evidence notes.
- Nothing in the earlier module is changed. Running the move again only adds what is new. The move is recorded in the audit log.

## Programme setup and ISMS controls

**Programme setup** needs an ISMS role that can run the programme.

1. Choose the frameworks the customer runs. Each stays on the content version chosen; a newer version is shown as available and is only adopted after a reviewed upgrade.
2. Answer the questions the chosen frameworks ask about the organization (for example whether it develops software or has premises).
3. **Review the changes** shows which requirements, controls and document sections would start or stop applying, and why. Nothing is saved until you choose **Apply**.

Mandatory clauses always apply. A requirement or control can be included or excluded by hand with a written justification, except that mandatory clauses and anything a rule requires cannot be excluded.

**ISMS controls** lists the customer's controls from the common control library. A control is not applicable when no applicable requirement needs it; its owner, state and notes are kept for when it applies again. ISMS managers set owners and states. A control's owner can change its state and notes, but not hand it to someone else. "Implemented with evidence" is set from current evidence, not by hand.

### Is this in place today?

Open a control on **ISMS controls** to answer whether it is in place: yes, partly, no, or (for ISMS managers) it does not apply. Yes and partly need a description of how it is done, which appears in the Statement of Applicability. "It does not apply" needs a justification and excludes the control and every requirement it fully satisfies; a later answer brings them back.

### Statement of Applicability

**Statement of Applicability** lists every non-mandatory requirement of a framework (for ISO 27001, the 93 Annex A controls) with its applicability, the reason or justification, the controls that implement it, its status and owners, and shows the framework's readiness. **Download (Excel)** gives a workbook with a cover sheet and one filterable sheet; every download is recorded in the audit log. Text in the workbook is always stored as plain text, never as a formula.

Readiness is the share of applicable requirements that are met, where a requirement is met when every control that fully satisfies it is implemented with current evidence.

## ISMS risks

**ISMS risks** is the customer's risk register. It is separate from the older **Risk register** tab, whose records will be moved across later.

- **Risk method** (ISMS managers): the likelihood and impact scales, the score bands, the appetite, the acceptance criteria and how often risks are reviewed. Score = likelihood x impact. Each saved change makes a new version. Until it is saved the default 5 x 5 method applies.
- **Add risk**: title, description, threat, vulnerability, owner, assets affected, inherent rating, treatment and plan, residual rating, and the controls that treat it. Risks are numbered R-001, R-002 and so on. Levels are written out (for example "16 Critical"), and the heat map is a table of counts, so colour is never the only signal.
- **Accept**: only the risk's owner can accept it, after a treatment is chosen. Above appetite the rationale must be at least 40 characters. The acceptance records who, when, the score and why, and lasts until the next review. Changing the accepted score or the owner ends it.
- A risk's owner can edit it without broader rights, but only ISMS managers can change who owns it.
- **Take a snapshot** keeps a dated copy of the whole assessment as evidence of when it was done.

## ISMS evidence

**ISMS evidence** holds evidence that controls operate: files, links, notes, and the results of Fenrir's automated GRC checks.

- A control counts as **implemented with evidence** while it is implemented and has at least one piece of current evidence: scanned clean, not past its valid-until date, and (for Fenrir checks) passing. This updates straight away after any change, and every hour so expiry is noticed.
- Files (up to 25 MB) are stored encrypted and checked by the ClamAV service set with `FENRIR_CLAMD_HOST` (the one the mail gateway uses). A file the scanner rejects is deleted at once, and the attempt is kept as a record. Without a scanner, production installations keep files waiting (they cannot be downloaded) until one is configured; development installations mark them as not scanned. Program and script files cannot be uploaded.
- Fenrir's automated GRC evidence is imported every hour (or with **Import Fenrir results now**): a passing result is evidence for the mapped controls and marks a control that was not started or in progress as implemented; a failing result moves an implemented control back to in progress.
- Evidence about to expire within 30 days is flagged once in the audit log. Downloads, uploads, rejected files and deletions are all audited.

## ISMS tasks and calendar

**ISMS tasks** shows the work that keeps the ISMS running (ISO 27001 8.1), as a list or a month calendar.

- Every applicable control not yet in place gets a task to put it in place (due in 90 days), which closes itself once the control is marked as in place. Controls in place with a regular test frequency get a recurring check, scheduled again each time it is done. ISMS managers can add other tasks. Tasks follow the control's owner.
- Completing a check records what was checked (a note, a piece of evidence, or both). People who do not run the programme see and complete only their own tasks.
- Emails go out (through Fenrir's mail settings) when a task is due within 7 days and when it is overdue, and after 14 days overdue it is escalated to the customer's ISMS administrators and managers. Each happens once per task. Owners of controls are also emailed when evidence for them expires within 30 days.

## ISMS documents

**ISMS documents** lists the policies and procedures the ISMS needs, written from the customer's live data (scope, roles, risk method, controls, risks, Statement of Applicability and so on).

- **Generate** makes a draft. A document is marked **out of date** when the data it uses has changed since its latest version; regenerating shows which sections would change. Sections switched off by the onboarding answers are left out (for example secure development when no software is developed).
- Lifecycle: draft, in review, approved, published, then superseded by the next published version or withdrawn. ISMS managers send drafts for review; approvers and ISMS managers approve, publish and withdraw. Approval stamps the Word and PDF copies with the approver's name and date.
- Approved and published versions never change: regenerating always makes a new draft, and the application refuses any edit to a version that has left draft.
- **Use our own wording** replaces one section with the customer's text in every future version (placeholders such as `{{organization.legal_name}}` still work).
- Staff, executives and auditors see only published versions. Every generation, step and download is recorded in the audit log.

## ISMS improvement

**ISMS improvement** has three views. Everyone with an ISMS role that can see controls can read them; ISMS managers make changes.

- **Nonconformities and improvements** (10.2). Each record gets a reference (NC-001, or OFI-001 for an improvement opportunity), a source (internal or external audit, incident, management review, monitoring, complaint or other) and, for a nonconformity, a severity. A nonconformity moves through: root cause needed, corrective action needed, actions in progress, ready for effectiveness check. The owner of a corrective action marks it done with a note. Once every action is done, the ISMS manager records how they checked it worked: effective closes it, not effective keeps it open for more action. Improvement opportunities close with a note; either kind can be cancelled with a reason.
- **Objectives and measures** (6.2, 9.1). Each objective has a measure, a target (at least or at most a value), an owner and a frequency. The owner or an ISMS manager records values; the list shows the latest value, whether it is on target, the trend and whether the measure is stale (no value for longer than its frequency). An objective is finished as achieved or retired with a note.
- **Planned changes** (6.3). Changes to the ISMS itself, with their purpose, possible consequences, resources and owner. A change marked done or cancelled needs the date it finished and its outcome.

Every step is recorded in the audit log.

## Internal audit

**Internal audit** (9.2) holds audit programmes, each covering a period, and the audits planned in them. ISMS managers plan; people with the auditor role (or ISMS managers) carry out audits.

- Each audit names the frameworks it covers, its dates (starting inside the programme period), a lead auditor with an ISMS role in the customer, and a note on how the auditors are independent of what they audit.
- **Generate checklist** adds every clause and every applicable requirement of those frameworks, optionally limited to some groups (for example clause 9 and the people controls). Each item is a snapshot, so later pack updates do not change it. Refreshing keeps items that already have a result.
- Once started, the auditor records a result for each item (conforms, observation, minor or major nonconformity, not assessed) with what was found and the evidence seen. A minor or major finding must be raised as a nonconformity before the audit can be completed; an observation can be raised as an improvement. Both then follow the **ISMS improvement** workflow.
- Completing needs a result for every item, the independence note and a summary. A completed audit and its checklist never change. Only a planned audit can be deleted.
- Coverage shows how many of the requirements that must be audited the programme's audits have checked.
- **Draw a sample** picks items from a list (for example leavers or changes) so the same list, size and seed always give the same sample, which lets anyone check it. Nothing is stored.

Objectives, the latest audit programme and improvement figures also appear in the generated ISMS documents (for example the objectives plan and the internal audit procedure).

## Organization, scope and assets

These tabs need an ISMS role that can run the programme (ISMS manager or ISMS administrator).

- **Organization** holds the ISMS scope (4.3) with its boundaries, interfaces and exclusions, the context issues (4.1, including whether climate change is relevant), the interested parties and their requirements (4.2), and the legal entities and sites in and out of scope. Each change to the scope wording makes a new version.
- **Assets** is the asset register: information, systems, services, people, suppliers and sites, each with a classification and an owner who has an ISMS role in the customer. **Import CSV** takes the columns name, type, classification, owner_email and description (up to 5,000 rows). If any row has a problem nothing is imported, and every problem is listed with its line. A row with the same type and name as an existing asset updates it.

Every change is recorded in the audit log.

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
