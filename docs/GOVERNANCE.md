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

## Programme setup and ISMS controls

**Programme setup** needs an ISMS role that can run the programme.

1. Choose the frameworks the customer runs. Each stays on the content version chosen; a newer version is shown as available and is only adopted after a reviewed upgrade.
2. Answer the questions the chosen frameworks ask about the organization (for example whether it develops software or has premises).
3. **Review the changes** shows which requirements, controls and document sections would start or stop applying, and why. Nothing is saved until you choose **Apply**.

Mandatory clauses always apply. A requirement or control can be included or excluded by hand with a written justification, except that mandatory clauses and anything a rule requires cannot be excluded.

**ISMS controls** lists the customer's controls from the common control library. A control is not applicable when no applicable requirement needs it; its owner, state and notes are kept for when it applies again. ISMS managers set owners and states. A control's owner can change its state and notes, but not hand it to someone else. "Implemented with evidence" is set from current evidence, not by hand.

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
