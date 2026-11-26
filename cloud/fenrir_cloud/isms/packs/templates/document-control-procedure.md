---
doc_type: document-control-procedure
title: Document control procedure
code: DCP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.isms_manager, roles.approvers, documents]
satisfies:
  - { framework: iso27001, ref: "7.5.1" }
  - { framework: iso27001, ref: "7.5.2" }
  - { framework: iso27001, ref: "7.5.3" }
  - { framework: iso27001, ref: A.5.37 }
sections: [dcp.purpose, dcp.create, dcp.approve, dcp.change, dcp.access, dcp.records, dcp.register]
---
::: block dcp.purpose
## Purpose

This procedure sets out how {{organization.legal_name}} creates, approves, publishes, changes and retires the documented information its ISMS depends on, so that people always use the current, approved version.
:::

::: block dcp.create
## Creating documents

Policies and procedures are generated from our live registers using standard templates, so names, owners, scope and decisions stay consistent. Each document has a unique number, a title, an owner, a classification and a review interval, shown in its document control table.
:::

::: block dcp.approve
## Review and approval

A draft is submitted for review, then approved by an authorized approver ({{roles.approvers}}) before it is published. Approval records who approved it and when, and stamps an approved copy. Approved and published versions are locked: they cannot be edited, only replaced by a new version.
:::

::: block dcp.change
## Changes and reviews

When the information a document relies on changes, the platform marks the document out of date and shows what would change. A new draft version is created and goes through approval again; the earlier published version is kept as superseded. Every document is reviewed at least by its review date, even if nothing has changed.
:::

::: block dcp.access
## Access and distribution

Published documents are available in the platform to the people who need them, according to their role. Staff are asked to read and acknowledge key policies, and completion is tracked. Confidential documents are shared only with those who need them.
:::

::: block dcp.records
## Records

Records such as audit results, management review minutes, risk assessments and evidence are kept in the platform with an audit trail of every change. Records are not altered after the event; corrections are made by adding a new entry. Downloads and exports are logged.
:::

::: block dcp.register
## Register of published documents

The ISMS manager ({{roles.isms_manager}}) maintains this register.

{{#if documents}}| Number | Title | Version | Published | Next review | Owner | Classification |
| --- | --- | --- | --- | --- | --- | --- |
{{#each documents}}| {{this.number}} | {{this.title}} | {{this.version}} | {{this.published}} | {{this.next_review}} | {{this.owner}} | {{this.classification}} |
{{/each}}{{else}}No other document has been published yet.{{/if}}
:::
