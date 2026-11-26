---
doc_type: internal-audit-procedure
title: Internal audit procedure
code: IAP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.isms_manager, audit_programme]
satisfies:
  - { framework: iso27001, ref: "9.2.1" }
  - { framework: iso27001, ref: "9.2.2" }
  - { framework: iso27001, ref: A.5.35 }
sections: [iap.purpose, iap.programme, iap.method, iap.independence, iap.findings, iap.current, iap.none]
---
::: block iap.purpose
## Purpose

This procedure explains how {{organization.legal_name}} checks, through planned internal audits, that its information security management system (ISMS) meets its own rules and the standards it has adopted, and that it is working in practice.
:::

::: block iap.programme
## The audit programme

The ISMS manager ({{roles.isms_manager}}) keeps an audit programme for each period, normally a calendar year. Over the period the programme must examine every clause of the management system standard and every control that applies to us. Areas that are higher risk, have changed, or had findings at the last audit are audited sooner or more often. The platform shows how much of the programme has been covered and lists anything not yet audited.
:::

::: block iap.method
## Planning and running an audit

1. Each audit has a defined scope, dates, a lead auditor and the frameworks it covers.
2. The checklist is generated from the requirements in scope, so nothing is missed. Each item lists the controls that implement it.
3. The auditor samples records, interviews owners and looks at evidence, then records a result for every item: conforms, observation, minor nonconformity, major nonconformity or not assessed, with what was found and the evidence seen.
4. The audit is completed with a written summary and conclusion, which is reported to the ISMS manager and top management. Completed audits cannot be changed.
:::

::: block iap.independence
## Objectivity

Auditors do not audit their own work. Each audit records how the auditors are independent of the areas they examine; an audit cannot be completed without this note. Where we lack independent staff we use a qualified external auditor.
:::

::: block iap.findings
## Findings

Every minor or major nonconformity is raised in the improvement register before the audit can be closed, and follows the nonconformity and corrective action procedure. Observations may be raised as improvement opportunities. Audit results are an input to management review.
:::

::: block iap.current
{{#if audit_programme}}## Current programme

{{audit_programme.title}} runs from {{audit_programme.period}}. Coverage so far: {{audit_programme.coverage}}.

| Audit | Title | Dates | Lead auditor | Status |
| --- | --- | --- | --- | --- |
{{#each audit_programme.audits}}| {{this.ref}} | {{this.title}} | {{this.dates}} | {{this.lead}} | {{this.status}} |
{{/each}}{{/if}}
:::

::: block iap.none
{{#unless audit_programme}}No audit programme has been set up yet.{{/unless}}
:::
