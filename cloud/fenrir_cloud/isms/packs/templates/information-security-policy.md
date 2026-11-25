---
doc_type: information-security-policy
title: Information security policy
code: POL
review_months: 12
classification: Internal
licence: original
merge_fields:
  - organization.legal_name
  - organization.short_name
  - scope.statement
  - risk.appetite
  - roles.isms_manager
  - roles.top_management
  - document.review_interval_months
  - controls
satisfies:
  - { framework: iso27001, ref: "5.2" }
  - { framework: iso27001, ref: A.5.1 }
sections:
  - isp.purpose
  - isp.scope
  - isp.commitments
  - isp.roles
  - isp.secure-development
  - isp.controls
  - isp.review
---
<!-- Blocks are the unit for rule conditions and tenant wording overrides. Keep refs stable. -->

::: block isp.purpose
## Purpose

This policy sets out how {{organization.legal_name}} ("{{organization.short_name}}") protects the
confidentiality, integrity and availability of the information it holds and the services it provides.
:::

::: block isp.scope
## Scope

{{scope.statement}}
:::

::: block isp.commitments
## Our commitments

Top management commits to:

- meeting legal, regulatory and contractual requirements for information security;
- setting information security objectives and reviewing progress against them;
- managing risk within the agreed appetite (a residual score of {{risk.appetite}} or less);
- continually improving the information security management system.
:::

::: block isp.roles
## Roles

{{roles.top_management}} owns this policy. {{roles.isms_manager}} runs the information security
management system day to day. Every member of staff is responsible for following this policy and
reporting incidents.
:::

::: block isp.secure-development
## Secure development

Software we build follows our secure development process: security requirements are agreed before
work starts, code is peer reviewed, dependencies are scanned and security tests pass before release.
:::

::: block isp.controls
## Supporting controls

{{#each controls}}
- **{{this.ref}}** {{this.title}} (owner: {{this.owner}}, status: {{this.status}})
{{/each}}
:::

::: block isp.review
## Review

This policy is reviewed every {{document.review_interval_months}} months, and sooner after a
significant change.
:::
