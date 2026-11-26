---
doc_type: roles-and-responsibilities
title: ISMS roles and responsibilities
code: RRS
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.top_management, isms_roles, raci]
satisfies:
  - { framework: iso27001, ref: "5.1" }
  - { framework: iso27001, ref: "5.3" }
  - { framework: iso27001, ref: A.5.2 }
sections: [rrs.purpose, rrs.roles, rrs.raci, rrs.review]
---
::: block rrs.purpose
## Purpose

This document records the roles that run the information security management system of {{organization.legal_name}}, who holds them, and what each is responsible and accountable for. Top management ({{roles.top_management}}) assigns these roles and makes sure they are understood.
:::

::: block rrs.roles
## Roles

{{#if isms_roles}}| Role | Held by | Responsibilities | Authorities |
| --- | --- | --- | --- |
{{#each isms_roles}}| {{this.name}} | {{this.holders}} | {{this.responsibilities}} | {{this.authorities}} |
{{/each}}{{else}}No ISMS roles have been defined yet.{{/if}}
:::

::: block rrs.raci
## Who does what

R: responsible, A: accountable, C: consulted, I: informed.

{{#if raci}}| Activity | Responsible | Accountable | Consulted | Informed |
| --- | --- | --- | --- | --- |
{{#each raci}}| {{this.activity}} | {{this.responsible}} | {{this.accountable}} | {{this.consulted}} | {{this.informed}} |
{{/each}}{{else}}The RACI matrix has not been filled in yet.{{/if}}
:::

::: block rrs.review
## Review

Roles are reviewed when the organization or the ISMS changes and at least once a year, and changes are communicated to the people affected.
:::
