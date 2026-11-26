---
doc_type: objectives-plan
title: Information security objectives and plan
code: OBJ
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.top_management, objectives]
satisfies:
  - { framework: iso27001, ref: "6.2" }
  - { framework: iso27001, ref: "9.1" }
sections: [obj.purpose, obj.table, obj.plans, obj.monitoring]
---
::: block obj.purpose
## Purpose

These are the information security objectives {{organization.legal_name}} has set, consistent with its information security policy and risk assessment, and how it plans to achieve them. They are agreed by top management ({{roles.top_management}}).
:::

::: block obj.table
## Objectives and measures

{{#if objectives}}| Ref | Objective | Measure | Target | Owner | By | Latest result |
| --- | --- | --- | --- | --- | --- | --- |
{{#each objectives}}| {{this.ref}} | {{this.title}} | {{this.measure}} | {{this.target}} | {{this.owner}} | {{this.due}} | {{this.latest}} |
{{/each}}{{else}}No objectives have been set yet.{{/if}}
:::

::: block obj.plans
## How each objective will be achieved

{{#each objectives}}- **{{this.ref}} {{this.title}}**: {{this.plan}} Resources: {{this.resources}} Measured {{this.frequency}}.
{{/each}}
:::

::: block obj.monitoring
## Monitoring and evaluation

Results are recorded in the platform at the frequency set for each objective, shown as trends against the target, and reviewed at management review. Objectives are updated when the business, risks or results change.
:::
