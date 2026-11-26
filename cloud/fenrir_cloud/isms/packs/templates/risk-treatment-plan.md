---
doc_type: risk-treatment-plan
title: Risk treatment plan
code: RTP
review_months: 6
classification: Confidential
licence: original
merge_fields: [organization.legal_name, risks, risk.appetite]
satisfies:
  - { framework: iso27001, ref: "6.1.3" }
  - { framework: iso27001, ref: "8.3" }
sections: [rtp.intro, rtp.table, rtp.none]
---
::: block rtp.intro
## About this plan

This plan records how {{organization.legal_name}} treats each assessed risk, which controls apply, the residual rating and whether the risk owner has accepted it. The appetite is a residual score of {{risk.appetite}} or less.
:::

::: block rtp.table
## Treatment by risk

{{#if risks}}| Risk | Owner | Before | Treatment | Plan and controls | After | Accepted |
| --- | --- | --- | --- | --- | --- | --- |
{{#each risks}}| {{this.ref}} {{this.title}} | {{this.owner}} | {{this.inherent}} | {{this.treatment}} | {{this.treatment_plan}} {{this.controls}} | {{this.residual}} | {{this.accepted}} |
{{/each}}{{/if}}
:::

::: block rtp.none
{{#unless risks}}No risks have been recorded yet.{{/unless}}
:::
