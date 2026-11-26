---
doc_type: statement-of-applicability
title: Statement of Applicability
code: SOA
review_months: 12
classification: Confidential
licence: original
merge_fields: [organization.legal_name, soa, soa_summary]
satisfies:
  - { framework: iso27001, ref: "6.1.3" }
sections: [soa.intro, soa.table]
---
::: block soa.intro
## About this statement

This Statement of Applicability lists every control in Annex A of ISO/IEC 27001 for {{organization.legal_name}}, whether it applies, why, how it is implemented and its current status. Of {{soa_summary.total}} controls, {{soa_summary.applicable}} apply and {{soa_summary.excluded}} are excluded with a justification. Control identifiers and short titles only are shown.
:::

::: block soa.table
## Controls

| Control | Title | Applies | Justification | Implemented by | Status | Owner |
| --- | --- | --- | --- | --- | --- | --- |
{{#each soa}}| {{this.ref}} | {{this.title}} | {{this.applicable}} | {{this.reason}} | {{this.implementation}} | {{this.status}} | {{this.owner}} |
{{/each}}
:::
