---
doc_type: competence-awareness-procedure
title: Competence and awareness procedure
code: CAP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.isms_manager, acknowledgements]
satisfies:
  - { framework: iso27001, ref: "7.2" }
  - { framework: iso27001, ref: "7.3" }
  - { framework: iso27001, ref: "7.4" }
  - { framework: iso27001, ref: A.6.3 }
sections: [cap.purpose, cap.competence, cap.awareness, cap.communication, cap.status]
---
::: block cap.purpose
## Purpose

This procedure describes how {{organization.legal_name}} makes sure the people whose work affects information security are competent, aware of their responsibilities, and kept informed.
:::

::: block cap.competence
## Competence

For each ISMS role we describe the responsibilities and the knowledge it needs. Managers check that role holders have the right education, training or experience, and arrange training where there is a gap. Training, qualifications and relevant experience are recorded as competence records, with expiry dates where they lapse, and linked to evidence such as certificates. The ISMS manager ({{roles.isms_manager}}) reviews expiring records and the effectiveness of training at least once a year.
:::

::: block cap.awareness
## Awareness

Everyone who works for us, including contractors, learns about the information security policy, how they contribute to the ISMS, the benefits of good security and the consequences of not following our rules. New starters complete awareness training before they are given access, and everyone repeats it at least once a year. Key policies are sent for acknowledgement and completion is tracked per person and per policy.
:::

::: block cap.communication
## Communication

We decide what to communicate about information security, when, to whom and how. Routine messages go through team briefings and the platform; urgent messages about incidents or threats go to affected staff directly. External communication with customers, suppliers and authorities is handled by the ISMS manager or a nominated deputy.
:::

::: block cap.status
## Current acknowledgement campaigns

{{#if acknowledgements}}| Document | Acknowledged | Status |
| --- | --- | --- |
{{#each acknowledgements}}| {{this.document}} | {{this.completion}} | {{this.status}} |
{{/each}}{{else}}No acknowledgement campaign has been run yet.{{/if}}
:::
