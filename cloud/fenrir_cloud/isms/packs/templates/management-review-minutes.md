---
doc_type: management-review-minutes
title: Management review minutes
code: MRM
review_months: 12
classification: Confidential
licence: original
merge_fields: [organization.legal_name, last_review]
satisfies:
  - { framework: iso27001, ref: "9.3.1" }
  - { framework: iso27001, ref: "9.3.2" }
  - { framework: iso27001, ref: "9.3.3" }
sections: [mrm.record, mrm.decisions, mrm.actions, mrm.none]
---
::: block mrm.record
{{#if last_review}}## Meeting

{{organization.legal_name}} held management review {{last_review.ref}} ({{last_review.title}}) on {{last_review.held_on}}, chaired by {{last_review.chair}}. It covered the period {{last_review.period}}.

Attendees: {{last_review.attendees}}

The review considered a pack built from live ISMS data covering earlier actions, changes in issues and interested parties, nonconformities, monitoring results, audit results, objectives, interested party feedback, risk and opportunities for improvement.

### Minutes

{{last_review.minutes}}{{/if}}
:::

::: block mrm.decisions
{{#if last_review}}## Decisions

{{last_review.decisions}}

### Changes needed to the ISMS

{{last_review.changes_needed}}{{/if}}
:::

::: block mrm.actions
{{#if last_review}}## Actions

{{#if last_review.actions}}| Action | Owner | Due | Status |
| --- | --- | --- | --- |
{{#each last_review.actions}}| {{this.description}} | {{this.owner}} | {{this.due}} | {{this.status}} |
{{/each}}{{else}}No actions were agreed.{{/if}}{{/if}}
:::

::: block mrm.none
{{#unless last_review}}No management review has been held yet. Record the meeting in the platform, then regenerate these minutes.{{/unless}}
:::
