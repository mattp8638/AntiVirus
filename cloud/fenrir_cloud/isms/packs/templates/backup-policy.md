---
doc_type: backup-policy
title: Backup policy
code: BKP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, c]
satisfies:
  - { framework: iso27001, ref: A.8.13 }
sections: [bkp.purpose, bkp.scope, bkp.rules, bkp.testing, bkp.practice]
---
::: block bkp.purpose
## Purpose

This policy makes sure {{organization.legal_name}} can recover its information and systems after loss, corruption or attack.
:::

::: block bkp.scope
## Scope

It covers business data, system configuration and anything needed to rebuild services, wherever they run, including cloud services.
:::

::: block bkp.rules
## Rules

- Backups run at least daily for business data and after every significant configuration change.
- Backups are encrypted and held separately from the systems they protect, with at least one copy that ransomware on the production network cannot alter.
- Retention periods meet legal and business needs.
- Backup failures are alerted and fixed promptly.
:::

::: block bkp.testing
## Restore testing

A restore is tested at least every quarter, and the result, including the time taken, is recorded as evidence.
:::

::: block bkp.practice
## How we do this today

{{#if c.CC_BKP_01.implementation}}{{c.CC_BKP_01.implementation}}{{else}}The current backup arrangements have not been described yet.{{/if}}

{{#if c.CC_BKP_01.owner}}Owner: {{c.CC_BKP_01.owner}}.{{/if}}
:::
