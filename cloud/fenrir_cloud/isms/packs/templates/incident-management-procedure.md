---
doc_type: incident-management-procedure
title: Incident management procedure
code: INC
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.isms_manager, roles.top_management, c]
satisfies:
  - { framework: iso27001, ref: A.5.24 }
  - { framework: iso27001, ref: A.5.25 }
  - { framework: iso27001, ref: A.5.26 }
  - { framework: iso27001, ref: A.5.27 }
  - { framework: iso27001, ref: A.5.28 }
  - { framework: iso27001, ref: A.6.8 }
sections: [inc.purpose, inc.roles, inc.report, inc.assess, inc.respond, inc.learn, inc.practice]
---
::: block inc.purpose
## Purpose

This procedure sets out how {{organization.legal_name}} reports, assesses, contains and learns from information security events and incidents.
:::

::: block inc.roles
## Roles

- **Incident lead:** {{roles.isms_manager}}, who coordinates the response.
- **Decision maker:** {{roles.top_management}}, for decisions on notification, communication and major spend.
- **Everyone:** reports events straight away.
:::

::: block inc.report
## 1. Report

Anyone who notices something suspicious reports it at once to the incident lead, with what happened, when and what is affected. Do not try to investigate alone or delete anything.
:::

::: block inc.assess
## 2. Assess

The incident lead decides whether the event is an incident, rates its severity and records it. Personal data breaches are assessed for notification to the regulator within 72 hours.
:::

::: block inc.respond
## 3. Contain, fix and recover

Contain the incident, remove the cause, restore services from known good sources and confirm they work. Preserve evidence in a way that keeps its integrity, recording who handled it and when.
:::

::: block inc.learn
## 4. Learn

After every significant incident, review the root cause and record improvements as corrective actions. The procedure is exercised at least once a year.
:::

::: block inc.practice
## How we do this today

{{#if c.CC_INC_01.implementation}}{{c.CC_INC_01.implementation}}{{else}}The current incident arrangements have not been described yet.{{/if}}
:::
