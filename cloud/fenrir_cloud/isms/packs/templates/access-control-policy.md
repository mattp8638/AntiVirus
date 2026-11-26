---
doc_type: access-control-policy
title: Access control policy
code: ACP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.isms_manager, c]
satisfies:
  - { framework: iso27001, ref: A.5.15 }
  - { framework: iso27001, ref: A.5.16 }
  - { framework: iso27001, ref: A.5.17 }
  - { framework: iso27001, ref: A.5.18 }
  - { framework: iso27001, ref: A.8.2 }
  - { framework: iso27001, ref: A.8.5 }
sections: [acp.purpose, acp.principles, acp.lifecycle, acp.authentication, acp.privileged, acp.review, acp.practice]
---
::: block acp.purpose
## Purpose and scope

This policy sets the rules for giving, changing and removing access to the information and systems of {{organization.legal_name}}. It applies to everyone with an account, including contractors and suppliers.
:::

::: block acp.principles
## Principles

- Access is given only where the role needs it, and no more.
- Each account belongs to one identified person or system. Shared accounts are not used unless approved and logged.
- The owner of a system or information asset approves access to it.
:::

::: block acp.lifecycle
## Joiners, movers and leavers

Accounts are created only after an approved request. When someone changes role their access is reviewed and anything no longer needed is removed. Leavers lose all access on their last working day.
:::

::: block acp.authentication
## Authentication

Multi-factor authentication protects remote access, cloud services and every administrator account. Passwords are long, unique and kept in an approved password manager, never shared or written down.

{{#if c.CC_IAM_02.implementation}}How we do this today: {{c.CC_IAM_02.implementation}}{{/if}}
:::

::: block acp.privileged
## Privileged access

Administrator rights are held in separate accounts, granted only when needed and removed when no longer required. Privileged activity is logged.

{{#if c.CC_IAM_03.implementation}}How we do this today: {{c.CC_IAM_03.implementation}}{{/if}}
:::

::: block acp.review
## Access reviews

System owners review who has access every quarter and remove anything that is no longer needed. Reviews are recorded as evidence.

{{#if c.CC_ACC_01.implementation}}How we do this today: {{c.CC_ACC_01.implementation}}{{/if}}
:::

::: block acp.practice
## Ownership

{{roles.isms_manager}} owns this policy. Breaches are reported as security events and may lead to disciplinary action.
:::
