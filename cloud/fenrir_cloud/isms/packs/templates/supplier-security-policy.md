---
doc_type: supplier-security-policy
title: Supplier security policy
code: SUP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, suppliers, c]
satisfies:
  - { framework: iso27001, ref: A.5.19 }
  - { framework: iso27001, ref: A.5.20 }
  - { framework: iso27001, ref: A.5.21 }
  - { framework: iso27001, ref: A.5.22 }
  - { framework: iso27001, ref: A.5.23 }
sections: [sup.purpose, sup.tiers, sup.onboarding, sup.contracts, sup.monitoring, sup.register, sup.practice]
---
::: block sup.purpose
## Purpose

This policy makes sure the suppliers of {{organization.legal_name}} protect the information and services they handle for us to the standard we expect of ourselves.
:::

::: block sup.tiers
## Risk tiers

Suppliers are tiered by how critical their service is and what information they can reach. Higher tiers get more scrutiny and more frequent review.
:::

::: block sup.onboarding
## Before we sign

We assess a supplier's security before onboarding, proportionate to its tier, including how it manages its own suppliers.
:::

::: block sup.contracts
## Contracts

Contracts include security terms covering confidentiality, incident notification, data protection, the right to assess and what happens to our information when the contract ends.
:::

::: block sup.monitoring
## Ongoing review

Supplier security is reviewed on a schedule matched to the tier, and changes to their services are assessed before they take effect.
:::

::: block sup.register
## Supplier register

{{#if suppliers}}| Supplier | Classification of information handled | Owner |
| --- | --- | --- |
{{#each suppliers}}| {{this.name}} | {{this.classification}} | {{this.owner}} |
{{/each}}{{else}}No suppliers are recorded in the asset register yet.{{/if}}
:::

::: block sup.practice
## How we do this today

{{#if c.CC_SUP_01.implementation}}{{c.CC_SUP_01.implementation}}{{else}}The current supplier assessment arrangements have not been described yet.{{/if}}
:::
