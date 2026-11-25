---
doc_type: scope-statement
title: ISMS scope statement
code: SCO
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, organization.services, scope.statement, scope.boundaries, scope.interfaces, scope.exclusions, scope.version, roles.isms_manager]
satisfies:
  - { framework: iso27001, ref: "4.3" }
sections: [sco.purpose, sco.scope, sco.boundaries, sco.interfaces, sco.exclusions, sco.ownership]
---
::: block sco.purpose
## Purpose

This statement defines the boundaries and applicability of the information security management system (ISMS) of {{organization.legal_name}}.
:::

::: block sco.scope
## What the ISMS covers

{{scope.statement}}

{{#if organization.services}}The services in scope include: {{organization.services}}{{/if}}
:::

::: block sco.boundaries
## Boundaries

{{#if scope.boundaries}}{{scope.boundaries}}{{else}}The boundaries have not been recorded yet.{{/if}}
:::

::: block sco.interfaces
## Interfaces and dependencies

{{#if scope.interfaces}}{{scope.interfaces}}{{else}}No interfaces outside the scope have been recorded.{{/if}}
:::

::: block sco.exclusions
## Exclusions

{{#if scope.exclusions}}{{scope.exclusions}}{{else}}Nothing within the organization is excluded from the scope.{{/if}}
:::

::: block sco.ownership
## Ownership

{{roles.isms_manager}} maintains this statement. It is reviewed when the organization, its services or its locations change, and at least once a year. This is version {{scope.version}} of the recorded scope.
:::
