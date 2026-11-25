---
doc_type: risk-methodology
title: Risk assessment and treatment methodology
code: RAM
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, risk.likelihood_scale, risk.impact_scale, risk.levels, risk.appetite, risk.acceptance_criteria, risk.review_months, risk.method_version, roles.isms_manager]
satisfies:
  - { framework: iso27001, ref: "6.1.2" }
  - { framework: iso27001, ref: "6.1.3" }
  - { framework: iso27001, ref: "8.2" }
sections: [ram.purpose, ram.process, ram.likelihood, ram.impact, ram.levels, ram.treatment, ram.acceptance, ram.review]
---
::: block ram.purpose
## Purpose

This document describes how {{organization.legal_name}} identifies, analyses, evaluates and treats information security risks, so that repeated assessments give consistent, valid and comparable results. This is version {{risk.method_version}} of the method.
:::

::: block ram.process
## Process

1. Identify risks to the confidentiality, integrity and availability of information within the ISMS scope, naming the assets affected, the threat and the vulnerability.
2. Give each risk an owner: the person accountable for managing it.
3. Rate likelihood and impact before treatment using the scales below. The score is likelihood multiplied by impact.
4. Compare the score with the risk appetite and decide a treatment.
5. Choose controls, compare them with Annex A of ISO/IEC 27001 and record them in the Statement of Applicability.
6. Rate the risk again after treatment and ask the risk owner to accept the residual risk.
:::

::: block ram.likelihood
## Likelihood scale

| Rating | Label | Meaning |
| --- | --- | --- |
{{#each risk.likelihood_scale}}| {{this.value}} | {{this.label}} | {{this.description}} |
{{/each}}
:::

::: block ram.impact
## Impact scale

| Rating | Label | Meaning |
| --- | --- | --- |
{{#each risk.impact_scale}}| {{this.value}} | {{this.label}} | {{this.description}} |
{{/each}}
:::

::: block ram.levels
## Risk levels

| Scores from | Level |
| --- | --- |
{{#each risk.levels}}| {{this.min}} | {{this.label}} |
{{/each}}
:::

::: block ram.treatment
## Treatment options

- **Modify:** apply controls that lower the likelihood or the impact.
- **Retain:** accept the risk as it is, within the acceptance criteria.
- **Avoid:** stop the activity that gives rise to the risk.
- **Share:** transfer part of the risk, for example to an insurer or a supplier, while keeping accountability.
:::

::: block ram.acceptance
## Risk appetite and acceptance

The risk appetite is a residual score of {{risk.appetite}} or less. {{risk.acceptance_criteria}}

Acceptance is recorded in the platform with the risk owner's identity, the date, the residual score and the rationale.
:::

::: block ram.review
## Review

Each risk is reviewed at least every {{risk.review_months}} months, and the whole assessment is repeated after significant change. Dated snapshots of each assessment are kept as evidence. {{roles.isms_manager}} owns this method.
:::
