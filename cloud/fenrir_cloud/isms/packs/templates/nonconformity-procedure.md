---
doc_type: nonconformity-procedure
title: Nonconformity and corrective action procedure
code: NCP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, roles.isms_manager, improvement]
satisfies:
  - { framework: iso27001, ref: "10.1" }
  - { framework: iso27001, ref: "10.2" }
sections: [ncp.purpose, ncp.raise, ncp.correct, ncp.cause, ncp.effectiveness, ncp.improve, ncp.status]
---
::: block ncp.purpose
## Purpose

This procedure explains how {{organization.legal_name}} deals with nonconformities, removes their causes so they do not happen again, and keeps improving its ISMS.
:::

::: block ncp.raise
## Raising a nonconformity

Anyone can report a suspected failure to meet our policies, procedures, contracts, the law or the standards we follow. Nonconformities come from internal and external audits, incidents, monitoring, management review and complaints. Each is recorded in the improvement register with a reference, its source, the requirement affected, a severity (minor or major) and an owner.
:::

::: block ncp.correct
## Correction

The owner first contains the problem and deals with its consequences, for example by disabling an account or restoring a backup. The correction is recorded straight away.
:::

::: block ncp.cause
## Root cause and corrective action

The owner then works out why it happened and whether similar problems exist or could occur elsewhere, and records the root cause. Corrective actions are planned to remove the cause, each with an owner and a due date. Overdue actions are reported to the ISMS manager ({{roles.isms_manager}}) and to top management.
:::

::: block ncp.effectiveness
## Effectiveness check

Once every action is complete, the ISMS manager checks whether the actions worked, for example by sampling records over the following months. A nonconformity is closed only when the check shows the actions were effective; otherwise further action is planned. The platform will not close a nonconformity without a root cause and a positive effectiveness check, and records are never deleted.
:::

::: block ncp.improve
## Continual improvement

Improvement opportunities are recorded in the same register and closed with a note on the outcome. Trends in nonconformities and improvements are reviewed at management review.
:::

::: block ncp.status
## Current position

{{improvement.open}} nonconformities are open, {{improvement.closed}} have been closed after an effectiveness check, and {{improvement.opportunities}} improvement opportunities are open.
:::
