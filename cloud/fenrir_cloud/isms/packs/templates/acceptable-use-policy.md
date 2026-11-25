---
doc_type: acceptable-use-policy
title: Acceptable use policy
code: AUP
review_months: 12
classification: Internal
licence: original
merge_fields: [organization.legal_name, organization.short_name, roles.isms_manager]
satisfies:
  - { framework: iso27001, ref: A.5.10 }
  - { framework: iso27001, ref: A.6.7 }
  - { framework: iso27001, ref: A.7.7 }
  - { framework: iso27001, ref: A.8.1 }
sections: [aup.purpose, aup.general, aup.devices, aup.remote, aup.reporting, aup.acceptance]
---
::: block aup.purpose
## Purpose

These rules explain how everyone at {{organization.legal_name}} may use its information, systems and equipment. You must accept them before you are given access, and again when they change.
:::

::: block aup.general
## General rules

- Use {{organization.short_name}} systems for work, with limited personal use that does not affect your duties or security.
- Do not try to get around security controls or access information you do not need for your role.
- Keep passwords and authentication codes to yourself.
- Handle information according to its classification label.
- Do not install software that has not been approved.
:::

::: block aup.devices
## Devices

Company devices must stay enrolled in device management, encrypted and up to date. Lock your screen whenever you leave your device, and keep desks clear of confidential papers.
:::

::: block aup.remote
## Working away from the office

When working remotely, use trusted networks or the company VPN, make sure others cannot see your screen and never leave devices unattended in public places.
:::

::: block aup.reporting
## Reporting

Report anything suspicious, including lost devices, phishing emails and mistakes, to {{roles.isms_manager}} straight away. Reporting quickly matters more than being sure.
:::

::: block aup.acceptance
## Acceptance

Breaking these rules may lead to access being removed and disciplinary action. By accepting this policy you confirm you have read and understood it.
:::
