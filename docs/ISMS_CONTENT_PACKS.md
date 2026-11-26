# ISMS content packs

Frameworks, common controls, mappings, onboarding questions, applicability rules and document templates are data, kept in `cloud/fenrir_cloud/isms/packs/`. Nothing about a framework is written into code: the ISO 27001 pack loads the same way as every other pack.

The packs came from the standalone ISMS Platform unchanged. The format is described in that project's `docs/04-content-packs.md`; this page covers what you need to change a pack in Fenrir.

## Licence basis

Every pack and every item in it has a `licence` field. The tests fail if one is missing.

| Value | Allowed content |
| --- | --- |
| `original` | Anything (written for this project) |
| `id-and-title` | Identifiers and short titles only; guidance must be original wording. Used for ISO and IEC packs |
| `crown-copyright-pending` | As `id-and-title`, until reuse terms are confirmed. Used for Cyber Essentials and NCSC CAF |
| `open` | Full text, with an `attribution` on the pack. Used for NIST CSF 2.0 and UK GDPR |
| `licensed:<agreement-ref>` | As the signed agreement allows |

Never add normative text, control statements or guidance copied from a standard. Short titles stay under 80 characters.

## Layout

```
packs/
  common-controls/     the platform's own control library (original wording)
  iso27001-2022/       pack.yaml, groups, requirements, questions, rules, mappings
  ...                  one folder per framework edition
  templates/           document templates (Markdown with front matter and ::: block sections)
  questionnaires/      supplier security questionnaire
```

## Checking a change

```bash
cd cloud && python3 -m pytest -q tests/test_isms_content.py
```

The check covers:

- every schema;
- unique refs;
- that every reference resolves (groups, controls, questions, template blocks);
- that rules never target a mandatory requirement or a group holding one;
- that rule conditions use only the supported operators;
- that template placeholders are declared;
- that no file contains an em dash.

YAML is read with `true` and `false` as the only booleans (so `no` stays text) and duplicate keys are an error.
