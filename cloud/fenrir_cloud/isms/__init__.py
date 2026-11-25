"""ISMS: the information security management system inside Fenrir Governance.

Ported from the standalone ISMS Platform (frozen at ``mattp8638/ISMS``, branch ``standalone-release``). See
``docs/ISMS_REWRITE_PLAN.md`` for the plan and the decisions behind it.

* ``domain``: pure logic (applicability, scoring, risk maths). No database, FastAPI or settings imports.
* ``content``: content pack schema, loader and validator. Frameworks, controls, mappings, rules and templates are
  data under ``packs/``, never code.
"""
