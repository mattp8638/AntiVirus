"""Questionnaires (supplier security and others), authored as YAML in ``packs/questionnaires``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from .loader import PACKS_ROOT, parse_yaml
from .schema import Questionnaire

QUESTIONNAIRE_DIR = PACKS_ROOT / "questionnaires"


def load_questionnaires(directory: Path = QUESTIONNAIRE_DIR) -> list[Questionnaire]:
    out = []
    for path in sorted(directory.glob("*.yaml")):
        errors: list[str] = []
        data = parse_yaml(path.read_text(encoding="utf-8"), str(path), errors)
        if errors:
            raise ValueError("; ".join(errors))
        out.append(Questionnaire.model_validate(data))
    return out


@lru_cache(maxsize=1)
def questionnaires() -> dict[str, Questionnaire]:
    return {q.id: q for q in load_questionnaires()}
