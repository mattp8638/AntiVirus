"""Content pack schemas. Unknown fields are rejected everywhere, so a restricted item cannot smuggle in extra text."""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, StringConstraints, model_validator

# Licence basis values. Restricted licences allow identifiers and short titles only.
LICENCE_VALUES = ("original", "id-and-title", "open", "crown-copyright-pending")
RESTRICTED_LICENCES = ("id-and-title", "crown-copyright-pending")
_LICENSED = re.compile(r"^licensed:[A-Za-z0-9._-]+$")

# Short titles stay under 80 characters to keep packs at identifier and title level.
SHORT_TITLE_MAX = 80


def _licence(v: str) -> str:
    if v in LICENCE_VALUES or _LICENSED.match(v):
        return v
    raise ValueError(f'unknown licence "{v}" (expected {", ".join(LICENCE_VALUES)} or licensed:<agreement-ref>)')


Licence = Annotated[StrictStr, AfterValidator(_licence)]
Kebab = Annotated[StrictStr, StringConstraints(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")]
Semver = Annotated[StrictStr, StringConstraints(pattern=r"^\d+\.\d+\.\d+$")]
NonEmpty = Annotated[StrictStr, StringConstraints(min_length=1)]


class Strict(BaseModel):
    """Rejects unknown fields. Scalars are strict (no "yes" for true, no "5" for 5); YAML lists become tuples."""
    model_config = ConfigDict(extra="forbid", frozen=True)


class PackMeta(Strict):
    id: Kebab
    kind: Literal["framework", "control-library", "templates"]
    title: NonEmpty | None = None
    framework: Kebab | None = None
    name: NonEmpty | None = None
    publisher: NonEmpty | None = None
    version: NonEmpty | None = None
    pack_version: Semver
    certifiable: StrictBool | None = None
    licence: Licence
    attribution: StrictStr | None = None
    depends_on: tuple[Kebab, ...] | None = None
    requires_modules: tuple[Kebab, ...] | None = None  # platform modules locked on for this framework

    @model_validator(mode="after")
    def _kind_fields(self) -> PackMeta:
        if self.kind == "framework":
            missing = [f for f in ("framework", "name", "version") if not getattr(self, f)]
            if missing:
                raise ValueError(f'framework packs need {", ".join(missing)}')
            if self.certifiable is None:
                raise ValueError('framework packs need "certifiable"')
        if self.kind == "control-library" and not self.version:
            raise ValueError('control libraries need "version"')
        return self


class Group(Strict):
    ref: NonEmpty
    parent: NonEmpty | None = None
    title: NonEmpty
    sort: StrictInt | None = None
    licence: Licence


class Requirement(Strict):
    ref: NonEmpty
    group: NonEmpty
    short_title: NonEmpty
    mandatory: StrictBool = False
    guidance: StrictStr | None = None  # original wording only
    text: StrictStr | None = None  # full requirement text, only where the licence permits it
    licence: Licence


EvidenceType = Literal["document", "record", "screenshot", "configuration", "report", "log", "attestation"]
Frequency = Literal["continuous", "daily", "weekly", "monthly", "quarterly", "six-monthly", "annual", "event-driven"]


class CommonControl(Strict):
    ref: Annotated[StrictStr, StringConstraints(pattern=r"^CC-[A-Z]{2,5}-\d{2,3}$")]
    title: Annotated[StrictStr, StringConstraints(min_length=1, max_length=120)]
    statement: NonEmpty
    test_procedure: NonEmpty
    default_frequency: Frequency
    evidence_types: Annotated[tuple[EvidenceType, ...], Field(min_length=1)]
    licence: Licence


class Mapping(Strict):
    requirement: NonEmpty
    control: NonEmpty
    strength: Literal["satisfies", "partial", "related"]
    rationale: NonEmpty
    licence: Licence


class Option(Strict):
    value: NonEmpty
    label: NonEmpty


class Question(Strict):
    ref: Annotated[StrictStr, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
    text: NonEmpty
    help: StrictStr | None = None
    type: Literal["bool", "single", "multi", "number"]
    options: tuple[Option, ...] | None = None
    licence: Licence

    @model_validator(mode="after")
    def _options(self) -> Question:
        needs = self.type in ("single", "multi")
        if needs and not self.options:
            raise ValueError(f"{self.type} questions need options")
        if not needs and self.options is not None:
            raise ValueError(f"{self.type} questions take no options")
        return self


class RuleTarget(Strict):
    type: Literal["group", "requirement", "control", "template_section"]
    ref: NonEmpty


class Rule(Strict):
    ref: Annotated[StrictStr, StringConstraints(pattern=r"^R-[A-Z0-9]+-\d{2,3}$")]
    reason: NonEmpty
    when: Any = None  # a missing "when" is reported by the validator
    effect: Literal["include", "exclude", "require"]
    targets: Annotated[tuple[RuleTarget, ...], Field(min_length=1)]
    licence: Licence


class Satisfies(Strict):
    framework: NonEmpty
    ref: NonEmpty


class TemplateFrontMatter(Strict):
    doc_type: Kebab
    title: NonEmpty
    code: Annotated[StrictStr, StringConstraints(pattern=r"^[A-Z]{2,5}$")] | None = None  # e.g. POL in HAL-POL-001
    review_months: Annotated[StrictInt, Field(ge=1, le=36)] | None = None
    classification: Literal["Public", "Internal", "Confidential"] | None = None
    licence: Licence
    merge_fields: tuple[NonEmpty, ...] = ()
    satisfies: tuple[Satisfies, ...] = ()
    sections: tuple[NonEmpty, ...] = ()


class QuestionnaireQuestion(Strict):
    ref: Annotated[StrictStr, StringConstraints(pattern=r"^q-[a-z0-9-]+$")]
    text: NonEmpty
    weight: Annotated[StrictInt, Field(ge=1, le=5)]
    critical: StrictBool | None = None


class Questionnaire(Strict):
    id: Annotated[StrictStr, StringConstraints(pattern=r"^[a-z0-9-]+$")]
    title: NonEmpty
    version: Semver
    licence: Licence
    questions: Annotated[tuple[QuestionnaireQuestion, ...], Field(min_length=1)]
