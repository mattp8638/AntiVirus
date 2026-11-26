"""AI management rules (ISO/IEC 42001). The risk tiers are the platform's own scheme, informed by common regulatory
approaches; wording is original. This is the AI system register, not AI assistance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

from ._js import js_trim

AI_ROLE_LABEL = {
    "developer": "We develop it",
    "provider": "We supply it to others",
    "deployer": "We use a system built by others",
}
AI_ROLES = tuple(AI_ROLE_LABEL)

# Use-case questions: a "yes" puts the system in at least this tier.
AI_USE_QUESTIONS = (
    ("manipulation", "unacceptable",
     "Influences people in ways they cannot detect, to their harm, or exploits vulnerabilities"),
    ("social_scoring", "unacceptable", "Scores people on social behaviour or personal traits for unrelated treatment"),
    ("biometric", "high", "Identifies or categorizes people from biometric data"),
    ("employment", "high", "Helps decide on recruitment, promotion, tasks or dismissal"),
    ("essential_services", "high",
     "Helps decide access to credit, insurance, housing, benefits or other essential services"),
    ("education", "high", "Helps decide admissions or assess learners"),
    ("safety", "high", "Is a safety component of a product or of critical infrastructure"),
    ("interacts", "limited", "Talks to people directly, such as a chatbot"),
    ("generates", "limited", "Generates text, images, audio or video that others will see"),
    ("emotion", "limited", "Recognizes emotions"),
)
AiRiskTier = Literal["unacceptable", "high", "limited", "minimal"]
AI_TIER_LABEL = {
    "unacceptable": "Unacceptable: do not use",
    "high": "High risk",
    "limited": "Limited risk: transparency needed",
    "minimal": "Minimal risk",
}
_ORDER = ("minimal", "limited", "high", "unacceptable")


def ai_risk_tier(answers: Mapping[str, bool]) -> AiRiskTier:
    tier = "minimal"
    for qid, q_tier, _ in AI_USE_QUESTIONS:
        if answers.get(qid) and _ORDER.index(q_tier) > _ORDER.index(tier):
            tier = q_tier
    return tier


@dataclass(frozen=True)
class AiSystem:
    tier: AiRiskTier
    status: Literal["planned", "in_use", "retired"]
    purpose: str
    human_oversight: str
    personal_data: bool
    processing_linked: bool
    has_approved_assessment: bool
    supplier_linked: bool
    role: str


def ai_system_gaps(s: AiSystem) -> list[str]:
    """Gaps before an AI system is acceptably governed."""
    out: list[str] = []
    if s.status == "retired":
        return out
    if s.tier == "unacceptable":
        out.append("This use is not acceptable. Stop or redesign it before going further.")
    if not js_trim(s.purpose):
        out.append("Describe the intended purpose.")
    if s.tier != "minimal" and not js_trim(s.human_oversight):
        out.append("Describe how people oversee its outputs.")
    if s.personal_data and not s.processing_linked:
        out.append("Link the record of processing for the personal data it uses.")
    if s.tier == "high" and not s.has_approved_assessment:
        out.append("Complete and approve an AI impact assessment.")
    if s.role == "deployer" and not s.supplier_linked:
        out.append("Link the supplier that provides it.")
    return out
