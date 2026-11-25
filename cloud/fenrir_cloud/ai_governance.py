"""AI governance (GRC-21): an inventory of AI systems and use-cases, a risk and impact assessment of each, the human
oversight around it, and its approval and review.

The assessment questions are our own, written for organisations adopting AI under frameworks such as ISO/IEC 42001
and the EU AI Act. The answers suggest a risk tier; a person confirms the tier with a rationale. The suggestion is
not a legal classification, and expert review or certification remain human or provider services.
"""

from __future__ import annotations

TIERS = ("unacceptable", "high", "limited", "minimal")

QUESTIONS = [
    {"id": "manipulation", "text": "Does it influence people's behaviour in ways they are not aware of, or exploit vulnerabilities of a group (age, disability, circumstances)?", "tier": "unacceptable"},
    {"id": "social-scoring", "text": "Does it score or rank people by social behaviour or personal traits to treat them less favourably elsewhere?", "tier": "unacceptable"},
    {"id": "biometric-id", "text": "Does it identify or categorise people from biometric data (face, voice, gait)?", "tier": "high"},
    {"id": "employment", "text": "Is it used to recruit, select, promote, monitor or dismiss staff, or to allocate work?", "tier": "high"},
    {"id": "essential-services", "text": "Does it decide or materially influence access to credit, insurance, housing, education, healthcare or public services?", "tier": "high"},
    {"id": "safety", "text": "Is it a safety component of a product or of critical infrastructure (energy, water, transport)?", "tier": "high"},
    {"id": "legal-decisions", "text": "Does it support decisions in law enforcement, migration, justice or elections?", "tier": "high"},
    {"id": "interacts", "text": "Do people interact with it directly (a chatbot or assistant), or does it generate text, images, audio or video they see?", "tier": "limited"},
    {"id": "personal-data", "text": "Does it process personal data (including in prompts, training or fine-tuning)?", "tier": None},
    {"id": "automated-decision", "text": "Does it make decisions about people without a person reviewing each one?", "tier": None},
    {"id": "customer-data-to-supplier", "text": "Is customer or confidential data sent to the model's supplier, and may the supplier keep or train on it?", "tier": None},
]
OVERSIGHT_NEEDED = {"high": 2, "limited": 1, "unacceptable": 0, "minimal": 0}


def suggest(answers: dict) -> tuple[str, list[str]]:
    """The tier the answers point to, and why (the questions answered yes that set it)."""
    order = {t: i for i, t in enumerate(TIERS)}
    tier, why = "minimal", []
    for q in QUESTIONS:
        if answers.get(q["id"]) is True and q["tier"]:
            why.append(q["text"])
            if order[q["tier"]] < order[tier]:
                tier = q["tier"]
    return tier, why


def findings(s) -> list[str]:
    """What still stands between this system and approval or continued use."""
    out = []
    missing = [q["id"] for q in QUESTIONS if q["id"] not in (s.answers or {})]
    if missing:
        out.append(f"{len(missing)} assessment question(s) unanswered")
    if not s.tier:
        out.append("risk tier not confirmed")
    elif s.tier == "unacceptable":
        out.append("an unacceptable-risk use cannot be approved")
    elif s.suggested_tier and TIERS.index(s.tier) > TIERS.index(s.suggested_tier) and len(s.tier_rationale.strip()) < 20:
        out.append("the confirmed tier is lower than the answers suggest: explain why")
    need = OVERSIGHT_NEEDED.get(s.tier or "", 0)
    if len(s.oversight or []) < need:
        out.append(f"a {s.tier}-risk system needs at least {need} human-oversight measure(s)")
    if (s.answers or {}).get("personal-data") and not s.impacts.strip():
        out.append("personal data is processed: record the impact assessment")
    if (s.answers or {}).get("customer-data-to-supplier") and not s.vendor_id:
        out.append("data goes to the supplier: link the supplier in third-party risk")
    if s.tier == "high" and not s.evidence_ids:
        out.append("a high-risk system needs evidence (testing, data governance, logging)")
    return out
