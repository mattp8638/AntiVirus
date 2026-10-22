"""Lifecycle-aware incident response playbook engine for Sentinel/Fenrir.

This package contains the first implementation of the dynamic playbook layer:
- incident lifecycle stages
- question-driven severity changes
- task and evidence generation
- closure gate calculation

It is intentionally self-contained so it can be wired into FastAPI/routes/UI without
risking disruption to the current application structure.
"""

from .engine import (
    IncidentLifecycleEngine,
    PlaybookContext,
    PlaybookResult,
    Question,
    Rule,
    Task,
)

__all__ = [
    "IncidentLifecycleEngine",
    "PlaybookContext",
    "PlaybookResult",
    "Question",
    "Rule",
    "Task",
]
