"""ISMS content packs: schema, loader and validator.

Packs live in ``fenrir_cloud/isms/packs`` (see ``docs/ISMS_CONTENT_PACKS.md``). Every pack and every item records its
licence basis; ``tests/test_isms_content.py`` fails if any item lacks one or if a restricted item carries more than an
identifier, a short title and original guidance.
"""

from .loader import PACKS_ROOT, find_pack_dirs, load_pack
from .validate import ValidationResult, validate_packs

__all__ = ["PACKS_ROOT", "ValidationResult", "find_pack_dirs", "load_pack", "validate_packs"]
