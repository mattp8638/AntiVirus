"""Scanning package exposing granular helpers.

The manager module pulls in a wide range of optional dependencies.  Importing
it unconditionally during package initialisation makes lightweight utilities –
like the word‑list brute forcers – difficult to test in isolation.  To keep the
package importable in minimal environments we attempt the import but gracefully
fall back to ``None`` if it fails.  Consumers that require the full scanning
manager can import :mod:`core.scanning.manager` directly.
"""

try:  # pragma: no cover - defensive to allow isolated testing
    from .manager import Scanning  # type: ignore
except Exception:  # pragma: no cover - the high level manager is optional here
    Scanning = None  # type: ignore

__all__ = ["Scanning"]
